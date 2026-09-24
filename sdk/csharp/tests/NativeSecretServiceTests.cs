using System.Buffers.Binary;
using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Orbit.Sdk;
using static SecretServiceTests;

internal static class NativeSecretServiceTests
{
    internal static async Task<int> RunAsync()
    {
        var stage = "isolated fixture authorization";
        string? root = null;
        var result = 1;
        try
        {
            var fixture = Fixture();
            root = CreatePrivate(Path.Combine(fixture, "csharp-storage-" + Guid.NewGuid().ToString("N")));
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(120));
            stage = "private lease boundaries";
            await LeaseAsync(deadline.Token);
            stage = "bounded helper termination and redaction";
            await HelperAsync(deadline.Token);
            stage = "keyring persistence and contention";
            var directory = CreatePrivate(Path.Combine(root, "state"));
            var scope = SecretTool.Scope(Config, TestDevice, directory);
            using (var storage = SecretServiceStorage.Open(directory, Config, TestDevice))
            {
                Require(storage.Version == 0 && storage.Load().Credential == null);
                Require(storage.Capability == StorageCapability.OperatingSystemProtected);
                ExpectStorage(() => SecretServiceStorage.Open(directory, Config, TestDevice));
                await ChildAsync("blocked", directory, deadline.Token);
                storage.Save(0, Credential());
                CheckEncryptedFixture(fixture, ProtectedStorageCodec.Encode(0, Credential(), Config, TestDevice));
                Require(storage.Load().Credential?.Credential == Secret && storage.Version == 0);
                Require(storage.Invalidate() == 1 && storage.Load().Credential == null);
                ExpectError(OrbitError.StaleResponse, () => storage.Save(0, Credential()));
                storage.Save(1, Credential());
                Require(!storage.ToString().Contains(Secret, StringComparison.Ordinal) &&
                    !JsonSerializer.Serialize(storage).Contains(Secret, StringComparison.Ordinal));
                await ChildAsync("blocked", directory, deadline.Token);
                storage.Dispose();
                ExpectClosed(storage);
            }
            using (var reopened = SecretServiceStorage.Open(directory, Config, TestDevice))
                Require(reopened.Version == 1 && reopened.Load().Credential?.Credential == Secret);
            stage = "scope corruption and missing item rejection";
            ScopeAndCorruption(directory, scope);
            stage = "durable uncertain-store rejection";
            var pending = CreatePrivate(Path.Combine(root, "pending"));
            using (var storage = SecretServiceStorage.Open(pending, Config, TestDevice)) storage.Save(0, Credential());
            using (var lease = LinuxStorageLease.Open(pending)) lease.BeginWrite();
            ExpectStorage(() => SecretServiceStorage.Open(pending, Config, TestDevice));
            Require(File.ReadAllBytes(Path.Combine(pending, LinuxStorageLease.Name)).SequenceEqual(new byte[] { 1 }));
            stage = "cache and failed-write poisoning";
            HelperFailure(root, timeout: false);
            stage = "actual store-helper deadline and reopen rejection";
            HelperFailure(root, timeout: true);
            stage = "live lease replacement rejection";
            using (var storage = SecretServiceStorage.Open(directory, Config, TestDevice))
            {
                var path = Path.Combine(directory, LinuxStorageLease.Name);
                File.Move(path, path + ".old");
                try
                {
                    PrivateEmpty(path);
                    ExpectStorage(() => storage.Load());
                }
                finally { File.Delete(path); File.Move(path + ".old", path); }
                ExpectClosed(storage);
            }
            stage = "process exit restart and invalidation";
            var restart = CreatePrivate(Path.Combine(root, "restart"));
            await ChildAsync("write-and-exit", restart, deadline.Token);
            await ChildAsync("read-invalidate", restart, deadline.Token);
            await ChildAsync("tombstone", restart, deadline.Token);
            stage = "generation exhaustion and concurrent invalidation";
            var maximum = ProtectedStorageCodec.Encode(long.MaxValue, null, Config, TestDevice);
            try { SecretTool.Store(scope, maximum); }
            finally { CryptographicOperations.ZeroMemory(maximum); }
            using (var storage = SecretServiceStorage.Open(directory, Config, TestDevice))
            {
                Require(storage.Version == long.MaxValue);
                ExpectStorage(() => storage.Invalidate());
                ExpectClosed(storage);
            }
            var race = CreatePrivate(Path.Combine(root, "race"));
            using (var storage = SecretServiceStorage.Open(race, Config, TestDevice))
            {
                var save = Task.Run(() =>
                {
                    try { storage.Save(0, Credential()); }
                    catch (OrbitException error) when (error.Error == OrbitError.StaleResponse) { }
                }, deadline.Token);
                await Task.WhenAll(save, Task.Run(() => storage.Invalidate(), deadline.Token));
                Require(storage.Version == 1 && storage.Load().Credential == null);
            }
            foreach (var path in Directory.GetFiles(root, "*", SearchOption.AllDirectories))
            {
                var bytes = File.ReadAllBytes(path);
                Require(Path.GetFileName(path) == LinuxStorageLease.Name && (bytes.Length == 0 || bytes.SequenceEqual(new byte[] { 1 })));
            }
            Console.WriteLine("PASS: isolated Linux Secret Service persistence, leases, restart, corruption and helper boundaries.");
            result = 0;
        }
        catch (Exception)
        {
            Console.Error.WriteLine("FAIL: Linux Secret Service " + stage + ".");
        }
        finally
        {
            // The harness owns the disposable encrypted keyring and all items.
            try { if (root != null) Directory.Delete(root, recursive: true); }
            catch (Exception) { Console.Error.WriteLine("FAIL: Linux Secret Service fixture cleanup."); result = 1; }
        }
        return result;
    }

    private static void HelperFailure(string root, bool timeout)
    {
        var directory = CreatePrivate(Path.Combine(root, timeout ? "timeout" : "unavailable"));
        var socketPath = Path.Combine(directory, "bus");
        using (var storage = SecretServiceStorage.Open(directory, Config, TestDevice))
        {
            storage.Save(0, Credential());
            using var listener = timeout ? new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified) : null;
            if (listener != null)
            {
                // Accept connections at the kernel boundary but never answer
                // D-Bus authentication, so the actual secret-tool must time out.
                listener.Bind(new UnixDomainSocketEndPoint(socketPath));
                listener.Listen(1);
            }
            var bus = Environment.GetEnvironmentVariable("DBUS_SESSION_BUS_ADDRESS");
            try
            {
                Environment.SetEnvironmentVariable("DBUS_SESSION_BUS_ADDRESS", "unix:path=" + socketPath);
                Require(storage.Version == 0 && storage.Load().Credential?.Credential == Secret &&
                    storage.Capability == StorageCapability.OperatingSystemProtected);
                var elapsed = Stopwatch.StartNew();
                ExpectStorage(() => storage.Save(0, Credential()));
                if (timeout) Require(elapsed.Elapsed >= TimeSpan.FromSeconds(4) && elapsed.Elapsed < TimeSpan.FromSeconds(8));
            }
            finally
            {
                Environment.SetEnvironmentVariable("DBUS_SESSION_BUS_ADDRESS", bus);
                listener?.Dispose();
                File.Delete(socketPath);
            }
            ExpectClosed(storage);
        }
        ExpectStorage(() => SecretServiceStorage.Open(directory, Config, TestDevice));
        Require(File.ReadAllBytes(Path.Combine(directory, LinuxStorageLease.Name)).SequenceEqual(new byte[] { 1 }));
    }

    private static void ScopeAndCorruption(string directory, string scope)
    {
        var original = SecretTool.Lookup(scope) ?? throw new InvalidOperationException("Fixture item missing");
        try
        {
            foreach (var changed in new[] { Config with { ApplicationId = "other" }, Config with { EnvironmentId = "live" }, Config with { Issuer = Config.Issuer + "/" } })
                ExpectStorage(() => SecretServiceStorage.Open(directory, changed, TestDevice));
            ExpectStorage(() => SecretServiceStorage.Open(directory, Config, TestDevice with { InstallationId = "another_installation" }));
            ExpectStorage(() => SecretServiceStorage.Open(directory, Config, TestDevice with { Fingerprint = new string('a', 64), FingerprintProvider = "machine_v1" }));
            var wrong = ProtectedStorageCodec.Encode(1, null, Config with { ApplicationId = "other" }, TestDevice);
            var unknown = original.ToArray();
            BinaryPrimitives.WriteInt64BigEndian(unknown.AsSpan("Orbit.CSharp.Storage\0"u8.Length), 2);
            foreach (var corrupt in new[] { wrong, unknown, original[..^1], "not a record"u8.ToArray() })
            {
                try
                {
                    SecretTool.Store(scope, corrupt);
                    ExpectStorage(() => SecretServiceStorage.Open(directory, Config, TestDevice));
                    var retained = SecretTool.Lookup(scope)!;
                    try { Require(retained.SequenceEqual(corrupt)); }
                    finally { CryptographicOperations.ZeroMemory(retained); }
                }
                finally { CryptographicOperations.ZeroMemory(corrupt); }
            }
            foreach (var malformed in new[] { "not base64"u8.ToArray(), Encoding.ASCII.GetBytes(Convert.ToBase64String(new byte[4097])) })
            {
                using var result = SecretTool.Run(SecretTool.Command(scope, store: true), malformed, SecretTool.Deadline);
                SecretTool.CheckStored(result);
                ExpectStorage(() => SecretServiceStorage.Open(directory, Config, TestDevice));
            }
            var clear = SecretTool.Command(scope, store: false);
            clear.ArgumentList[0] = "clear"; // Only this opt-in fixture removes its synthetic item.
            using (var result = SecretTool.Run(clear, [], SecretTool.Deadline)) SecretTool.CheckStored(result);
            ExpectStorage(() => SecretServiceStorage.Open(directory, Config, TestDevice));
            Require(SecretTool.Lookup(scope) == null);
        }
        finally
        {
            try { SecretTool.Store(scope, original); }
            finally { CryptographicOperations.ZeroMemory(original); }
        }
    }

    private static void CheckEncryptedFixture(string fixture, byte[] record)
    {
        byte[]? encoded = null;
        try
        {
            if (!OperatingSystem.IsLinux()) throw new InvalidOperationException("Linux fixture required");
            encoded = SecretTool.Encode(record);
            var files = Directory.GetFiles(Path.Combine(fixture, "data", "keyrings"), "*.keyring");
            Require(files.Length > 0);
            foreach (var path in files)
            {
                var metadata = new FileInfo(path);
                Require((metadata.Attributes & FileAttributes.ReparsePoint) == 0 && metadata.Length is > 0 and <= 1_048_576 &&
                    (File.GetUnixFileMode(path) & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
                        UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) == 0);
                var bytes = File.ReadAllBytes(path);
                try { Require(bytes.AsSpan().IndexOf(encoded) < 0 && bytes.AsSpan().IndexOf(Encoding.UTF8.GetBytes(Secret)) < 0); }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(record);
            if (encoded != null) CryptographicOperations.ZeroMemory(encoded);
        }
    }

    private static string Fixture()
    {
        if (!LinuxStorageLease.Supported || Environment.GetEnvironmentVariable("ORBIT_NATIVE_STORAGE_TEST") != "1")
            throw new InvalidOperationException("Isolated Linux fixture required");
        var root = Environment.GetEnvironmentVariable("ORBIT_KEYRING_FIXTURE") ?? "";
        if (!root.StartsWith("/tmp/orbit-keyring-session-", StringComparison.Ordinal) || LinuxStorageLease.Normalize(root) != root)
            throw new InvalidOperationException("Isolated Linux fixture required");
        LinuxStorageLease.CheckPrivateDirectory(root);
        foreach (var pair in new[] { ("XDG_DATA_HOME", "data"), ("XDG_CONFIG_HOME", "config"), ("XDG_CACHE_HOME", "cache"),
            ("XDG_RUNTIME_DIR", "runtime"), ("GNOME_KEYRING_CONTROL", "control") })
        {
            var path = Path.Combine(root, pair.Item2);
            if (Environment.GetEnvironmentVariable(pair.Item1) != path) throw new InvalidOperationException("Isolated Linux fixture required");
            LinuxStorageLease.CheckPrivateDirectory(path);
        }
        var bus = Environment.GetEnvironmentVariable("DBUS_SESSION_BUS_ADDRESS");
        if (bus == null || bus.Length > 4096 || !bus.StartsWith("unix:", StringComparison.Ordinal))
            throw new InvalidOperationException("Isolated Linux fixture required");
        return root;
    }

    private static async Task ChildAsync(string action, string directory, CancellationToken cancellationToken)
    {
        var start = ChildStart("--secret-storage-child", action, directory);
        start.UseShellExecute = false;
        start.RedirectStandardOutput = start.RedirectStandardError = true;
        using var process = Process.Start(start) ?? throw new InvalidOperationException("Fixture process unavailable");
        try { await process.WaitForExitAsync(cancellationToken); Require(process.ExitCode == 0); }
        finally { if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(); } }
    }

    internal static int Child(string action, string directory)
    {
        try
        {
            var fixture = Fixture();
            if (!directory.StartsWith(fixture + "/csharp-storage-", StringComparison.Ordinal) || LinuxStorageLease.Normalize(directory) != directory)
                return 2;
            LinuxStorageLease.CheckPrivateDirectory(directory);
            if (action == "blocked") { ExpectStorage(() => SecretServiceStorage.Open(directory, Config, TestDevice)); return 0; }
            if (action is not ("write-and-exit" or "read-invalidate" or "tombstone")) return 2;
            using var storage = SecretServiceStorage.Open(directory, Config, TestDevice);
            switch (action)
            {
                case "write-and-exit": storage.Save(0, Credential()); Environment.Exit(0); break;
                case "read-invalidate": Require(storage.Load().Credential?.Credential == Secret); Require(storage.Invalidate() == 1); break;
                case "tombstone": Require(storage.Version == 1 && storage.Load().Credential == null); break;
            }
            return 0;
        }
        catch (Exception) { Console.Error.WriteLine("Native Secret Service child failed"); return 1; }
    }
}
