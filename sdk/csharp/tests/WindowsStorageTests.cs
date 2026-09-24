using System.Buffers.Binary;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using Orbit.Sdk;

internal static class WindowsStorageTests
{
    private static readonly OrbitConfig Config = new("app", "test", "https://orbit.example.test");
    private static readonly Device Device = new("installation_1234");
    private static readonly string Secret = new('s', 43);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);

    private static StoredCredential Credential(OrbitConfig? config = null, Device? device = null, string? secret = null) => new()
    {
        ApplicationId = (config ?? Config).ApplicationId, EnvironmentId = (config ?? Config).EnvironmentId,
        InstallationId = (device ?? Device).InstallationId, Fingerprint = (device ?? Device).Fingerprint,
        FingerprintProvider = (device ?? Device).FingerprintProvider, ActivationId = "activation", LicenceId = "licence",
        Credential = secret ?? Secret, CredentialExpiresAt = 1_900_000_000
    };

    internal static Task CodecAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var expected = SHA256.HashData(Encoding.UTF8.GetBytes(
            "orbit.sdk.storage.v1\0\0\0\0\u0006issuer\0\0\0\u0003app\0\0\0\u0004test\0\0\0\u0011installation_1234"));
        Require(ProtectedStorageCodec.Entropy(Config with { Issuer = "issuer" }, Device).SequenceEqual(expected));
        Require(!ProtectedStorageCodec.Entropy(Config with { ApplicationId = "ab", EnvironmentId = "c" }, Device)
            .SequenceEqual(ProtectedStorageCodec.Entropy(Config with { ApplicationId = "a", EnvironmentId = "bc" }, Device)));
        var valid = ProtectedStorageCodec.Encode(7, Credential(), Config, Device);
        var decoded = ProtectedStorageCodec.Decode(valid, Config, Device);
        Require(decoded.Version == 7 && decoded.Credential?.Credential == Secret && decoded.Credential.ActivationId == "activation");
        foreach (var version in new long[] { 0, long.MaxValue })
        {
            var tombstone = ProtectedStorageCodec.Decode(ProtectedStorageCodec.Encode(version, null, Config, Device), Config, Device);
            Require(tombstone.Version == version && tombstone.Credential == null);
        }
        var bound = Device with { Fingerprint = new string('a', 64), FingerprintProvider = "custom:device.v1" };
        var boundBytes = ProtectedStorageCodec.Encode(3, Credential(device: bound), Config, bound);
        Require(ProtectedStorageCodec.Decode(boundBytes, Config, bound).Credential?.Fingerprint == bound.Fingerprint);
        ExpectStorage(() => ProtectedStorageCodec.Decode(boundBytes, Config, Device));
        ExpectStorage(() => ProtectedStorageCodec.Decode(ProtectedStorageCodec.Encode(0, null, Config, bound), Config, Device));
        foreach (var changed in new[] { Config with { ApplicationId = "other" }, Config with { EnvironmentId = "live" }, Config with { Issuer = Config.Issuer + "/" } })
            ExpectStorage(() => ProtectedStorageCodec.Decode(valid, changed, Device));
        ExpectStorage(() => ProtectedStorageCodec.Decode(valid, Config, Device with { InstallationId = "another_installation" }));
        for (var size = 0; size < valid.Length; size++)
        {
            var truncated = valid[..size];
            ExpectStorage(() => ProtectedStorageCodec.Decode(truncated, Config, Device));
        }
        ExpectStorage(() => ProtectedStorageCodec.Decode([.. valid, 0], Config, Device));
        ExpectStorage(() => ProtectedStorageCodec.Decode(new byte[ProtectedStorageCodec.MaximumPlaintext + 1], Config, Device));
        var magicLength = Encoding.UTF8.GetByteCount("Orbit.CSharp.Storage\0");
        var unknown = (byte[])valid.Clone();
        BinaryPrimitives.WriteInt64BigEndian(unknown.AsSpan(magicLength), 2);
        ExpectStorage(() => ProtectedStorageCodec.Decode(unknown, Config, Device));
        var negative = (byte[])valid.Clone();
        BinaryPrimitives.WriteInt64BigEndian(negative.AsSpan(magicLength + 8), -1);
        ExpectStorage(() => ProtectedStorageCodec.Decode(negative, Config, Device));
        var incompatible = (byte[])valid.Clone();
        incompatible[0] ^= 1;
        ExpectStorage(() => ProtectedStorageCodec.Decode(incompatible, Config, Device));
        var invalidUtf8 = (byte[])valid.Clone();
        // Magic + format/generation + scope hash + two nullable markers + state marker + string length.
        invalidUtf8[magicLength + 16 + 32 + 3 + 4] = 0xff;
        ExpectStorage(() => ProtectedStorageCodec.Decode(invalidUtf8, Config, Device));
        var excessiveLength = (byte[])valid.Clone();
        BinaryPrimitives.WriteUInt32BigEndian(excessiveLength.AsSpan(magicLength + 16 + 32 + 3), uint.MaxValue);
        ExpectStorage(() => ProtectedStorageCodec.Decode(excessiveLength, Config, Device));
        ExpectStorage(() => ProtectedStorageCodec.Encode(-1, null, Config, Device));
        ExpectStorage(() => ProtectedStorageCodec.Encode(0, Credential(secret: "invalid"), Config, Device));
        ExpectStorage(() => ProtectedStorageCodec.Encode(0, Credential(config: Config with { ApplicationId = "other" }), Config, Device));
        foreach (var bad in new[] { Device with { Fingerprint = "raw-identifier" }, Device with { FingerprintProvider = "machine_v1" },
                                   Device with { Fingerprint = new string('a', 64), FingerprintProvider = "custom:INVALID" } })
            ExpectStorage(() => ProtectedStorageCodec.Entropy(Config, bad));
        Require(!Credential().ToString().Contains(Secret, StringComparison.Ordinal));
        string? json = null;
        try { json = JsonSerializer.Serialize(Credential()); }
        catch (InvalidOperationException)
        {
            // System.Text.Json may reject the existing required/JsonIgnore
            // combination entirely. Keep that fail-closed public guard intact.
        }
        if (json != null)
        {
            Require(!json.Contains(Secret, StringComparison.Ordinal));
            using var document = JsonDocument.Parse(json);
            Require(!document.RootElement.TryGetProperty("Credential", out _));
        }
        if (!OperatingSystem.IsWindows()) ExpectStorage(() => WindowsStorage.Open("relative", Config, Device));
        return Task.CompletedTask;
    }

    internal static async Task NativeAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.WriteLine("SKIP: Windows storage persistence and leases require native Windows.");
            return;
        }
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OrbitStorageChecks", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            ExpectStorage(() => WindowsStorage.Open("relative", Config, Device));
            ExpectStorage(() => WindowsStorage.Open(Path.Combine(root, "missing"), Config, Device));
            var directory = Directory.CreateDirectory(Path.Combine(root, "state")).FullName;
            var data = Path.Combine(directory, WindowsStorage.DataName);
            var lease = Path.Combine(directory, WindowsStorage.LockName);
            using (var storage = WindowsStorage.Open(directory, Config, Device))
            {
                Require(storage.Version == 0 && storage.Load().Credential == null && File.Exists(data));
                Require(storage.Capability == StorageCapability.OperatingSystemProtected);
                ExpectStorage(() => WindowsStorage.Open(directory, Config, Device));
                await ChildAsync("blocked", directory, cancellationToken);
                storage.Save(0, Credential());
                Require(storage.Load().Credential?.Credential == Secret && storage.Version == 0);
                Require(storage.Invalidate() == 1 && storage.Load().Credential == null);
                ExpectError(OrbitError.StaleResponse, () => storage.Save(0, Credential()));
                await ChildAsync("blocked", directory, cancellationToken);
                storage.Save(1, Credential());
                Require(!storage.ToString().Contains(Secret, StringComparison.Ordinal));
                Require(!JsonSerializer.Serialize(storage).Contains(Secret, StringComparison.Ordinal));
                AssertCiphertextOnly(directory);
                storage.Dispose();
                ExpectClosed(storage);
            }
            Require(File.Exists(lease) && File.ReadAllBytes(lease).Length == 0);
            using (var reopened = WindowsStorage.Open(directory, Config, Device))
                Require(reopened.Version == 1 && reopened.Load().Credential?.Credential == Secret);
            var original = File.ReadAllBytes(data);
            foreach (var changed in new[] { Config with { ApplicationId = "other" }, Config with { EnvironmentId = "live" }, Config with { Issuer = Config.Issuer + "/" } })
                ExpectStorage(() => WindowsStorage.Open(directory, changed, Device));
            ExpectStorage(() => WindowsStorage.Open(directory, Config, Device with { InstallationId = "another_installation" }));
            ExpectStorage(() => WindowsStorage.Open(directory, Config, Device with { Fingerprint = new string('a', 64), FingerprintProvider = "machine_v1" }));
            Require(File.ReadAllBytes(data).SequenceEqual(original));
            var tampered = (byte[])original.Clone();
            tampered[^1] ^= 255;
            foreach (var corrupt in new[] { tampered, original[..(original.Length / 2)], Array.Empty<byte>(), new byte[65537], Encoding.UTF8.GetBytes("invalid ciphertext") })
            {
                File.WriteAllBytes(data, corrupt);
                ExpectStorage(() => WindowsStorage.Open(directory, Config, Device));
                Require(File.ReadAllBytes(data).SequenceEqual(corrupt));
            }
            File.Delete(data);
            ExpectStorage(() => WindowsStorage.Open(directory, Config, Device));
            Require(!File.Exists(data)); // Existing lease never silently resets deleted state.
            File.WriteAllBytes(data, original);
            using (var storage = WindowsStorage.Open(directory, Config, Device))
            {
                using (var denyReplacement = new FileStream(data, FileMode.Open, FileAccess.Read, FileShare.Read))
                    ExpectStorage(() => storage.Save(1, Credential()));
                ExpectClosed(storage); // Failed write poisons every operation, even after the blocker closes.
                Require(File.ReadAllBytes(data).SequenceEqual(original));
                AssertCiphertextOnly(directory);
            }
            using (var reopened = WindowsStorage.Open(directory, Config, Device))
                Require(reopened.Load().Credential?.Credential == Secret);
            using (var storage = WindowsStorage.Open(directory, Config, Device))
            {
                File.WriteAllBytes(data, tampered);
                ExpectStorage(() => storage.Load());
                File.WriteAllBytes(data, original);
                ExpectClosed(storage); // Repairing a file does not revive a poisoned object.
            }
            var restart = Directory.CreateDirectory(Path.Combine(root, "restart")).FullName;
            await ChildAsync("write-and-exit", restart, cancellationToken);
            await ChildAsync("read-invalidate", restart, cancellationToken);
            await ChildAsync("tombstone", restart, cancellationToken);
            var abandoned = Directory.CreateDirectory(Path.Combine(root, "abandoned")).FullName;
            File.WriteAllBytes(Path.Combine(abandoned, WindowsStorage.LockName), []);
            ExpectStorage(() => WindowsStorage.Open(abandoned, Config, Device));
            var maximum = WindowsDataProtection.Protect(ProtectedStorageCodec.Encode(long.MaxValue, null, Config, Device), ProtectedStorageCodec.Entropy(Config, Device));
            File.WriteAllBytes(data, maximum);
            using (var storage = WindowsStorage.Open(directory, Config, Device))
            {
                Require(storage.Version == long.MaxValue);
                ExpectStorage(() => storage.Invalidate());
                ExpectClosed(storage);
            }
            await RaceAsync(Directory.CreateDirectory(Path.Combine(root, "race")).FullName, cancellationToken);
            CheckHandleReplacement(root);
            CheckDirectoryValidation(root);
            CheckReparse(root, directory);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private static void CheckHandleReplacement(string root)
    {
        var directory = Directory.CreateDirectory(Path.Combine(root, "handle-replacement")).FullName;
        var data = Path.Combine(directory, WindowsStorage.DataName);
        var temporary = Path.Combine(directory, "replacement.tmp");
        var ciphertext = WindowsDataProtection.Protect(ProtectedStorageCodec.Encode(0, null, Config, Device),
            ProtectedStorageCodec.Entropy(Config, Device));
        File.WriteAllBytes(data, [0]);
        List<SafeFileHandle> pins = [];
        try
        {
            WindowsStorageFiles.PinDirectory(directory, pins);
            ExpectIoDenied(() => Directory.Move(directory, directory + "-moved"));
            // DELETE access and no sharing: neither the source name nor its
            // contents can be substituted while the rename uses this handle.
            using (var handle = CreateFileW(temporary, 0x80000000 | 0x40000000 | 0x00010000,
                0, IntPtr.Zero, 1, 0x00200000, IntPtr.Zero))
            {
                Require(!handle.IsInvalid);
                using var stream = new FileStream(handle, FileAccess.ReadWrite);
                stream.Write(ciphertext);
                stream.Flush(flushToDisk: true);
                ExpectIoDenied(() => File.Move(temporary, temporary + "-moved"));
                ExpectIoDenied(() => File.WriteAllBytes(temporary, [1]));
                WindowsStorageFiles.Replace(handle, pins[^1]);
                Require(!File.Exists(temporary));
                ExpectIoDenied(() => File.OpenRead(data).Dispose());
                stream.Flush(flushToDisk: true);
                stream.Position = 0;
                var fromSameHandle = new byte[ciphertext.Length];
                stream.ReadExactly(fromSameHandle);
                Require(fromSameHandle.SequenceEqual(ciphertext));
            }
            Require(File.ReadAllBytes(data).SequenceEqual(ciphertext));
            Require(Directory.GetFiles(directory).Select(Path.GetFileName).SequenceEqual([WindowsStorage.DataName]));
        }
        finally { foreach (var pin in pins) pin.Dispose(); }
    }

    private static void CheckDirectoryValidation(string root)
    {
        Action<WindowsStorage>[] operations = [storage => _ = storage.Capability, storage => _ = storage.Version,
            storage => _ = storage.Load(), storage => storage.Save(0, Credential()), storage => _ = storage.Invalidate()];
        for (var index = 0; index < operations.Length; index++)
        {
            var directory = Directory.CreateDirectory(Path.Combine(root, $"directory-validation-{index}")).FullName;
            using var storage = WindowsStorage.Open(directory, Config, Device);
            var pins = Pins(storage);
            var original = pins[^1];
            using var regular = File.OpenHandle(Path.Combine(directory, WindowsStorage.DataName), FileMode.Open,
                FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            // Simulate a pin whose metadata is no longer a directory without
            // adding an injection API or requiring privileged reparse mutation.
            pins[^1] = regular;
            try { ExpectStorage(() => operations[index](storage)); }
            finally { pins[^1] = original; }
            ExpectClosed(storage); // Restoring valid pins cannot unpoison it.
        }
        var closedDirectory = Directory.CreateDirectory(Path.Combine(root, "closed-directory-pin")).FullName;
        using var closed = WindowsStorage.Open(closedDirectory, Config, Device);
        var closedPins = Pins(closed);
        closedPins[0].Dispose(); // Ancestors, including the root, are revalidated too.
        ExpectStorage(() => closed.Load());
        ExpectClosed(closed);
    }

    private static List<SafeFileHandle> Pins(WindowsStorage storage) => (List<SafeFileHandle>)typeof(WindowsStorage)
        .GetField("directoryPins", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(storage)!;

    private static void ExpectIoDenied(Action action)
    {
        try { action(); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { return; }
        throw new InvalidOperationException("An exclusive storage handle allowed path substitution");
    }

    private static async Task RaceAsync(string directory, CancellationToken cancellationToken)
    {
        using var storage = WindowsStorage.Open(directory, Config, Device);
        var save = Task.Run(() =>
        {
            try { storage.Save(0, Credential()); }
            catch (OrbitException error) when (error.Error == OrbitError.StaleResponse) { }
        }, cancellationToken);
        var invalidate = Task.Run(() => storage.Invalidate(), cancellationToken);
        await Task.WhenAll(save, invalidate);
        Require(storage.Version == 1 && storage.Load().Credential == null);
    }

    private static void CheckReparse(string root, string target)
    {
        var link = Path.Combine(root, "reparse");
        try { Directory.CreateSymbolicLink(link, target); }
        catch (Exception error) when (error is UnauthorizedAccessException || error is IOException && (error.HResult & 0xffff) == 1314)
        {
            Console.WriteLine("SKIP: storage reparse fixture requires Windows symbolic-link permission.");
            return;
        }
        try
        {
            ExpectStorage(() => WindowsStorage.Open(link, Config, Device));
            using (var reparse = CreateFileW(link, 0x80, 3, IntPtr.Zero, 3, 0x00200000 | 0x02000000, IntPtr.Zero))
            using (var storage = WindowsStorage.Open(target, Config, Device))
            {
                Require(!reparse.IsInvalid);
                var pins = Pins(storage);
                var original = pins[^1];
                pins[^1] = reparse;
                try { ExpectStorage(() => storage.Load()); }
                finally { pins[^1] = original; }
                ExpectClosed(storage);
            }
            var fileLinkDirectory = Directory.CreateDirectory(Path.Combine(root, "file-reparse")).FullName;
            var dataLink = Path.Combine(fileLinkDirectory, WindowsStorage.DataName);
            File.CreateSymbolicLink(dataLink, Path.Combine(target, WindowsStorage.DataName));
            try { ExpectStorage(() => WindowsStorage.Open(fileLinkDirectory, Config, Device)); }
            finally { File.Delete(dataLink); }
            var lockLinkDirectory = Directory.CreateDirectory(Path.Combine(root, "lock-reparse")).FullName;
            var lockLink = Path.Combine(lockLinkDirectory, WindowsStorage.LockName);
            File.CreateSymbolicLink(lockLink, Path.Combine(target, WindowsStorage.LockName));
            try { ExpectStorage(() => WindowsStorage.Open(lockLinkDirectory, Config, Device)); }
            finally { File.Delete(lockLink); }
        }
        finally { Directory.Delete(link); }
    }

    private static void AssertCiphertextOnly(string directory)
    {
        Require(Directory.GetFiles(directory).Select(Path.GetFileName).Order().SequenceEqual(new[] { WindowsStorage.DataName, WindowsStorage.LockName }.Order()));
        // The lifetime lease deliberately denies reads while storage is open.
        // Check its empty contents after disposal; only ciphertext is readable now.
        ExpectIoDenied(() => File.OpenRead(Path.Combine(directory, WindowsStorage.LockName)).Dispose());
        Require(!Encoding.UTF8.GetString(File.ReadAllBytes(Path.Combine(directory, WindowsStorage.DataName)))
            .Contains(Secret, StringComparison.Ordinal));
    }

    private static async Task ChildAsync(string action, string directory, CancellationToken cancellationToken)
    {
        var executable = Environment.ProcessPath ?? throw new InvalidOperationException("Storage test executable unavailable");
        var start = new ProcessStartInfo(executable) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            start.ArgumentList.Add(Assembly.GetExecutingAssembly().Location);
        foreach (var argument in new[] { "--storage-child", action, directory }) start.ArgumentList.Add(argument);
        using var child = Process.Start(start) ?? throw new InvalidOperationException("Storage child unavailable");
        try { await child.WaitForExitAsync(cancellationToken); Require(child.ExitCode == 0); }
        finally { if (!child.HasExited) { child.Kill(entireProcessTree: true); await child.WaitForExitAsync(); } }
    }

    internal static int Child(string action, string directory)
    {
        try
        {
            if (!OperatingSystem.IsWindows()) return 2;
            if (action == "blocked") { ExpectStorage(() => WindowsStorage.Open(directory, Config, Device)); return 0; }
            using var storage = WindowsStorage.Open(directory, Config, Device);
            switch (action)
            {
                case "write-and-exit": storage.Save(0, Credential()); Environment.Exit(0); break;
                case "read-invalidate": Require(storage.Load().Credential?.Credential == Secret); Require(storage.Invalidate() == 1); break;
                case "tombstone": Require(storage.Version == 1 && storage.Load().Credential == null); break;
                default: return 2;
            }
            return 0;
        }
        catch (Exception) { Console.Error.WriteLine("Native storage child failed"); return 1; }
    }

    private static void ExpectClosed(WindowsStorage storage)
    {
        ExpectStorage(() => storage.Version);
        ExpectStorage(() => storage.Capability);
        ExpectStorage(() => storage.Load());
        ExpectStorage(() => storage.Save(0, Credential()));
        ExpectStorage(() => storage.Invalidate());
    }

    private static void ExpectStorage<T>(Func<T> action) => ExpectError(OrbitError.Storage, () =>
    {
        if (action() is IDisposable unexpected) unexpected.Dispose();
    });
    private static void ExpectStorage(Action action) => ExpectError(OrbitError.Storage, action);
    private static void ExpectError(OrbitError classification, Action action)
    {
        try { action(); }
        catch (OrbitException error) when (error.Error == classification && error.Code == null && error.InnerException == null)
        {
            Require(!error.ToString().Contains(Secret, StringComparison.Ordinal));
            return;
        }
        throw new InvalidOperationException("Storage boundary accepted invalid state or exposed an unsafe error");
    }

    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidOperationException("Protected storage assertion failed");
    }
}
