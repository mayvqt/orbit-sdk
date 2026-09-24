using System.Buffers.Binary;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Orbit.Sdk;

internal static class SecretServiceTests
{
    internal static readonly OrbitConfig Config = new("app", "test", "https://orbit.example.test");
    internal static readonly Device TestDevice = new("installation_1234");
    internal static readonly string Secret = new('q', 43);
    internal const UnixFileMode PrivateDirectory = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    internal const UnixFileMode PrivateFile = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    internal static StoredCredential Credential() => new()
    {
        ApplicationId = Config.ApplicationId, EnvironmentId = Config.EnvironmentId, InstallationId = TestDevice.InstallationId,
        ActivationId = "activation", LicenceId = "licence", Credential = Secret, CredentialExpiresAt = 1_900_000_000
    };

    internal static Task CodecAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var framing = new MemoryStream();
        framing.Write("orbit.sdk.secret-service.v1\0\0\0\0\u0006csharp"u8);
        framing.Write(ProtectedStorageCodec.Entropy(Config, TestDevice));
        var directory = "/private/storage"u8.ToArray();
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, (uint)directory.Length);
        framing.Write(length);
        framing.Write(directory);
        var expected = Convert.ToHexStringLower(SHA256.HashData(framing.ToArray()));
        Require(SecretTool.Scope(Config, TestDevice, "/private/storage") == expected);
        Require(SecretTool.Scope(Config, TestDevice, "/private/other") != expected);
        Require(SecretTool.Scope(Config with { EnvironmentId = "live" }, TestDevice, "/private/storage") != expected);
        var command = SecretTool.Command(expected, store: true);
        Require(command.FileName == "/usr/bin/secret-tool" && command.Arguments == "" &&
            command.ArgumentList.SequenceEqual(new[] { "store", "--label=Orbit SDK credential", "application", "orbit-sdk", "sdk", "csharp", "scope", expected }));
        ExpectStorage(() => SecretTool.Command("../invalid", store: false));
        var record = ProtectedStorageCodec.Encode(7, Credential(), Config, TestDevice);
        var encoded = SecretTool.Encode(record);
        try
        {
            foreach (var output in new[] { encoded, encoded.Concat(new byte[] { 10 }).ToArray() })
            {
                var decoded = SecretTool.Decode(output);
                try { Require(ProtectedStorageCodec.Decode(decoded, Config, TestDevice).Version == 7); }
                finally { CryptographicOperations.ZeroMemory(decoded); }
            }
            foreach (var invalid in new[] { Array.Empty<byte>(), "AB=="u8.ToArray(), "AA==\r\n"u8.ToArray(), "AA==\n\n"u8.ToArray(),
                " AA=="u8.ToArray(), "A A=="u8.ToArray(), "AA==\t"u8.ToArray(), new byte[5466],
                Encoding.ASCII.GetBytes(Convert.ToBase64String(new byte[4097])) }) ExpectStorage(() => SecretTool.Decode(invalid));
            Require(SecretTool.Decode(SecretTool.Encode(new byte[4096])).Length == 4096);
            ExpectStorage(() => SecretTool.Encode(new byte[4097]));
            using var absent = new SecretTool.Result(1, [], []);
            Require(SecretTool.LookupRecord(absent) == null);
            foreach (var invalid in new[] { new SecretTool.Result(1, [1], []), new SecretTool.Result(1, [], [1]),
                new SecretTool.Result(2, [], []), new SecretTool.Result(0, [], []), new SecretTool.Result(0, encoded.ToArray(), [1]) })
            {
                using (invalid) ExpectStorage(() => SecretTool.LookupRecord(invalid));
            }
            using var success = new SecretTool.Result(0, [], []);
            SecretTool.CheckStored(success);
            foreach (var invalid in new[] { new SecretTool.Result(1, [], []), new SecretTool.Result(0, [1], []), new SecretTool.Result(0, [], [1]) })
                using (invalid) ExpectStorage(() => SecretTool.CheckStored(invalid));
            var privateResult = new SecretTool.Result(0, encoded.ToArray(), Encoding.UTF8.GetBytes(Secret));
            Require(!privateResult.ToString().Contains(Secret, StringComparison.Ordinal));
            privateResult.Dispose();
            Require(privateResult.Output.All(b => b == 0) && privateResult.Error.All(b => b == 0));
        }
        finally { CryptographicOperations.ZeroMemory(record); CryptographicOperations.ZeroMemory(encoded); }
        var metadata = new LinuxStorageLease.Metadata { Mask = 0x30f, Owner = 123, Links = 1, Mode = 0x8180 };
        LinuxStorageLease.CheckPrivate(metadata, 123, directory: false);
        for (var index = 0; index < 7; index++)
        {
            var invalid = metadata;
            switch (index)
            {
                case 0: invalid.Owner++; break;
                case 1: invalid.Links = 0; break;
                case 2: invalid.Links = 2; break;
                case 3: invalid.Mode |= 4; break;
                case 4: invalid.Mode = 0xa180; break;
                case 5: invalid.Size = 1; break;
                case 6: invalid.Mask = 0; break;
            }
            ExpectStorage(() => LinuxStorageLease.CheckPrivate(invalid, 123, directory: false));
        }
        if (!LinuxStorageLease.Supported) ExpectStorage(() => SecretServiceStorage.Open("unsupported", Config, TestDevice));
        return Task.CompletedTask;
    }

    internal static Task LeaseAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsLinux()) return Task.CompletedTask;
        if (!LinuxStorageLease.Supported) return Task.CompletedTask;
        var root = CreatePrivate(Path.Combine(Path.GetTempPath(), "orbit-csharp-lease-" + Guid.NewGuid().ToString("N")));
        try
        {
            ExpectStorage(() => LinuxStorageLease.Open("relative"));
            ExpectStorage(() => LinuxStorageLease.Open(Path.Combine(root, "missing")));
            var directory = CreatePrivate(Path.Combine(root, "scope"));
            var path = Path.Combine(directory, LinuxStorageLease.Name);
            using (var lease = LinuxStorageLease.Open(directory))
            {
                Require(lease.Created && File.GetUnixFileMode(path) == PrivateFile);
                ExpectStorage(() => LinuxStorageLease.Open(directory));
                File.Move(path, path + ".old");
                PrivateEmpty(path);
                ExpectStorage(() => lease.Check());
                File.Delete(path);
                File.Move(path + ".old", path);
                lease.Check();
                File.SetUnixFileMode(path, PrivateFile | UnixFileMode.OtherRead);
                ExpectStorage(() => lease.Check());
                File.SetUnixFileMode(path, PrivateFile);
                File.SetUnixFileMode(directory, PrivateDirectory | UnixFileMode.GroupExecute);
                ExpectStorage(() => lease.Check());
                File.SetUnixFileMode(directory, PrivateDirectory);
                Directory.Move(directory, directory + "-moved");
                ExpectStorage(() => lease.Check());
                Directory.Move(directory + "-moved", directory);
                lease.Check();
                File.Delete(path);
                ExpectStorage(() => lease.Check());
            }
            var linked = Path.Combine(root, "linked");
            Directory.CreateSymbolicLink(linked, directory);
            ExpectStorage(() => LinuxStorageLease.Open(linked));
            Directory.Delete(linked);
            File.CreateSymbolicLink(path, Path.Combine(root, "absent"));
            ExpectStorage(() => LinuxStorageLease.Open(directory));
            File.Delete(path);
            Directory.CreateDirectory(path);
            ExpectStorage(() => LinuxStorageLease.Open(directory));
            Directory.Delete(path);
            using (var lease = LinuxStorageLease.Open(directory)) { lease.Check(); }
            using (var reopened = LinuxStorageLease.Open(directory)) Require(!reopened.Created);
            using (var lease = LinuxStorageLease.Open(directory))
            {
                lease.BeginWrite();
                lease.Check(pending: true);
                ExpectStorage(() => lease.Check());
                lease.CompleteWrite();
                lease.Check();
                Require(new FileInfo(path).Length == 0);
                lease.BeginWrite();
            }
            ExpectStorage(() => LinuxStorageLease.Open(directory));
            Require(File.ReadAllBytes(path).SequenceEqual(new byte[] { 1 }));
            File.WriteAllBytes(path, [2]);
            ExpectStorage(() => LinuxStorageLease.Open(directory));
            Require(File.ReadAllBytes(path).SequenceEqual(new byte[] { 2 }));
        }
        finally { Directory.Delete(root, recursive: true); }
        return Task.CompletedTask;
    }

    internal static Task HelperAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var input = Encoding.UTF8.GetBytes(Secret);
        try
        {
            using (var echo = SecretTool.Run(ChildStart("--secret-tool-fixture", "echo"), input, SecretTool.Deadline))
                Require(echo.ExitCode == 0 && echo.Output.SequenceEqual(input) && echo.Error.SequenceEqual(input));
            foreach (var mode in new[] { "stdout-overflow", "stderr-overflow", "hang" })
            {
                var marker = Path.Combine(Path.GetTempPath(), "orbit-csharp-helper-" + Guid.NewGuid().ToString("N"));
                try
                {
                    var elapsed = Stopwatch.StartNew();
                    ExpectStorage(() => SecretTool.Run(ChildStart("--secret-tool-fixture", mode, marker), [], SecretTool.Deadline));
                    Require(elapsed.Elapsed < TimeSpan.FromSeconds(mode == "hang" ? 8 : 4));
                    Require(File.Exists(marker));
                    var pid = int.Parse(File.ReadAllText(marker), System.Globalization.CultureInfo.InvariantCulture);
                    try { using var child = Process.GetProcessById(pid); Require(child.HasExited); }
                    catch (ArgumentException) { }
                }
                finally { File.Delete(marker); }
            }
            ExpectStorage(() => SecretTool.Run(ChildStart("--secret-tool-fixture", "echo"), new byte[5465], SecretTool.Deadline));
        }
        finally { CryptographicOperations.ZeroMemory(input); }
        return Task.CompletedTask;
    }

    internal static async Task<int> HelperChild(string[] arguments)
    {
        if (arguments.Length is < 1 or > 2) return 2;
        if (arguments.Length == 2) File.WriteAllText(arguments[1], Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture));
        var output = Console.OpenStandardOutput();
        var error = Console.OpenStandardError();
        switch (arguments[0])
        {
            case "echo":
                var input = new byte[SecretTool.MaximumBase64];
                var count = 0;
                var stdin = Console.OpenStandardInput();
                while (count < input.Length)
                {
                    var read = await stdin.ReadAsync(input.AsMemory(count));
                    if (read == 0) break;
                    count += read;
                }
                await output.WriteAsync(input.AsMemory(0, count));
                await error.WriteAsync(input.AsMemory(0, count));
                CryptographicOperations.ZeroMemory(input);
                return 0;
            case "stdout-overflow": await output.WriteAsync(new byte[SecretTool.MaximumOutput + 1]); await output.FlushAsync(); break;
            case "stderr-overflow": await error.WriteAsync(new byte[SecretTool.MaximumError + 1]); await error.FlushAsync(); break;
            case "hang": break;
            default: return 2;
        }
        await Task.Delay(TimeSpan.FromSeconds(30));
        return 2;
    }

    internal static ProcessStartInfo ChildStart(params string[] arguments)
    {
        var start = new ProcessStartInfo(Environment.ProcessPath ?? throw new InvalidOperationException("Fixture executable unavailable"));
        if (Path.GetFileNameWithoutExtension(start.FileName).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            start.ArgumentList.Add(Assembly.GetExecutingAssembly().Location);
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        return start;
    }

    internal static string CreatePrivate(string directory)
    {
        if (!OperatingSystem.IsLinux()) throw new InvalidOperationException("Linux fixture required");
        return Directory.CreateDirectory(directory, PrivateDirectory).FullName;
    }

    internal static void PrivateEmpty(string path)
    {
        if (!OperatingSystem.IsLinux()) throw new InvalidOperationException("Linux fixture required");
        using var file = new FileStream(path, new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, UnixCreateMode = PrivateFile });
    }

    internal static void ExpectClosed(SecretServiceStorage storage)
    {
        ExpectStorage(() => storage.Capability);
        ExpectStorage(() => storage.Version);
        ExpectStorage(() => storage.Load());
        ExpectStorage(() => storage.Save(0, Credential()));
        ExpectStorage(() => storage.Invalidate());
    }
    internal static void ExpectStorage<T>(Func<T> action) => ExpectStorage(() => { if (action() is IDisposable unexpected) unexpected.Dispose(); });
    internal static void ExpectStorage(Action action) => ExpectError(OrbitError.Storage, action);
    internal static void ExpectError(OrbitError expected, Action action)
    {
        try { action(); }
        catch (OrbitException error) when (error.Error == expected && error.Code == null && error.InnerException == null &&
            !error.ToString().Contains(Secret, StringComparison.Ordinal)) { return; }
        throw new InvalidOperationException("Secret Service boundary accepted invalid state or exposed an unsafe error");
    }
    internal static void Require(bool condition) { if (!condition) throw new InvalidOperationException("Secret Service fixture assertion failed"); }
}
