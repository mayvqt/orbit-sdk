using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Orbit.Sdk;

internal static class DeviceIdentityTests
{
    internal static int RunNative()
    {
        var expected = Environment.GetEnvironmentVariable("ORBIT_NATIVE_FINGERPRINT_EXPECTED");
        if (!ValidDigest(expected))
        {
            Console.Error.WriteLine("FAIL: ORBIT_NATIVE_FINGERPRINT_EXPECTED must contain 64 lowercase hex characters.");
            return 2;
        }
        try
        {
            const string application = "native_test_app";
            const string environment = "native_test_env";
            var first = DeviceIdentity.NativeFingerprint(application, environment);
            var repeat = DeviceIdentity.NativeFingerprint(application, environment);
            var otherApplication = DeviceIdentity.NativeFingerprint("other_native_test_app", environment);
            var otherEnvironment = DeviceIdentity.NativeFingerprint(application, "other_native_test_env");
            if (first != expected || repeat != expected || !ValidDigest(otherApplication) || !ValidDigest(otherEnvironment) ||
                otherApplication == first || otherEnvironment == first || otherApplication == otherEnvironment)
            {
                Console.Error.WriteLine("FAIL: native fingerprint agreement, stability or scope isolation.");
                return 1;
            }
        }
        catch (Exception)
        {
            Console.Error.WriteLine("FAIL: native fingerprint acquisition.");
            return 1;
        }
        Console.WriteLine("PASS: native fingerprint agreement, stability and scope isolation.");
        return 0;
    }

    private static bool ValidDigest(string? value) => value is { Length: 64 } &&
        value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    internal static Task RunAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // Literal preimages fix every separator and the absence of a trailing newline
        // independently of the implementation, matching the Go machine_v1 vectors.
        (string Application, string Environment, string Family, string MachineId, string Preimage)[] vectors =
        [
            ("app", "test", "linux", "00112233445566778899aabbccddeeff", "orbit-machine-v1\napp\ntest\nlinux\n00112233445566778899aabbccddeeff"),
            ("app", "test", "linux", " \t\r\n00112233-4455-6677-8899-AABBCCDDEEFF\v\f ", "orbit-machine-v1\napp\ntest\nlinux\n00112233445566778899aabbccddeeff"),
            ("app", "test", "windows", "00112233-4455-6677-8899-AABBCCDDEEFF", "orbit-machine-v1\napp\ntest\nwindows\n00112233445566778899aabbccddeeff"),
            ("other_app", "live", "linux", "0123456789ABCDEF0123456789ABCDEF", "orbit-machine-v1\nother_app\nlive\nlinux\n0123456789abcdef0123456789abcdef")
        ];
        foreach (var vector in vectors)
        {
            var expected = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(vector.Preimage)));
            var actual = DeviceIdentity.MachineFingerprint(vector.Application, vector.Environment, vector.Family, vector.MachineId);
            if (actual != expected) throw new InvalidOperationException("Machine fingerprint framing mismatch");
        }
        if (DeviceIdentity.Provider != "machine_v1") throw new InvalidOperationException("Machine fingerprint provider mismatch");

        foreach (var machineId in new[]
        {
            "", new string('0', 32), new string('F', 32), "00112233445566778899aabbccddeef",
            "00112233445566778899aabbccddeeff00", "00112233445566778899aabbccddeefg",
            "00112233 445566778899aabbccddeeff", "\u00a000112233445566778899aabbccddeeff"
        })
            Expect(OrbitError.Denied, "device_identity_unavailable",
                () => DeviceIdentity.MachineFingerprint("app", "test", "linux", machineId));

        (string Application, string Environment, string Family)[] invalidScopes =
        [
            ("app\nother", "test", "linux"), ("app", "test/live", "linux"), ("app", "test", "macos"),
            ("", "test", "linux"), ("app", "", "linux"), (new string('a', 129), "test", "linux"),
            ("app", new string('a', 129), "linux"), ("äpp", "test", "linux"), ("app", "test", "Linux")
        ];
        foreach (var scope in invalidScopes)
            Expect(OrbitError.Configuration, null,
                () => DeviceIdentity.MachineFingerprint(scope.Application, scope.Environment, scope.Family, "00112233445566778899aabbccddeeff"));

        // Invalid scope must fail before reading any native identity, on every platform.
        Expect(OrbitError.Configuration, null, () => DeviceIdentity.NativeFingerprint("app\nother", "test"));
        Expect(OrbitError.Configuration, null, () => DeviceIdentity.NativeFingerprint("app", "test/live"));
        SmbiosIdentity();
        return Task.CompletedTask;
    }

    private static void SmbiosIdentity()
    {
        const string canonical = "00112233-4455-6677-8899-aabbccddeeff";
        byte[] system =
        [
            1, 25, 0, 1, 0, 0, 0, 0,
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0,
            0, 0
        ];
        byte[] end = [127, 4, 0xff, 0xff, 0, 0];
        byte[] preceding = [0, 4, 0, 0, (byte)'x', 0, (byte)'y', 0, 0];
        var valid = RawSmbios(system, end);
        foreach (var table in new[] { valid, RawSmbios(preceding, system, end), RawSmbios(system, end, [1, 0, 255]) })
            if (WindowsDeviceIdentity.Parse(table) != canonical) throw new InvalidOperationException("SMBIOS UUID byte order mismatch");
        var derived = DeviceIdentity.MachineFingerprint("app", "test", "windows", WindowsDeviceIdentity.Parse(valid));
        var expected = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(
            "orbit-machine-v1\napp\ntest\nwindows\n00112233445566778899aabbccddeeff")));
        if (derived != expected) throw new InvalidOperationException("SMBIOS fingerprint framing mismatch");

        var minimumVersion = (byte[])valid.Clone();
        minimumVersion[1] = 2;
        minimumVersion[2] = 6;
        if (WindowsDeviceIdentity.Parse(minimumVersion) != canonical) throw new InvalidOperationException("SMBIOS minimum version rejected");

        var invalid = new List<byte[]>
        {
            Array.Empty<byte>(), new byte[7], new byte[1024 * 1024 + 1], RawSmbios(), RawSmbios(end),
            RawSmbios(system), RawSmbios(system, system, end), RawSmbios([1, 3, 0, 0], end),
            RawSmbios([1, 255, 0, 0], end), RawSmbios([1, 25, 0]),
            RawSmbios(system[..25]), RawSmbios(system[..26]),
            RawSmbios(system, end[..4]), RawSmbios(system, [127, 3, 0, 0, 0, 0])
        };
        foreach (var length in new uint[] { (uint)(valid.Length - 9), (uint)(valid.Length - 7), uint.MaxValue })
        {
            var badLength = (byte[])valid.Clone();
            BinaryPrimitives.WriteUInt32LittleEndian(badLength.AsSpan(4, 4), length);
            invalid.Add(badLength);
        }
        foreach (var version in new (byte Major, byte Minor)[] { (0, 6), (1, 9), (2, 0), (2, 5) })
        {
            var oldVersion = (byte[])valid.Clone();
            oldVersion[1] = version.Major;
            oldVersion[2] = version.Minor;
            invalid.Add(oldVersion);
        }
        foreach (var fill in new byte[] { 0, 255 })
        {
            var missingUuid = (byte[])system.Clone();
            missingUuid.AsSpan(8, 16).Fill(fill);
            invalid.Add(RawSmbios(missingUuid, end));
        }
        var shortSystem = (byte[])system.Clone();
        shortSystem[1] = 24;
        invalid.Add(RawSmbios(shortSystem, end));
        foreach (var table in invalid)
            Expect(OrbitError.Denied, "device_identity_unavailable", () => WindowsDeviceIdentity.Parse(table));
    }

    private static byte[] RawSmbios(params byte[][] records)
    {
        var size = records.Sum(record => record.Length);
        var table = new byte[8 + size];
        table[1] = 3;
        table[2] = 8;
        BinaryPrimitives.WriteUInt32LittleEndian(table.AsSpan(4, 4), (uint)size);
        var offset = 8;
        foreach (var record in records)
        {
            record.CopyTo(table, offset);
            offset += record.Length;
        }
        return table;
    }

    private static void Expect(OrbitError expected, string? code, Func<string> operation)
    {
        try { _ = operation(); }
        catch (OrbitException error) when (error.Error == expected && error.Code == code) { return; }
        throw new InvalidOperationException("Invalid machine identity was accepted or misclassified");
    }
}
