using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace Orbit.Sdk;

/// <summary>Derives scoped machine fingerprints without exporting the raw operating-system identifier.</summary>
public static class DeviceIdentity
{
    public const string Provider = "machine_v1";

    public static string MachineFingerprint(string applicationId, string environmentId, string osFamily, string machineId)
    {
        CheckScope(applicationId, environmentId);
        if (osFamily is not ("linux" or "windows")) throw new OrbitException(OrbitError.Configuration);
        if (string.IsNullOrEmpty(machineId)) throw Unavailable();
        var normalized = machineId.Trim(' ', '\t', '\n', '\r', '\v', '\f')
            .Replace("-", "", StringComparison.Ordinal).ToLowerInvariant();
        if (normalized.Length != 32 || !normalized.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f') ||
            normalized.All(c => c == '0') || normalized.All(c => c == 'f'))
            throw Unavailable();
        var preimage = $"orbit-machine-v1\n{applicationId}\n{environmentId}\n{osFamily}\n{normalized}";
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(preimage)));
    }

    /// <summary>Reads the native machine identity. An unavailable provider never falls back to a random identity.</summary>
    public static string NativeFingerprint(string applicationId, string environmentId)
    {
        CheckScope(applicationId, environmentId);
        if (OperatingSystem.IsWindows())
            return MachineFingerprint(applicationId, environmentId, "windows", WindowsDeviceIdentity.Read());
        if (!OperatingSystem.IsLinux()) throw Unavailable();
        try
        {
            using var file = new FileStream("/etc/machine-id", FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, bufferSize: 1);
            Span<byte> bytes = stackalloc byte[257];
            var length = file.ReadAtLeast(bytes, bytes.Length, throwOnEndOfStream: false);
            if (length > 256) throw Unavailable();
            var machineId = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true).GetString(bytes[..length]);
            return MachineFingerprint(applicationId, environmentId, "linux", machineId);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or SecurityException or DecoderFallbackException)
        {
            throw Unavailable();
        }
    }

    private static void CheckScope(string applicationId, string environmentId)
    {
        if (string.IsNullOrEmpty(applicationId) || string.IsNullOrEmpty(environmentId) ||
            !JsonWire.Opaque(applicationId) || !JsonWire.Opaque(environmentId))
            throw new OrbitException(OrbitError.Configuration);
    }

    private static OrbitException Unavailable() => new(OrbitError.Denied, "device_identity_unavailable");
}
