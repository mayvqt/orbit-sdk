using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Orbit.Sdk;

// Keep the firmware ABI and bounded SMBIOS parser separate from scoped hashing.
internal static class WindowsDeviceIdentity
{
    private const uint RawSmbios = 0x52534d42;
    private const int MaxBytes = 1024 * 1024;

    [DllImport("kernel32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetSystemFirmwareTable(uint providerSignature, uint tableId, [Out] byte[]? buffer, uint size);

    internal static string Read()
    {
        try
        {
            var size = GetSystemFirmwareTable(RawSmbios, 0, null, 0);
            if (size is < 8 or > MaxBytes) throw Unavailable();
            var bytes = new byte[(int)size];
            if (GetSystemFirmwareTable(RawSmbios, 0, bytes, size) != size) throw Unavailable();
            return Parse(bytes);
        }
        catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            throw Unavailable();
        }
    }

    internal static string Parse(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length is < 8 or > MaxBytes || bytes[1] < 2 || bytes[1] == 2 && bytes[2] < 6 ||
            BinaryPrimitives.ReadUInt32LittleEndian(bytes[4..8]) != (uint)(bytes.Length - 8))
            throw Unavailable();
        string? identity = null;
        var offset = 8;
        while (offset < bytes.Length)
        {
            if (bytes.Length - offset < 4) throw Unavailable();
            var type = bytes[offset];
            var length = bytes[offset + 1];
            if (length < 4 || length > bytes.Length - offset) throw Unavailable();
            var strings = offset + length;
            while (strings < bytes.Length - 1 && (bytes[strings] != 0 || bytes[strings + 1] != 0)) strings++;
            if (strings >= bytes.Length - 1) throw Unavailable();

            if (type == 1)
            {
                if (length < 25 || identity != null) throw Unavailable();
                var uuid = bytes.Slice(offset + 8, 16);
                if (uuid.IndexOfAnyExcept((byte)0) < 0 || uuid.IndexOfAnyExcept((byte)255) < 0) throw Unavailable();
                // Guid's byte constructor uses the SMBIOS 2.6+ mixed-endian layout:
                // little-endian 4/2/2-byte fields, followed by eight unchanged bytes.
                identity = new Guid(uuid).ToString("D");
            }
            if (type == 127) return identity ?? throw Unavailable();
            offset = strings + 2;
        }
        throw Unavailable();
    }

    private static OrbitException Unavailable() => new(OrbitError.Denied, "device_identity_unavailable");
}
