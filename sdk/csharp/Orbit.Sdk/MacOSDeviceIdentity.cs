using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Orbit.Sdk;

// IOKit and CoreFoundation values are retained by their respective APIs. Keep
// ownership in SafeHandles so every unsuccessful lookup path releases them.
internal static class MacOSDeviceIdentity
{
    private const string Iokit = "/System/Library/Frameworks/IOKit.framework/IOKit";
    private const string CoreFoundation = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    private const uint Utf8 = 0x08000100;

    private sealed class IoObjectHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal IoObjectHandle(IntPtr value) : base(true) => SetHandle(value);
        protected override bool ReleaseHandle() => IOObjectRelease(handle) == 0;
    }

    private sealed class CfHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal CfHandle(IntPtr value) : base(true) => SetHandle(value);
        protected override bool ReleaseHandle()
        {
            CFRelease(handle);
            return true;
        }
    }

    [DllImport(Iokit, EntryPoint = "IOServiceMatching")]
    private static extern IntPtr IOServiceMatching([MarshalAs(UnmanagedType.LPUTF8Str)] string name);
    [DllImport(Iokit, EntryPoint = "IOServiceGetMatchingService")]
    private static extern uint IOServiceGetMatchingService(uint masterPort, IntPtr matching);
    [DllImport(Iokit, EntryPoint = "IORegistryEntryCreateCFProperty")]
    private static extern IntPtr IORegistryEntryCreateCFProperty(IoObjectHandle entry, CfHandle key, IntPtr allocator, uint options);
    [DllImport(Iokit, EntryPoint = "IOObjectRelease")]
    private static extern int IOObjectRelease(IntPtr value);
    [DllImport(CoreFoundation, EntryPoint = "CFStringCreateWithCString")]
    private static extern IntPtr CFStringCreateWithCString(IntPtr allocator, [MarshalAs(UnmanagedType.LPUTF8Str)] string value, uint encoding);
    [DllImport(CoreFoundation, EntryPoint = "CFGetTypeID")]
    private static extern nint CFGetTypeID(CfHandle value);
    [DllImport(CoreFoundation, EntryPoint = "CFStringGetTypeID")]
    private static extern nint CFStringGetTypeID();
    [DllImport(CoreFoundation, EntryPoint = "CFStringGetLength")]
    private static extern nint CFStringGetLength(CfHandle value);
    [DllImport(CoreFoundation, EntryPoint = "CFStringGetCharacterAtIndex")]
    private static extern ushort CFStringGetCharacterAtIndex(CfHandle value, nint index);
    [DllImport(CoreFoundation, EntryPoint = "CFRelease")]
    private static extern void CFRelease(IntPtr value);

    internal static string NormalizePlatformUuid(string? raw)
    {
        if (string.IsNullOrEmpty(raw)) throw Unavailable();
        var normalized = raw.Trim(' ', '\t', '\n', '\r', '\v', '\f')
            .Replace("-", "", StringComparison.Ordinal).ToLowerInvariant();
        if (normalized.Length != 32 || !normalized.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f') ||
            normalized.All(c => c == '0') || normalized.All(c => c == 'f'))
            throw Unavailable();
        return normalized;
    }

    internal static string Read()
    {
        try
        {
            var matching = IOServiceMatching("IOPlatformExpertDevice");
            if (matching == IntPtr.Zero) throw Unavailable();
            // IOServiceGetMatchingService consumes the matching dictionary.
            using var service = new IoObjectHandle(new IntPtr(IOServiceGetMatchingService(0, matching)));
            if (service.IsInvalid) throw Unavailable();
            using var key = new CfHandle(CFStringCreateWithCString(IntPtr.Zero, "IOPlatformUUID", Utf8));
            if (key.IsInvalid) throw Unavailable();
            var property = new CfHandle(IORegistryEntryCreateCFProperty(service, key, IntPtr.Zero, 0));
            if (property.IsInvalid) { property.Dispose(); throw Unavailable(); }
            return ReadOwnedProperty(property, () => ReadString(property));
        }
        catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException or
            MarshalDirectiveException or OverflowException)
        {
            throw Unavailable();
        }
    }

    internal static string ReadOwnedProperty(IDisposable owner, Func<string> read)
    {
        using (owner) return NormalizePlatformUuid(read());
    }

    private static string ReadString(CfHandle property)
    {
        if (CFGetTypeID(property) != CFStringGetTypeID()) throw Unavailable();
        var length = CFStringGetLength(property);
        if (length <= 0 || length > 256) throw Unavailable();
        var characters = new char[(int)length];
        for (nint index = 0; index < length; index++)
        {
            var character = CFStringGetCharacterAtIndex(property, index);
            if (character == 0 || character > 0x7f) throw Unavailable();
            characters[(int)index] = (char)character;
        }
        return new string(characters);
    }

    private static OrbitException Unavailable() => new(OrbitError.Denied, "device_identity_unavailable");
}
