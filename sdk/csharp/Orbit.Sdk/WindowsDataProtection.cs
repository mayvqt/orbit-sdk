using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Orbit.Sdk;

// Current-user DPAPI byte protection only; persistence and scope ownership belong to callers.
internal static class WindowsDataProtection
{
    internal const int MaxPlaintextBytes = 32 * 1024;
    internal const int MaxCiphertextBytes = 64 * 1024;
    private const int MaxEntropyBytes = 1024;
    private const uint UiForbidden = 1;

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        internal uint Length;
        internal IntPtr Data;
    }

    [DllImport("crypt32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptProtectData(ref DataBlob input, IntPtr description, ref DataBlob entropy,
        IntPtr reserved, IntPtr prompt, uint flags, ref DataBlob output);

    [DllImport("crypt32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(ref DataBlob input, IntPtr description, ref DataBlob entropy,
        IntPtr reserved, IntPtr prompt, uint flags, ref DataBlob output);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr LocalFree(IntPtr memory);

    internal static byte[] Protect(byte[] plaintext, byte[] entropy)
    {
        if (!OperatingSystem.IsWindows() || plaintext == null || plaintext.Length > MaxPlaintextBytes ||
            entropy == null || entropy.Length is < 1 or > MaxEntropyBytes)
            throw Storage();
        return Transform(plaintext, entropy, protect: true);
    }

    internal static byte[] Unprotect(byte[] ciphertext, byte[] entropy)
    {
        if (!OperatingSystem.IsWindows() || ciphertext == null || ciphertext.Length is < 1 or > MaxCiphertextBytes ||
            entropy == null || entropy.Length is < 1 or > MaxEntropyBytes)
            throw Storage();
        return Transform(ciphertext, entropy, protect: false);
    }

    private static byte[] Transform(byte[] input, byte[] entropy, bool protect)
    {
        byte[]? result = null;
        try
        {
            // Allocate cleanup scratch before any native allocation can exist.
            var zeroes = new byte[4096];
            var output = new DataBlob();
            try
            {
                var inputHandle = new GCHandle();
                var entropyHandle = new GCHandle();
                try
                {
                    inputHandle = GCHandle.Alloc(input, GCHandleType.Pinned);
                    entropyHandle = GCHandle.Alloc(entropy, GCHandleType.Pinned);
                    var inputBlob = new DataBlob { Length = (uint)input.Length, Data = inputHandle.AddrOfPinnedObject() };
                    var entropyBlob = new DataBlob { Length = (uint)entropy.Length, Data = entropyHandle.AddrOfPinnedObject() };
                    // Both borrowed arrays are input-only and pinned for this synchronous call.
                    // Null description/prompt/reserved and UI_FORBIDDEN request no UI or extra
                    // allocation. Omitting LOCAL_MACHINE retains the current Windows user scope.
                    var success = protect
                        ? CryptProtectData(ref inputBlob, IntPtr.Zero, ref entropyBlob, IntPtr.Zero, IntPtr.Zero, UiForbidden, ref output)
                        : CryptUnprotectData(ref inputBlob, IntPtr.Zero, ref entropyBlob, IntPtr.Zero, IntPtr.Zero, UiForbidden, ref output);
                    if (!success) throw Storage();
                }
                finally
                {
                    try { if (entropyHandle.IsAllocated) entropyHandle.Free(); }
                    finally { if (inputHandle.IsAllocated) inputHandle.Free(); }
                }
                var limit = protect ? MaxCiphertextBytes : MaxPlaintextBytes;
                if (output.Length > limit || output.Length > 0 && output.Data == IntPtr.Zero || protect && output.Length == 0)
                    throw Storage();
                result = new byte[(int)output.Length];
                if (result.Length != 0) Marshal.Copy(output.Data, result, 0, result.Length);
            }
            finally { WipeAndFree(output, zeroes); }
            return result;
        }
        catch (Exception)
        {
            // A copy or cleanup failure must not release partially copied plaintext.
            if (result != null) CryptographicOperations.ZeroMemory(result);
            throw Storage();
        }
    }

    private static void WipeAndFree(DataBlob output, byte[] zeroes)
    {
        if (output.Data == IntPtr.Zero) return;
        try
        {
            var pointer = output.Data;
            var remaining = output.Length;
            // DPAPI owns allocation/length consistency, including failure output.
            // Marshal.Copy writes foreign memory and cannot be removed as a dead
            // managed-buffer clear. Erase the entire allocation even above our cap.
            while (remaining != 0)
            {
                var count = (int)Math.Min((uint)zeroes.Length, remaining);
                Marshal.Copy(zeroes, 0, pointer, count);
                remaining -= (uint)count;
                pointer = IntPtr.Add(pointer, count);
            }
        }
        finally
        {
            if (LocalFree(output.Data) != IntPtr.Zero) throw Storage();
        }
    }

    private static OrbitException Storage() => new(OrbitError.Storage);
}
