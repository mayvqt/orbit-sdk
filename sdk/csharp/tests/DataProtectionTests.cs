using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Orbit.Sdk;

internal static class DataProtectionTests
{
    internal static Task RunAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows()) throw new InvalidOperationException("Native data protection checks require Windows");
        var entropy = Encoding.UTF8.GetBytes("orbit-synthetic-dpapi-test-scope");
        foreach (var plaintext in new[] { Array.Empty<byte>(), new byte[] { 0, 1, 2, 255, 0, 128 }, Filled(32 * 1024, 0x5a) })
        {
            cancellationToken.ThrowIfCancellationRequested();
            RoundTrip(plaintext, entropy);
        }
        RoundTrip(Encoding.UTF8.GetBytes("synthetic"), [0x6b]);
        RoundTrip(Encoding.UTF8.GetBytes("synthetic"), Filled(1024, 0x6b));
        var oversizedCiphertext = ProtectOversizedFixture(entropy);
        ExpectStorage(() => WindowsDataProtection.Unprotect(oversizedCiphertext, entropy));

        var ciphertext = WindowsDataProtection.Protect(Encoding.UTF8.GetBytes("synthetic protected credential"), entropy);
        var tampered = (byte[])ciphertext.Clone();
        // The final integrity byte must reject; opaque header mutations need not.
        tampered[^1] ^= 255;
        foreach (var fixture in new (byte[] Ciphertext, byte[] Entropy)[]
        {
            (ciphertext, Encoding.UTF8.GetBytes("another-synthetic-scope")),
            (tampered, entropy), (ciphertext[..(ciphertext.Length / 2)], entropy),
            (Encoding.UTF8.GetBytes("not a DPAPI blob"), entropy), (Array.Empty<byte>(), entropy)
        })
        {
            cancellationToken.ThrowIfCancellationRequested();
            var originalCiphertext = (byte[])fixture.Ciphertext.Clone();
            var originalEntropy = (byte[])fixture.Entropy.Clone();
            ExpectStorage(() => WindowsDataProtection.Unprotect(fixture.Ciphertext, fixture.Entropy));
            Require(fixture.Ciphertext.SequenceEqual(originalCiphertext) && fixture.Entropy.SequenceEqual(originalEntropy));
        }

        ExpectStorage(() => WindowsDataProtection.Protect(new byte[32 * 1024 + 1], entropy));
        ExpectStorage(() => WindowsDataProtection.Unprotect(new byte[64 * 1024 + 1], entropy));
        foreach (var invalidEntropy in new[] { Array.Empty<byte>(), new byte[1025] })
        {
            ExpectStorage(() => WindowsDataProtection.Protect([1], invalidEntropy));
            ExpectStorage(() => WindowsDataProtection.Unprotect(ciphertext, invalidEntropy));
        }
        return Task.CompletedTask;
    }

    private static void RoundTrip(byte[] plaintext, byte[] entropy)
    {
        var originalPlaintext = (byte[])plaintext.Clone();
        var originalEntropy = (byte[])entropy.Clone();
        var ciphertext = WindowsDataProtection.Protect(plaintext, entropy);
        Require(ciphertext.Length is > 0 and <= 64 * 1024 && !ciphertext.SequenceEqual(originalPlaintext));
        Require(plaintext.SequenceEqual(originalPlaintext) && entropy.SequenceEqual(originalEntropy));
        var originalCiphertext = (byte[])ciphertext.Clone();
        var recovered = WindowsDataProtection.Unprotect(ciphertext, entropy);
        Require(recovered.SequenceEqual(originalPlaintext));
        Require(ciphertext.SequenceEqual(originalCiphertext) && entropy.SequenceEqual(originalEntropy));
    }

    private static byte[] Filled(int length, byte value)
    {
        var bytes = new byte[length];
        Array.Fill(bytes, value);
        return bytes;
    }

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

    [DllImport("kernel32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr LocalFree(IntPtr memory);

    private static byte[] ProtectOversizedFixture(byte[] entropy)
    {
        // A different current-user application can produce valid DPAPI data just
        // above the SDK plaintext cap. Only this fixture bypasses Protect's guard.
        var plaintext = Filled(32 * 1024 + 1, 0x5a);
        var zeroes = new byte[4096];
        var output = new DataBlob();
        byte[]? result = null;
        try
        {
            try
            {
                var inputHandle = new GCHandle();
                var entropyHandle = new GCHandle();
                try
                {
                    inputHandle = GCHandle.Alloc(plaintext, GCHandleType.Pinned);
                    entropyHandle = GCHandle.Alloc(entropy, GCHandleType.Pinned);
                    var input = new DataBlob { Length = (uint)plaintext.Length, Data = inputHandle.AddrOfPinnedObject() };
                    var scope = new DataBlob { Length = (uint)entropy.Length, Data = entropyHandle.AddrOfPinnedObject() };
                    // CurrentUser, UI forbidden, and no optional native allocation.
                    Require(CryptProtectData(ref input, IntPtr.Zero, ref scope, IntPtr.Zero, IntPtr.Zero, 1, ref output));
                }
                finally
                {
                    try { if (entropyHandle.IsAllocated) entropyHandle.Free(); }
                    finally { if (inputHandle.IsAllocated) inputHandle.Free(); }
                }
                Require(output.Length is > 0 and < 64 * 1024 && output.Data != IntPtr.Zero);
                result = new byte[(int)output.Length];
                Marshal.Copy(output.Data, result, 0, result.Length);
            }
            finally
            {
                if (output.Data != IntPtr.Zero)
                {
                    try
                    {
                        var pointer = output.Data;
                        var remaining = output.Length;
                        while (remaining != 0)
                        {
                            var count = (int)Math.Min((uint)zeroes.Length, remaining);
                            Marshal.Copy(zeroes, 0, pointer, count);
                            remaining -= (uint)count;
                            pointer = IntPtr.Add(pointer, count);
                        }
                    }
                    finally { Require(LocalFree(output.Data) == IntPtr.Zero); }
                }
            }
            return result;
        }
        catch (Exception)
        {
            if (result != null) CryptographicOperations.ZeroMemory(result);
            throw new InvalidOperationException("Native oversized data protection fixture failed");
        }
        finally { CryptographicOperations.ZeroMemory(plaintext); }
    }

    private static void ExpectStorage(Func<byte[]> operation)
    {
        try { _ = operation(); }
        catch (OrbitException error) when (error.Error == OrbitError.Storage && error.Code == null) { return; }
        throw new InvalidOperationException("Invalid protected data was accepted or misclassified");
    }

    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidOperationException("Native data protection assertion failed");
    }
}
