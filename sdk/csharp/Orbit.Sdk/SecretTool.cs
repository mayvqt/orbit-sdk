using System.Buffers;
using System.Buffers.Binary;
using System.Buffers.Text;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Orbit.Sdk;

// Private pipe buffers are bounded and wiped. No shell, credential argument,
// raw helper error, or public executable override is exposed by the adapter.
internal static class SecretTool
{
    internal const int MaximumRecord = 4096, MaximumBase64 = 5464, MaximumOutput = 5465, MaximumError = 4096;
    internal static readonly TimeSpan Deadline = TimeSpan.FromSeconds(5);

    internal static string Scope(OrbitConfig config, Device device, string normalizedDirectory)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData("orbit.sdk.secret-service.v1\0"u8);
        AppendText(hash, "csharp");
        hash.AppendData(ProtectedStorageCodec.Entropy(config, device));
        AppendText(hash, normalizedDirectory);
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static void AppendText(IncrementalHash hash, string text)
    {
        var bytes = new UTF8Encoding(false, true).GetBytes(text);
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)bytes.Length));
        hash.AppendData(length);
        hash.AppendData(bytes);
    }

    internal static ProcessStartInfo Command(string scope, bool store)
    {
        if (scope.Length != 64 || !scope.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f')) throw Storage();
        var start = new ProcessStartInfo("/usr/bin/secret-tool");
        start.ArgumentList.Add(store ? "store" : "lookup");
        if (store) start.ArgumentList.Add("--label=Orbit SDK credential");
        foreach (var argument in new[] { "application", "orbit-sdk", "sdk", "csharp", "scope", scope }) start.ArgumentList.Add(argument);
        return start;
    }

    internal static byte[]? Lookup(string scope)
    {
        using var result = Run(Command(scope, store: false), [], Deadline);
        return LookupRecord(result);
    }

    internal static byte[]? LookupRecord(Result result)
    {
        if (result.ExitCode == 1 && result.Output.Length == 0 && result.Error.Length == 0) return null;
        if (result.ExitCode != 0 || result.Error.Length != 0) throw Storage();
        return Decode(result.Output);
    }

    internal static void Store(string scope, ReadOnlySpan<byte> record)
    {
        var encoded = Encode(record);
        try
        {
            using var result = Run(Command(scope, store: true), encoded, Deadline);
            CheckStored(result);
        }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }

    internal static void CheckStored(Result result)
    {
        if (result.ExitCode != 0 || result.Output.Length != 0 || result.Error.Length != 0) throw Storage();
    }

    internal static byte[] Encode(ReadOnlySpan<byte> record)
    {
        if (record.Length is 0 or > MaximumRecord) throw Storage();
        var encoded = new byte[Base64.GetMaxEncodedToUtf8Length(record.Length)];
        if (Base64.EncodeToUtf8(record, encoded, out var consumed, out var written) != OperationStatus.Done ||
            consumed != record.Length || written != encoded.Length) { CryptographicOperations.ZeroMemory(encoded); throw Storage(); }
        return encoded;
    }

    internal static byte[] Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length is 0 or > MaximumOutput) throw Storage();
        if (encoded[^1] == (byte)'\n') encoded = encoded[..^1];
        if (encoded.Length is 0 or > MaximumBase64) throw Storage();
        var bytes = new byte[MaximumRecord];
        byte[]? canonical = null;
        try
        {
            if (Base64.DecodeFromUtf8(encoded, bytes, out var consumed, out var written) != OperationStatus.Done ||
                consumed != encoded.Length || written == 0) throw Storage();
            canonical = Encode(bytes.AsSpan(0, written));
            if (!canonical.AsSpan().SequenceEqual(encoded)) throw Storage();
            return bytes.AsSpan(0, written).ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
            if (canonical != null) CryptographicOperations.ZeroMemory(canonical);
        }
    }

    internal sealed class Result(int exitCode, byte[] output, byte[] error) : IDisposable
    {
        internal int ExitCode { get; } = exitCode;
        internal byte[] Output { get; } = output;
        internal byte[] Error { get; } = error;
        public void Dispose() { CryptographicOperations.ZeroMemory(Output); CryptographicOperations.ZeroMemory(Error); }
        public override string ToString() => "Orbit secret helper result (redacted)";
    }

    // Internal process boundary also exercises harmless child fixtures in the
    // ordinary suite; production callers always use the fixed Command above.
    internal static Result Run(ProcessStartInfo start, byte[] input, TimeSpan deadline)
    {
        try { return RunAsync(start, input, deadline).GetAwaiter().GetResult(); }
        catch (Exception) { throw Storage(); }
    }

    private static async Task<Result> RunAsync(ProcessStartInfo start, byte[] input, TimeSpan deadline)
    {
        if (input.Length > MaximumBase64 || deadline <= TimeSpan.Zero || deadline > Deadline) throw Storage();
        start.UseShellExecute = false;
        start.RedirectStandardInput = start.RedirectStandardOutput = start.RedirectStandardError = true;
        start.CreateNoWindow = true;
        using var timeout = new CancellationTokenSource(deadline);
        using var process = new Process { StartInfo = start };
        if (!process.Start()) throw Storage();
        var output = new byte[MaximumOutput + 1];
        var error = new byte[MaximumError + 1];
        var readOutput = Drain(process.StandardOutput.BaseStream, output, timeout);
        var readError = Drain(process.StandardError.BaseStream, error, timeout);
        var write = Feed(process.StandardInput.BaseStream, input, timeout.Token);
        var exit = process.WaitForExitAsync(timeout.Token);
        var work = Task.WhenAll(readOutput, readError, write, exit);
        try
        {
            await work.WaitAsync(timeout.Token).ConfigureAwait(false);
            var outputLength = await readOutput.ConfigureAwait(false);
            var errorLength = await readError.ConfigureAwait(false);
            return new Result(process.ExitCode, output.AsSpan(0, outputLength).ToArray(), error.AsSpan(0, errorLength).ToArray());
        }
        catch (Exception)
        {
            timeout.Cancel();
            try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
            catch (InvalidOperationException) { }
            await process.WaitForExitAsync().ConfigureAwait(false); // Reap after termination.
            try { await work.ConfigureAwait(false); } catch (Exception) { }
            throw Storage();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(output);
            CryptographicOperations.ZeroMemory(error);
        }
    }

    private static async Task<int> Drain(Stream stream, byte[] buffer, CancellationTokenSource timeout)
    {
        var count = 0;
        try
        {
            while (true)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(count), timeout.Token).ConfigureAwait(false);
                if (read == 0) return count;
                count += read;
                if (count == buffer.Length) throw Storage();
            }
        }
        catch (Exception) { timeout.Cancel(); throw; }
    }

    private static async Task Feed(Stream stream, byte[] input, CancellationToken cancellationToken)
    {
        try { await stream.WriteAsync(input, cancellationToken).ConfigureAwait(false); await stream.FlushAsync(cancellationToken).ConfigureAwait(false); }
        finally { stream.Dispose(); }
    }

    private static OrbitException Storage() => new(OrbitError.Storage);
}
