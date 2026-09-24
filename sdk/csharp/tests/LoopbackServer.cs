#if ORBIT_LOCAL_DEVELOPMENT
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

internal sealed record FixtureRequest(string Method, string Path, IReadOnlyDictionary<string, string> Headers, string Body);
internal sealed record FixtureReply(int Status, string Body, string? Location = null, string? RetryAfter = null);

/// <summary>Bounded local HTTP fixture. Owns and awaits its connection loop; never forwards requests.</summary>
internal sealed class LoopbackServer : IAsyncDisposable
{
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stopping = new();
    private readonly Func<FixtureRequest, CancellationToken, Task<FixtureReply>> respond;
    private readonly Task serving;
    private int requestCount;

    internal string Origin { get; }
    internal int RequestCount => Volatile.Read(ref requestCount);

    internal LoopbackServer(Func<FixtureRequest, CancellationToken, Task<FixtureReply>> respond)
    {
        this.respond = respond;
        listener.Start();
        Origin = $"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}";
        serving = ServeAsync();
    }

    private async Task ServeAsync()
    {
        var connections = new List<Task>();
        try
        {
            while (!stopping.IsCancellationRequested)
            {
                var connection = await listener.AcceptTcpClientAsync(stopping.Token);
                connections.Add(ServeConnectionAsync(connection));
            }
        }
        catch (OperationCanceledException) when (stopping.IsCancellationRequested) { }
        catch (SocketException) when (stopping.IsCancellationRequested) { }
        catch (ObjectDisposedException) when (stopping.IsCancellationRequested) { }
        finally { await Task.WhenAll(connections); }
    }

    private async Task ServeConnectionAsync(TcpClient connection)
    {
        using (connection)
        {
            try
            {
                await using var stream = connection.GetStream();
                var request = await ReadRequestAsync(stream, stopping.Token);
                Interlocked.Increment(ref requestCount);
                var response = await respond(request, stopping.Token);
                var body = Encoding.UTF8.GetBytes(response.Body);
                var headers = $"HTTP/1.1 {response.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {body.Length}\r\nConnection: close\r\n";
                if (response.Location != null) headers += $"Location: {response.Location}\r\n";
                if (response.RetryAfter != null) headers += $"Retry-After: {response.RetryAfter}\r\n";
                try
                {
                    await stream.WriteAsync(Encoding.ASCII.GetBytes(headers + "\r\n"), stopping.Token);
                    await stream.WriteAsync(body, stopping.Token);
                }
                // Cancellation can close the client's connection before a gated reply is released.
                catch (IOException) { }
            }
            catch (OperationCanceledException) when (stopping.IsCancellationRequested) { }
        }
    }

    private static async Task<FixtureRequest> ReadRequestAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        using var header = new MemoryStream();
        var next = new byte[1];
        var matched = 0;
        byte[] delimiter = [13, 10, 13, 10];
        while (matched < delimiter.Length)
        {
            if (header.Length == 16 * 1024) throw new InvalidOperationException("Fixture header exceeds limit");
            await stream.ReadExactlyAsync(next, cancellationToken);
            header.WriteByte(next[0]);
            matched = next[0] == delimiter[matched] ? matched + 1 : next[0] == delimiter[0] ? 1 : 0;
        }
        var lines = Encoding.ASCII.GetString(header.ToArray()).Split("\r\n", StringSplitOptions.None);
        var first = lines[0].Split(' ');
        if (first.Length != 3) throw new InvalidOperationException("Fixture request line is malformed");
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines.Skip(1).Where(line => line.Length != 0))
        {
            var colon = line.IndexOf(':');
            if (colon < 1 || !headers.TryAdd(line[..colon], line[(colon + 1)..].Trim()))
                throw new InvalidOperationException("Fixture request header is malformed");
        }
        if (headers.ContainsKey("Transfer-Encoding")) throw new InvalidOperationException("Fixture requires bounded Content-Length");
        var length = headers.TryGetValue("Content-Length", out var value) ? int.Parse(value, CultureInfo.InvariantCulture) : 0;
        if (length is < 0 or > 64 * 1024) throw new InvalidOperationException("Fixture body exceeds limit");
        var body = new byte[length];
        await stream.ReadExactlyAsync(body, cancellationToken);
        return new FixtureRequest(first[0], first[1], headers, Encoding.UTF8.GetString(body));
    }

    public async ValueTask DisposeAsync()
    {
        stopping.Cancel();
        listener.Stop();
        try { await serving; }
        finally { stopping.Dispose(); }
    }
}
#endif
