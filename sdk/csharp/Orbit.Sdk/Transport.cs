using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text.Json;

namespace Orbit.Sdk;

/// <summary>Configured-origin HTTPS transport. Redirects and cookies are disabled.</summary>
public sealed class Transport : IDisposable
{
    private readonly Uri origin;
    private readonly HttpClient client;
    internal string CanonicalOrigin => origin.GetLeftPart(UriPartial.Authority);
    internal CancellationToken? InstallationCancellation
    {
        get; set;
    }
    private readonly object installedGate = new();
    private int installedRequests;
    private bool installedClosed;
    private TaskCompletionSource installedIdle = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal Task SettleInstalledAsync()
    {
        lock (installedGate)
        {
            installedClosed = true;
            return installedRequests == 0 ? Task.CompletedTask : installedIdle.Task;
        }
    }
    public Transport(string origin) : this(ParseOrigin(origin, "https"), false) { }

    private Transport(Uri origin, bool local)
    {
        this.origin = origin;
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            ConnectTimeout = TimeSpan.FromSeconds(3),
            MaxResponseHeadersLength = 16,
            AutomaticDecompression = DecompressionMethods.None,
            UseProxy = !local
        };
        client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
    }

#if ORBIT_LOCAL_DEVELOPMENT
    /// <summary>Available only in an explicit local development build; accepts literal loopback addresses.</summary>
    public static Transport LocalLoopback(string origin)
    {
        var uri = ParseOrigin(origin, "http");
        var authority = origin[(origin.IndexOf("://", StringComparison.Ordinal) + 3)..].TrimEnd('/');
        var host = authority.StartsWith('[') ? authority[1..authority.IndexOf(']')] : authority.Split(':')[0];
        if (!IPAddress.TryParse(host, out var address) || !IPAddress.IsLoopback(address) ||
            (address.AddressFamily == AddressFamily.InterNetwork &&
             (host.Split('.').Length != 4 || host.Split('.').Any(part => part.Length == 0 ||
                 !part.All(char.IsAsciiDigit) || (part.Length > 1 && part[0] == '0')))))
            throw new OrbitException(OrbitError.Configuration);
        return new Transport(uri, true);
    }
#endif

    private static Uri ParseOrigin(string value, string scheme)
    {
        if (value.Length > 2048 || value.Any(c => char.IsControl(c) || char.IsWhiteSpace(c)) ||
            value.Contains('\\') || !Uri.TryCreate(value, UriKind.Absolute, out var parsed) ||
            parsed.Scheme != scheme || string.IsNullOrEmpty(parsed.Host) || parsed.UserInfo.Length != 0 ||
            parsed.AbsolutePath != "/" || parsed.Query.Length != 0 || parsed.Fragment.Length != 0)
            throw new OrbitException(OrbitError.Configuration);
        var authority = value[(value.IndexOf("://", StringComparison.Ordinal) + 3)..].TrimEnd('/');
        if (authority.Length == 0 || authority.IndexOfAny(['/', '@', '?', '#']) >= 0)
            throw new OrbitException(OrbitError.Configuration);
        return parsed;
    }

    private Uri Endpoint(string path)
    {
        var parts = path.Split('?', 2);
        var route = parts[0];
        if (path.Length > 2048 || !(route.StartsWith("/api/client/v1/", StringComparison.Ordinal) ||
            route == "/.well-known/orbit-jwks.json") || path.Contains("//", StringComparison.Ordinal) ||
            path.IndexOfAny(['\\', '#']) >= 0 || path.Any(c => char.IsControl(c) || char.IsWhiteSpace(c)) ||
            !Uri.TryCreate(origin, path, out var endpoint) || endpoint.GetLeftPart(UriPartial.Authority) != origin.GetLeftPart(UriPartial.Authority) ||
            endpoint.AbsolutePath != route)
            throw new OrbitException(OrbitError.Configuration);
        if (parts.Length == 2)
        {
            if (route is not ("/.well-known/orbit-jwks.json" or "/api/client/v1/licences" or "/api/client/v1/sessions/current"))
                throw new OrbitException(OrbitError.Configuration);
            var pairs = parts[1].Split('&');
            if (pairs.Length != 2 && !(route == "/api/client/v1/licences" && pairs.Length == 3))
                throw new OrbitException(OrbitError.Configuration);
            string[] names = ["application_id", "environment_id", "after"];
            for (var index = 0; index < pairs.Length; index++)
            {
                var pair = pairs[index].Split('=', 2);
                if (pair.Length != 2 || pair[0] != names[index] || !JsonWire.Opaque(pair[1]))
                    throw new OrbitException(OrbitError.Configuration);
            }
        }
        return endpoint;
    }

    internal Task<JsonElement?> GetAsync(string path, CancellationToken cancellationToken, string? bearer = null) =>
        RequestAsync(HttpMethod.Get, path, null, bearer, true, cancellationToken);

    internal Task<JsonElement?> DeleteAsync(string path, string bearer, CancellationToken cancellationToken) =>
        RequestAsync(HttpMethod.Delete, path, null, bearer, false, cancellationToken);

    internal Task<JsonElement?> PostAsync(string path, Dictionary<string, object?> body, bool retrySafe, CancellationToken cancellationToken)
    {
        OrbitException.CheckCancellation(cancellationToken);
        byte[] bytes;
        try
        {
            using var stream = new LimitedStream();
            JsonSerializer.Serialize(stream, body);
            bytes = stream.ToArray();
        }
        catch (JsonException) { throw new OrbitException(OrbitError.Configuration); }
        return RequestAsync(HttpMethod.Post, path, bytes, null, retrySafe, cancellationToken);
    }

    private async Task<JsonElement?> RequestAsync(HttpMethod method, string path, byte[]? body, string? bearer, bool retrySafe, CancellationToken cancellationToken)
    {
        if (InstallationCancellation is not { } lifetime)
            return await RequestCoreAsync(method, path, body, bearer, retrySafe, cancellationToken).ConfigureAwait(false);
        lock (installedGate)
        {
            if (installedClosed)
                throw new OrbitException(OrbitError.Cancelled);
            if (installedRequests++ == 0)
                installedIdle = new(TaskCreationOptions.RunContinuationsAsynchronously);
        }
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime);
            return await RequestCoreAsync(method, path, body, bearer, retrySafe, linked.Token).ConfigureAwait(false);
        }
        finally { lock (installedGate) { if (--installedRequests == 0) installedIdle.TrySetResult(); } }
    }

    private async Task<JsonElement?> RequestCoreAsync(HttpMethod method, string path, byte[]? body, string? bearer,
        bool retrySafe, CancellationToken cancellationToken)
    {
        OrbitException.CheckCancellation(cancellationToken);
        var endpoint = Endpoint(path);
        if (bearer != null && (!JsonWire.Bearer(bearer) ||
            !(method == HttpMethod.Get && endpoint.AbsolutePath == "/api/client/v1/licences" ||
              method == HttpMethod.Delete && endpoint.AbsolutePath == "/api/client/v1/sessions/current")))
            throw new OrbitException(OrbitError.Configuration);
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        operation.CancelAfter(TimeSpan.FromSeconds(30));
        var started = Stopwatch.GetTimestamp();
        try
        {
            for (var attempt = 0; ; attempt++)
            {
                try
                {
                    var result = await AttemptAsync(method, endpoint, body, bearer, operation.Token).ConfigureAwait(false);
                    OrbitException.CheckCancellation(cancellationToken);
                    return result;
                }
                catch (AttemptFailure failure)
                {
                    OrbitException.CheckCancellation(cancellationToken);
                    if (!retrySafe || attempt == 2 || failure.Error.Error != OrbitError.Transient) throw failure.Error;
                    var backoff = TimeSpan.FromMilliseconds((250 + RandomNumberGenerator.GetInt32(256)) << attempt);
                    var delay = failure.RetryAfter > backoff ? failure.RetryAfter : backoff;
                    if (delay >= TimeSpan.FromSeconds(30) - Stopwatch.GetElapsedTime(started)) throw failure.Error;
                    await Task.Delay(delay, operation.Token).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException)
        {
            throw new OrbitException(cancellationToken.IsCancellationRequested ? OrbitError.Cancelled : OrbitError.Transient);
        }
    }

    private static bool HasOrbitErrorMember(ReadOnlyMemory<byte> body)
    {
        try
        {
            using var document = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 16 });
            return document.RootElement.ValueKind == JsonValueKind.Object &&
                   document.RootElement.TryGetProperty("error", out _);
        }
        catch (JsonException) { return false; }
    }

    private async Task<JsonElement?> AttemptAsync(HttpMethod method, Uri endpoint, byte[]? body, string? bearer,
        CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        try
        {
            using var request = new HttpRequestMessage(method, endpoint);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            if (bearer != null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
            if (body != null)
            {
                request.Content = new ByteArrayContent(body);
                request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            }
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
            if (response.Content.Headers.ContentLength > JsonWire.MaxBytes) throw JsonWire.Invalid();
            await using var content = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
            using var buffer = new MemoryStream();
            var chunk = new byte[8192];
            int count;
            while ((count = await content.ReadAsync(chunk, deadline.Token).ConfigureAwait(false)) != 0)
            {
                if (count > JsonWire.MaxBytes - buffer.Length) throw JsonWire.Invalid();
                buffer.Write(chunk, 0, count);
            }
            var bytes = buffer.ToArray();
            if (response.StatusCode == HttpStatusCode.NoContent)
                return bytes.Length == 0 ? null : throw JsonWire.Invalid();
            var status = (int)response.StatusCode;
            if (status is 502 or 503 or 504 && !HasOrbitErrorMember(bytes))
                throw new AttemptFailure(new OrbitException(OrbitError.Transient));
            var json = JsonWire.Parse(bytes);
            if (response.IsSuccessStatusCode) return json;
            if (status is not (401 or 403 or 404 or 409 or 422 or 429) && status is not (>= 500 and <= 599)) throw JsonWire.Invalid();
            var envelope = JsonWire.Field(json, "error");
            var code = JsonWire.String(envelope, "code");
            var requestId = JsonWire.String(envelope, "request_id");
            if (!OrbitException.ValidCode(code) || !OrbitException.ValidRequestId(requestId) ||
                JsonWire.String(envelope, "message").Length == 0)
                throw JsonWire.Invalid();
            var retryAfter = TimeSpan.Zero;
            if (response.Headers.TryGetValues("Retry-After", out var values))
            {
                var delays = values.ToArray();
                if (delays.Length != 1) throw JsonWire.Invalid();
                var delay = delays[0];
                if (delay is { Length: > 0 } && delay.All(char.IsAsciiDigit))
                    retryAfter = long.TryParse(delay, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds) && seconds < 30
                        ? TimeSpan.FromSeconds(seconds) : TimeSpan.FromSeconds(30);
            }
            var transient = status == 429 && code == "rate_limited" || status == 503 && code == "service_unavailable";
            throw new AttemptFailure(new OrbitException(transient ? OrbitError.Transient : OrbitError.Denied, code, requestId), retryAfter);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { throw new AttemptFailure(new OrbitException(OrbitError.Transient)); }
        catch (HttpRequestException error) { throw new AttemptFailure(ClassifyTransport(error)); }
        catch (IOException error) { throw new AttemptFailure(ClassifyTransport(error)); }
        catch (AuthenticationException) { throw new AttemptFailure(new OrbitException(OrbitError.TransportSecurity)); }
        catch (OrbitException error) { throw new AttemptFailure(error); }
    }

    private static OrbitException ClassifyTransport(Exception error)
    {
        var transient = false;
        for (Exception? cause = error; cause != null; cause = cause.InnerException)
        {
            if (cause is AuthenticationException || cause is HttpRequestException { HttpRequestError: HttpRequestError.SecureConnectionError })
                return new OrbitException(OrbitError.TransportSecurity);
            if (cause is SocketException socket && socket.SocketErrorCode is
                SocketError.ConnectionRefused or SocketError.ConnectionReset or SocketError.NetworkUnreachable or SocketError.HostUnreachable or SocketError.TimedOut)
                transient = true;
        }
        return new OrbitException(transient ? OrbitError.Transient : OrbitError.TransportSecurity);
    }

    public void Dispose() => client.Dispose();

    private sealed class AttemptFailure(OrbitException error, TimeSpan retryAfter = default) : Exception
    {
        internal OrbitException Error { get; } = error;
        internal TimeSpan RetryAfter { get; } = retryAfter;
    }

    private sealed class LimitedStream : MemoryStream
    {
        public override void Write(byte[] buffer, int offset, int count)
        {
            if (count > JsonWire.MaxBytes - Length) throw new OrbitException(OrbitError.Configuration);
            base.Write(buffer, offset, count);
        }
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (buffer.Length > JsonWire.MaxBytes - Length) throw new OrbitException(OrbitError.Configuration);
            base.Write(buffer);
        }
    }
}
