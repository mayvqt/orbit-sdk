using System.Net;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Orbit.Sdk;

public sealed record UpdateTarget(string Platform, string Architecture)
{
    public static UpdateTarget Runtime => new(
        OperatingSystem.IsWindows() ? "windows" : OperatingSystem.IsMacOS() ? "macos" :
        OperatingSystem.IsLinux() ? "linux" : throw new OrbitException(OrbitError.Configuration, "explicit_target_required"),
        RuntimeInformation.ProcessArchitecture switch
        {
            System.Runtime.InteropServices.Architecture.X64 => "x64",
            System.Runtime.InteropServices.Architecture.Arm64 => "arm64",
            System.Runtime.InteropServices.Architecture.X86 => "x86",
            System.Runtime.InteropServices.Architecture.Arm => "armv7",
            _ => throw new OrbitException(OrbitError.Configuration, "explicit_target_required")
        });
}
public enum DeliveryMode { Public, Protected }
public sealed record ReleaseArtifact(string Id, string ReleaseId, UpdateTarget Target, string Filename,
    long ByteLength, string Sha256, DeliveryMode DeliveryMode, string Url, string? RequiredFeature)
{
    public override string ToString() => "ReleaseArtifact(<redacted>)";
}
public sealed record Release(string Id, string Channel, string Version, string Notes, long ReleaseNumber,
    DateTimeOffset CreatedAt, DateTimeOffset PublishedAt, IReadOnlyList<ReleaseArtifact> Artifacts);
public sealed record AvailableUpdate(Release Release, ReleaseArtifact Artifact);
public sealed record DownloadAuthorization(ReleaseArtifact Artifact, string? Ticket, DateTimeOffset? ExpiresAt)
{
    public override string ToString() => "DownloadAuthorization(<redacted>)";
    /// <summary>Download and verify bytes before atomically exposing the caller's destination. Never executes them.</summary>
    public Task DownloadAsync(string destination, long maximumBytes, bool replace = false,
        CancellationToken cancellationToken = default) =>
        ArtifactDownload.DownloadAsync(this, destination, maximumBytes, replace, cancellationToken);
}

public sealed partial class OrbitClient
{
    public Task<AvailableUpdate?> CheckForUpdateAsync(long installedReleaseNumber, string channel = "stable",
        UpdateTarget? target = null, CancellationToken cancellationToken = default)
    {
        target ??= UpdateTarget.Runtime;
        if (installedReleaseNumber is < 0 or > OnlineWire.Maximum || !DownloadWire.Label(channel) ||
            !DownloadWire.Label(target.Platform) || !DownloadWire.Label(target.Architecture))
            throw new OrbitException(OrbitError.Configuration);
        return OnlineAsync<AvailableUpdate?>("updates", new()
        {
            ["installed_release_number"] = installedReleaseNumber,
            ["channel"] = channel,
            ["platform"] = target.Platform,
            ["architecture"] = target.Architecture
        }, v => DownloadWire.Update(v, installedReleaseNumber, channel, target), cancellationToken);
    }

    public Task<DownloadAuthorization> AuthorizeDownloadAsync(string releaseId, string artifactId,
        CancellationToken cancellationToken = default)
    {
        if (!JsonWire.Opaque(releaseId) || !JsonWire.Opaque(artifactId)) throw new OrbitException(OrbitError.Configuration);
        return OnlineAsync("downloads/authorize", new() { ["release_id"] = releaseId, ["artifact_id"] = artifactId }, v =>
        {
            JsonWire.ExactFields(v, "artifact", "ticket", "expires_at");
            var artifact = DownloadWire.Artifact(JsonWire.Field(v, "artifact"));
            if (artifact.Id != artifactId || artifact.ReleaseId != releaseId) throw JsonWire.Invalid();
            var ticketValue = JsonWire.Field(v, "ticket");
            var ticket = ticketValue.ValueKind == JsonValueKind.Null ? null : JsonWire.Text(ticketValue);
            var expiry = OnlineWire.Time(v, "expires_at");
            var authorization = new DownloadAuthorization(artifact, ticket, expiry);
            DownloadWire.Authorization(authorization);
            return authorization;
        }, cancellationToken);
    }
}

internal static class DownloadWire
{
    internal static bool Label(string? value) => value is { Length: >= 1 and <= 32 } && value[0] is >= 'a' and <= 'z' &&
        value.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '-');
    internal static void Artifact(ReleaseArtifact a)
    {
        if (!JsonWire.Opaque(a.Id) || !JsonWire.Opaque(a.ReleaseId) || !Label(a.Target.Platform) ||
            !Label(a.Target.Architecture) || a.ByteLength is < 1 or > OnlineWire.Maximum || a.Sha256.Length != 64 ||
            !a.Sha256.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f') || a.Filename.Length == 0 ||
            Encoding.UTF8.GetByteCount(a.Filename) > 255 || a.Filename is "." or ".." ||
            a.Filename.Any(c => char.IsControl(c) || c is '/' or '\\') ||
            a.RequiredFeature != null && !JsonWire.Feature(a.RequiredFeature) ||
            a.DeliveryMode is not (DeliveryMode.Public or DeliveryMode.Protected)) throw JsonWire.Invalid();
        try { DownloadTicketVerifier.ValidateEndpoint(a.Url, a.DeliveryMode == DeliveryMode.Public); }
        catch (OrbitException) { throw JsonWire.Invalid(); }
    }
    internal static ReleaseArtifact Artifact(JsonElement v)
    {
        JsonWire.ExactFields(v, "id", "release_id", "platform", "architecture", "filename", "byte_length",
            "sha256", "delivery_mode", "url", "required_feature");
        var mode = JsonWire.String(v, "delivery_mode") switch
        { "public" => DeliveryMode.Public, "protected" => DeliveryMode.Protected, _ => throw JsonWire.Invalid() };
        var feature = JsonWire.Field(v, "required_feature");
        var result = new ReleaseArtifact(JsonWire.String(v, "id"), JsonWire.String(v, "release_id"),
            new(JsonWire.String(v, "platform"), JsonWire.String(v, "architecture")), JsonWire.String(v, "filename"),
            OnlineWire.Number(v, "byte_length", 1), JsonWire.String(v, "sha256"), mode, JsonWire.String(v, "url"),
            feature.ValueKind == JsonValueKind.Null ? null : JsonWire.Text(feature));
        Artifact(result);
        return result;
    }
    internal static AvailableUpdate? Update(JsonElement v, long installed, string channel, UpdateTarget target)
    {
        JsonWire.ExactFields(v, "release", "artifact");
        var release = JsonWire.Field(v, "release");
        var selected = JsonWire.Field(v, "artifact");
        if (release.ValueKind == JsonValueKind.Null && selected.ValueKind == JsonValueKind.Null) return null;
        var artifact = Artifact(selected);
        JsonWire.ExactFields(release, "id", "channel", "version", "notes", "release_number", "state",
            "created_at", "published_at", "artifacts");
        var artifacts = JsonWire.Field(release, "artifacts");
        if (artifacts.ValueKind != JsonValueKind.Array || artifacts.GetArrayLength() != 1 ||
            Artifact(artifacts[0]) != artifact || artifact.Target != target ||
            JsonWire.String(release, "id") != artifact.ReleaseId || JsonWire.String(release, "channel") != channel ||
            JsonWire.String(release, "state") != "published") throw JsonWire.Invalid();
        var number = OnlineWire.Number(release, "release_number", 1);
        var version = JsonWire.String(release, "version");
        var notes = JsonWire.String(release, "notes");
        if (number <= installed || version.Length == 0 || Encoding.UTF8.GetByteCount(version) > 64 ||
            Encoding.UTF8.GetByteCount(notes) > 8192 || version.Any(char.IsControl)) throw JsonWire.Invalid();
        return new(new(artifact.ReleaseId, channel, version, notes, number,
            OnlineWire.Time(release, "created_at") ?? throw JsonWire.Invalid(),
            OnlineWire.Time(release, "published_at") ?? throw JsonWire.Invalid(), Array.AsReadOnly(new[] { artifact })), artifact);
    }
    internal static void Authorization(DownloadAuthorization a)
    {
        Artifact(a.Artifact);
        if (a.Artifact.DeliveryMode == DeliveryMode.Public)
        { if (a.Ticket != null || a.ExpiresAt != null) throw JsonWire.Invalid(); }
        else if (a.ExpiresAt == null || a.Ticket == null || a.Ticket.Length is < 1 or > 16384 ||
            a.Ticket.Split('.').Length != 3 || !a.Ticket.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.'))
            throw JsonWire.Invalid();
    }
}

internal static class ArtifactDownload
{
    internal static Func<HttpMessageHandler>? TestHandler;
    internal static TimeSpan? TestTimeout;
    internal static async Task DownloadAsync(DownloadAuthorization authorization, string destination,
        long maximumBytes, bool replace, CancellationToken cancellationToken)
    {
        DownloadWire.Authorization(authorization);
        if (maximumBytes is < 1 or > OnlineWire.Maximum || authorization.Artifact.ByteLength > maximumBytes ||
            string.IsNullOrWhiteSpace(destination)) throw new OrbitException(OrbitError.Configuration);
        OrbitException.CheckCancellation(cancellationToken);
        if (authorization.ExpiresAt <= DateTimeOffset.UtcNow) throw new OrbitException(OrbitError.Denied, "download_ticket_expired");
        var path = Path.GetFullPath(destination);
        if (!replace && File.Exists(path)) throw new OrbitException(OrbitError.Storage, "destination_exists");
        var temporary = Path.Combine(Path.GetDirectoryName(path)!, ".orbit-download-" + Guid.NewGuid().ToString("N"));
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        operation.CancelAfter(TestTimeout ?? TimeSpan.FromMinutes(30));
        var transferToken = operation.Token;
        try
        {
            using var handler = TestHandler?.Invoke() ?? new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseCookies = false,
                UseProxy = false,
                Credentials = null,
                DefaultProxyCredentials = null,
                AutomaticDecompression = DecompressionMethods.None,
                MaxResponseHeadersLength = 16,
                ConnectTimeout = TimeSpan.FromSeconds(10)
            };
            using var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
            var url = authorization.Artifact.Url;
            for (var redirect = 0; ; redirect++)
            {
                DownloadTicketVerifier.ValidateEndpoint(url, allowQuery: true);
                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.AcceptEncoding.Add(new StringWithQualityHeaderValue("identity"));
                if (redirect == 0 && authorization.Ticket != null)
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", authorization.Ticket);
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, transferToken)
                    .ConfigureAwait(false);
                if ((int)response.StatusCode is 301 or 302 or 303 or 307 or 308)
                {
                    if (redirect >= 5 || response.Headers.Location == null) throw JsonWire.Invalid();
                    var location = response.Headers.Location.OriginalString;
                    if (location.Length > 2048 || location.Any(c => c <= 32 || c >= 127 || c is '\\' or '#')) throw JsonWire.Invalid();
                    if (location.StartsWith("//", StringComparison.Ordinal))
                        DownloadTicketVerifier.ValidateEndpoint("https:" + location, allowQuery: true);
                    else if (response.Headers.Location.IsAbsoluteUri)
                        DownloadTicketVerifier.ValidateEndpoint(location, allowQuery: true);
                    url = new Uri(new Uri(url), response.Headers.Location).AbsoluteUri;
                    continue;
                }
                if (response.StatusCode != HttpStatusCode.OK ||
                    response.Content.Headers.ContentEncoding.Any(e => !string.Equals(e, "identity", StringComparison.OrdinalIgnoreCase)) ||
                    response.Content.Headers.ContentLength is { } length && length != authorization.Artifact.ByteLength)
                    throw JsonWire.Invalid();
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                var fileOptions = new FileStreamOptions
                {
                    Mode = FileMode.CreateNew,
                    Access = FileAccess.Write,
                    Share = FileShare.None,
                    BufferSize = 65536,
                    Options = FileOptions.Asynchronous | FileOptions.SequentialScan
                };
                if (!OperatingSystem.IsWindows()) fileOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
                await using (var output = new FileStream(temporary, fileOptions))
                await using (var input = await response.Content.ReadAsStreamAsync(transferToken).ConfigureAwait(false))
                {
                    var buffer = new byte[65536];
                    long received = 0;
                    int read;
                    while ((read = await ReadBodyAsync(input, buffer, transferToken).ConfigureAwait(false)) != 0)
                    {
                        if (read > maximumBytes - received || read > authorization.Artifact.ByteLength - received) throw JsonWire.Invalid();
                        received += read;
                        hash.AppendData(buffer, 0, read);
                        await output.WriteAsync(buffer.AsMemory(0, read), transferToken).ConfigureAwait(false);
                    }
                    if (received != authorization.Artifact.ByteLength ||
                        !CryptographicOperations.FixedTimeEquals(hash.GetHashAndReset(), Convert.FromHexString(authorization.Artifact.Sha256)))
                        throw JsonWire.Invalid();
                    await output.FlushAsync(transferToken).ConfigureAwait(false);
                    output.Flush(flushToDisk: true);
                }
                transferToken.ThrowIfCancellationRequested();
                File.Move(temporary, path, replace);
                return;
            }
        }
        catch (OperationCanceledException) { throw new OrbitException(cancellationToken.IsCancellationRequested ? OrbitError.Cancelled : OrbitError.Transient); }
        catch (HttpRequestException) { throw new OrbitException(OrbitError.TransportSecurity); }
        catch (IOException) { throw new OrbitException(OrbitError.Storage); }
        catch (UnauthorizedAccessException) { throw new OrbitException(OrbitError.Storage); }
        finally
        {
            try { File.Delete(temporary); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
        }
    }

    // A failed or truncated response body is a delivery failure, not a local storage failure.
    private static async ValueTask<int> ReadBodyAsync(Stream input, byte[] buffer, CancellationToken cancellationToken)
    {
        try { return await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false); }
        catch (IOException) { throw JsonWire.Invalid(); }
    }
}
