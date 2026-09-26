using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Orbit.Sdk;

/// <summary>Verified download metadata. Match it to the seller's artifact registry before delivery.</summary>
public sealed record DownloadTicket(string LicenceId, string ReleaseId, string ArtifactId,
    string Sha256, long ByteLength, string TicketId, DateTimeOffset IssuedAt, DateTimeOffset ExpiresAt)
{
    public override string ToString() => "DownloadTicket(<redacted>)";
}

/// <summary>Verifies short download capabilities using configured public keys. Never fetches keys or files.</summary>
public sealed class DownloadTicketVerifier
{
    private const int MaximumBytes = 16384;
    private const long MaximumTime = 253402300799;
    private readonly AppKey app;
    private readonly string endpoint;
    private readonly Dictionary<string, ECParameters> keys = new(StringComparer.Ordinal);

    /// <param name="appKey">Public app key for the seller's application and environment.</param>
    /// <param name="endpoint">Exact HTTPS audience of this protected download endpoint.</param>
    /// <param name="publicKeys">Trusted connected-purpose JWKS JSON, obtained through trusted configuration or verified HTTPS.</param>
    public DownloadTicketVerifier(string appKey, string endpoint, ReadOnlyMemory<byte> publicKeys)
    {
        app = AppKey.Parse(appKey);
        ValidateEndpoint(endpoint);
        this.endpoint = endpoint;
        try
        {
            if (publicKeys.Length is < 1 or > MaximumBytes) throw InvalidKeys();
            var value = JsonWire.Parse(publicKeys);
            JsonWire.ExactFields(value, "keys");
            var entries = JsonWire.Field(value, "keys");
            if (entries.ValueKind != JsonValueKind.Array || entries.GetArrayLength() is < 1 or > 8) throw InvalidKeys();
            var prefix = app.Environment + "-";
            foreach (var entry in entries.EnumerateArray())
            {
                JsonWire.ExactFields(entry, "kty", "crv", "alg", "use", "kid", "x", "y");
                var kid = JsonWire.String(entry, "kid");
                if (JsonWire.String(entry, "kty") != "EC" || JsonWire.String(entry, "crv") != "P-256" ||
                    JsonWire.String(entry, "alg") != "ES256" || JsonWire.String(entry, "use") != "sig" ||
                    !JsonWire.Opaque(kid) || !kid.StartsWith(prefix, StringComparison.Ordinal) || kid.Length == prefix.Length)
                    throw InvalidKeys();
                var x = JsonWire.DecodeBase64(JsonWire.String(entry, "x"));
                var y = JsonWire.DecodeBase64(JsonWire.String(entry, "y"));
                if (x.Length != 32 || y.Length != 32) throw InvalidKeys();
                var parameters = new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } };
                using var publicKey = ECDsa.Create(parameters);
                if (!keys.TryAdd(kid, parameters)) throw InvalidKeys();
            }
        }
        catch (Exception error) when (error is OrbitException or CryptographicException or ArgumentException or InvalidOperationException)
        { throw InvalidKeys(); }
    }

    /// <summary>Verifies the exact ticket bytes and returns immutable metadata, or denies invalid/expired tickets.</summary>
    /// <param name="token">Compact bearer ticket, without whitespace or an Authorization header prefix.</param>
    /// <param name="now">Optional trusted application clock. Never take this value from the download request.</param>
    public DownloadTicket Verify(string token, DateTimeOffset? now = null)
    {
        try { return VerifyCore(token, now ?? DateTimeOffset.UtcNow); }
        catch (Exception error) when (error is OrbitException or CryptographicException or ArgumentException or InvalidOperationException or OverflowException)
        { throw new OrbitException(OrbitError.Denied, "invalid_download_ticket"); }
    }

    private DownloadTicket VerifyCore(string token, DateTimeOffset now)
    {
        if (token == null || token.Length is < 1 or > MaximumBytes || !token.All(char.IsAscii)) throw JsonWire.Invalid();
        var nowTicks = now.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks;
        if (nowTicks < 0 || nowTicks > MaximumTime * TimeSpan.TicksPerSecond) throw JsonWire.Invalid();
        var parts = token.Split('.');
        if (parts.Length != 3) throw JsonWire.Invalid();
        var header = JsonWire.Parse(JsonWire.DecodeBase64(parts[0]));
        var payload = JsonWire.DecodeBase64(parts[1]);
        var signature = JsonWire.DecodeBase64(parts[2]);
        JsonWire.ExactFields(header, "alg", "typ", "kid");
        if (JsonWire.String(header, "alg") != "ES256" || JsonWire.String(header, "typ") != "orbit-download+jwt" ||
            signature.Length != 64 || !keys.TryGetValue(JsonWire.String(header, "kid"), out var parameters)) throw JsonWire.Invalid();
        using (var publicKey = ECDsa.Create(parameters))
        {
            if (!publicKey.VerifyData(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), signature,
                HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) throw JsonWire.Invalid();
        }
        var claims = JsonWire.Parse(payload);
        JsonWire.ExactFields(claims, "ver", "iss", "aud", "sub", "jti", "iat", "nbf", "exp",
            "application_id", "environment_id", "release_id", "artifact_id", "sha256", "byte_length");
        foreach (var name in new[] { "sub", "jti", "application_id", "environment_id", "release_id", "artifact_id" })
            if (!JsonWire.Opaque(JsonWire.String(claims, name))) throw JsonWire.Invalid();
        var issued = JsonWire.Integer(claims, "iat");
        var expiry = JsonWire.Integer(claims, "exp");
        var length = JsonWire.Integer(claims, "byte_length");
        var digest = JsonWire.String(claims, "sha256");
        if (JsonWire.Integer(claims, "ver") != 1 || JsonWire.String(claims, "iss") != app.Issuer ||
            JsonWire.String(claims, "aud") != endpoint || JsonWire.String(claims, "application_id") != app.ApplicationId ||
            JsonWire.String(claims, "environment_id") != app.EnvironmentId || issued is < 0 or > MaximumTime ||
            JsonWire.Integer(claims, "nbf") != issued || expiry is < 0 or > MaximumTime || expiry <= issued || expiry - issued > 120 ||
            issued * TimeSpan.TicksPerSecond > nowTicks + 30 * TimeSpan.TicksPerSecond || expiry * TimeSpan.TicksPerSecond <= nowTicks ||
            length is < 1 or > 9007199254740991 || digest.Length != 64 || !digest.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f'))
            throw JsonWire.Invalid();
        return new DownloadTicket(JsonWire.String(claims, "sub"), JsonWire.String(claims, "release_id"),
            JsonWire.String(claims, "artifact_id"), digest, length, JsonWire.String(claims, "jti"),
            DateTimeOffset.FromUnixTimeSeconds(issued), DateTimeOffset.FromUnixTimeSeconds(expiry));
    }

    private static void ValidateEndpoint(string endpoint)
    {
        try
        {
            if (endpoint == null || endpoint.Length is < 1 or > 2048 || !endpoint.StartsWith("https://", StringComparison.Ordinal) ||
                endpoint.Any(c => !char.IsAscii(c) || c <= 32 || c == 127 || "\\?#<>\"{}|^`".Contains(c))) throw InvalidEndpoint();
            for (var index = 0; index < endpoint.Length; index++)
            {
                if (endpoint[index] != '%') continue;
                if (index + 2 >= endpoint.Length || !char.IsAsciiHexDigit(endpoint[index + 1]) || !char.IsAsciiHexDigit(endpoint[index + 2]))
                    throw InvalidEndpoint();
                index += 2;
            }
            var pathStart = endpoint.IndexOf('/', 8);
            var origin = Transport.ValidateOrigin(pathStart < 0 ? endpoint : endpoint[..pathStart]);
            if (new Uri(origin).Port is < 1 or > 65535) throw InvalidEndpoint();
        }
        catch (Exception error) when (error is OrbitException or ArgumentException)
        { throw InvalidEndpoint(); }
    }

    private static OrbitException InvalidEndpoint() => new(OrbitError.Configuration, "invalid_download_endpoint");
    private static OrbitException InvalidKeys() => new(OrbitError.Configuration, "invalid_download_keys");
}
