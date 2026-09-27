using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Orbit.Sdk;

internal sealed record OfflineExpected(AppKey AppKey, Device Device, long Now, long MinimumSequence = 1);

internal sealed record OfflineFile(string Token, string KeyId, string LicenceId, string ActivationId,
    string InstallationId, string IssuanceId, long IssuedAt, long ExpiresAt, long? LicenceExpiresAt,
    long Sequence, int PolicyVersion, IReadOnlyDictionary<string, bool> Entitlements, string ContentDigest)
{
    public override string ToString() => "OfflineFile(<redacted>)";
}

internal sealed record OfflineRuntime(OfflineFile File, ClockAnchor Anchor, InstalledOffline Saved,
    bool Uncertain = false, long LastCheckpointElapsedTicks = 0);

internal sealed record OfflineClockState(ClockAnchor Anchor, long TimeHighWater, long WallHighWater,
    bool Uncertain = false, long LastCheckpointElapsedTicks = 0);

// Original signed files, sequence floors and clock evidence are integrated by
// the installed client separately. This verifier alone is not restored access.
/// <summary>Trusted offline-purpose verification keys configured by the application.</summary>
public sealed class OfflineKeys
{
    internal const int MaximumFileBytes = 16384;
    internal const long MaximumLifetime = 366L * 86400;
    internal const long MaximumTime = 253402300799;
    internal const long MaximumSequence = 9007199254740991;
    private readonly string environment;
    private readonly Dictionary<string, ECParameters> keys = new(StringComparer.Ordinal);

    private OfflineKeys(string environment) => this.environment = environment;

    /// <summary>Parse a trusted public JWKS for one app-key environment.</summary>
    public static OfflineKeys Parse(string jwksJson, string environment)
    {
        ArgumentNullException.ThrowIfNull(jwksJson);
        if (Encoding.UTF8.GetByteCount(jwksJson) > MaximumFileBytes) throw InvalidKeys();
        return Parse(Encoding.UTF8.GetBytes(jwksJson), environment);
    }

    /// <summary>Parse a trusted public JWKS for one app-key environment.</summary>
    internal string Environment => environment;

    public static OfflineKeys Parse(ReadOnlyMemory<byte> bytes, string environment)
    {
        if (bytes.Length > MaximumFileBytes) throw InvalidKeys();
        try { return Parse(JsonWire.Parse(bytes), environment); }
        catch (OrbitException) { throw InvalidKeys(); }
    }

    internal static OfflineKeys Parse(JsonElement value, string environment)
    {
        try
        {
            if (environment is not ("test" or "live") ||
                Encoding.UTF8.GetByteCount(value.GetRawText()) > MaximumFileBytes) throw InvalidKeys();
            JsonWire.ExactFields(value, "keys");
            var entries = JsonWire.Field(value, "keys");
            if (entries.ValueKind != JsonValueKind.Array || entries.GetArrayLength() is < 1 or > 8) throw InvalidKeys();
            var result = new OfflineKeys(environment);
            var prefix = $"offline-{environment}-";
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
                // Validate every configured point, including a retained key that
                // is not selected by the next file. No native handles are kept.
                using var publicKey = ECDsa.Create(parameters);
                if (!result.keys.TryAdd(kid, parameters)) throw InvalidKeys();
            }
            return result;
        }
        catch (Exception exception) when (exception is OrbitException or CryptographicException or ArgumentException or InvalidOperationException)
        { throw InvalidKeys(); }
    }

    internal OfflineFile Verify(string token, OfflineExpected expected)
    {
        try { return VerifyCore(token, expected); }
        catch (Exception exception) when (exception is OrbitException or CryptographicException or ArgumentException or InvalidOperationException or OverflowException)
        { throw InvalidFile(); }
    }

    private OfflineFile VerifyCore(string token, OfflineExpected expected)
    {
        if (token == null || token.Length > MaximumFileBytes || !token.All(char.IsAscii) ||
            expected.Now is < 0 or > MaximumTime || expected.MinimumSequence is < 1 or > MaximumSequence ||
            expected.AppKey.Environment != environment) throw InvalidFile();
        new OrbitConfig(expected.AppKey.ApplicationId, expected.AppKey.EnvironmentId, expected.AppKey.Issuer).Validate(expected.Device);
        token = token.Trim(' ', '\t', '\r', '\n', '\v', '\f');
        var parts = token.Split('.');
        if (parts.Length != 3) throw InvalidFile();
        var header = JsonWire.Parse(JsonWire.DecodeBase64(parts[0]));
        var payload = JsonWire.DecodeBase64(parts[1]);
        var signature = JsonWire.DecodeBase64(parts[2]);
        JsonWire.ExactFields(header, "alg", "typ", "kid");
        var kid = JsonWire.String(header, "kid");
        if (JsonWire.String(header, "alg") != "ES256" || JsonWire.String(header, "typ") != "orbit-offline+jwt" ||
            signature.Length != 64 || !keys.TryGetValue(kid, out var parameters)) throw InvalidFile();
        using (var publicKey = ECDsa.Create(parameters))
        {
            if (!publicKey.VerifyData(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), signature,
                HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) throw InvalidFile();
        }
        var claims = JsonWire.Parse(payload);
        var binding = JsonWire.String(claims, "binding_mode");
        var hasExpiry = claims.TryGetProperty("licence_expires_at", out _);
        var fields = new List<string>
        {
            "ver", "iss", "aud", "sub", "jti", "iat", "nbf", "exp", "application_id", "environment_id",
            "activation_id", "installation_id", "sequence", "binding_mode", "policy_version", "entitlements"
        };
        if (hasExpiry) fields.Add("licence_expires_at");
        if (binding == "hwid") fields.AddRange(["fingerprint", "fingerprint_provider"]);
        JsonWire.ExactFields(claims, fields.ToArray());
        foreach (var name in new[] { "sub", "jti", "application_id", "environment_id", "activation_id", "installation_id" })
            if (!JsonWire.Opaque(JsonWire.String(claims, name))) throw InvalidFile();
        var installation = JsonWire.String(claims, "installation_id");
        var issued = JsonWire.Integer(claims, "iat");
        var notBefore = JsonWire.Integer(claims, "nbf");
        var expiry = JsonWire.Integer(claims, "exp");
        var sequence = JsonWire.Integer(claims, "sequence");
        var policy = JsonWire.Integer(claims, "policy_version");
        long? licenceExpiry = hasExpiry ? JsonWire.Integer(claims, "licence_expires_at") : null;
        if (JsonWire.Integer(claims, "ver") != 1 || installation.Length < 16 ||
            JsonWire.String(claims, "iss") != expected.AppKey.Issuer ||
            JsonWire.String(claims, "aud") != $"orbit-offline:{expected.AppKey.ApplicationId}:{expected.AppKey.EnvironmentId}" ||
            JsonWire.String(claims, "application_id") != expected.AppKey.ApplicationId ||
            JsonWire.String(claims, "environment_id") != expected.AppKey.EnvironmentId || installation != expected.Device.InstallationId ||
            policy is < 1 or > int.MaxValue || sequence < expected.MinimumSequence || sequence > MaximumSequence ||
            issued is < 0 or > MaximumTime || notBefore != issued || issued > expected.Now + 30 ||
            expiry is < 0 or > MaximumTime || expiry <= expected.Now || expiry <= issued || expiry - issued > MaximumLifetime ||
            licenceExpiry is < 0 or > MaximumTime || (licenceExpiry != null && licenceExpiry < expiry)) throw InvalidFile();
        if (binding == "hwid")
        {
            if (expected.Device.Fingerprint == null || expected.Device.FingerprintProvider == null ||
                JsonWire.String(claims, "fingerprint") != expected.Device.Fingerprint ||
                JsonWire.String(claims, "fingerprint_provider") != expected.Device.FingerprintProvider) throw InvalidFile();
        }
        else if (binding != "none") throw InvalidFile();
        var entitlements = JsonWire.Entitlements(JsonWire.Field(claims, "entitlements"));
        using var canonical = new MemoryStream();
        using (var writer = new Utf8JsonWriter(canonical, new JsonWriterOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
            WriteCanonical(writer, claims);
        var digest = Convert.ToHexStringLower(SHA256.HashData(canonical.GetBuffer().AsSpan(0, checked((int)canonical.Length))));
        return new OfflineFile(token, kid, JsonWire.String(claims, "sub"), JsonWire.String(claims, "activation_id"),
            installation, JsonWire.String(claims, "jti"), issued, expiry, licenceExpiry, sequence, (int)policy, entitlements, digest);
    }

    private static void WriteCanonical(Utf8JsonWriter writer, JsonElement value)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in value.EnumerateObject().OrderBy(item => item.Name, StringComparer.Ordinal))
                {
                    writer.WritePropertyName(property.Name);
                    WriteCanonical(writer, property.Value);
                }
                writer.WriteEndObject();
                break;
            case JsonValueKind.String: writer.WriteStringValue(value.GetString()); break;
            case JsonValueKind.Number: writer.WriteNumberValue(value.GetInt64()); break;
            case JsonValueKind.True: writer.WriteBooleanValue(true); break;
            case JsonValueKind.False: writer.WriteBooleanValue(false); break;
            default: throw InvalidFile();
        }
    }

    private static OrbitException InvalidKeys() => new(OrbitError.InvalidResponse, "invalid_offline_keys");
    private static OrbitException InvalidFile() => new(OrbitError.InvalidResponse, "invalid_offline_file");
}

/// <summary>Public installation information to send to an authenticated seller for offline issuance.</summary>
public sealed record OfflineRequest(
    [property: JsonPropertyName("format")] string Format,
    [property: JsonPropertyName("version")] int Version,
    [property: JsonPropertyName("app_key")] string AppKey,
    [property: JsonPropertyName("installation_id")] string InstallationId,
    [property: JsonPropertyName("fingerprint"), JsonIgnore(Condition = JsonIgnoreCondition.Never)] string? Fingerprint,
    [property: JsonPropertyName("fingerprint_provider"), JsonIgnore(Condition = JsonIgnoreCondition.Never)] string? FingerprintProvider);
