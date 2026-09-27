using System.Text;
using System.Text.Json;

namespace Orbit.Sdk;

internal sealed record SessionExpected(GrantExpected Grant, string SessionId, long Sequence);

internal sealed record SessionGrant(string SessionId, long Sequence, string LicenceId, string ActivationId,
    string InstallationId, string BindingMode, string TokenId, long IssuedAt, long ExpiresAt, long RefreshAfter, long? LicenceExpiresAt,
    int PolicyVersion, IReadOnlyDictionary<string, bool> Entitlements)
{
    public override string ToString() => "SessionGrant(<redacted>)";
}

// Session acquisition, generation fencing and renewal are integrated separately.
// A verified session grant must never be persisted as restorable access.
public sealed class SessionKeys
{
    private const int MaximumBytes = 16384;
    private const long MaximumTime = 253402300799;
    private const long MaximumSequence = 9007199254740991;
    private static readonly HashSet<string> KnownFields = new(StringComparer.Ordinal)
    {
        "iss", "aud", "sub", "jti", "iat", "nbf", "exp", "application_id", "environment_id",
        "activation_id", "installation_id", "binding_mode", "fingerprint", "fingerprint_provider",
        "policy_version", "entitlements", "refresh_after", "offline_allowed", "licence_expires_at",
        "session_id", "session_sequence"
    };
    private static readonly HashSet<string> FoldedFields = new(KnownFields, StringComparer.OrdinalIgnoreCase);
    private readonly GrantKeys keys;

    private SessionKeys(GrantKeys keys, string environment) { this.keys = keys; Environment = environment; }

    public string Environment { get; }

    public static SessionKeys Parse(string json, string environment) =>
        Parse(Encoding.UTF8.GetBytes(json), environment);

    public static SessionKeys Parse(ReadOnlyMemory<byte> bytes, string environment)
    {
        if (bytes.Length > MaximumBytes) throw InvalidKeys();
        try { return Parse(JsonWire.Parse(bytes), environment); }
        catch (OrbitException) { throw InvalidKeys(); }
    }

    internal static SessionKeys Parse(JsonElement value, string environment)
    {
        try
        {
            if (environment is not ("test" or "live") || Encoding.UTF8.GetByteCount(value.GetRawText()) > MaximumBytes)
                throw InvalidKeys();
            JsonWire.ExactFields(value, "keys");
            var keys = GrantKeys.Parse(value);
            var prefix = environment + "-";
            foreach (var entry in JsonWire.Field(value, "keys").EnumerateArray())
            {
                var kid = JsonWire.String(entry, "kid");
                if (!JsonWire.Opaque(kid) || !kid.StartsWith(prefix, StringComparison.Ordinal) || kid.Length == prefix.Length)
                    throw InvalidKeys();
            }
            return new SessionKeys(keys, environment);
        }
        catch (Exception error) when (error is OrbitException or ArgumentException or InvalidOperationException)
        { throw InvalidKeys(); }
    }

    internal bool Contains(string token)
    {
        try
        {
            var claims = keys.VerifySessionSignature(token);
            _ = claims;
            return true;
        }
        catch (OrbitException) { return false; }
    }

    internal SessionGrant Verify(string token, SessionExpected expected)
    {
        try { return VerifyCore(token, expected); }
        catch (Exception error) when (error is OrbitException or ArgumentException or InvalidOperationException or OverflowException)
        { throw InvalidGrant(); }
    }

    private SessionGrant VerifyCore(string token, SessionExpected expected)
    {
        var context = expected.Grant;
        if (!JsonWire.OperationId(expected.SessionId) || expected.Sequence is < 1 or > MaximumSequence ||
            context.Now is < 0 or > MaximumTime) throw InvalidGrant();
        var claims = keys.VerifySessionSignature(token);
        if (claims.ValueKind != JsonValueKind.Object) throw InvalidGrant();
        foreach (var property in claims.EnumerateObject())
            if (!KnownFields.Contains(property.Name) && FoldedFields.Contains(property.Name)) throw InvalidGrant();
        foreach (var name in new[] { "sub", "jti", "application_id", "environment_id", "activation_id", "installation_id" })
        {
            var value = JsonWire.String(claims, name);
            if (value.Length == 0 || Encoding.UTF8.GetByteCount(value) > 128) throw InvalidGrant();
        }
        var session = JsonWire.String(claims, "session_id");
        var sequence = JsonWire.Integer(claims, "session_sequence");
        var licence = JsonWire.String(claims, "sub");
        var issued = JsonWire.Integer(claims, "iat");
        var expiry = JsonWire.Integer(claims, "exp");
        var refresh = JsonWire.Integer(claims, "refresh_after");
        var policy = JsonWire.Integer(claims, "policy_version");
        var licenceExpiry = JsonWire.OptionalInteger(claims, "licence_expires_at");
        var binding = JsonWire.String(claims, "binding_mode");
        var fingerprint = JsonWire.OptionalString(claims, "fingerprint");
        var provider = JsonWire.OptionalString(claims, "fingerprint_provider");
        var expectedUnbound = context.Device.Fingerprint == null && context.Device.FingerprintProvider == null;
        var optionalBinding = context.AllowUnboundFingerprint && context.Device.Fingerprint != null && context.Device.FingerprintProvider != null;
        var bound = (context.ExpectedBindingMode == null || binding == context.ExpectedBindingMode) &&
            (binding == "none" && !claims.TryGetProperty("fingerprint", out _) &&
                !claims.TryGetProperty("fingerprint_provider", out _) && (expectedUnbound || optionalBinding) ||
             binding == "hwid" && ValidFingerprint(fingerprint, provider) &&
                fingerprint == context.Device.Fingerprint && provider == context.Device.FingerprintProvider);
        if (!JsonWire.OperationId(session) || session != expected.SessionId || sequence is < 1 or > MaximumSequence ||
            sequence != expected.Sequence || JsonWire.Boolean(claims, "offline_allowed") ||
            JsonWire.String(claims, "iss") != context.Config.Issuer ||
            JsonWire.String(claims, "aud") != $"orbit-session:{context.Config.ApplicationId}:{context.Config.EnvironmentId}" ||
            (context.LicenceId != null && licence != context.LicenceId) ||
            JsonWire.String(claims, "application_id") != context.Config.ApplicationId ||
            JsonWire.String(claims, "environment_id") != context.Config.EnvironmentId ||
            JsonWire.String(claims, "activation_id") != context.ActivationId ||
            JsonWire.String(claims, "installation_id") != context.Device.InstallationId || !bound || policy is < 1 or > int.MaxValue ||
            issued is < 0 or > MaximumTime || expiry is < 0 or > MaximumTime || refresh is < 0 or > MaximumTime ||
            JsonWire.Integer(claims, "nbf") != issued || issued > context.Now + 30 || expiry <= context.Now ||
            expiry <= issued || expiry - issued > 120 || expiry > context.CredentialExpiresAt ||
            licenceExpiry is < 0 or > MaximumTime || licenceExpiry != context.LicenceExpiresAt || expiry > licenceExpiry ||
            refresh <= issued || refresh > expiry || refresh > issued + 75 || (refresh < issued + 45 && refresh != expiry))
            throw InvalidGrant();
        return new SessionGrant(session, sequence, licence, context.ActivationId, context.Device.InstallationId, binding,
            JsonWire.String(claims, "jti"), issued, expiry, refresh, licenceExpiry, (int)policy,
            JsonWire.Entitlements(JsonWire.Field(claims, "entitlements")));
    }

    private static bool ValidFingerprint(string? fingerprint, string? provider)
    {
        if (fingerprint is not { Length: 64 } || !fingerprint.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f')) return false;
        if (provider == "machine_v1") return true;
        if (provider is not { Length: >= 8 and <= 55 } || !provider.StartsWith("custom:", StringComparison.Ordinal)) return false;
        foreach (var c in provider.AsSpan(7))
            if (!(c is >= 'a' and <= 'z' or >= '0' and <= '9' or '_' or '.' or '-')) return false;
        return true;
    }

    private static OrbitException InvalidKeys() => new(OrbitError.InvalidResponse, "invalid_session_keys");
    private static OrbitException InvalidGrant() => new(OrbitError.InvalidResponse, "invalid_session_grant");
}
