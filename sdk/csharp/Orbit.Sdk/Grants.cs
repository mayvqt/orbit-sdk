using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Orbit.Sdk;

internal sealed record GrantClaims(string LicenceId, long IssuedAt, long ExpiresAt, long RefreshAfter,
    bool OfflineAllowed, int PolicyVersion, IReadOnlyDictionary<string, bool> Entitlements);

internal sealed record GrantExpected(OrbitConfig Config, Device Device, string? LicenceId, string ActivationId,
    long? CredentialExpiresAt, long? LicenceExpiresAt, long Now,
    bool AllowUnboundFingerprint = false, string? ExpectedBindingMode = null);

internal sealed class GrantKeys
{
    private readonly Dictionary<string, ECParameters> keys = new(StringComparer.Ordinal);

    internal static GrantKeys Parse(JsonElement value)
    {
        var entries = JsonWire.Field(value, "keys");
        if (entries.ValueKind != JsonValueKind.Array || entries.GetArrayLength() is < 1 or > 8) throw JsonWire.Invalid();
        var result = new GrantKeys();
        foreach (var key in entries.EnumerateArray())
        {
            JsonWire.ExactFields(key, "kty", "crv", "alg", "use", "kid", "x", "y");
            var kid = JsonWire.String(key, "kid");
            var x = JsonWire.DecodeBase64(JsonWire.String(key, "x"));
            var y = JsonWire.DecodeBase64(JsonWire.String(key, "y"));
            if (JsonWire.String(key, "kty") != "EC" || JsonWire.String(key, "crv") != "P-256" ||
                JsonWire.String(key, "alg") != "ES256" || JsonWire.String(key, "use") != "sig" ||
                kid.Length is < 1 or > 128 || !kid.All(char.IsAscii) ||
                x.Length != 32 || y.Length != 32)
                throw JsonWire.Invalid();
            var parameters = new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } };
            try
            {
                // Validate retained points as well as the selected signing key.
                // Keep only public parameters; verification owns its native handle.
                using var publicKey = ECDsa.Create(parameters);
                if (!result.keys.TryAdd(kid, parameters)) throw JsonWire.Invalid();
            }
            catch (Exception error) when (error is CryptographicException or ArgumentException)
            { throw JsonWire.Invalid(); }
        }
        return result;
    }

    internal JsonElement Export(string token)
    {
        var kid = ParseToken(token).Kid;
        if (!keys.TryGetValue(kid, out var key)) throw JsonWire.Invalid();
        return JsonSerializer.SerializeToElement(new
        {
            keys = new[] { new { kty = "EC", crv = "P-256", alg = "ES256", use = "sig", kid,
                x = JsonWire.EncodeBase64(key.Q.X!), y = JsonWire.EncodeBase64(key.Q.Y!) } }
        });
    }

    internal bool Contains(string token) => keys.ContainsKey(ParseToken(token).Kid);

    private static (string Kid, string Signed, byte[] Signature, JsonElement Claims) ParseToken(
        string token, string purpose = "orbit-access+jwt")
    {
        if (token == null || token.Length > 16384) throw JsonWire.Invalid();
        var parts = token.Split('.');
        if (parts.Length != 3) throw JsonWire.Invalid();
        var signature = JsonWire.DecodeBase64(parts[2]);
        if (signature.Length != 64) throw JsonWire.Invalid();
        var header = JsonWire.Parse(JsonWire.DecodeBase64(parts[0]));
        JsonWire.ExactFields(header, "alg", "typ", "kid");
        var claims = JsonWire.Parse(JsonWire.DecodeBase64(parts[1]));
        var kid = JsonWire.String(header, "kid");
        if (JsonWire.String(header, "alg") != "ES256" || JsonWire.String(header, "typ") != purpose ||
            kid.Length is < 1 or > 128 || !kid.All(char.IsAscii)) throw JsonWire.Invalid();
        return (kid, parts[0] + "." + parts[1], signature, claims);
    }

    private JsonElement VerifySignature(string token, string purpose)
    {
        var parsed = ParseToken(token, purpose);
        if (!keys.TryGetValue(parsed.Kid, out var key)) throw JsonWire.Invalid();
        try
        {
            using var publicKey = ECDsa.Create(key);
            if (!publicKey.VerifyData(Encoding.ASCII.GetBytes(parsed.Signed), parsed.Signature,
                HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) throw JsonWire.Invalid();
        }
        catch (Exception error) when (error is CryptographicException or ArgumentException)
        { throw JsonWire.Invalid(); }
        return parsed.Claims;
    }

    internal JsonElement VerifySessionSignature(string token) => VerifySignature(token, "orbit-session+jwt");

    internal ValueTask<GrantClaims> VerifyAsync(string token, GrantExpected expected)
    {
        var claims = VerifySignature(token, "orbit-access+jwt");
        var audience = $"orbit:{expected.Config.ApplicationId}:{expected.Config.EnvironmentId}";
        // Scope, purpose, duplicates and exact numeric lifetimes belong to the
        // Orbit contract. Built-in cryptography only verifies the ES256 bytes.
        var licence = JsonWire.String(claims, "sub");
        var jti = JsonWire.String(claims, "jti");
        var issued = JsonWire.Integer(claims, "iat");
        var expiry = JsonWire.Integer(claims, "exp");
        var refresh = JsonWire.Integer(claims, "refresh_after");
        var offline = JsonWire.Boolean(claims, "offline_allowed");
        var policy = JsonWire.Integer(claims, "policy_version");
        var licenceExpiry = JsonWire.OptionalInteger(claims, "licence_expires_at");
        var binding = JsonWire.String(claims, "binding_mode");
        var hasFingerprintClaim = claims.TryGetProperty("fingerprint", out _);
        var hasProviderClaim = claims.TryGetProperty("fingerprint_provider", out _);
        var claimFingerprint = JsonWire.OptionalString(claims, "fingerprint");
        var claimProvider = JsonWire.OptionalString(claims, "fingerprint_provider");
        var expectedUnbound = expected.Device.Fingerprint == null && expected.Device.FingerprintProvider == null;
        var expectedOptionalBinding = expected.AllowUnboundFingerprint &&
            expected.Device.Fingerprint != null && expected.Device.FingerprintProvider != null;
        var bound = (expected.ExpectedBindingMode == null || binding == expected.ExpectedBindingMode) &&
            (binding == "none" && !hasFingerprintClaim && !hasProviderClaim &&
                (expectedUnbound || expectedOptionalBinding) ||
             binding == "hwid" && expected.Device.Fingerprint != null && expected.Device.FingerprintProvider != null &&
                claimFingerprint == expected.Device.Fingerprint && claimProvider == expected.Device.FingerprintProvider);
        // Bound values before addition so attacker-controlled integer dates cannot overflow.
        if (issued is < 0 or > 253402300799 || expected.Now is < 0 or > 253402300799 ||
            JsonWire.String(claims, "iss") != expected.Config.Issuer || JsonWire.String(claims, "aud") != audience ||
            !JsonWire.Opaque(licence) || (expected.LicenceId != null && licence != expected.LicenceId) ||
            jti.Length is < 1 or > 128 || JsonWire.String(claims, "application_id") != expected.Config.ApplicationId ||
            JsonWire.String(claims, "environment_id") != expected.Config.EnvironmentId ||
            JsonWire.String(claims, "activation_id") != expected.ActivationId ||
            JsonWire.String(claims, "installation_id") != expected.Device.InstallationId || !bound || policy is < 1 or > int.MaxValue ||
            JsonWire.Integer(claims, "nbf") != issued || issued > expected.Now + 30 || issued < expected.Now - 30 ||
            expiry <= expected.Now || expiry <= issued || expiry > issued + (offline ? 86400 : 300) ||
            expiry > expected.CredentialExpiresAt || licenceExpiry != expected.LicenceExpiresAt ||
            (licenceExpiry != null && expiry > licenceExpiry) || refresh <= issued || refresh > expiry ||
            refresh > issued + (expected.CredentialExpiresAt == null && offline ? 1125 : 75) || (refresh < issued + (expected.CredentialExpiresAt == null && offline ? 675 : 45) && refresh != expiry))
            throw JsonWire.Invalid();
        return ValueTask.FromResult(new GrantClaims(licence, issued, expiry, refresh, offline, (int)policy,
            JsonWire.Entitlements(JsonWire.Field(claims, "entitlements"))));
    }
}
