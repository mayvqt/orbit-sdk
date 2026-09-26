using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Orbit.Sdk;

internal sealed record GrantClaims(string LicenceId, long IssuedAt, long ExpiresAt, long RefreshAfter,
    bool OfflineAllowed, int PolicyVersion, IReadOnlyDictionary<string, bool> Entitlements);

internal sealed record GrantExpected(OrbitConfig Config, Device Device, string? LicenceId, string ActivationId,
    long? CredentialExpiresAt, long? LicenceExpiresAt, long Now);

internal sealed class GrantKeys
{
    private readonly Dictionary<string, SecurityKey> keys = new(StringComparer.Ordinal);

    internal static GrantKeys Parse(JsonElement value)
    {
        var entries = JsonWire.Field(value, "keys");
        if (entries.ValueKind != JsonValueKind.Array || entries.GetArrayLength() is < 1 or > 8) throw JsonWire.Invalid();
        var result = new GrantKeys();
        foreach (var key in entries.EnumerateArray())
        {
            JsonWire.ExactFields(key, "kty", "crv", "alg", "use", "kid", "x", "y");
            var kid = JsonWire.String(key, "kid");
            var x = JsonWire.String(key, "x");
            var y = JsonWire.String(key, "y");
            if (JsonWire.String(key, "kty") != "EC" || JsonWire.String(key, "crv") != "P-256" ||
                JsonWire.String(key, "alg") != "ES256" || JsonWire.String(key, "use") != "sig" ||
                kid.Length is < 1 or > 128 || !kid.All(char.IsAscii) ||
                JsonWire.DecodeBase64(x).Length != 32 || JsonWire.DecodeBase64(y).Length != 32 ||
                !result.keys.TryAdd(kid, new JsonWebKey { Kty = "EC", Crv = "P-256", Alg = "ES256", Use = "sig", Kid = kid, X = x, Y = y }))
                throw JsonWire.Invalid();
        }
        return result;
    }

    internal JsonElement Export(string token)
    {
        if (!keys.TryGetValue(Header(token), out var key) || key is not JsonWebKey jwk)
            throw JsonWire.Invalid();
        return JsonSerializer.SerializeToElement(new
        {
            keys = new[] { new { kty = jwk.Kty, crv = jwk.Crv, alg = jwk.Alg, use = jwk.Use, kid = jwk.Kid, x = jwk.X, y = jwk.Y } }
        });
    }

    internal bool Contains(string token) => keys.ContainsKey(Header(token));

    private static string Header(string token)
    {
        if (token.Length > 16384) throw JsonWire.Invalid();
        var parts = token.Split('.');
        if (parts.Length != 3 || JsonWire.DecodeBase64(parts[2]).Length != 64) throw JsonWire.Invalid();
        var header = JsonWire.Parse(JsonWire.DecodeBase64(parts[0]));
        JsonWire.ExactFields(header, "alg", "typ", "kid");
        // Parse the exact signed payload before passing it to JOSE; duplicate fields
        // must never disappear into a library's claim dictionary.
        _ = JsonWire.Parse(JsonWire.DecodeBase64(parts[1]));
        var kid = JsonWire.String(header, "kid");
        if (JsonWire.String(header, "alg") != "ES256" || JsonWire.String(header, "typ") != "orbit-access+jwt" ||
            kid.Length is < 1 or > 128 || !kid.All(char.IsAscii)) throw JsonWire.Invalid();
        return kid;
    }

    internal async Task<GrantClaims> VerifyAsync(string token, GrantExpected expected)
    {
        var kid = Header(token);
        if (!keys.TryGetValue(kid, out var key)) throw JsonWire.Invalid();
        var audience = $"orbit:{expected.Config.ApplicationId}:{expected.Config.EnvironmentId}";
        var handler = new JsonWebTokenHandler { MaximumTokenSizeInBytes = 16384 };
        TokenValidationResult validated;
        try
        {
            validated = await handler.ValidateTokenAsync(token, new TokenValidationParameters
            {
                RequireSignedTokens = true,
                RequireExpirationTime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key,
                TryAllIssuerSigningKeys = false,
                ValidAlgorithms = [SecurityAlgorithms.EcdsaSha256],
                ValidTypes = ["orbit-access+jwt"],
                ValidateIssuer = true,
                ValidIssuer = expected.Config.Issuer,
                ValidateAudience = true,
                ValidAudience = audience,
                IgnoreTrailingSlashWhenValidatingAudience = false,
                // Verified server time + suspend-aware elapsed time owns lifetime,
                // rather than the process wall clock used by the JOSE default.
                ValidateLifetime = false,
                ClockSkew = TimeSpan.Zero,
                IncludeTokenOnFailedValidation = false,
                LogTokenId = false
            }).ConfigureAwait(false);
        }
        catch (Exception error) when (error is SecurityTokenException or ArgumentException or InvalidOperationException)
        { throw JsonWire.Invalid(); }
        if (!validated.IsValid) throw JsonWire.Invalid();
        var claims = JsonWire.Parse(JsonWire.DecodeBase64(token.Split('.')[1]));
        var licence = JsonWire.String(claims, "sub");
        var jti = JsonWire.String(claims, "jti");
        var issued = JsonWire.Integer(claims, "iat");
        var expiry = JsonWire.Integer(claims, "exp");
        var refresh = JsonWire.Integer(claims, "refresh_after");
        var offline = JsonWire.Boolean(claims, "offline_allowed");
        var policy = JsonWire.Integer(claims, "policy_version");
        var licenceExpiry = JsonWire.OptionalInteger(claims, "licence_expires_at");
        var binding = JsonWire.String(claims, "binding_mode");
        var bound = expected.Device.Fingerprint == null
            ? binding == "none" && JsonWire.OptionalString(claims, "fingerprint") == null && JsonWire.OptionalString(claims, "fingerprint_provider") == null
            : binding == "hwid" && JsonWire.OptionalString(claims, "fingerprint") == expected.Device.Fingerprint &&
              JsonWire.OptionalString(claims, "fingerprint_provider") == expected.Device.FingerprintProvider;
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
        return new GrantClaims(licence, issued, expiry, refresh, offline, (int)policy,
            JsonWire.Entitlements(JsonWire.Field(claims, "entitlements")));
    }
}
