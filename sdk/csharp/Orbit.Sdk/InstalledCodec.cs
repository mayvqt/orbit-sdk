using System.Security.Cryptography;
using System.Text.Json;

namespace Orbit.Sdk;

internal sealed record InstalledScope(string ApiOrigin, string Issuer, string ApplicationId, string EnvironmentId);
internal sealed record InstalledIdentity(string Id, string? Fingerprint, string? FingerprintProvider);
internal sealed record InstalledCredential(string ActivationId, string LicenceId, string Bearer, long? ExpiresAt);
internal sealed record InstalledPending(string OperationId, string PrincipalKind, string InputDigest, long CreatedAt);
internal sealed record InstalledAccess(string Jws, JsonElement Jwks, long? LicenceExpiresAt, long ReceivedServerTime,
    long ReceivedWallTime, long ServerHighWater, long WallHighWater);
internal sealed record InstalledOffline(string? Jws, long Sequence, string IssuanceId, string ContentDigest,
    long VerifiedAt, long TimeHighWater, long WallHighWater);
internal sealed record InstalledRecord(string Sdk, int Format, string Provider, InstalledScope Scope,
    InstalledIdentity Installation, long Generation, InstalledCredential? Credential, InstalledPending? PendingActivation,
    InstalledAccess? Access,
    [property: System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    InstalledOffline? Offline = null)
{
    internal StoredCredential? Stored => Credential is not { } c ? null : new()
    {
        ApplicationId = Scope.ApplicationId,
        EnvironmentId = Scope.EnvironmentId,
        InstallationId = Installation.Id,
        Fingerprint = Installation.Fingerprint,
        FingerprintProvider = Installation.FingerprintProvider,
        ActivationId = c.ActivationId,
        LicenceId = c.LicenceId,
        Credential = c.Bearer,
        CredentialExpiresAt = c.ExpiresAt ?? 0
    };
}

internal static class InstalledCodec
{
    internal const int Limit = 64 * 1024;
    internal const string Sdk = "orbit.installed-client";
    internal static readonly JsonSerializerOptions Options = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };
    internal static byte[] Encode(InstalledRecord record)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(record, Options);
        if (bytes.Length > Limit)
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw new OrbitException(OrbitError.Storage);
        }
        return bytes;
    }
    internal static InstalledRecord Decode(byte[] bytes, InstalledScope scope, string provider, string? fingerprint, string? fingerprintProvider,
        bool allowIdentityMismatch = false)
    {
        try
        {
            if (bytes.Length is 0 or > Limit)
                throw JsonWire.Invalid();
            var json = JsonWire.Parse(bytes);
            var format = JsonWire.Integer(json, "format");
            if (format == 2)
                JsonWire.ExactFields(json, "sdk", "format", "provider", "scope", "installation", "generation", "credential", "pending_activation", "access");
            else if (format == 3)
                JsonWire.ExactFields(json, "sdk", "format", "provider", "scope", "installation", "generation", "credential", "pending_activation", "access", "offline");
            else throw JsonWire.Invalid();
            JsonWire.ExactFields(JsonWire.Field(json, "scope"), "api_origin", "issuer", "application_id", "environment_id");
            JsonWire.ExactFields(JsonWire.Field(json, "installation"), "id", "fingerprint", "fingerprint_provider");
            if (JsonWire.Field(json, "credential").ValueKind != JsonValueKind.Null)
                JsonWire.ExactFields(JsonWire.Field(json, "credential"), "activation_id", "licence_id", "bearer", "expires_at");
            if (JsonWire.Field(json, "pending_activation").ValueKind != JsonValueKind.Null)
                JsonWire.ExactFields(JsonWire.Field(json, "pending_activation"), "operation_id", "principal_kind", "input_digest", "created_at");
            if (JsonWire.Field(json, "access").ValueKind != JsonValueKind.Null)
                JsonWire.ExactFields(JsonWire.Field(json, "access"), "jws", "jwks", "licence_expires_at", "received_server_time", "received_wall_time", "server_high_water", "wall_high_water");
            if (format == 3)
                JsonWire.ExactFields(JsonWire.Field(json, "offline"), "jws", "sequence", "issuance_id", "content_digest", "verified_at", "time_high_water", "wall_high_water");
            var r = JsonSerializer.Deserialize<InstalledRecord>(bytes, Options) ?? throw JsonWire.Invalid();
            var identityMatches = r.Installation.Fingerprint == fingerprint && r.Installation.FingerprintProvider == fingerprintProvider;
            if (r.Sdk != Sdk || r.Format != format || r.Provider != provider || r.Scope != scope || r.Generation < 0 ||
                (format == 2) != (r.Offline == null) ||
                (!allowIdentityMismatch && !identityMatches))
                throw JsonWire.Invalid();
            new OrbitConfig(scope.ApplicationId, scope.EnvironmentId, scope.Issuer).Validate(new Device(r.Installation.Id,
                r.Installation.Fingerprint, r.Installation.FingerprintProvider));
            if (r.Credential is { } c && (!JsonWire.Opaque(c.ActivationId) || !JsonWire.Opaque(c.LicenceId) || !JsonWire.Bearer(c.Bearer) || !Expiry(c.ExpiresAt)))
                throw JsonWire.Invalid();
            if (r.PendingActivation is { } p && (!JsonWire.OperationId(p.OperationId) || p.PrincipalKind is not ("key" or "account") ||
                p.InputDigest.Length != 64 || !p.InputDigest.All(c => c is >= 'a' and <= 'f' or >= '0' and <= '9') || !Time(p.CreatedAt)))
                throw JsonWire.Invalid();
            if (r.Access is { } a)
            {
                if (r.Credential == null || a.Jws.Length is 0 or > 16384 || !Expiry(a.LicenceExpiresAt) ||
                    !Time(a.ReceivedServerTime) || !Time(a.ReceivedWallTime) || !Time(a.ServerHighWater) || !Time(a.WallHighWater))
                    throw JsonWire.Invalid();
                JsonWire.ExactFields(a.Jwks, "keys");
                if (JsonWire.Field(a.Jwks, "keys").GetArrayLength() != 1)
                    throw JsonWire.Invalid();
                _ = GrantKeys.Parse(a.Jwks);
            }
            if (r.Offline is { } offline && (offline.Sequence is < 1 or > OfflineKeys.MaximumSequence ||
                !JsonWire.Opaque(offline.IssuanceId) || offline.ContentDigest.Length != 64 ||
                !offline.ContentDigest.All(c => c is >= 'a' and <= 'f' or >= '0' and <= '9') ||
                !Time(offline.VerifiedAt) || offline.TimeHighWater < offline.VerifiedAt ||
                !Time(offline.TimeHighWater) || !Time(offline.WallHighWater) ||
                offline.Jws is { } jws && (jws.Length is 0 or > OfflineKeys.MaximumFileBytes ||
                    r.Credential != null || r.PendingActivation != null || r.Access != null)))
                throw JsonWire.Invalid();
            return r;
        }
        catch (Exception) { throw new OrbitException(OrbitError.Storage); }
    }
    private static bool Time(long stamp) => stamp is >= 0 and <= 253402300799;
    private static bool Expiry(long? stamp) => stamp == null || stamp is > 0 and <= 253402300799;
}
