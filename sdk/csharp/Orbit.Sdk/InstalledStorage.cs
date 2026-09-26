using System.Security.Cryptography;
using System.Text.Json;

namespace Orbit.Sdk;

internal interface IInstalledFiles : IDisposable
{
    string Provider
    {
        get;
    }
    bool Created
    {
        get;
    }
    byte[]? Read();
    void Write(byte[] data);
    void Check();
}

internal sealed class InstalledStorage : ICredentialStorage, IDisposable
{
    private readonly object gate = new();
    private readonly IInstalledFiles files;
    private bool poisoned, disposed;
    internal InstalledRecord Record
    {
        get; private set;
    }
    public StorageCapability Capability => files.Provider == "private_file" ? StorageCapability.PrivateFile : StorageCapability.OperatingSystemProtected;
    internal InstalledStorage(IInstalledFiles files, InstalledScope scope, string? fingerprint, string? provider)
    {
        this.files = files;
        var bytes = files.Read();
        if (bytes == null)
        {
            if (!files.Created)
                throw Storage();
            Record = new(InstalledCodec.Sdk, 2, files.Provider, scope, new(Device.NewInstallation().InstallationId, fingerprint, provider), 0, null, null, null);
            Write(Record);
        }
        else
        {
            try
            {
                Record = InstalledCodec.Decode(bytes, scope, files.Provider, fingerprint, provider);
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
    }
    private static OrbitException Storage() => new(OrbitError.Storage);
    private void Check()
    {
        if (disposed || poisoned)
            throw Storage();
        files.Check();
    }
    private void Write(InstalledRecord value)
    {
        Check();
        var bytes = InstalledCodec.Encode(value);
        try
        {
            files.Write(bytes);
            Record = value;
        }
        catch (Exception) { poisoned = true; throw Storage(); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    public long Version
    {
        get
        {
            lock (gate)
            {
                Check();
                return Record.Generation;
            }
        }
    }
    public (long Version, StoredCredential? Credential) Load()
    {
        lock (gate)
        {
            Check();
            return (Record.Generation, Record.Stored);
        }
    }
    public void Save(long version, StoredCredential credential)
    {
        lock (gate)
        {
            Match(version);
            Write(Record with
            {
                Credential = Saved(credential),
                Access = null
            });
        }
    }
    private static InstalledCredential Saved(StoredCredential c) => new(c.ActivationId, c.LicenceId, c.Credential, c.CredentialExpiresAt == 0 ? null : c.CredentialExpiresAt);
    private void Match(long expected)
    {
        Check();
        if (Record.Generation != expected)
            throw new OrbitException(OrbitError.StaleResponse);
    }
    public long Invalidate() => Invalidate(clearPending: true);
    internal long Invalidate(bool clearPending)
    {
        lock (gate)
        {
            if (Record.Generation == long.MaxValue)
                throw Storage();
            Write(Record with
            {
                Generation = Record.Generation + 1,
                Credential = null,
                Access = null,
                PendingActivation = clearPending ? null : Record.PendingActivation
            });
            return Record.Generation;
        }
    }
    internal void DropCache()
    {
        lock (gate)
        {
            Check();
            if (Record.Access != null)
                Write(Record with
                {
                    Access = null
                });
        }
    }
    internal (string OperationId, long Version) Begin(string principal, bool account, string? previous, string? operation)
    {
        lock (gate)
        {
            // Explicit sorted maps provide a deterministic digest without saving principal secrets.
            var data = JsonSerializer.SerializeToUtf8Bytes(new SortedDictionary<string, object?>(StringComparer.Ordinal)
            {
                ["scope"] = new SortedDictionary<string, object?>(StringComparer.Ordinal) { ["api_origin"] = Record.Scope.ApiOrigin, ["issuer"] = Record.Scope.Issuer, ["application_id"] = Record.Scope.ApplicationId, ["environment_id"] = Record.Scope.EnvironmentId },
                ["installation"] = new SortedDictionary<string, object?>(StringComparer.Ordinal) { ["id"] = Record.Installation.Id, ["fingerprint"] = Record.Installation.Fingerprint, ["fingerprint_provider"] = Record.Installation.FingerprintProvider },
                ["principal_kind"] = account ? "account" : "key",
                ["licence_input"] = principal,
                ["previous_credential"] = previous,
                ["credential_mode"] = "persistent"
            });
            var digest = Convert.ToHexStringLower(SHA256.HashData(data));
            CryptographicOperations.ZeroMemory(data);
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (now is < 0 or > 253402300799)
                throw new OrbitException(OrbitError.ClockUncertain);
            var pending = Record.PendingActivation;
            if (pending != null)
            {
                if (now < pending.CreatedAt || now - pending.CreatedAt >= 86400)
                    throw new OrbitException(OrbitError.Storage, "pending_activation_expired");
                if (pending.InputDigest != digest || operation != null && operation != pending.OperationId)
                    throw new OrbitException(OrbitError.Storage, "pending_activation");
                operation = pending.OperationId;
            }
            else
            {
                operation ??= Device.NewInstallation().InstallationId;
                pending = new(operation, account ? "account" : "key", digest, now);
            }
            if (Record.Generation == long.MaxValue)
                throw Storage();
            Write(Record with
            {
                Generation = Record.Generation + 1,
                Credential = null,
                Access = null,
                PendingActivation = pending
            });
            return (operation, Record.Generation);
        }
    }
    internal void Commit(long version, StoredCredential credential, JsonElement response, GrantKeys keys, ClockAnchor anchor)
    {
        var token = JsonWire.String(response, "grant");
        var licence = JsonWire.OptionalString(response, "licence_expires_at");
        var access = new InstalledAccess(token, keys.Export(token), licence == null ? null : JsonWire.Timestamp(licence), anchor.ServerSeconds, anchor.WallSeconds, anchor.Now(), DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        lock (gate)
        {
            Match(version);
            if (Record.PendingActivation != null && JsonWire.Field(response, "credential").ValueKind == JsonValueKind.Null)
                throw new OrbitException(OrbitError.Storage, "pending_activation");
            Write(Record with
            {
                Credential = Saved(credential),
                Access = access,
                PendingActivation = null
            });
        }
    }
    internal void Checkpoint(long server, long wall)
    {
        lock (gate)
        {
            Check();
            if (Record.Access is not { } access)
                return;
            if (server < access.ServerHighWater || wall < access.WallHighWater || server > 253402300799 || wall > 253402300799 || Math.Abs((server - access.ReceivedServerTime) - (wall - access.ReceivedWallTime)) > 30)
                throw new OrbitException(OrbitError.ClockUncertain);
            Write(Record with
            {
                Access = access with
                {
                    ServerHighWater = server,
                    WallHighWater = wall
                }
            });
        }
    }
    public void Dispose()
    {
        lock (gate)
        {
            if (disposed)
                return;
            disposed = true;
            Record = Record with
            {
                Credential = null,
                Access = null,
                PendingActivation = null
            };
            files.Dispose();
        }
    }
}
