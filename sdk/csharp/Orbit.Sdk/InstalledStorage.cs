using System.Security.Cryptography;
using System.Text.Json;

namespace Orbit.Sdk;

#if ORBIT_LOCAL_DEVELOPMENT
internal static class InstalledStorageDiagnostics
{
    private static long versionReads, writes;
    private static int enabled, countVersionReads;
    private static Action<string>? offlineWriteCompleted;
    private static Action? offlineImportQueued;

    internal static long VersionReads => Interlocked.Read(ref versionReads);
    internal static long Writes => Interlocked.Read(ref writes);
    internal static Action<string>? OfflineWriteCompleted
    {
        get => Volatile.Read(ref offlineWriteCompleted);
        set => Volatile.Write(ref offlineWriteCompleted, value);
    }
    internal static Action? OfflineImportQueued
    {
        get => Volatile.Read(ref offlineImportQueued);
        set => Volatile.Write(ref offlineImportQueued, value);
    }

    internal static void Begin()
    {
        Interlocked.Exchange(ref versionReads, 0);
        Interlocked.Exchange(ref writes, 0);
        Volatile.Write(ref countVersionReads, 0);
        Volatile.Write(ref enabled, 1);
    }

    internal static void CountVersionReads(bool value) =>
        Volatile.Write(ref countVersionReads, value ? 1 : 0);

    internal static void End() => Volatile.Write(ref enabled, 0);

    internal static void NoteVersionRead()
    {
        if (Volatile.Read(ref enabled) != 0 && Volatile.Read(ref countVersionReads) != 0)
            Interlocked.Increment(ref versionReads);
    }

    internal static void NoteWrite()
    {
        if (Volatile.Read(ref enabled) != 0)
            Interlocked.Increment(ref writes);
    }
    internal static void NoteOfflineWrite(string stage) => Volatile.Read(ref offlineWriteCompleted)?.Invoke(stage);
}
#endif

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
                Record = InstalledCodec.Decode(bytes, scope, files.Provider, fingerprint, provider, allowIdentityMismatch: true);
                if (Record.Installation.Fingerprint != fingerprint || Record.Installation.FingerprintProvider != provider)
                {
                    // A changed or unavailable device identity starts a new installation scope. Never
                    // carry a pending mutation or signed grant onto the new identity.
                    Write(Record with
                    {
                        Installation = new(Device.NewInstallation().InstallationId, fingerprint, provider),
                        Generation = 0,
                        Credential = null,
                        PendingActivation = null,
                        Access = null,
                        Offline = null
                    });
                }
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
    }
    private static OrbitException Storage() => new(OrbitError.Storage);
    private void Check()
    {
        if (disposed || poisoned)
            throw Storage();
        try { files.Check(); }
        catch (Exception) { poisoned = true; throw Storage(); }
    }
    private void Write(InstalledRecord value)
    {
        Check();
        value = value with { Format = value.Offline == null ? 2 : 3 };
        var bytes = InstalledCodec.Encode(value);
        try
        {
            files.Write(bytes);
#if ORBIT_LOCAL_DEVELOPMENT
            InstalledStorageDiagnostics.NoteWrite();
#endif
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
#if ORBIT_LOCAL_DEVELOPMENT
                InstalledStorageDiagnostics.NoteVersionRead();
#endif
                return Record.Generation;
            }
        }
    }
    public (long Version, StoredCredential? Credential) Load()
    {
        lock (gate)
        {
            Check();
#if ORBIT_LOCAL_DEVELOPMENT
            InstalledStorageDiagnostics.NoteVersionRead();
#endif
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
    internal long Invalidate(bool clearPending, bool clearCredential = true)
    {
        lock (gate)
        {
            if (Record.Generation == long.MaxValue)
                throw Storage();
            Write(Record with
            {
                Generation = Record.Generation + 1,
                Credential = clearCredential ? null : Record.Credential,
                Access = null,
                PendingActivation = clearPending ? null : Record.PendingActivation,
                Offline = Record.Offline is { } offline ? offline with { Jws = null } : null
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
    internal (string OperationId, long Version) Begin(string principal, bool account, string? previous,
        string? operation, string? principalIdentity = null)
    {
        lock (gate)
        {
            // Explicit sorted maps provide a deterministic digest without saving principal secrets.
            var data = JsonSerializer.SerializeToUtf8Bytes(new SortedDictionary<string, object?>(StringComparer.Ordinal)
            {
                ["scope"] = new SortedDictionary<string, object?>(StringComparer.Ordinal) { ["api_origin"] = Record.Scope.ApiOrigin, ["issuer"] = Record.Scope.Issuer, ["application_id"] = Record.Scope.ApplicationId, ["environment_id"] = Record.Scope.EnvironmentId },
                ["installation"] = new SortedDictionary<string, object?>(StringComparer.Ordinal) { ["id"] = Record.Installation.Id, ["fingerprint"] = Record.Installation.Fingerprint, ["fingerprint_provider"] = Record.Installation.FingerprintProvider },
                ["principal_kind"] = account ? "account" : "key",
                ["principal_identity"] = principalIdentity,
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
                PendingActivation = pending,
                Offline = Record.Offline is { } offline ? offline with { Jws = null } : null
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
    internal void CommitFloating(long version, StoredCredential credential, JsonElement response)
    {
        lock (gate)
        {
            Match(version);
            if (Record.PendingActivation != null && JsonWire.Field(response, "credential").ValueKind == JsonValueKind.Null)
                throw new OrbitException(OrbitError.Storage, "pending_activation");
            Write(Record with
            {
                Credential = Saved(credential),
                Access = null,
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
    internal InstalledOffline? OfflineState()
    {
        lock (gate)
        {
            Check();
            return Record.Offline;
        }
    }
    internal long SaveOffline(long version, InstalledOffline offline)
    {
        lock (gate)
        {
            Match(version);
            if (Record.Offline is { } previous && (offline.Sequence < previous.Sequence ||
                offline.Sequence == previous.Sequence &&
                    (offline.IssuanceId != previous.IssuanceId || offline.ContentDigest != previous.ContentDigest) ||
                offline.TimeHighWater < previous.TimeHighWater || offline.WallHighWater < previous.WallHighWater))
                throw new OrbitException(OrbitError.Denied, "offline_sequence");
            if (Record.Generation == long.MaxValue)
                throw Storage();
            Write(Record with
            {
                Generation = Record.Generation + 1,
                Credential = null,
                Access = null,
                PendingActivation = null,
                Offline = offline
            });
#if ORBIT_LOCAL_DEVELOPMENT
            InstalledStorageDiagnostics.NoteOfflineWrite("save");
#endif
            return Record.Generation;
        }
    }
    internal void CheckpointOffline(InstalledOffline offline)
    {
        lock (gate)
        {
            Check();
            if (Record.Offline is not { Jws: not null } previous ||
                offline.Jws != previous.Jws || offline.Sequence != previous.Sequence ||
                offline.IssuanceId != previous.IssuanceId || offline.ContentDigest != previous.ContentDigest ||
                offline.VerifiedAt != previous.VerifiedAt || offline.TimeHighWater < previous.TimeHighWater ||
                offline.WallHighWater < previous.WallHighWater)
                throw new OrbitException(OrbitError.StaleResponse);
            Write(Record with { Offline = offline });
#if ORBIT_LOCAL_DEVELOPMENT
            InstalledStorageDiagnostics.NoteOfflineWrite("checkpoint");
#endif
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
