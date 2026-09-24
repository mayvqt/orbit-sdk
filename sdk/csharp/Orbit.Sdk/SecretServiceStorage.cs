using System.Security.Cryptography;

namespace Orbit.Sdk;

/// <summary>
/// Optional Linux Secret Service storage for one scope in an existing private
/// directory. Requires the host's operational keyring and /usr/bin/secret-tool.
/// </summary>
public sealed class SecretServiceStorage : ICredentialStorage, IDisposable
{
    private readonly object gate = new();
    private readonly OrbitConfig config;
    private readonly Device device;
    private readonly string scope;
    private LinuxStorageLease? lease;
    private StoredCredential? credential;
    private long version;
    private bool poisoned;

    private SecretServiceStorage(OrbitConfig config, Device device, LinuxStorageLease lease)
    {
        this.config = config;
        this.device = device;
        this.lease = lease;
        scope = SecretTool.Scope(config, device, lease.Directory);
    }

    public static SecretServiceStorage Open(string directory, OrbitConfig config, Device device)
    {
        LinuxStorageLease? lease = null;
        SecretServiceStorage? storage = null;
        byte[]? plaintext = null;
        try
        {
            if (!LinuxStorageLease.Supported) throw Storage();
            config.Validate(device);
            lease = LinuxStorageLease.Open(directory);
            storage = new SecretServiceStorage(config, device, lease);
            plaintext = SecretTool.Lookup(storage.scope);
            lease.Check();
            if (plaintext == null)
            {
                if (!lease.Created) throw Storage();
                storage.Persist(0, null);
            }
            else (storage.version, storage.credential) = ProtectedStorageCodec.Decode(plaintext, config, device);
            return storage;
        }
        catch (Exception) { storage?.Dispose(); lease?.Dispose(); throw Storage(); }
        finally { if (plaintext != null) CryptographicOperations.ZeroMemory(plaintext); }
    }

    public StorageCapability Capability { get { lock (gate) { EnsureUsable(); return StorageCapability.OperatingSystemProtected; } } }
    public long Version { get { lock (gate) { EnsureUsable(); return version; } } }
    public (long Version, StoredCredential? Credential) Load() { lock (gate) { EnsureUsable(); return (version, credential); } }

    public void Save(long version, StoredCredential credential)
    {
        lock (gate)
        {
            EnsureUsable();
            if (version != this.version) throw new OrbitException(OrbitError.StaleResponse);
            if (credential == null) { Poison(); throw Storage(); }
            Persist(version, credential);
        }
    }

    public long Invalidate()
    {
        lock (gate)
        {
            EnsureUsable();
            if (version == long.MaxValue) { Poison(); throw Storage(); }
            Persist(version + 1, null);
            return version;
        }
    }

    private void EnsureUsable()
    {
        if (lease == null || poisoned) throw Storage();
        try { lease.Check(); }
        catch (Exception) { Poison(); throw Storage(); }
    }

    private void Persist(long nextVersion, StoredCredential? nextCredential)
    {
        byte[]? plaintext = null;
        try
        {
            EnsureUsable();
            plaintext = ProtectedStorageCodec.Encode(nextVersion, nextCredential, config, device);
            lease!.BeginWrite();
            SecretTool.Store(scope, plaintext);
            lease.CompleteWrite();
            version = nextVersion;
            credential = nextCredential;
        }
        catch (Exception) { Poison(); throw Storage(); }
        finally { if (plaintext != null) CryptographicOperations.ZeroMemory(plaintext); }
    }

    private void Poison() { poisoned = true; credential = null; }
    public void Dispose()
    {
        lock (gate) { credential = null; lease?.Dispose(); lease = null; }
    }
    public override string ToString() => "Orbit Secret Service storage (redacted)";
    private static OrbitException Storage() => new(OrbitError.Storage);
}
