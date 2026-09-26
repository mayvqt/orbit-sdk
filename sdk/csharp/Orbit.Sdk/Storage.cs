using System.Text.Json.Serialization;

namespace Orbit.Sdk;

/// <summary>Sensitive bearer material. Use an SDK storage provider; custom storage owns its protection.</summary>
public sealed class StoredCredential
{
    public required string ApplicationId { get; init; }
    public required string EnvironmentId { get; init; }
    public required string ActivationId { get; init; }
    public required string LicenceId { get; init; }
    public required string InstallationId { get; init; }
    [JsonIgnore] public required string Credential { get; init; }
    /// <summary>Unix seconds; zero denotes an explicitly negotiated persistent credential.</summary>
    public required long CredentialExpiresAt { get; init; }
    public string? Fingerprint { get; init; }
    public string? FingerprintProvider { get; init; }
    public override string ToString() => "Orbit stored credential (redacted)";
}

public enum StorageCapability { MemoryOnly, CallerProtected, OperatingSystemProtected, PrivateFile }

/// <summary>
/// Implement using OS-protected storage. Version reads must observe other writers;
/// Save must compare the version atomically with Invalidate. Isolate storage when
/// cross-process atomic invalidation cannot be guaranteed. Never persist account sessions.
/// </summary>
public interface ICredentialStorage
{
    StorageCapability Capability { get; }
    long Version { get; }
    (long Version, StoredCredential? Credential) Load();
    void Save(long version, StoredCredential credential);
    long Invalidate();
}

public sealed class MemoryStorage : ICredentialStorage
{
    private readonly object gate = new();
    private long version;
    private StoredCredential? credential;
    public StorageCapability Capability => StorageCapability.MemoryOnly;
    public long Version { get { lock (gate) return version; } }
    public (long Version, StoredCredential? Credential) Load() { lock (gate) return (version, credential); }
    public void Save(long version, StoredCredential credential)
    {
        lock (gate)
        {
            if (version != this.version) throw new OrbitException(OrbitError.StaleResponse);
            this.credential = credential;
        }
    }
    public long Invalidate()
    {
        lock (gate)
        {
            credential = null;
            if (version == long.MaxValue) throw new OrbitException(OrbitError.Storage);
            return ++version;
        }
    }
}
