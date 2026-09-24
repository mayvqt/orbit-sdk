using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace Orbit.Sdk;

/// <summary>
/// Current-user DPAPI storage for one Config/Device scope in an existing private
/// local Windows profile directory. Own and dispose one shared adapter per scope.
/// </summary>
public sealed class WindowsStorage : ICredentialStorage, IDisposable
{
    internal const string LockName = "orbit-storage.lock";
    internal const string DataName = "orbit-storage.bin";
    private readonly object gate = new();
    private readonly OrbitConfig config;
    private readonly Device device;
    private readonly List<SafeFileHandle> directoryPins = [];
    private readonly byte[] entropy;
    private SafeFileHandle? lease;
    private string dataPath = "";
    private byte[]? expectedCiphertextHash;
    private StoredCredential? credential;
    private long version;
    private bool poisoned;
    private bool disposed;

    private WindowsStorage(OrbitConfig config, Device device)
    {
        this.config = config;
        this.device = device;
        entropy = ProtectedStorageCodec.Entropy(config, device);
    }

    public static WindowsStorage Open(string directory, OrbitConfig config, Device device)
    {
        WindowsStorage? storage = null;
        try
        {
            if (!OperatingSystem.IsWindows()) throw Storage();
            storage = new WindowsStorage(config, device);
            var path = WindowsStorageFiles.PinDirectory(directory, storage.directoryPins);
            storage.dataPath = Path.Combine(path, DataName);
            bool created;
            (storage.lease, created) = WindowsStorageFiles.Lease(Path.Combine(path, LockName));
            var ciphertext = WindowsStorageFiles.Read(storage.dataPath, allowAbsent: created, storage.directoryPins);
            if (ciphertext == null)
                storage.Persist(0, null); // Commit the initial scope-bound tombstone.
            else
            {
                var plaintext = WindowsDataProtection.Unprotect(ciphertext, storage.entropy);
                try { (storage.version, storage.credential) = ProtectedStorageCodec.Decode(plaintext, config, device); }
                finally { CryptographicOperations.ZeroMemory(plaintext); }
                storage.expectedCiphertextHash = SHA256.HashData(ciphertext);
            }
            return storage;
        }
        catch (Exception)
        {
            storage?.Dispose();
            throw Storage();
        }
    }

    public StorageCapability Capability
    {
        get { lock (gate) { EnsureUsable(); return StorageCapability.OperatingSystemProtected; } }
    }

    public long Version { get { lock (gate) { EnsureUsable(); return version; } } }

    public (long Version, StoredCredential? Credential) Load()
    {
        lock (gate) { EnsureUsable(); return (version, credential); }
    }

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
        if (disposed || poisoned || lease == null || lease.IsClosed) throw Storage();
        try
        {
            // A lifetime lease excludes cooperating writers. Detect outside
            // deletion/tampering instead of silently replacing damaged state.
            var ciphertext = WindowsStorageFiles.Read(dataPath, allowAbsent: false, directoryPins)!;
            if (expectedCiphertextHash == null || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(ciphertext), expectedCiphertextHash))
                throw Storage();
        }
        catch (Exception) { Poison(); throw Storage(); }
    }

    private void Persist(long nextVersion, StoredCredential? nextCredential)
    {
        byte[]? plaintext = null;
        try
        {
            plaintext = ProtectedStorageCodec.Encode(nextVersion, nextCredential, config, device);
            var ciphertext = WindowsDataProtection.Protect(plaintext, entropy);
            var hash = SHA256.HashData(ciphertext);
            var temporary = Path.Combine(Path.GetDirectoryName(dataPath)!, $".orbit-storage-{Guid.NewGuid():N}.tmp");
            WindowsStorageFiles.Write(temporary, directoryPins, ciphertext);
            if (expectedCiphertextHash != null) CryptographicOperations.ZeroMemory(expectedCiphertextHash);
            expectedCiphertextHash = hash;
            version = nextVersion;
            credential = nextCredential;
        }
        catch (Exception) { Poison(); throw Storage(); }
        finally
        {
            if (plaintext != null) CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private void Poison()
    {
        poisoned = true;
        credential = null;
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (disposed) return;
            disposed = true;
            credential = null;
            CryptographicOperations.ZeroMemory(entropy);
            if (expectedCiphertextHash != null) CryptographicOperations.ZeroMemory(expectedCiphertextHash);
            expectedCiphertextHash = null;
            lease?.Dispose();
            lease = null;
            foreach (var handle in directoryPins) handle.Dispose();
            directoryPins.Clear();
        }
    }

    public override string ToString() => "Orbit Windows storage (redacted)";
    private static OrbitException Storage() => new(OrbitError.Storage);
}
