using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace Orbit.Sdk;

[SupportedOSPlatform("windows")]
internal sealed class InstalledWindowsFiles : IInstalledFiles
{
    private readonly List<SafeFileHandle> pins = [];
    private readonly InstalledWindowsSecurity security = new();
    private readonly byte[] entropy;
    private SafeFileHandle? lease;
    private readonly string directory;
    private bool allowMissing;
    public string Provider => "windows_dpapi";
    public bool Created
    {
        get;
    }
    internal InstalledWindowsFiles(string path, byte[] entropy)
    {
        this.entropy = entropy;
        try
        {
            directory = WindowsStorageFiles.PinDirectory(path, pins, security);
            (lease, Created) = WindowsStorageFiles.Lease(Path.Combine(directory, WindowsStorage.LockName), security);
            security.Check(lease);
            allowMissing = Created;
            if (Created)
                RandomAccess.FlushToDisk(lease);
        }
        catch { Dispose(); throw; }
    }
    public void Check()
    {
        if (lease == null || pins.Count == 0)
            throw new OrbitException(OrbitError.Storage);
        WindowsStorageFiles.CheckInstalledLease(lease);
        security.Check(lease);
        security.Check(pins[^1]);
    }
    public byte[]? Read()
    {
        Check();
        var cipher = WindowsStorageFiles.Read(Path.Combine(directory, WindowsStorage.DataName), allowMissing, pins, security);
        return cipher == null ? null : WindowsDataProtection.UnprotectInstalled(cipher, entropy);
    }
    public void Write(byte[] bytes)
    {
        Check();
        // Validate an existing destination before committing an invalidation.
        _ = WindowsStorageFiles.Read(Path.Combine(directory, WindowsStorage.DataName), allowMissing, pins, security);
        RandomAccess.Write(lease!, new byte[] { 1 }, 0);
        RandomAccess.FlushToDisk(lease!);
        var cipher = WindowsDataProtection.ProtectInstalled(bytes, entropy);
        var temporary = Path.Combine(directory, "orbit-storage." + Guid.NewGuid().ToString("N") + ".tmp");
        WindowsStorageFiles.Write(temporary, pins, cipher, security);
        try
        {
            RandomAccess.SetLength(lease!, 0);
            RandomAccess.FlushToDisk(lease!);
            allowMissing = false;
            Check();
        }
        catch
        {
            // Failed acknowledgement must leave the held lease visibly uncertain.
            try
            {
                RandomAccess.Write(lease!, new byte[] { 1 }, 0);
                RandomAccess.FlushToDisk(lease!);
            }
            catch (Exception) { }
            throw;
        }
    }
    public void Dispose()
    {
        lease?.Dispose();
        lease = null;
        for (var i = pins.Count - 1; i >= 0; i--)
            pins[i].Dispose();
        pins.Clear();
        security.Dispose();
        Array.Clear(entropy);
    }
}
