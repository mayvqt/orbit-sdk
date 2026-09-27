namespace Orbit.Sdk;

internal sealed class InstalledMacOSFiles : IInstalledFiles
{
    private readonly MacOSStorageLease lease;
    private bool allowMissing;
    internal InstalledMacOSFiles(string path)
    {
        lease = MacOSStorageLease.Open(path, installed: true);
        allowMissing = lease.Created;
    }
    public string Provider => "private_file";
    public bool Created => lease.Created;
    public byte[]? Read() => lease.ReadInstalled(allowMissing);
    public void Write(byte[] data)
    {
        lease.WriteInstalled(data, allowMissing);
        allowMissing = false;
    }
    public void Check() => lease.Check();
    public void Dispose() => lease.Dispose();
}
