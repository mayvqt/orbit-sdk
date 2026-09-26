using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Orbit.Sdk;

internal sealed partial class LinuxStorageLease
{
    [DllImport("libc.so.6", EntryPoint = "mkdirat", SetLastError = true)]
    private static extern int MakeDirectory(Descriptor directory, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, uint mode);
    [DllImport("libc.so.6", EntryPoint = "renameat", SetLastError = true)]
    private static extern int Rename(Descriptor directory, [MarshalAs(UnmanagedType.LPUTF8Str)] string source, Descriptor destination, [MarshalAs(UnmanagedType.LPUTF8Str)] string target);
    [DllImport("libc.so.6", EntryPoint = "unlinkat", SetLastError = true)]
    private static extern int Unlink(Descriptor directory, [MarshalAs(UnmanagedType.LPUTF8Str)] string name, int flags);
    // Linux x64 and ARM64 statfs begin with a native 64-bit filesystem type.
    [DllImport("libc.so.6", EntryPoint = "fstatfs", SetLastError = true)]
    private static extern int Filesystem(Descriptor descriptor, [Out] byte[] buffer);

    private static void CheckLocal(Descriptor descriptor)
    {
        var data = new byte[256];
        if (Filesystem(descriptor, data) != 0)
            throw Storage();
        var kind = BitConverter.ToUInt64(data);
        if (kind is not (0xef53 or 0x9123683e or 0x58465342 or 0x01021994 or 0x858458f6 or 0x794c7630 or 0x2fc12fc1 or 0xf2f52010 or 0x24051905 or 0x3153464a or 0x52654973 or 0x73717368))
            throw Storage();
    }

    internal byte[]? ReadInstalled(bool allowMissing)
    {
        Check();
        foreach (var directory in directories)
            CheckLocal(directory.Handle);
        var parent = directories[^1].Handle;
        var fd = OpenAt(parent, WindowsStorage.DataName, NoFollow | CloseOnExec | NonBlock, 0);
        if (fd < 0 && Marshal.GetLastPInvokeError() == 2 && allowMissing)
            return null;
        using var file = new Descriptor(fd);
        var held = Read(file, "");
        CheckInstalledFile(held);
        if (!Same(held, Read(parent, WindowsStorage.DataName)))
            throw Storage();
        var data = new byte[checked((int)held.Size)];
        if (ReadAt(file, data, (nuint)data.Length, 0) != data.Length || !Same(held, Read(parent, WindowsStorage.DataName)))
            throw Storage();
        return data;
    }

    private static void CheckInstalledFile(Metadata metadata)
    {
        if ((metadata.Mask & RequiredMetadata) != RequiredMetadata || metadata.Owner != UserId() || metadata.Links != 1 ||
            (metadata.Mode & 0xffff) != 0x8180 || metadata.Size is 0 or > InstalledCodec.Limit)
            throw Storage();
    }

    internal void WriteInstalled(byte[] data, bool allowMissing)
    {
        if (data.Length is 0 or > InstalledCodec.Limit)
            throw Storage();
        var old = ReadInstalled(allowMissing);
        if (old != null)
            CryptographicOperations.ZeroMemory(old);
        BeginWrite();
        var parent = directories[^1].Handle;
        var name = "orbit-storage." + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)) + ".tmp";
        try
        {
            using var file = new Descriptor(OpenAt(parent, name, 1 | 0x40 | 0x80 | NoFollow | CloseOnExec, 0x180));
            // The temporary file is initially empty, with the same private metadata as the lease.
            CheckPrivate(Read(file, ""), UserId(), directory: false);
            if (WriteAt(file, data, (nuint)data.Length, 0) != data.Length || Sync(file) != 0)
                throw Storage();
            Check(pending: true);
            CheckInstalledFile(Read(file, ""));
            if (!Same(Read(file, ""), Read(parent, name)) || Rename(parent, name, parent, WindowsStorage.DataName) != 0 || Sync(parent) != 0)
                throw Storage();
            CompleteWrite();
        }
        finally { _ = Unlink(parent, name, 0); }
    }
}

internal sealed class InstalledLinuxFiles(string path) : IInstalledFiles
{
    private readonly LinuxStorageLease lease = LinuxStorageLease.Open(path, installed: true);
    private bool allowMissing;
    public string Provider => "private_file";
    public bool Created => lease.Created;
    public byte[]? Read()
    {
        allowMissing = lease.Created;
        return lease.ReadInstalled(allowMissing);
    }
    public void Write(byte[] data)
    {
        lease.WriteInstalled(data, allowMissing);
        allowMissing = false;
    }
    public void Check() => lease.Check();
    public void Dispose() => lease.Dispose();
}
