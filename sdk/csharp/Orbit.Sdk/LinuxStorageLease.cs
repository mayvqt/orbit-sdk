using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Orbit.Sdk;

// Linux's fixed statx ABI avoids architecture-dependent libc struct stat layouts.
// Missing libc/statx support fails closed; no pathname-only metadata fallback.
internal sealed class LinuxStorageLease : IDisposable
{
    internal const string Name = "orbit-storage.lock";
    internal static bool Supported => OperatingSystem.IsLinux() && RuntimeInformation.ProcessArchitecture == Architecture.X64;
    private const int NoFollow = 0x20000, DirectoryFlag = 0x10000, CloseOnExec = 0x80000, NonBlock = 0x800;
    private const uint RequiredMetadata = 0x30f; // type, mode, links, uid, inode, size
    private readonly List<(Descriptor Handle, string Name)> directories = [];
    private Descriptor? lease;
    internal string Directory { get; private set; } = "";
    internal bool Created { get; private set; }

    private sealed class Descriptor : SafeHandleMinusOneIsInvalid
    {
        internal Descriptor(int descriptor) : base(true) => SetHandle((IntPtr)descriptor);
        protected override bool ReleaseHandle() => LinuxStorageLease.Close(handle.ToInt32()) == 0;
    }

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    internal struct Metadata
    {
        [FieldOffset(0)] internal uint Mask;
        [FieldOffset(16)] internal uint Links;
        [FieldOffset(20)] internal uint Owner;
        [FieldOffset(28)] internal ushort Mode;
        [FieldOffset(32)] internal ulong Inode;
        [FieldOffset(40)] internal ulong Size;
        [FieldOffset(136)] internal uint DeviceMajor;
        [FieldOffset(140)] internal uint DeviceMinor;
    }

    [DllImport("libc.so.6", EntryPoint = "open", SetLastError = true)]
    private static extern int OpenRoot([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);
    [DllImport("libc.so.6", EntryPoint = "openat", SetLastError = true)]
    private static extern int OpenAt(Descriptor directory, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, uint mode);
    [DllImport("libc.so.6", EntryPoint = "statx", SetLastError = true)]
    private static extern int Stat(Descriptor directory, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, uint mask, out Metadata metadata);
    [DllImport("libc.so.6", EntryPoint = "flock", SetLastError = true)]
    private static extern int Flock(Descriptor descriptor, int operation);
    [DllImport("libc.so.6", EntryPoint = "fsync", SetLastError = true)]
    private static extern int Sync(Descriptor descriptor);
    [DllImport("libc.so.6", EntryPoint = "pread", SetLastError = true)]
    private static extern nint ReadAt(Descriptor descriptor, [Out] byte[] buffer, nuint count, long offset);
    [DllImport("libc.so.6", EntryPoint = "pwrite", SetLastError = true)]
    private static extern nint WriteAt(Descriptor descriptor, [In] byte[] buffer, nuint count, long offset);
    [DllImport("libc.so.6", EntryPoint = "ftruncate", SetLastError = true)]
    private static extern int Truncate(Descriptor descriptor, long length);
    [DllImport("libc.so.6", EntryPoint = "close", SetLastError = true)]
    private static extern int Close(int descriptor);
    [DllImport("libc.so.6", EntryPoint = "geteuid")]
    private static extern uint UserId();

    internal static string Normalize(string directory)
    {
        if (!Supported || string.IsNullOrEmpty(directory) || !Path.IsPathFullyQualified(directory) ||
            directory.Contains('\0') || new UTF8Encoding(false, true).GetByteCount(directory) >= 4096) throw Storage();
        var result = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
        if (result == "/") throw Storage();
        return result;
    }

    internal static LinuxStorageLease Open(string directory)
    {
        var result = new LinuxStorageLease();
        try
        {
            result.PinDirectory(directory);
            var final = result.directories[^1].Handle;
            var fd = OpenAt(final, Name, 2 | 0x40 | 0x80 | NoFollow | CloseOnExec | NonBlock, 0x180); // RDWR, CREAT, EXCL, 0600
            result.Created = fd >= 0;
            if (fd < 0)
            {
                if (Marshal.GetLastPInvokeError() != 17) throw Storage(); // EEXIST only
                fd = OpenAt(final, Name, 2 | NoFollow | CloseOnExec | NonBlock, 0);
            }
            result.lease = new Descriptor(fd);
            CheckPrivate(Read(result.lease, ""), UserId(), directory: false);
            if (Flock(result.lease, 2 | 4) != 0) throw Storage(); // LOCK_EX | LOCK_NB
            result.Check();
            if (result.Created && (Sync(result.lease) != 0 || Sync(final) != 0)) throw Storage();
            return result;
        }
        catch (Exception) { result.Dispose(); throw Storage(); }
    }

    // Also used by the opt-in native fixture to validate its private root without
    // opening a keyring or creating a lease in the harness's own directory.
    internal static void CheckPrivateDirectory(string directory)
    {
        using var boundary = new LinuxStorageLease();
        try { boundary.PinDirectory(directory); }
        catch (Exception) { throw Storage(); }
    }

    private void PinDirectory(string directory)
    {
        Directory = Normalize(directory);
        directories.Add((new Descriptor(OpenRoot("/", DirectoryFlag | NoFollow | CloseOnExec)), "/"));
        foreach (var component in Directory[1..].Split('/'))
        {
            var parent = directories[^1].Handle;
            _ = Read(parent, "");
            directories.Add((new Descriptor(OpenAt(parent, component, DirectoryFlag | NoFollow | CloseOnExec, 0)), component));
        }
        CheckDirectories();
    }

    internal void Check(bool pending = false)
    {
        try
        {
            CheckDirectories();
            if (lease == null) throw Storage();
            var held = Read(lease, "");
            var named = Read(directories[^1].Handle, Name);
            CheckPrivate(held, UserId(), directory: false, pending);
            CheckPrivate(named, UserId(), directory: false, pending);
            if (!Same(held, named)) throw Storage();
            if (pending)
            {
                var marker = new byte[1];
                if (ReadAt(lease, marker, 1, 0) != 1 || marker[0] != 1) throw Storage();
            }
        }
        catch (Exception) { throw Storage(); }
    }

    internal void BeginWrite()
    {
        try
        {
            Check();
            if (WriteAt(lease!, [1], 1, 0) != 1 || Sync(lease!) != 0) throw Storage();
            Check(pending: true);
        }
        catch (Exception) { throw Storage(); }
    }

    // Call only after the store helper has succeeded and been reaped. Until this
    // durable clear succeeds, another opener must reject the uncertain store.
    internal void CompleteWrite()
    {
        try
        {
            Check(pending: true);
            if (Truncate(lease!, 0) != 0 || Sync(lease!) != 0) throw Storage();
            Check();
        }
        catch (Exception)
        {
            // A failure during clearing must not intentionally leave a clean
            // receipt. Repair only the held descriptor, never a replaced path.
            try { if (lease != null && !lease.IsClosed && !lease.IsInvalid && WriteAt(lease, [1], 1, 0) == 1) _ = Sync(lease); }
            catch (Exception) { }
            throw Storage();
        }
    }

    private void CheckDirectories()
    {
        if (directories.Count < 2) throw Storage();
        for (var index = 0; index < directories.Count; index++)
        {
            var (handle, name) = directories[index];
            var held = Read(handle, "");
            if ((held.Mode & 0xf000) != 0x4000 || held.Links == 0) throw Storage();
            if (index > 0 && !Same(held, Read(directories[index - 1].Handle, name))) throw Storage();
            if (index == directories.Count - 1) CheckPrivate(held, UserId(), directory: true);
        }
    }

    internal static void CheckPrivate(Metadata metadata, uint owner, bool directory, bool pending = false)
    {
        if ((metadata.Mask & RequiredMetadata) != RequiredMetadata || metadata.Owner != owner ||
            (metadata.Mode & 0xf000) != (directory ? 0x4000 : 0x8000) || (metadata.Mode & 0xfff) != (directory ? 0x1c0 : 0x180) ||
            metadata.Links == 0 || !directory && (metadata.Links != 1 || metadata.Size != (pending ? 1UL : 0UL))) throw Storage();
    }

    private static Metadata Read(Descriptor descriptor, string path)
    {
        if (descriptor.IsClosed || descriptor.IsInvalid || Stat(descriptor, path, 0x100 | (path.Length == 0 ? 0x1000 : 0),
                RequiredMetadata, out var metadata) != 0 || (metadata.Mask & RequiredMetadata) != RequiredMetadata) throw Storage();
        return metadata;
    }

    private static bool Same(Metadata left, Metadata right) => left.Inode == right.Inode &&
        left.DeviceMajor == right.DeviceMajor && left.DeviceMinor == right.DeviceMinor && (right.Mode & 0xf000) == (left.Mode & 0xf000);

    public void Dispose()
    {
        lease?.Dispose();
        lease = null;
        foreach (var item in directories) item.Handle.Dispose();
        directories.Clear();
    }

    private static OrbitException Storage() => new(OrbitError.Storage);
}
