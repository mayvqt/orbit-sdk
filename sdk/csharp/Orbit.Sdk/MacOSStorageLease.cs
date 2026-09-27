using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Orbit.Sdk;

// Darwin's native stat layout and open flags are defined separately from the
// Linux statx/flag ABI used by LinuxStorageLease.
internal sealed class MacOSStorageLease : IDisposable
{
    internal const string LeaseName = "orbit-storage.lock";
    private const string DataName = "orbit-storage.bin";
    private const int DirectoryFlag = 0x00100000;
    private const int NoFollow = 0x00000100;
    private const int CloseOnExec = 0x01000000;
    private const int Create = 0x00000200;
    private const int Exclusive = 0x00000800;
    private const int NonBlock = 0x00000004;
    private const int LockExclusive = 2, LockNonBlocking = 4;
    private const int AtSymlinkNoFollow = 0x0020;
    private const int FullFsync = 51;

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeTimespec { internal long Seconds, Nanoseconds; }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeStat
    {
        internal int Device;
        internal ushort Mode, Links;
        internal ulong Inode;
        internal uint Owner, Group;
        internal int SpecialDevice;
        internal NativeTimespec Access, Modify, Change, Birth;
        internal long Size, Blocks;
        internal int BlockSize;
        internal uint Flags, Generation;
        internal int Spare;
        internal long Spare0, Spare1;
    }

    private sealed class Descriptor : SafeHandleMinusOneIsInvalid
    {
        internal Descriptor(int value) : base(true) => SetHandle((IntPtr)value);
        protected override bool ReleaseHandle() => MacOSStorageLease.Close(handle.ToInt32()) == 0;
    }

    [DllImport("orbit_macos_shim", EntryPoint = "orbit_open", SetLastError = true)]
    private static extern int Open([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, uint mode);
    [DllImport("orbit_macos_shim", EntryPoint = "orbit_openat", SetLastError = true)]
    private static extern int OpenAt(Descriptor directory, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, uint mode);
    [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "fstat$INODE64", SetLastError = true)]
    private static extern int FStatX64(Descriptor descriptor, out NativeStat value);
    [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "fstat", SetLastError = true)]
    private static extern int FStatArm64(Descriptor descriptor, out NativeStat value);
    [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "fstatat$INODE64", SetLastError = true)]
    private static extern int FStatAtX64(Descriptor directory, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, out NativeStat value, int flags);
    [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "fstatat", SetLastError = true)]
    private static extern int FStatAtArm64(Descriptor directory, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, out NativeStat value, int flags);
    [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "mkdirat", SetLastError = true)]
    private static extern int MakeDirectory(Descriptor directory, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, uint mode);
    [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "renameat", SetLastError = true)]
    private static extern int Rename(Descriptor directory, [MarshalAs(UnmanagedType.LPUTF8Str)] string source, Descriptor destination, [MarshalAs(UnmanagedType.LPUTF8Str)] string target);
    [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "unlinkat", SetLastError = true)]
    private static extern int Unlink(Descriptor directory, [MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);
    [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "flock", SetLastError = true)]
    private static extern int FLock(Descriptor descriptor, int operation);
    [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "pread", SetLastError = true)]
    private static extern nint ReadAt(Descriptor descriptor, [Out] byte[] buffer, nuint count, long offset);
    [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "pwrite", SetLastError = true)]
    private static extern nint WriteAt(Descriptor descriptor, [In] byte[] buffer, nuint count, long offset);
    [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "ftruncate", SetLastError = true)]
    private static extern int Truncate(Descriptor descriptor, long length);
    [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "fsync", SetLastError = true)]
    private static extern int Sync(Descriptor descriptor);
    [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "fcntl", SetLastError = true)]
    private static extern int Fcntl(Descriptor descriptor, int command);
    [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "close", SetLastError = true)]
    private static extern int Close(int descriptor);
    [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "fchmod", SetLastError = true)]
    private static extern int FChmod(Descriptor descriptor, uint mode);
    [DllImport("/usr/lib/libSystem.B.dylib", EntryPoint = "geteuid")]
    private static extern uint UserId();

    private readonly List<(Descriptor Handle, string Name)> directories = [];
    private Descriptor? lease;
#if ORBIT_LOCAL_DEVELOPMENT
    internal Action? BeforeLeaseCommitForTest { get; set; }
#endif
    internal string Directory { get; private set; } = "";
    internal bool Created { get; private set; }
    internal static bool Supported => OperatingSystem.IsMacOS() &&
        RuntimeInformation.ProcessArchitecture is Architecture.X64 or Architecture.Arm64 && IntPtr.Size == 8 &&
        Marshal.SizeOf<NativeStat>() == 144;

    private static bool UsesInode64Alias(Architecture architecture) => architecture switch
    {
        Architecture.X64 => true,
        Architecture.Arm64 => false,
        _ => throw Storage()
    };

    internal static string StatEntryPoint(Architecture architecture, bool at)
    {
        var name = at ? "fstatat" : "fstat";
        return UsesInode64Alias(architecture) ? name + "$INODE64" : name;
    }

    private static int FStat(Descriptor descriptor, out NativeStat value)
    {
        if (UsesInode64Alias(RuntimeInformation.ProcessArchitecture))
        {
            return FStatX64(descriptor, out value);
        }
        return FStatArm64(descriptor, out value);
    }

    private static int FStatAt(Descriptor directory, string path, out NativeStat value, int flags)
    {
        if (UsesInode64Alias(RuntimeInformation.ProcessArchitecture))
        {
            return FStatAtX64(directory, path, out value, flags);
        }
        return FStatAtArm64(directory, path, out value, flags);
    }

    private MacOSStorageLease() { }

    internal static string Normalize(string directory)
    {
        if (!Supported || string.IsNullOrEmpty(directory) || directory[0] != '/' || directory.Contains('\0') ||
            new UTF8Encoding(false, true).GetByteCount(directory) >= 4096)
            throw Storage();
        var parts = directory.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Any(part => part is "." or "..")) throw Storage();
        var result = "/" + string.Join('/', parts);
        if (result == "/") throw Storage();
        return result;
    }

    internal static MacOSStorageLease Open(string directory, bool installed = false)
    {
        var result = new MacOSStorageLease();
        try
        {
            result.PinDirectory(directory, create: true);
            var parent = result.directories[^1].Handle;
            var fd = OpenAt(parent, LeaseName, 2 | Create | Exclusive | NoFollow | CloseOnExec | NonBlock, 0x180);
            result.Created = fd >= 0;
            if (fd < 0)
            {
                if (Marshal.GetLastPInvokeError() != 17) throw Storage();
                fd = OpenAt(parent, LeaseName, 2 | NoFollow | CloseOnExec | NonBlock, 0);
            }
            result.lease = new Descriptor(fd);
            if (result.Created && FChmod(result.lease, 0x180) != 0) throw Storage();
            result.CheckLease(pending: false, allowPending: true);
            if (FLock(result.lease, LockExclusive | LockNonBlocking) != 0)
                throw new OrbitException(OrbitError.Storage, installed && Marshal.GetLastPInvokeError() == 35 ? "installation_in_use" : null);
            result.Check();
            if (result.Created && (FullSync(result.lease) != 0 || Sync(parent) != 0)) throw Storage();
            return result;
        }
        catch (OrbitException) { result.Dispose(); throw; }
        catch (Exception) { result.Dispose(); throw Storage(); }
    }

    internal void Check()
    {
        try
        {
            if (lease == null) throw Storage();
            CheckLease(pending: false, allowPending: false);
        }
        catch (Exception) { throw Storage(); }
    }

    private void PinDirectory(string directory, bool create)
    {
        Directory = Normalize(directory);
        var root = Open("/", DirectoryFlag | NoFollow | CloseOnExec, 0);
        directories.Add((new Descriptor(root), "/"));
        foreach (var component in Directory[1..].Split('/'))
        {
            var parent = directories[^1].Handle;
            var fd = OpenAt(parent, component, DirectoryFlag | NoFollow | CloseOnExec, 0);
            if (fd < 0 && create && Marshal.GetLastPInvokeError() == 2)
            {
                if (MakeDirectory(parent, component, 0x1c0) != 0 && Marshal.GetLastPInvokeError() != 17) throw Storage();
                fd = OpenAt(parent, component, DirectoryFlag | NoFollow | CloseOnExec, 0);
                using var created = new Descriptor(fd);
                if (FChmod(created, 0x1c0) != 0 || Sync(created) != 0 || Sync(parent) != 0) throw Storage();
                fd = OpenAt(parent, component, DirectoryFlag | NoFollow | CloseOnExec, 0);
            }
            directories.Add((new Descriptor(fd), component));
        }
        CheckDirectories();
    }

    private void CheckDirectories()
    {
        if (directories.Count < 2) throw Storage();
        for (var index = 0; index < directories.Count; index++)
        {
            var (handle, name) = directories[index];
            var held = ReadStat(handle);
            if ((held.Mode & 0xf000) != 0x4000 || held.Links == 0) throw Storage();
            if (index > 0 && !Same(held, ReadNamed(directories[index - 1].Handle, name))) throw Storage();
            if (index == directories.Count - 1) CheckPrivate(held, directory: true);
        }
    }

    private void CheckLease(bool pending, bool allowPending)
    {
        CheckDirectories();
        if (lease == null) throw Storage();
        var held = ReadStat(lease);
        var named = ReadNamed(directories[^1].Handle, LeaseName);
        if (!Same(held, named)) throw Storage();
        CheckPrivate(held, directory: false);
        if (held.Size == 1 && allowPending)
        {
            var marker = new byte[1];
            if (ReadAt(lease, marker, 1, 0) != 1 || marker[0] != 1) throw Storage();
            return;
        }
        if (pending)
        {
            var marker = new byte[1];
            if (held.Size != 1 || ReadAt(lease, marker, 1, 0) != 1 || marker[0] != 1) throw Storage();
        }
        else if (held.Size != 0) throw Storage();
    }

    private static void CheckPrivate(NativeStat value, bool directory)
    {
        var type = (value.Mode & 0xf000) == (directory ? 0x4000 : 0x8000);
        var mode = value.Mode & 0x0fff;
        if (!type || value.Owner != UserId() || mode != (directory ? 0x1c0 : 0x180) || value.Links == 0 ||
            (!directory && value.Links != 1)) throw Storage();
    }

    private static NativeStat ReadStat(Descriptor descriptor)
    {
        if (FStat(descriptor, out var value) != 0) throw Storage();
        return value;
    }

    private static NativeStat ReadNamed(Descriptor directory, string name)
    {
        if (FStatAt(directory, name, out var value, AtSymlinkNoFollow) != 0) throw Storage();
        return value;
    }

    private static bool Same(NativeStat left, NativeStat right) => left.Device == right.Device &&
        left.Inode == right.Inode && (left.Mode & 0xf000) == (right.Mode & 0xf000);

    private static int FullSync(Descriptor descriptor) => Fcntl(descriptor, FullFsync);

    private void BeginWrite()
    {
        Check();
        if (WriteAt(lease!, [1], 1, 0) != 1 || Truncate(lease!, 1) != 0 || FullSync(lease!) != 0) throw Storage();
        CheckLease(pending: true, allowPending: false);
    }

    private void CompleteWrite()
    {
        CheckLease(pending: true, allowPending: false);
        try
        {
            if (Truncate(lease!, 0) != 0 || FullSync(lease!) != 0) throw Storage();
            CheckLease(pending: false, allowPending: false);
        }
        catch
        {
            try
            {
                if (WriteAt(lease!, [1], 1, 0) == 1 && Truncate(lease!, 1) == 0)
                    _ = FullSync(lease!);
            }
            catch (Exception) { }
            throw;
        }
    }

    internal byte[]? ReadInstalled(bool allowMissing)
    {
        Check();
        var parent = directories[^1].Handle;
        var fd = OpenAt(parent, DataName, NoFollow | CloseOnExec | NonBlock, 0);
        if (fd < 0 && Marshal.GetLastPInvokeError() == 2 && allowMissing) return null;
        using var file = new Descriptor(fd);
        var held = ReadStat(file);
        CheckPrivate(held, directory: false);
        if (held.Size is <= 0 or > InstalledCodec.Limit || !Same(held, ReadNamed(parent, DataName))) throw Storage();
        var bytes = new byte[checked((int)held.Size)];
        if (ReadAt(file, bytes, (nuint)bytes.Length, 0) != bytes.Length || !Same(held, ReadNamed(parent, DataName))) throw Storage();
        return bytes;
    }

    internal void WriteInstalled(byte[] data, bool allowMissing)
    {
        if (data.Length is 0 or > InstalledCodec.Limit) throw Storage();
        var prior = ReadInstalled(allowMissing);
        if (prior != null) CryptographicOperations.ZeroMemory(prior);
        BeginWrite();
        var parent = directories[^1].Handle;
        var temp = "orbit-storage." + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16)) + ".tmp";
        try
        {
            using var file = new Descriptor(OpenAt(parent, temp, 1 | Create | Exclusive | NoFollow | CloseOnExec, 0x180));
            if (FChmod(file, 0x180) != 0 || WriteAt(file, data, (nuint)data.Length, 0) != data.Length || FullSync(file) != 0)
                throw Storage();
#if ORBIT_LOCAL_DEVELOPMENT
            BeforeLeaseCommitForTest?.Invoke();
#endif
            CheckLease(pending: true, allowPending: false);
            var info = ReadStat(file);
            CheckPrivate(info, directory: false);
            if (info.Size != data.Length || !Same(info, ReadNamed(parent, temp)) || Rename(parent, temp, parent, DataName) != 0 || Sync(parent) != 0)
                throw Storage();
            CompleteWrite();
        }
        finally { _ = Unlink(parent, temp, 0); }
    }

    public void Dispose()
    {
        lease?.Dispose();
        lease = null;
        foreach (var item in directories) item.Handle.Dispose();
        directories.Clear();
    }

    private static OrbitException Storage() => new(OrbitError.Storage);
}
