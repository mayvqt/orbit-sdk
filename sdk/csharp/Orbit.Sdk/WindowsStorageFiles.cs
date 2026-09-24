using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Orbit.Sdk;

// Handles are opened without following reparse points. Directory ancestors stay
// pinned without delete sharing until disposal, including during replacement.
internal static class WindowsStorageFiles
{
    internal const int MaximumCiphertext = WindowsDataProtection.MaxCiphertextBytes;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint BackupSemantics = 0x02000000;
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint DeleteAccess = 0x00010000;

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInformation
    {
        internal FileAttributes Attributes;
        internal System.Runtime.InteropServices.ComTypes.FILETIME CreationTime, AccessTime, WriteTime;
        internal uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }

    // Natural HANDLE alignment matches FILE_RENAME_INFO on both 32- and 64-bit Windows.
    [StructLayout(LayoutKind.Sequential)]
    private struct RenameInformation
    {
        internal uint ReplaceIfExists;
        internal IntPtr RootDirectory;
        internal uint FileNameLength;
        internal ushort FileName;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetFileType(SafeFileHandle handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle,
        StringBuilder path, uint capacity, uint flags);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int informationClass,
        [In] byte[] information, uint size);

    internal static string PinDirectory(string directory, List<SafeFileHandle> pins)
    {
        if (string.IsNullOrEmpty(directory) || !Path.IsPathFullyQualified(directory) ||
            directory.Length < 3 || !char.IsAsciiLetter(directory[0]) || directory[1] != ':' ||
            directory[2] is not ('\\' or '/') || directory[2..].Contains(':')) throw Storage();
        var path = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory));
        var root = Path.GetPathRoot(path)!;
        if (new DriveInfo(root).DriveType is not (DriveType.Fixed or DriveType.Removable or DriveType.Ram)) throw Storage();
        var current = root;
        Pin(current, pins);
        var components = path[root.Length..].Split(Path.DirectorySeparatorChar);
        if (components.Length == 0 || components.Any(string.IsNullOrEmpty)) throw Storage();
        foreach (var component in components)
        {
            var stem = component.Split('.')[0].ToUpperInvariant();
            if (component.EndsWith(' ') || component.EndsWith('.') || component.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
                stem is "CON" or "PRN" or "AUX" or "NUL" ||
                stem.Length == 4 && (stem.StartsWith("COM", StringComparison.Ordinal) || stem.StartsWith("LPT", StringComparison.Ordinal)) && stem[3] is >= '1' and <= '9')
                throw Storage();
            current = Path.Combine(current, component);
            Pin(current, pins);
        }
        return path;
    }

    private static void Pin(string path, List<SafeFileHandle> pins)
    {
        // Metadata-only access does not enforce the no-delete sharing boundary.
        var handle = CreateFileW(path, GenericRead, 3, IntPtr.Zero, 3, OpenReparsePoint | BackupSemantics, IntPtr.Zero);
        try { _ = Information(handle, directory: true); pins.Add(handle); }
        catch { handle.Dispose(); throw; }
    }

    private static long Information(SafeFileHandle handle, bool directory)
    {
        if (handle.IsClosed || handle.IsInvalid || GetFileType(handle) != 1 || !GetFileInformationByHandle(handle, out var info) ||
            (info.Attributes & FileAttributes.ReparsePoint) != 0 ||
            ((info.Attributes & FileAttributes.Directory) != 0) != directory || !directory && info.Links != 1)
            throw Storage();
        var length = ((ulong)info.SizeHigh << 32) | info.SizeLow;
        if (!directory && length > MaximumCiphertext) throw Storage();
        return directory ? 0 : (long)length;
    }

    private static void CheckDirectories(IReadOnlyList<SafeFileHandle> directories)
    {
        if (directories.Count == 0) throw Storage();
        foreach (var handle in directories) _ = Information(handle, directory: true);
    }

    internal static (SafeFileHandle Handle, bool Created) Lease(string path)
    {
        var handle = CreateFileW(path, GenericRead | GenericWrite, 0, IntPtr.Zero, 1, OpenReparsePoint, IntPtr.Zero);
        var created = !handle.IsInvalid;
        if (!created)
        {
            var error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            if (error is not (80 or 183)) throw Storage();
            handle = CreateFileW(path, GenericRead | GenericWrite, 0, IntPtr.Zero, 3, OpenReparsePoint, IntPtr.Zero);
        }
        try
        {
            if (Information(handle, directory: false) != 0) throw Storage();
            return (handle, created);
        }
        catch { handle.Dispose(); throw; }
    }

    internal static byte[]? Read(string path, bool allowAbsent, IReadOnlyList<SafeFileHandle> directories)
    {
        CheckDirectories(directories);
        using var handle = CreateFileW(path, GenericRead, 1, IntPtr.Zero, 3, OpenReparsePoint, IntPtr.Zero);
        if (handle.IsInvalid && allowAbsent && Marshal.GetLastPInvokeError() == 2) return null;
        var length = Information(handle, directory: false);
        if (length < 1) throw Storage();
        using var stream = new FileStream(handle, FileAccess.Read);
        var bytes = new byte[(int)length];
        stream.ReadExactly(bytes);
        if (stream.ReadByte() != -1) throw Storage();
        return bytes;
    }

    internal static void Write(string temporary, IReadOnlyList<SafeFileHandle> directories, byte[] ciphertext)
    {
        CheckDirectories(directories);
        var created = false;
        var renamed = false;
        try
        {
            using (var handle = CreateFileW(temporary, GenericRead | GenericWrite | DeleteAccess, 0, IntPtr.Zero, 1, OpenReparsePoint, IntPtr.Zero))
            {
                created = !handle.IsInvalid;
                if (Information(handle, directory: false) != 0) throw Storage();
                using var stream = new FileStream(handle, FileAccess.Write);
                stream.Write(ciphertext);
                stream.Flush(flushToDisk: true);
                CheckDirectories(directories);
                Replace(handle, directories[^1]);
                renamed = true;
                stream.Flush(flushToDisk: true);
            }
        }
        finally { if (created && !renamed) File.Delete(temporary); }
    }

    internal static void Replace(SafeFileHandle source, SafeFileHandle directory)
    {
        _ = Information(source, directory: false);
        _ = Information(directory, directory: true);
        var retained = false;
        try
        {
            directory.DangerousAddRef(ref retained);
            const int maximumPathUnits = 32768;
            var path = new StringBuilder(maximumPathUnits);
            var length = GetFinalPathNameByHandleW(directory, path, maximumPathUnits, 0);
            if (length == 0 || length >= maximumPathUnits) throw Storage();
            if (path[path.Length - 1] != '\\') path.Append('\\');
            path.Append(WindowsStorage.DataName);
            if (path.Length >= maximumPathUnits) throw Storage();
            var name = Encoding.Unicode.GetBytes(path.ToString());
            var offset = Marshal.OffsetOf<RenameInformation>(nameof(RenameInformation.FileName)).ToInt32();
            var buffer = new byte[offset + name.Length + sizeof(ushort)];
            var information = new RenameInformation
            {
                ReplaceIfExists = 1, RootDirectory = IntPtr.Zero,
                FileNameLength = (uint)name.Length, FileName = 0
            };
            MemoryMarshal.Write(buffer.AsSpan(), in information);
            name.CopyTo(buffer, offset);
            // FileRenameInfo = 3. The exclusive DELETE-capable source remains open;
            // the absolute destination comes from the pinned directory handle.
            // Windows rejects the relative-name/non-null RootDirectory form.
            // No source pathname is reopened; all ancestor pins remain held.
            if (!SetFileInformationByHandle(source, 3, buffer, (uint)buffer.Length)) throw Storage();
        }
        finally { if (retained) directory.DangerousRelease(); }
    }

    private static OrbitException Storage() => new(OrbitError.Storage);
}
