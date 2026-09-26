using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Orbit.Sdk;

[SupportedOSPlatform("windows")]
internal sealed class InstalledWindowsSecurity : IDisposable
{
    private readonly SecurityIdentifier user = CurrentUser();
    private IntPtr descriptor;
    internal IntPtr Attributes
    {
        get; private set;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        internal uint Length; internal IntPtr Descriptor; internal int Inherit;
    }
    [DllImport("advapi32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetSecurityInfo(SafeFileHandle handle, int kind, uint flags, out IntPtr owner, IntPtr group, out IntPtr dacl, IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("kernel32.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryW(string path, IntPtr security);
    internal InstalledWindowsSecurity()
    {
        RejectImpersonation();
        var sd = new RawSecurityDescriptor($"O:{user.Value}D:P(A;OICI;FA;;;{user.Value})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        var bytes = new byte[sd.BinaryLength];
        sd.GetBinaryForm(bytes, 0);
        try
        {
            descriptor = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, descriptor, bytes.Length);
            Attributes = Marshal.AllocHGlobal(Marshal.SizeOf<SecurityAttributes>());
            Marshal.StructureToPtr(new SecurityAttributes { Length = (uint)Marshal.SizeOf<SecurityAttributes>(), Descriptor = descriptor }, Attributes, false);
        }
        catch { Dispose(); throw; }
    }
    internal void CreateDirectory(string path)
    {
        if (!CreateDirectoryW(path, Attributes) && Marshal.GetLastPInvokeError() != 183)
            throw new OrbitException(OrbitError.Storage);
    }
    internal void Check(SafeFileHandle handle)
    {
        RejectImpersonation();
        var result = GetSecurityInfo(handle, 1, 5, out _, IntPtr.Zero, out _, IntPtr.Zero, out var memory);
        try
        {
            if (result != 0 || memory == IntPtr.Zero)
                throw new OrbitException(OrbitError.Storage);
            var length = GetSecurityDescriptorLength(memory);
            if (length is 0 or > 65536)
                throw new OrbitException(OrbitError.Storage);
            var bytes = new byte[(int)length];
            Marshal.Copy(memory, bytes, 0, bytes.Length);
            var sd = new RawSecurityDescriptor(bytes, 0);
            if (sd.Owner == null || !user.Equals(sd.Owner) || !sd.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected | ControlFlags.DiscretionaryAclPresent) || sd.DiscretionaryAcl is not { } acl || acl.Count is < 1 or > 3)
                throw new OrbitException(OrbitError.Storage);
            var permitted = false;
            foreach (GenericAce ace in acl)
            {
                if (ace is not CommonAce common || common.AceQualifier != AceQualifier.AccessAllowed || common.IsCallback || common.AceFlags.HasFlag(AceFlags.InheritOnly) ||
                    !common.SecurityIdentifier.Equals(user) && !common.SecurityIdentifier.IsWellKnown(WellKnownSidType.LocalSystemSid) && !common.SecurityIdentifier.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
                    throw new OrbitException(OrbitError.Storage);
                if (common.SecurityIdentifier.Equals(user) && (common.AccessMask & 0x1f01ff) == 0x1f01ff)
                    permitted = true;
            }
            if (!permitted)
                throw new OrbitException(OrbitError.Storage);
        }
        finally { if (memory != IntPtr.Zero) _ = LocalFree(memory); }
    }
    internal static void RejectImpersonation()
    {
        using var identity = WindowsIdentity.GetCurrent(true);
        if (identity != null)
            throw new OrbitException(OrbitError.Storage);
    }
    private static SecurityIdentifier CurrentUser()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User ?? throw new OrbitException(OrbitError.Storage);
    }
    public void Dispose()
    {
        if (Attributes != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(Attributes);
            Attributes = IntPtr.Zero;
        }
        if (descriptor != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(descriptor);
            descriptor = IntPtr.Zero;
        }
    }
}
