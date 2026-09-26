//! Windows owner/DACL checks and secure-at-creation objects for installed state.
use std::{
    ffi::c_void,
    fs::File,
    io,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, INVALID_HANDLE_VALUE, LocalFree},
    Storage::FileSystem::{
        CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_FLAG_OPEN_REPARSE_POINT,
    },
};

#[repr(C)]
struct SidAndAttributes {
    sid: *mut c_void,
    attributes: u32,
}
#[repr(C)]
struct Acl {
    revision: u8,
    sbz1: u8,
    size: u16,
    count: u16,
    sbz2: u16,
}
#[repr(C)]
struct Ace {
    kind: u8,
    flags: u8,
    size: u16,
    mask: u32,
    sid: u32,
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
    fn OpenThreadToken(
        thread: *mut c_void,
        access: u32,
        open_as_self: i32,
        token: *mut *mut c_void,
    ) -> i32;
    fn GetTokenInformation(
        token: *mut c_void,
        class: i32,
        buffer: *mut c_void,
        length: u32,
        needed: *mut u32,
    ) -> i32;
    fn ConvertSidToStringSidW(sid: *mut c_void, text: *mut *mut u16) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        revision: u32,
        descriptor: *mut *mut c_void,
        size: *mut u32,
    ) -> i32;
    fn GetSecurityInfo(
        object: *mut c_void,
        kind: i32,
        information: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut Acl,
        sacl: *mut *mut Acl,
        descriptor: *mut *mut c_void,
    ) -> u32;
    fn GetSecurityDescriptorControl(
        descriptor: *mut c_void,
        control: *mut u16,
        revision: *mut u32,
    ) -> i32;
    fn GetAce(acl: *mut Acl, index: u32, ace: *mut *mut c_void) -> i32;
    fn IsValidSid(sid: *mut c_void) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn GetCurrentThread() -> *mut c_void;
}
struct Allocation(*mut c_void);
impl Drop for Allocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}
struct Token(*mut c_void);
impl Drop for Token {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}
fn failure() -> io::Error {
    io::Error::other("Private Windows storage security check failed")
}
fn wide(path: &Path) -> io::Result<Vec<u16>> {
    let mut text: Vec<_> = path.as_os_str().encode_wide().collect();
    if text.is_empty() || text.len() > 32760 || text.contains(&0) {
        return Err(failure());
    }
    text.push(0);
    Ok(text)
}
// The SID originates from a live token or security descriptor owned by the caller.
unsafe fn sid_text(sid: *mut c_void) -> io::Result<String> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(failure());
    }
    let mut text = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(failure());
    }
    let _allocation = Allocation(text.cast());
    let mut length = 0;
    while length < 256 && unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    if length == 256 {
        return Err(failure());
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) }).map_err(|_| failure())
}
/// Installed state and DPAPI use the process account exclusively. Reject every
/// impersonation token, including an impersonation of the same user, and fail
/// closed if Windows cannot establish that there is no thread token.
pub fn process_user_context() -> bool {
    let mut token = Token(ptr::null_mut());
    // SAFETY: GetCurrentThread returns a borrowed pseudo-handle; token is a live
    // writable output and its guard closes any returned owned token handle.
    if unsafe { OpenThreadToken(GetCurrentThread(), 8, 1, &mut token.0) } != 0 {
        return false;
    }
    io::Error::last_os_error().raw_os_error() == Some(1008) // ERROR_NO_TOKEN
}
fn user_sid() -> io::Result<String> {
    if !process_user_context() {
        return Err(failure());
    }
    let mut token = Token(ptr::null_mut());
    // All buffers/handles remain alive for each synchronous Windows API call.
    if unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut token.0) } == 0 {
        return Err(failure());
    }
    let mut needed = 0;
    unsafe {
        GetTokenInformation(token.0, 1, ptr::null_mut(), 0, &mut needed);
    }
    if needed < size_of::<SidAndAttributes>() as u32 || needed > 65536 {
        return Err(failure());
    }
    let mut buffer = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    if unsafe { GetTokenInformation(token.0, 1, buffer.as_mut_ptr().cast(), needed, &mut needed) }
        == 0
    {
        return Err(failure());
    }
    let user = unsafe { &*buffer.as_ptr().cast::<SidAndAttributes>() };
    unsafe { sid_text(user.sid) }
}
fn descriptor() -> io::Result<Allocation> {
    let user = user_sid()?;
    let sddl = format!("O:{user}D:P(A;;FA;;;{user})(A;;FA;;;SY)(A;;FA;;;BA)");
    let text: Vec<_> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut allocation = Allocation(ptr::null_mut());
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            1,
            &mut allocation.0,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(failure());
    }
    Ok(allocation)
}
/// Existing private objects must belong to this user and grant only user/SYSTEM/Administrators.
/// This function never repairs permissions or ownership.
pub fn private_storage_object(file: &File) -> bool {
    let Ok(user) = user_sid() else {
        return false;
    };
    let mut allocation = Allocation(ptr::null_mut());
    let mut owner = ptr::null_mut();
    let mut acl = ptr::null_mut();
    if unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            1,
            5,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut allocation.0,
        )
    } != 0
    {
        return false;
    }
    let mut control = 0u16;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(allocation.0, &mut control, &mut revision) } == 0
        || control & 0x1000 == 0
        || acl.is_null()
    {
        return false;
    }
    if unsafe { sid_text(owner) }.ok().as_deref() != Some(user.as_str()) {
        return false;
    }
    let count = unsafe { (*acl).count };
    if count == 0 || count > 32 {
        return false;
    }
    let mut user_access = false;
    for index in 0..count {
        let mut pointer = ptr::null_mut();
        if unsafe { GetAce(acl, index.into(), &mut pointer) } == 0 || pointer.is_null() {
            return false;
        }
        let ace = unsafe { &*pointer.cast::<Ace>() };
        if ace.kind != 0
            || ace.flags != 0
            || ace.size < size_of::<Ace>() as u16
            || ace.mask != 0x001f01ff
        {
            return false;
        }
        let Ok(sid) = (unsafe { sid_text(ptr::addr_of!(ace.sid).cast_mut().cast()) }) else {
            return false;
        };
        if sid == user {
            user_access = true;
        } else if sid != "S-1-5-18" && sid != "S-1-5-32-544" {
            return false;
        }
    }
    user_access
}
/// Create a directory with a protected, current-user-owned DACL before it is visible.
pub fn create_private_storage_directory(path: &Path) -> io::Result<()> {
    let descriptor = descriptor()?;
    let text = wide(path)?;
    let security = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        nLength: size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    if unsafe { CreateDirectoryW(text.as_ptr(), &security) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
/// Create an exclusive file with private security; DELETE permits handle-owned atomic replacement.
pub fn create_private_storage_file(path: &Path) -> io::Result<File> {
    let descriptor = descriptor()?;
    let text = wide(path)?;
    let security = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        nLength: size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let handle = unsafe {
        CreateFileW(
            text.as_ptr(),
            0xc0010000,
            0,
            &security,
            CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_handle(handle) })
    }
}

/// Inspect the borrowed handle, avoiding path reopening and unstable metadata APIs.
pub fn storage_file_single_link(file: &File) -> bool {
    let mut information =
        windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: file retains the live borrowed handle, and information is writable
    // for the synchronous API call, which initializes it on success.
    unsafe {
        windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(
            file.as_raw_handle(),
            &mut information,
        ) != 0
            && information.nNumberOfLinks == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ImpersonateSelf(level: i32) -> i32;
        fn RevertToSelf() -> i32;
    }
    struct Impersonation;
    impl Drop for Impersonation {
        fn drop(&mut self) {
            // SAFETY: This guard owns the impersonation on its dedicated test
            // thread and restores that thread before any cleanup runs.
            assert_ne!(unsafe { RevertToSelf() }, 0);
        }
    }
    #[test]
    fn impersonating_thread_cannot_create_check_or_protect_installed_state() {
        std::thread::spawn(|| {
            assert!(process_user_context());
            let suffix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory = std::env::temp_dir().join(format!(
                "orbit-impersonation-{}-{suffix}",
                std::process::id()
            ));
            create_private_storage_directory(&directory).unwrap();
            let path = directory.join("state");
            let file = create_private_storage_file(&path).unwrap();
            assert!(private_storage_object(&file));
            let encrypted = crate::protect_user_data(b"synthetic state", b"scope").unwrap();
            // SAFETY: This dedicated thread has no existing impersonation token;
            // SecurityImpersonation creates a same-user token without credentials.
            assert_ne!(unsafe { ImpersonateSelf(2) }, 0);
            let impersonation = Impersonation;
            assert!(!process_user_context());
            assert!(!private_storage_object(&file));
            assert!(create_private_storage_file(&directory.join("blocked-file")).is_err());
            assert!(create_private_storage_directory(&directory.join("blocked-dir")).is_err());
            assert!(crate::protect_user_data(b"synthetic state", b"scope").is_none());
            assert!(crate::unprotect_user_data(&encrypted, b"scope").is_none());
            assert!(!directory.join("blocked-file").exists());
            assert!(!directory.join("blocked-dir").exists());
            drop(impersonation);
            assert!(process_user_context());
            assert!(private_storage_object(&file));
            assert_eq!(
                crate::unprotect_user_data(&encrypted, b"scope").unwrap(),
                b"synthetic state"
            );
            drop(file);
            std::fs::remove_dir_all(directory).unwrap();
        })
        .join()
        .unwrap();
    }
}
