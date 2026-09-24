//! Narrow Windows handle operations for private local persistent storage.

use std::{fs::File, os::windows::fs::MetadataExt, os::windows::io::AsRawHandle};
use windows_sys::Win32::{
    Foundation::HANDLE,
    Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_RENAME_INFO, FILE_RENAME_INFO_0, FileRenameInfo,
        GetDriveTypeW, GetFinalPathNameByHandleW, SetFileInformationByHandle,
    },
    System::WindowsProgramming::{DRIVE_FIXED, DRIVE_RAMDISK, DRIVE_REMOVABLE},
};

pub const STORAGE_CIPHERTEXT_FILE: &str = "orbit-storage.bin";

#[repr(C)]
struct RenameInformation {
    replacement: FILE_RENAME_INFO_0,
    directory: HANDLE,
    name_bytes: u32,
    name: [u16; 1],
}

// Retain native pointer alignment for the API's variable-length UTF-16 tail.
const _: () = {
    assert!(std::mem::offset_of!(RenameInformation, replacement) == 0);
    assert!(std::mem::align_of::<usize>() >= std::mem::align_of::<RenameInformation>());
    assert!(
        std::mem::offset_of!(RenameInformation, directory)
            == std::mem::offset_of!(FILE_RENAME_INFO, RootDirectory)
    );
    assert!(
        std::mem::offset_of!(RenameInformation, name_bytes)
            == std::mem::offset_of!(FILE_RENAME_INFO, FileNameLength)
    );
    assert!(
        std::mem::offset_of!(RenameInformation, name)
            == std::mem::offset_of!(FILE_RENAME_INFO, FileName)
    );
};

/// Replace the fixed ciphertext leaf through borrowed, already-open handles.
/// The source must retain exclusive sharing and DELETE access; the directory
/// must remain pinned against deletion by its owner for the whole operation.
pub fn replace_storage_ciphertext(source: &File, directory: &File) -> bool {
    let Ok(source_metadata) = source.metadata() else {
        return false;
    };
    let Ok(directory_metadata) = directory.metadata() else {
        return false;
    };
    if !source_metadata.is_file()
        || !directory_metadata.is_dir()
        || (source_metadata.file_attributes() | directory_metadata.file_attributes())
            & FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    {
        return false;
    }
    const MAX_PATH_UNITS: usize = 32768;
    let mut path = vec![0_u16; MAX_PATH_UNITS];
    // SAFETY: The borrowed directory and initialized writable UTF-16 buffer stay
    // alive for the synchronous call. Zero flags request a normalized DOS path.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            directory.as_raw_handle(),
            path.as_mut_ptr(),
            MAX_PATH_UNITS as u32,
            0,
        )
    } as usize;
    if length == 0 || length >= MAX_PATH_UNITS {
        return false;
    }
    path.truncate(length);
    if path.last() != Some(&(b'\\' as u16)) {
        path.push(b'\\' as u16);
    }
    path.extend(STORAGE_CIPHERTEXT_FILE.encode_utf16());
    path.push(0);
    if path.len() > MAX_PATH_UNITS {
        return false;
    }
    let offset = std::mem::offset_of!(RenameInformation, name);
    let bytes = offset + path.len() * size_of::<u16>();
    let mut buffer = vec![0_usize; bytes.div_ceil(size_of::<usize>())];
    // SAFETY: Both borrowed Files keep their handles alive during this synchronous
    // call. The zeroed, pointer-aligned allocation holds the checked header plus
    // its bounded UTF-16 tail. The full path comes from the pinned directory;
    // all ancestor pins remain held by the adapter. Native Windows rejects the
    // relative-name/non-null RootDirectory form with ERROR_INVALID_PARAMETER.
    // Only the destination is named: the source pathname is never reopened.
    unsafe {
        let information = buffer.as_mut_ptr().cast::<RenameInformation>();
        (*information).replacement = FILE_RENAME_INFO_0 { Flags: 1 };
        (*information).directory = std::ptr::null_mut();
        (*information).name_bytes = ((path.len() - 1) * size_of::<u16>()) as u32;
        std::ptr::copy_nonoverlapping(
            path.as_ptr(),
            buffer.as_mut_ptr().cast::<u8>().add(offset).cast::<u16>(),
            path.len(),
        );
        SetFileInformationByHandle(
            source.as_raw_handle(),
            FileRenameInfo,
            buffer.as_ptr().cast(),
            bytes as u32,
        ) != 0
    }
}

/// Reject unavailable and network-mapped drives as well as non-drive inputs.
pub fn is_local_storage_drive(letter: u8) -> bool {
    if !letter.is_ascii_alphabetic() {
        return false;
    }
    let root = [letter as u16, b':' as u16, b'\\' as u16, 0];
    // SAFETY: root is a live, initialized, NUL-terminated UTF-16 drive root.
    // The synchronous query only reads it and never retains the pointer.
    matches!(
        unsafe { GetDriveTypeW(root.as_ptr()) },
        DRIVE_FIXED | DRIVE_RAMDISK | DRIVE_REMOVABLE
    )
}
