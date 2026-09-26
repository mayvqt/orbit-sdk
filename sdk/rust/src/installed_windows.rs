//! DPAPI current-user state with protected owner/DACL checks and pinned ancestors.
use super::*;
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{ErrorKind, Read, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Prefix},
};
const LOCK: &str = "orbit-storage.lock";
const DATA: &str = orbit_sdk_native::STORAGE_CIPHERTEXT_FILE;
const ENTROPY: &[u8] = b"orbit.installed-client.format-2";
const MAX_CIPHERTEXT: usize = 96 * 1024;
const REPARSE: u32 = 0x400;
const OPEN_REPARSE: u32 = 0x00200000;
const BACKUP: u32 = 0x02000000;
pub(super) struct Backend {
    path: PathBuf,
    directories: Vec<File>,
    lease: File,
    #[cfg(test)]
    pub(super) fault: WriteFault,
}
fn regular(m: &Metadata) -> bool {
    m.is_file() && m.file_attributes() & REPARSE == 0
}
fn safe_file(file: &File) -> bool {
    file.metadata().is_ok_and(|m| regular(&m))
        && orbit_sdk_native::private_storage_object(file)
        && orbit_sdk_native::storage_file_single_link(file)
}
fn directory(file: &File) -> bool {
    file.metadata()
        .is_ok_and(|m| m.is_dir() && m.file_attributes() & REPARSE == 0)
}
impl Backend {
    pub(super) fn open(path: &Path) -> Result<(Self, Option<Vec<u8>>)> {
        if !orbit_sdk_native::process_user_context() {
            return Err(Error::Storage);
        }
        let mut components = path.components();
        let Some(Component::Prefix(prefix)) = components.next() else {
            return Err(Error::Configuration);
        };
        let Prefix::Disk(drive) = prefix.kind() else {
            return Err(Error::Configuration);
        };
        if components.next() != Some(Component::RootDir)
            || !orbit_sdk_native::is_local_storage_drive(drive)
        {
            return Err(Error::Configuration);
        }
        let mut current = PathBuf::from(prefix.as_os_str());
        current.push("\\");
        let mut paths = vec![current.clone()];
        for component in components {
            let Component::Normal(name) = component else {
                return Err(Error::Configuration);
            };
            use std::os::windows::ffi::OsStrExt;
            if name.encode_wide().any(|u| u == 0 || u == b':' as u16) {
                return Err(Error::Configuration);
            }
            current.push(name);
            paths.push(current.clone());
        }
        if paths.len() < 2 {
            return Err(Error::Configuration);
        }
        let mut directories = Vec::new();
        for (index, path) in paths.iter().enumerate() {
            let open = || {
                OpenOptions::new()
                    .read(true)
                    .share_mode(3)
                    .custom_flags(OPEN_REPARSE | BACKUP)
                    .open(path)
            };
            let file = match open() {
                Ok(f) => f,
                Err(e) if e.kind() == ErrorKind::NotFound => {
                    orbit_sdk_native::create_private_storage_directory(path)
                        .map_err(|_| Error::Storage)?;
                    open().map_err(|_| Error::Storage)?
                }
                Err(_) => return Err(Error::Storage),
            };
            if !directory(&file)
                || (index + 1 == paths.len() && !orbit_sdk_native::private_storage_object(&file))
            {
                return Err(Error::Storage);
            }
            directories.push(file);
        }
        let (lease, new) = match orbit_sdk_native::create_private_storage_file(&path.join(LOCK)) {
            Ok(f) => (f, true),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .share_mode(0)
                    .custom_flags(OPEN_REPARSE)
                    .open(path.join(LOCK))
                    .map_err(|e| {
                        if e.raw_os_error() == Some(32) {
                            Error::InstallationInUse
                        } else {
                            Error::Storage
                        }
                    })?;
                (file, false)
            }
            Err(e) if e.raw_os_error() == Some(32) => return Err(Error::InstallationInUse),
            Err(_) => return Err(Error::Storage),
        };
        if !safe_file(&lease) {
            return Err(Error::Storage);
        }
        check_write_marker(&lease, &[])?;
        if new {
            lease.sync_all().map_err(|_| Error::Storage)?;
        }
        let backend = Self {
            path: path.into(),
            directories,
            lease,
            #[cfg(test)]
            fault: WriteFault::default(),
        };
        backend.verify()?;
        let bytes = backend.read()?;
        if bytes.is_none() != new {
            return Err(Error::CorruptState);
        }
        Ok((backend, bytes))
    }
    fn verify(&self) -> Result<()> {
        self.verify_marker(&[])
    }
    fn verify_marker(&self, marker: &[u8]) -> Result<()> {
        if !orbit_sdk_native::process_user_context()
            || !self.directories.iter().all(directory)
            || !self
                .directories
                .last()
                .is_some_and(orbit_sdk_native::private_storage_object)
            || !safe_file(&self.lease)
        {
            return Err(Error::Storage);
        }
        check_write_marker(&self.lease, marker)
    }
    fn read(&self) -> Result<Option<Vec<u8>>> {
        if !orbit_sdk_native::process_user_context() {
            return Err(Error::Storage);
        }
        let file = match OpenOptions::new()
            .read(true)
            .share_mode(0)
            .custom_flags(OPEN_REPARSE)
            .open(self.path.join(DATA))
        {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(Error::CorruptState),
        };
        let size = file.metadata().map_err(|_| Error::Storage)?.len();
        if !safe_file(&file) || size == 0 || size > MAX_CIPHERTEXT as u64 {
            return Err(Error::CorruptState);
        }
        let mut bytes = Vec::new();
        file.take(MAX_CIPHERTEXT as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Storage)?;
        if bytes.len() > MAX_CIPHERTEXT {
            return Err(Error::CorruptState);
        }
        orbit_sdk_native::unprotect_user_data(&bytes, ENTROPY)
            .map(Some)
            .ok_or(Error::CorruptState)
    }
    pub(super) fn write(&self, bytes: &[u8]) -> Result<()> {
        self.verify()?;
        let _ = self.read()?;
        write_pending_marker(&self.lease)?;
        self.verify_marker(WRITE_PENDING)?;
        #[cfg(test)]
        self.fault.check(1)?;
        let ciphertext =
            orbit_sdk_native::protect_user_data(bytes, ENTROPY).ok_or(Error::Storage)?;
        let name = self.path.join(format!(
            "orbit-{}.tmp",
            Device::new_installation()?.installation_id
        ));
        let mut file =
            orbit_sdk_native::create_private_storage_file(&name).map_err(|_| Error::Storage)?;
        let result = (|| {
            file.write_all(&ciphertext)
                .and_then(|()| file.sync_all())
                .map_err(|_| Error::Storage)?;
            #[cfg(test)]
            self.fault.check(2)?;
            self.verify_marker(WRITE_PENDING)?;
            if !safe_file(&file)
                || !orbit_sdk_native::replace_storage_ciphertext(
                    &file,
                    self.directories.last().ok_or(Error::Storage)?,
                )
            {
                return Err(Error::Storage);
            }
            file.sync_all().map_err(|_| Error::Storage)?;
            self.verify_marker(WRITE_PENDING)?;
            #[cfg(test)]
            self.fault.check(3)?;
            let completed = (|| {
                self.lease.set_len(0).map_err(|_| Error::Storage)?;
                #[cfg(test)]
                self.fault.check(4)?;
                self.lease.sync_all().map_err(|_| Error::Storage)?;
                self.verify()
            })();
            if completed.is_err() {
                let _ = write_pending_marker(&self.lease);
            }
            completed
        })();
        drop(file);
        if result.is_err() {
            let _ = fs::remove_file(name);
        }
        result
    }
}
