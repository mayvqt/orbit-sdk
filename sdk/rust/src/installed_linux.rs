//! Descriptor-relative private Linux state; a fixed durable marker owns the lease.
use super::*;
use rustix::{
    fs::{self, FlockOperation, Mode, OFlags},
    io::Errno,
    process::geteuid,
};
use std::{
    fs::{File, Metadata, symlink_metadata},
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::Component,
};
const LOCK: &str = "orbit-storage.lock";
const DATA: &str = "orbit-storage.json";
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
pub(super) struct Backend {
    directories: Vec<(PathBuf, File)>,
    lease: File,
    current: Mutex<Option<File>>,
    #[cfg(test)]
    pub(super) fault: WriteFault,
}
fn same(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}
fn private(m: &Metadata) -> bool {
    m.uid() == geteuid().as_raw() && m.mode() & 0o077 == 0
}
fn regular(m: &Metadata) -> bool {
    m.is_file() && private(m) && m.nlink() == 1 && m.mode() & 0o7000 == 0
}
fn local(file: &File) -> Result<()> {
    let fs = fs::fstatfs(file).map_err(|_| Error::Storage)?;
    // Explicit supported local filesystems; reject NFS/CIFS/FUSE and unknown storage.
    if !matches!(
        fs.f_type as u64,
        0xef53
            | 0x58465342
            | 0x9123683e
            | 0x01021994
            | 0x794c7630
            | 0x858458f6
            | 0xf2f52010
            | 0x2fc12fc1
            | 0x3153464a
            | 0x52654973
    ) {
        return Err(Error::Storage);
    }
    Ok(())
}
fn directory(m: &Metadata, leaf: bool) -> bool {
    m.is_dir()
        && m.nlink() > 0
        && if leaf {
            private(m)
        } else {
            (m.uid() == 0 || m.uid() == geteuid().as_raw())
                && (m.mode() & 0o022 == 0 || (m.uid() == 0 && m.mode() & 0o1000 != 0))
        }
}
impl Backend {
    pub(super) fn open(path: &Path) -> Result<(Self, Option<Vec<u8>>)> {
        if !path.is_absolute()
            || path
                .components()
                .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        {
            return Err(Error::Configuration);
        }
        let root =
            File::from(fs::open("/", DIRECTORY_FLAGS, Mode::empty()).map_err(|_| Error::Storage)?);
        let mut directories = vec![(PathBuf::from("/"), root)];
        for component in path.components() {
            let Component::Normal(name) = component else {
                continue;
            };
            let (parent_path, parent) = directories.last().ok_or(Error::Storage)?;
            if !directory(&parent.metadata().map_err(|_| Error::Storage)?, false) {
                return Err(Error::Storage);
            }
            let child = match fs::openat(parent, name, DIRECTORY_FLAGS, Mode::empty()) {
                Ok(child) => child,
                Err(Errno::NOENT) => {
                    fs::mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR)
                        .map_err(|_| Error::Storage)?;
                    parent.sync_all().map_err(|_| Error::Storage)?;
                    fs::openat(parent, name, DIRECTORY_FLAGS, Mode::empty())
                        .map_err(|_| Error::Storage)?
                }
                Err(_) => return Err(Error::Storage),
            };
            let child = File::from(child);
            local(&child)?;
            let child_path = parent_path.join(name);
            directories.push((child_path, child));
        }
        let (_, parent) = directories.last().ok_or(Error::Storage)?;
        if directories.len() < 2
            || !directory(&parent.metadata().map_err(|_| Error::Storage)?, true)
        {
            return Err(Error::Storage);
        }
        let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let (lease, new) = match fs::openat(
            parent,
            LOCK,
            flags | OFlags::CREATE | OFlags::EXCL,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(f) => (File::from(f), true),
            Err(Errno::EXIST) => (
                File::from(
                    fs::openat(parent, LOCK, flags, Mode::empty()).map_err(|_| Error::Storage)?,
                ),
                false,
            ),
            Err(_) => return Err(Error::Storage),
        };
        if !regular(&lease.metadata().map_err(|_| Error::Storage)?) {
            return Err(Error::Storage);
        }
        fs::flock(&lease, FlockOperation::NonBlockingLockExclusive).map_err(|e| {
            if e == Errno::WOULDBLOCK {
                Error::InstallationInUse
            } else {
                Error::Storage
            }
        })?;
        check_write_marker(&lease, &[])?;
        if new {
            lease.sync_all().map_err(|_| Error::Storage)?;
            parent.sync_all().map_err(|_| Error::Storage)?;
        }
        let file = match fs::openat(
            parent,
            DATA,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(file) => Some(File::from(file)),
            Err(Errno::NOENT) => None,
            Err(_) => return Err(Error::CorruptState),
        };
        if file.is_none() != new {
            return Err(Error::CorruptState);
        }
        let bytes = if let Some(file) = &file {
            let metadata = file.metadata().map_err(|_| Error::Storage)?;
            if !regular(&metadata) || metadata.len() == 0 || metadata.len() > MAX_BYTES as u64 {
                return Err(Error::CorruptState);
            }
            let mut bytes = Vec::new();
            file.take(MAX_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| Error::Storage)?;
            if bytes.len() > MAX_BYTES {
                return Err(Error::CorruptState);
            }
            Some(bytes)
        } else {
            None
        };
        let backend = Self {
            directories,
            lease,
            current: Mutex::new(file),
            #[cfg(test)]
            fault: WriteFault::default(),
        };
        backend.verify()?;
        Ok((backend, bytes))
    }
    fn verify(&self) -> Result<()> {
        self.verify_marker(&[])
    }
    fn verify_marker(&self, marker: &[u8]) -> Result<()> {
        for (i, (path, file)) in self.directories.iter().enumerate() {
            let held = file.metadata().map_err(|_| Error::Storage)?;
            let actual = symlink_metadata(path).map_err(|_| Error::Storage)?;
            let leaf = i + 1 == self.directories.len();
            if !same(&held, &actual) || !directory(&held, leaf) || !directory(&actual, leaf) {
                return Err(Error::Storage);
            }
        }
        let (path, _) = self.directories.last().ok_or(Error::Storage)?;
        let held = self.lease.metadata().map_err(|_| Error::Storage)?;
        let actual = symlink_metadata(path.join(LOCK)).map_err(|_| Error::Storage)?;
        if !same(&held, &actual) || !regular(&held) || !regular(&actual) {
            return Err(Error::Storage);
        }
        check_write_marker(&self.lease, marker)?;
        if let Some(file) = self.current.lock().map_err(|_| Error::Storage)?.as_ref() {
            let held = file.metadata().map_err(|_| Error::Storage)?;
            let actual = symlink_metadata(path.join(DATA)).map_err(|_| Error::Storage)?;
            if !same(&held, &actual) || !regular(&held) || !regular(&actual) {
                return Err(Error::Storage);
            }
        }
        Ok(())
    }
    pub(super) fn write(&self, bytes: &[u8]) -> Result<()> {
        self.verify()?;
        write_pending_marker(&self.lease)?;
        self.verify_marker(WRITE_PENDING)?;
        #[cfg(test)]
        self.fault.check(1)?;
        let (_, parent) = self.directories.last().ok_or(Error::Storage)?;
        let name = format!(".orbit-{}", Device::new_installation()?.installation_id);
        let mut file = File::from(
            fs::openat(
                parent,
                &name,
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| Error::Storage)?,
        );
        let result = (|| {
            file.write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_| Error::Storage)?;
            #[cfg(test)]
            self.fault.check(2)?;
            self.verify_marker(WRITE_PENDING)?;
            fs::renameat(parent, &name, parent, DATA).map_err(|_| Error::Storage)?;
            parent.sync_all().map_err(|_| Error::Storage)?;
            *self.current.lock().map_err(|_| Error::Storage)? = Some(file);
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
        if result.is_err() {
            let _ = fs::unlinkat(parent, &name, fs::AtFlags::empty());
        }
        result
    }
}
impl Drop for Backend {
    fn drop(&mut self) {
        let _ = fs::flock(&self.lease, FlockOperation::Unlock);
    }
}
