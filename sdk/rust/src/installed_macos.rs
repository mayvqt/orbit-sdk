//! Descriptor-relative private macOS state with required full-sync durability.
use super::*;
use rustix::{
    fs::{self, AtFlags, FileType, FlockOperation, Mode, OFlags, Stat},
    io::Errno,
    process::geteuid,
};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path},
};

const LOCK: &str = "orbit-storage.lock";
const DATA: &str = "orbit-storage.json";
// Darwin sys/mount.h defines MNT_LOCAL as 0x00001000. Do not reuse Linux
// filesystem magic numbers or a Linux stat layout on this target.
const MNT_LOCAL: u32 = 0x0000_1000;
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

fn same(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev && a.st_ino == b.st_ino
}

fn local(file: &File) -> Result<()> {
    let stat = fs::fstatfs(file).map_err(|_| Error::Storage)?;
    if stat.f_flags as u32 & MNT_LOCAL == 0 {
        return Err(Error::Storage);
    }
    Ok(())
}

fn directory(stat: &Stat, leaf: bool) -> bool {
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory || stat.st_nlink == 0 {
        return false;
    }
    let uid = stat.st_uid as u32;
    let mode = stat.st_mode as u32 & 0o7777;
    if leaf {
        uid == geteuid().as_raw() && mode & 0o077 == 0
    } else {
        (uid == 0 || uid == geteuid().as_raw())
            && (mode & 0o022 == 0 || uid == 0 && mode & 0o1000 != 0)
    }
}

fn regular(stat: &Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
        && stat.st_uid as u32 == geteuid().as_raw()
        && stat.st_mode as u32 & 0o7777 == 0o600
        && stat.st_nlink == 1
}

fn status(file: &File) -> Result<Stat> {
    fs::fstat(file).map_err(|_| Error::Storage)
}

fn status_at<P: rustix::path::Arg>(parent: &File, name: P) -> Result<Stat> {
    fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| Error::Storage)
}

fn write_pending(file: &File) -> Result<()> {
    let mut file = file;
    file.seek(SeekFrom::Start(0))
        .and_then(|()| file.write_all(WRITE_PENDING))
        .map_err(|_| Error::Storage)?;
    orbit_sdk_native::full_fsync(file).map_err(|_| Error::Storage)
}

impl Backend {
    pub(super) fn open(path: &Path) -> Result<(Self, Option<Vec<u8>>)> {
        if !path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
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
            if !directory(&status(parent)?, false) {
                return Err(Error::Storage);
            }
            local(parent)?;
            let (child, created) = match fs::openat(parent, name, DIRECTORY_FLAGS, Mode::empty()) {
                Ok(child) => (File::from(child), false),
                Err(Errno::NOENT) => {
                    fs::mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR)
                        .map_err(|_| Error::Storage)?;
                    let child = File::from(
                        fs::openat(parent, name, DIRECTORY_FLAGS, Mode::empty())
                            .map_err(|_| Error::Storage)?,
                    );
                    (child, true)
                }
                Err(_) => return Err(Error::Storage),
            };
            if created {
                child.sync_all().map_err(|_| Error::Storage)?;
                parent.sync_all().map_err(|_| Error::Storage)?;
            }
            let child_stat = status(&child)?;
            let named = status_at(parent, name)?;
            if !same(&child_stat, &named)
                || !directory(&child_stat, false)
                || !directory(&named, false)
            {
                return Err(Error::Storage);
            }
            local(&child)?;
            let child_path = parent_path.join(name);
            directories.push((child_path, child));
        }
        if directories.len() < 2 {
            return Err(Error::Configuration);
        }
        let parent = &directories.last().ok_or(Error::Storage)?.1;
        if !directory(&status(parent)?, true) {
            return Err(Error::Storage);
        }
        let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let (lease, created) = match fs::openat(
            parent,
            LOCK,
            flags | OFlags::CREATE | OFlags::EXCL,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(file) => (File::from(file), true),
            Err(Errno::EXIST) => (
                File::from(
                    fs::openat(parent, LOCK, flags, Mode::empty()).map_err(|_| Error::Storage)?,
                ),
                false,
            ),
            Err(_) => return Err(Error::Storage),
        };
        let lease_stat = status(&lease)?;
        if !regular(&lease_stat) {
            return Err(Error::Storage);
        }
        fs::flock(&lease, FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            if error == Errno::WOULDBLOCK {
                Error::InstallationInUse
            } else {
                Error::Storage
            }
        })?;
        check_write_marker(&lease, &[])?;
        if created {
            orbit_sdk_native::full_fsync(&lease).map_err(|_| Error::Storage)?;
            parent.sync_all().map_err(|_| Error::Storage)?;
        }
        let current = match fs::openat(
            parent,
            DATA,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(file) => Some(File::from(file)),
            Err(Errno::NOENT) => None,
            Err(_) => return Err(Error::CorruptState),
        };
        if current.is_none() != created {
            return Err(Error::CorruptState);
        }
        let bytes = if let Some(file) = &current {
            let held = status(file)?;
            let named = status_at(parent, DATA)?;
            if !same(&held, &named)
                || !regular(&held)
                || !regular(&named)
                || held.st_size <= 0
                || held.st_size as u64 > MAX_BYTES as u64
            {
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
            current: Mutex::new(current),
            #[cfg(test)]
            fault: WriteFault::default(),
        };
        backend.verify()?;
        Ok((backend, bytes))
    }

    pub(super) fn verify(&self) -> Result<()> {
        self.verify_marker(&[])
    }

    fn verify_marker(&self, marker: &[u8]) -> Result<()> {
        for (index, (path, file)) in self.directories.iter().enumerate() {
            let held = status(file)?;
            let actual = if index == 0 {
                held
            } else {
                let (parent_path, parent) = &self.directories[index - 1];
                if path.parent() != Some(parent_path.as_path()) {
                    return Err(Error::Storage);
                }
                status_at(parent, path.file_name().ok_or(Error::Storage)?)?
            };
            let leaf = index + 1 == self.directories.len();
            if !same(&held, &actual) || !directory(&held, leaf) || !directory(&actual, leaf) {
                return Err(Error::Storage);
            }
            local(file)?;
        }
        let (_, parent) = self.directories.last().ok_or(Error::Storage)?;
        let held = status(&self.lease)?;
        let actual = status_at(parent, Path::new(LOCK))?;
        if !same(&held, &actual) || !regular(&held) || !regular(&actual) {
            return Err(Error::Storage);
        }
        check_write_marker(&self.lease, marker)?;
        if let Some(file) = self.current.lock().map_err(|_| Error::Storage)?.as_ref() {
            let held = status(file)?;
            let actual = status_at(parent, Path::new(DATA))?;
            if !same(&held, &actual) || !regular(&held) || !regular(&actual) {
                return Err(Error::Storage);
            }
        } else {
            match fs::statat(parent, DATA, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(_) => return Err(Error::Storage),
                Err(Errno::NOENT) => {}
                Err(_) => return Err(Error::Storage),
            }
        }
        Ok(())
    }

    pub(super) fn write(&self, bytes: &[u8]) -> Result<()> {
        self.verify()?;
        write_pending(&self.lease)?;
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
            file.write_all(bytes).map_err(|_| Error::Storage)?;
            orbit_sdk_native::full_fsync(&file).map_err(|_| Error::Storage)?;
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
                orbit_sdk_native::full_fsync(&self.lease).map_err(|_| Error::Storage)?;
                self.verify()
            })();
            if completed.is_err() {
                write_pending(&self.lease)?;
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
