//! Descriptor-owned Linux lifetime lease; every operation checks its pathname.

use crate::{Error, Result};
use rustix::{
    fs::{self, FlockOperation, Mode, OFlags},
    io::Errno,
    process::geteuid,
};
use std::{
    fs::{File, Metadata, symlink_metadata},
    os::unix::fs::{FileExt, MetadataExt},
    path::{Component, Path, PathBuf},
};

pub(super) const NAME: &str = "orbit-storage.lock";
const PENDING: &[u8] = &[1];

pub(super) struct Lease {
    file: File,
    directories: Vec<(PathBuf, File)>,
    path: PathBuf,
    pub(super) created: bool,
    pub(super) directory: String,
}

impl Drop for Lease {
    fn drop(&mut self) {
        // Concurrent process spawning can briefly inherit the open description
        // before CLOEXEC closes it. Release our lifetime lock explicitly rather
        // than waiting for every inherited descriptor to close. Pending markers
        // independently fence writes whose service-side outcome is uncertain.
        let _ = fs::flock(&self.file, FlockOperation::Unlock);
    }
}

fn same(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn private(metadata: &Metadata) -> bool {
    metadata.uid() == geteuid().as_raw() && metadata.mode() & 0o077 == 0
}

impl Lease {
    pub(super) fn open(directory: &Path) -> Result<Self> {
        if !directory.is_absolute() {
            return Err(Error::Storage);
        }
        let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let root = File::from(fs::open("/", flags, Mode::empty()).map_err(|_| Error::Storage)?);
        let mut paths = vec![(PathBuf::from("/"), root)];
        let mut normalized = PathBuf::from("/");
        for component in directory.components() {
            match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => {
                    let parent = &paths.last().ok_or(Error::Storage)?.1;
                    let fd = fs::openat(parent, name, flags, Mode::empty())
                        .map_err(|_| Error::Storage)?;
                    normalized.push(name);
                    paths.push((normalized.clone(), File::from(fd)));
                }
                _ => return Err(Error::Storage),
            }
        }
        let directory = normalized.to_str().ok_or(Error::Storage)?.to_owned();
        let parent = &paths.last().ok_or(Error::Storage)?.1;
        let metadata = parent.metadata().map_err(|_| Error::Storage)?;
        if !private(&metadata) || !metadata.is_dir() || metadata.nlink() == 0 {
            return Err(Error::Storage);
        }
        let flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let (fd, created) = match fs::openat(
            parent,
            NAME,
            flags | OFlags::CREATE | OFlags::EXCL,
            Mode::RUSR | Mode::WUSR,
        ) {
            Ok(fd) => (fd, true),
            Err(Errno::EXIST) => (
                fs::openat(parent, NAME, flags, Mode::empty()).map_err(|_| Error::Storage)?,
                false,
            ),
            Err(_) => return Err(Error::Storage),
        };
        let file = File::from(fd);
        let metadata = file.metadata().map_err(|_| Error::Storage)?;
        if !metadata.is_file() || !private(&metadata) || metadata.nlink() != 1 {
            return Err(Error::Storage);
        }
        fs::flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|_| Error::Storage)?;
        let lease = Self {
            file,
            directories: paths,
            path: normalized.join(NAME),
            created,
            directory,
        };
        lease.verify()?;
        if created {
            // Persist the new directory entry as well as the file before any
            // subsequent pending marker can authorize a keyring write.
            lease.file.sync_all().map_err(|_| Error::Storage)?;
            let parent = &lease.directories.last().ok_or(Error::Storage)?.1;
            let directory = File::from(
                fs::openat(
                    parent,
                    ".",
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| Error::Storage)?,
            );
            directory.sync_all().map_err(|_| Error::Storage)?;
            lease.verify()?;
        }
        Ok(lease)
    }

    pub(super) fn verify(&self) -> Result<()> {
        self.verify_marker(&[])
    }

    /// Fence uncertain service-side writes before starting their helper.
    pub(super) fn begin_write(&self) -> Result<()> {
        self.verify()?;
        self.write_pending()?;
        self.verify_marker(PENDING)
    }

    /// Called only after the helper completed successfully and was reaped.
    pub(super) fn complete_write(&self) -> Result<()> {
        self.verify_marker(PENDING)?;
        let result = (|| {
            self.file.set_len(0).map_err(|_| Error::Storage)?;
            self.file.sync_all().map_err(|_| Error::Storage)?;
            self.verify()
        })();
        if result.is_err() {
            // A clearing/flush failure poisons the adapter. Restore the fence
            // where the filesystem still permits writes; never clear on error.
            let _ = self.write_pending();
        }
        result
    }

    fn write_pending(&self) -> Result<()> {
        self.file
            .write_all_at(PENDING, 0)
            .and_then(|()| self.file.sync_all())
            .map_err(|_| Error::Storage)
    }

    fn verify_marker(&self, expected: &[u8]) -> Result<()> {
        for (index, (path, file)) in self.directories.iter().enumerate() {
            let descriptor = file.metadata().map_err(|_| Error::Storage)?;
            let current = symlink_metadata(path).map_err(|_| Error::Storage)?;
            if !descriptor.is_dir()
                || !current.is_dir()
                || !same(&descriptor, &current)
                || descriptor.nlink() == 0
                || current.nlink() == 0
                || (index == self.directories.len() - 1
                    && (!private(&descriptor) || !private(&current)))
            {
                return Err(Error::Storage);
            }
        }
        let descriptor = self.file.metadata().map_err(|_| Error::Storage)?;
        let current = symlink_metadata(&self.path).map_err(|_| Error::Storage)?;
        if !descriptor.is_file()
            || !current.is_file()
            || !same(&descriptor, &current)
            || !private(&descriptor)
            || !private(&current)
            || descriptor.nlink() != 1
            || current.nlink() != 1
            || descriptor.len() != expected.len() as u64
            || current.len() != expected.len() as u64
        {
            return Err(Error::Storage);
        }
        let mut marker = [0; 2];
        let length = self
            .file
            .read_at(&mut marker, 0)
            .map_err(|_| Error::Storage)?;
        if &marker[..length] != expected {
            return Err(Error::Storage);
        }
        Ok(())
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
    };

    pub(in crate::storage::secret_service) struct Directory(
        pub(in crate::storage::secret_service) PathBuf,
    );
    impl Directory {
        pub(in crate::storage::secret_service) fn new() -> Self {
            let mut bytes = [0; 16];
            aws_lc_rs::rand::fill(&mut bytes).unwrap();
            let path = std::env::temp_dir().join(format!(
                "orbit-rust-storage-{:032x}",
                u128::from_be_bytes(bytes)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn private_lease_is_nonblocking_and_releases_without_unlinking() {
        let directory = Directory::new();
        let lease = Lease::open(&directory.0).unwrap();
        assert!(lease.created);
        assert!(Lease::open(&directory.0).is_err());
        assert_eq!(
            fs::metadata(directory.0.join(NAME)).unwrap().mode() & 0o777,
            0o600
        );
        drop(lease);
        assert!(directory.0.join(NAME).exists());
        assert!(!Lease::open(&directory.0).unwrap().created);
    }

    #[test]
    fn drop_unlocks_even_if_a_spawn_temporarily_inherits_the_description() {
        let directory = Directory::new();
        let lease = Lease::open(&directory.0).unwrap();
        // dup shares the same open description as a fork-inherited descriptor.
        let inherited = lease.file.try_clone().unwrap();
        drop(lease);
        let reopened = Lease::open(&directory.0).unwrap();
        assert!(!reopened.created);
        assert!(inherited.metadata().unwrap().is_file());
        assert!(Lease::open(&directory.0).is_err());
    }

    #[test]
    fn pending_write_requires_explicit_completion_and_survives_drop() {
        let directory = Directory::new();
        let path = directory.0.join(NAME);
        let lease = Lease::open(&directory.0).unwrap();
        assert!(lease.complete_write().is_err());
        lease.begin_write().unwrap();
        assert_eq!(fs::read(&path).unwrap(), PENDING);
        assert!(lease.verify().is_err());
        assert!(lease.begin_write().is_err());
        lease.complete_write().unwrap();
        assert!(fs::read(&path).unwrap().is_empty());
        drop(lease);
        let lease = Lease::open(&directory.0).unwrap();
        lease.begin_write().unwrap();
        drop(lease);
        assert!(Lease::open(&directory.0).is_err());
        assert_eq!(fs::read(&path).unwrap(), PENDING);
    }

    #[test]
    fn unknown_markers_and_changed_pending_identity_are_never_reset() {
        for marker in [vec![0], vec![2], vec![1, 0], vec![1; 4096]] {
            let directory = Directory::new();
            let path = directory.0.join(NAME);
            let lease = Lease::open(&directory.0).unwrap();
            lease.begin_write().unwrap();
            fs::write(&path, &marker).unwrap();
            assert!(lease.complete_write().is_err());
            drop(lease);
            assert!(Lease::open(&directory.0).is_err());
            assert_eq!(fs::read(&path).unwrap(), marker);
        }
        let directory = Directory::new();
        let path = directory.0.join(NAME);
        let lease = Lease::open(&directory.0).unwrap();
        lease.begin_write().unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(lease.complete_write().is_err());
        assert_eq!(fs::read(&path).unwrap(), PENDING);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let moved = directory.0.join("moved");
        fs::rename(&path, &moved).unwrap();
        assert!(lease.complete_write().is_err());
        assert_eq!(fs::read(&moved).unwrap(), PENDING);
    }

    #[test]
    fn lease_rejects_links_permissions_nonregular_and_replaced_paths() {
        let directory = Directory::new();
        assert!(Lease::open(Path::new("relative")).is_err());
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(Lease::open(&directory.0).is_err());
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
        let target = directory.0.join(NAME);
        fs::create_dir(&target).unwrap();
        assert!(Lease::open(&directory.0).is_err());
        fs::remove_dir(&target).unwrap();
        symlink("/dev/null", &target).unwrap();
        assert!(Lease::open(&directory.0).is_err());
        fs::remove_file(&target).unwrap();
        let lease = Lease::open(&directory.0).unwrap();
        fs::hard_link(&target, directory.0.join("linked")).unwrap();
        assert!(lease.verify().is_err());
        fs::remove_file(directory.0.join("linked")).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(lease.verify().is_err());
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(&target).unwrap();
        assert!(lease.verify().is_err());
        fs::write(&target, []).unwrap();
        assert!(lease.verify().is_err());
        drop(lease);
        let link = directory.0.join("alias");
        symlink(&directory.0, &link).unwrap();
        assert!(Lease::open(&link).is_err());
    }

    #[test]
    fn directory_normalization_is_stable_and_renamed_parent_is_rejected() {
        let directory = Directory::new();
        let child = directory.0.join("child");
        fs::DirBuilder::new().mode(0o700).create(&child).unwrap();
        let lease = Lease::open(&child.join(".")).unwrap();
        assert_eq!(lease.directory, child.to_str().unwrap());
        assert!(Lease::open(&child.join("..")).is_err());
        fs::rename(&child, directory.0.join("moved")).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&child).unwrap();
        assert!(lease.verify().is_err());
    }
}
