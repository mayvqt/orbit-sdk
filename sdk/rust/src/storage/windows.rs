use crate::{Config, Device, Error, Result, Storage, StoredCredential};
use std::{fmt, path::Path};

/// Current-user Windows DPAPI storage for one Orbit scope and installation.
///
/// The caller must supply an existing dedicated absolute local directory under
/// its private Windows profile. Share this object through `Arc` within a process;
/// a second opener fails promptly. Drop releases the lifetime lease. Corrupt,
/// incompatible or deleted state requires deliberate host recovery, never reset.
/// Only activation credentials are retained; sessions and signed grants are not.
pub struct WindowsStorage {
    #[cfg(target_os = "windows")]
    state: std::sync::Mutex<persistence::State>,
}

impl fmt::Debug for WindowsStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsStorage { [redacted] }")
    }
}

impl WindowsStorage {
    pub fn open(directory: impl AsRef<Path>, config: &Config, device: &Device) -> Result<Self> {
        #[cfg(target_os = "windows")]
        {
            Ok(Self {
                state: std::sync::Mutex::new(persistence::State::open(
                    directory.as_ref(),
                    config,
                    device,
                )?),
            })
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (directory, config, device);
            Err(Error::Storage)
        }
    }
}

#[cfg(not(target_os = "windows"))]
impl Storage for WindowsStorage {
    fn version(&self) -> Result<u64> {
        Err(Error::Storage)
    }
    fn load(&self) -> Result<(u64, Option<StoredCredential>)> {
        Err(Error::Storage)
    }
    fn save(&self, _: u64, _: StoredCredential) -> Result<()> {
        Err(Error::Storage)
    }
    fn invalidate(&self) -> Result<u64> {
        Err(Error::Storage)
    }
}

#[cfg(target_os = "windows")]
impl Storage for WindowsStorage {
    fn version(&self) -> Result<u64> {
        let state = self.state.lock().map_err(|_| Error::Storage)?;
        state.check()?;
        Ok(state.generation)
    }
    fn load(&self) -> Result<(u64, Option<StoredCredential>)> {
        let state = self.state.lock().map_err(|_| Error::Storage)?;
        state.check()?;
        Ok((state.generation, state.credential.clone()))
    }
    fn save(&self, version: u64, credential: StoredCredential) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| Error::Storage)?;
        state.check()?;
        if version != state.generation {
            return Err(Error::StaleResponse);
        }
        state.commit(version, Some(credential))
    }
    fn invalidate(&self) -> Result<u64> {
        let mut state = self.state.lock().map_err(|_| Error::Storage)?;
        state.check()?;
        if state.generation == super::codec::MAX_GENERATION {
            state.poison();
            return Err(Error::Storage);
        }
        let next = state.generation + 1;
        state.commit(next, None)?;
        Ok(next)
    }
}

#[cfg(target_os = "windows")]
mod persistence {
    use super::*;
    use crate::storage::codec;
    use std::{
        fs::{self, File, Metadata, OpenOptions},
        io::{ErrorKind, Read, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, PathBuf, Prefix},
    };

    pub(super) const LOCK_FILE: &str = "orbit-storage.lock";
    pub(super) const DATA_FILE: &str = orbit_sdk_native::STORAGE_CIPHERTEXT_FILE;
    pub(super) const MAX_CIPHERTEXT: usize = 64 * 1024;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_SHARE_READ_WRITE: u32 = 3;
    const GENERIC_WRITE_DELETE: u32 = 0x4001_0000;

    pub(super) struct State {
        pub(super) generation: u64,
        pub(super) credential: Option<StoredCredential>,
        poisoned: bool,
        config: Config,
        device: Device,
        entropy: [u8; 32],
        directory: PathBuf,
        // The lease uses no sharing and is independent of ciphertext replacement.
        // Directory handles deny delete sharing, pinning each checked ancestor.
        _lease: File,
        directories: Vec<File>,
    }

    impl State {
        pub(super) fn open(directory: &Path, config: &Config, device: &Device) -> Result<Self> {
            let entropy = codec::entropy(config, device)?;
            // Reject an unencodable initial scope before creating the lease.
            codec::encode(config, device, 0, None)?;
            let directories = pin_directories(directory)?;
            let (lease, new_lease) = lease(&directory.join(LOCK_FILE))?;
            let mut state = Self {
                generation: 0,
                credential: None,
                poisoned: false,
                config: config.clone(),
                device: device.clone(),
                entropy,
                directory: directory.to_path_buf(),
                _lease: lease,
                directories,
            };
            state.check()?;
            match read_ciphertext(&directory.join(DATA_FILE))? {
                Some(ciphertext) => {
                    let plaintext = orbit_sdk_native::unprotect_user_data(&ciphertext, &entropy)
                        .ok_or(Error::Storage)?;
                    let (generation, credential) = codec::decode(config, device, &plaintext)?;
                    state.generation = generation;
                    state.credential = credential;
                }
                None if new_lease => state.commit(0, None)?,
                // A lost state file or interrupted initialization never rolls
                // generation back to zero just because the file is absent.
                None => return Err(Error::Storage),
            }
            Ok(state)
        }

        pub(super) fn check(&self) -> Result<()> {
            if self.poisoned || self.directories.is_empty() {
                return Err(Error::Storage);
            }
            for directory in &self.directories {
                checked_directory(directory)?;
            }
            Ok(())
        }

        pub(super) fn poison(&mut self) {
            self.poisoned = true;
            self.credential = None;
        }

        pub(super) fn commit(
            &mut self,
            generation: u64,
            credential: Option<StoredCredential>,
        ) -> Result<()> {
            let result = (|| {
                self.check()?;
                let plaintext =
                    codec::encode(&self.config, &self.device, generation, credential.as_ref())?;
                let ciphertext = orbit_sdk_native::protect_user_data(&plaintext, &self.entropy)
                    .ok_or(Error::Storage)?;
                if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT {
                    return Err(Error::Storage);
                }
                self.check()?;
                replace_ciphertext(
                    &self.directory,
                    self.directories.last().ok_or(Error::Storage)?,
                    &ciphertext,
                )
            })();
            if result.is_err() {
                self.poison();
                return Err(Error::Storage);
            }
            self.generation = generation;
            self.credential = credential;
            Ok(())
        }
    }

    fn regular(metadata: &Metadata) -> bool {
        metadata.is_file() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
    }

    fn checked_directory(directory: &File) -> Result<()> {
        let metadata = directory.metadata().map_err(|_| Error::Storage)?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(Error::Storage);
        }
        Ok(())
    }

    fn pin_directories(directory: &Path) -> Result<Vec<File>> {
        let mut components = directory.components();
        let Some(Component::Prefix(prefix)) = components.next() else {
            return Err(Error::Storage);
        };
        let Prefix::Disk(drive) = prefix.kind() else {
            return Err(Error::Storage);
        };
        if components.next() != Some(Component::RootDir)
            || !orbit_sdk_native::is_local_storage_drive(drive)
        {
            return Err(Error::Storage);
        }
        let mut current = PathBuf::from(prefix.as_os_str());
        current.push(Path::new("\\"));
        let mut paths = vec![current.clone()];
        for component in components {
            let Component::Normal(name) = component else {
                return Err(Error::Storage);
            };
            use std::os::windows::ffi::OsStrExt;
            if name
                .encode_wide()
                .any(|unit| unit == 0 || unit == b':' as u16)
            {
                return Err(Error::Storage);
            }
            current.push(name);
            paths.push(current.clone());
        }
        let mut handles = Vec::with_capacity(paths.len());
        for path in paths {
            let handle = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ_WRITE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)
                .map_err(|_| Error::Storage)?;
            checked_directory(&handle)?;
            handles.push(handle);
        }
        Ok(handles)
    }

    fn lease(path: &Path) -> Result<(File, bool)> {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let (file, new) = match options.create_new(true).open(path) {
            Ok(file) => (file, true),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => (
                options
                    .create_new(false)
                    .open(path)
                    .map_err(|_| Error::Storage)?,
                false,
            ),
            Err(_) => return Err(Error::Storage),
        };
        if !regular(&file.metadata().map_err(|_| Error::Storage)?) {
            return Err(Error::Storage);
        }
        Ok((file, new))
    }

    fn read_ciphertext(path: &Path) -> Result<Option<Vec<u8>>> {
        let file = match OpenOptions::new()
            .read(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(Error::Storage),
        };
        let metadata = file.metadata().map_err(|_| Error::Storage)?;
        if !regular(&metadata) || metadata.len() == 0 || metadata.len() > MAX_CIPHERTEXT as u64 {
            return Err(Error::Storage);
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_CIPHERTEXT as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Storage)?;
        if bytes.len() as u64 != metadata.len() {
            return Err(Error::Storage);
        }
        Ok(Some(bytes))
    }

    struct Temporary {
        path: Option<PathBuf>,
        file: Option<File>,
    }

    impl Drop for Temporary {
        fn drop(&mut self) {
            drop(self.file.take());
            if let Some(path) = &self.path {
                let _ = fs::remove_file(path);
            }
        }
    }

    fn replace_ciphertext(directory: &Path, pinned: &File, bytes: &[u8]) -> Result<()> {
        checked_directory(pinned)?;
        let destination = directory.join(DATA_FILE);
        match fs::symlink_metadata(&destination) {
            Ok(metadata) if regular(&metadata) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            _ => return Err(Error::Storage),
        }
        let mut random = [0_u8; 16];
        aws_lc_rs::rand::fill(&mut random).map_err(|_| Error::Storage)?;
        let suffix = u128::from_be_bytes(random);
        let path = directory.join(format!("orbit-storage-{suffix:032x}.tmp"));
        let file = OpenOptions::new()
            .write(true)
            .access_mode(GENERIC_WRITE_DELETE)
            .create_new(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
            .map_err(|_| Error::Storage)?;
        let mut temporary = Temporary {
            path: Some(path),
            file: Some(file),
        };
        let file = temporary.file.as_mut().ok_or(Error::Storage)?;
        file.write_all(bytes).map_err(|_| Error::Storage)?;
        file.sync_all().map_err(|_| Error::Storage)?;
        if !orbit_sdk_native::replace_storage_ciphertext(file, pinned) {
            return Err(Error::Storage);
        }
        // The source handle still owns the replaced object exclusively. Never
        // remove a newly substituted old temporary pathname after replacement.
        temporary.path = None;
        file.sync_all().map_err(|_| Error::Storage)
    }
}

#[cfg(all(test, not(target_os = "windows")))]
mod unsupported_tests {
    use super::*;

    #[test]
    fn unsupported_windows_storage_fails_closed() {
        let (config, device) = crate::storage::codec::tests::scope();
        assert!(matches!(
            WindowsStorage::open("/tmp", &config, &device),
            Err(Error::Storage)
        ));
    }
}

#[cfg(all(test, target_os = "windows"))]
mod native_tests {
    use super::*;
    use crate::storage::codec::{
        self,
        tests::{credential, scope},
    };
    use persistence::{DATA_FILE, LOCK_FILE, MAX_CIPHERTEXT};
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::windows::fs::OpenOptionsExt,
        path::PathBuf,
        process::Command,
        sync::{Arc, Barrier},
    };

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let profile = std::env::var_os("LOCALAPPDATA").expect("Windows user profile required");
            let mut random = [0; 16];
            aws_lc_rs::rand::fill(&mut random).unwrap();
            let path = PathBuf::from(profile).join(format!(
                "orbit-storage-test-{:032x}",
                u128::from_be_bytes(random)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("Remove synthetic storage fixture");
        }
    }

    fn open(directory: &Directory) -> WindowsStorage {
        let (config, device) = scope();
        WindowsStorage::open(&directory.0, &config, &device).unwrap()
    }

    fn child(directory: &Directory, mode: &str) {
        let result = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "storage::windows::native_tests::storage_process_probe",
                "--ignored",
            ])
            .env("ORBIT_STORAGE_TEST_DIRECTORY", &directory.0)
            .env("ORBIT_STORAGE_TEST_MODE", mode)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "Synthetic storage subprocess failed"
        );
    }

    #[test]
    fn native_storage_replacement_retains_exclusive_source_handle() {
        let directory = Directory::new();
        let destination = directory.0.join(DATA_FILE);
        let temporary = directory.0.join("replacement.tmp");
        fs::write(&destination, b"synthetic old ciphertext").unwrap();
        let pinned = OpenOptions::new()
            .read(true)
            .share_mode(3)
            .custom_flags(0x0200_0000 | 0x0020_0000)
            .open(&directory.0)
            .unwrap();
        let mut source = OpenOptions::new()
            .write(true)
            .access_mode(0x4001_0000)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .create_new(true)
            .open(&temporary)
            .unwrap();
        source.write_all(b"synthetic new ciphertext").unwrap();
        source.sync_all().unwrap();

        // Incorrect handle types fail without touching either pathname.
        assert!(!orbit_sdk_native::replace_storage_ciphertext(
            &source, &source
        ));
        assert!(!orbit_sdk_native::replace_storage_ciphertext(
            &pinned, &pinned
        ));
        assert!(temporary.exists());
        assert_eq!(fs::read(&destination).unwrap(), b"synthetic old ciphertext");
        // A competing writer cannot replace the source before it is installed.
        assert!(fs::rename(&temporary, directory.0.join("substitution.tmp")).is_err());
        assert!(fs::remove_file(&temporary).is_err());
        assert!(OpenOptions::new().write(true).open(&temporary).is_err());
        assert!(fs::rename(&directory.0, directory.0.with_extension("moved")).is_err());

        assert!(orbit_sdk_native::replace_storage_ciphertext(
            &source, &pinned
        ));
        source.sync_all().unwrap();
        assert!(!temporary.exists());
        // Successful replacement retains the same exclusive handle, including
        // through the post-replacement flush; no reopened source path is needed.
        assert!(fs::read(&destination).is_err());
        assert!(fs::remove_file(&destination).is_err());
        drop(source);
        assert_eq!(fs::read(&destination).unwrap(), b"synthetic new ciphertext");
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
    }

    #[test]
    #[ignore = "invoked by the native persistence test with its synthetic directory"]
    fn storage_process_probe() {
        let directory = std::env::var_os("ORBIT_STORAGE_TEST_DIRECTORY")
            .expect("Synthetic storage subprocess directory required");
        let mode = std::env::var("ORBIT_STORAGE_TEST_MODE")
            .expect("Synthetic storage subprocess mode required");
        let (config, device) = scope();
        match mode.as_str() {
            "blocked" => assert!(matches!(
                WindowsStorage::open(directory, &config, &device),
                Err(Error::Storage)
            )),
            "load-invalidate" => {
                let storage = WindowsStorage::open(directory, &config, &device).unwrap();
                let (version, stored) = storage.load().unwrap();
                assert_eq!(version, 0);
                assert!(stored.unwrap().credential == credential().credential);
                assert_eq!(storage.invalidate().unwrap(), 1);
            }
            _ => panic!("Unknown synthetic storage subprocess mode"),
        }
    }

    #[test]
    fn native_storage_restart_tombstone_stale_write_and_lifetime_lease() {
        let directory = Directory::new();
        let storage = open(&directory);
        assert_eq!(storage.version().unwrap(), 0);
        assert!(storage.load().unwrap().1.is_none());
        assert!(directory.0.join(DATA_FILE).is_file());
        child(&directory, "blocked");
        storage.save(0, credential()).unwrap();
        assert_eq!(storage.version().unwrap(), 0);
        child(&directory, "blocked");
        let disk = fs::read(directory.0.join(DATA_FILE)).unwrap();
        assert!(
            !disk
                .windows(43)
                .any(|part| part == credential().credential.as_bytes())
        );
        assert!(
            !disk
                .windows(b"synthetic_activation".len())
                .any(|part| part == b"synthetic_activation")
        );
        assert_eq!(format!("{storage:?}"), "WindowsStorage { [redacted] }");
        assert!(WindowsStorage::open(&directory.0, &scope().0, &scope().1).is_err());
        drop(storage);
        assert!(directory.0.join(LOCK_FILE).is_file());
        child(&directory, "load-invalidate");
        let storage = open(&directory);
        assert_eq!(storage.version().unwrap(), 1);
        assert!(storage.load().unwrap().1.is_none());
        assert!(matches!(
            storage.save(0, credential()),
            Err(Error::StaleResponse)
        ));
        assert_eq!(storage.version().unwrap(), 1);
        storage.save(1, credential()).unwrap();
        assert_eq!(storage.invalidate().unwrap(), 2);
        drop(storage);
        let storage = open(&directory);
        assert_eq!(storage.version().unwrap(), 2);
        assert!(storage.load().unwrap().1.is_none());
    }

    #[test]
    fn native_storage_rejects_scope_corruption_size_and_deleted_state() {
        let directory = Directory::new();
        let storage = open(&directory);
        storage.save(0, credential()).unwrap();
        drop(storage);
        let path = directory.0.join(DATA_FILE);
        let original = fs::read(&path).unwrap();
        for field in 0..6 {
            let (mut config, mut device) = scope();
            match field {
                0 => config.issuer.push('/'),
                1 => config.application_id.push('2'),
                2 => config.environment_id.push('2'),
                3 => device.installation_id.push('2'),
                4 => device.fingerprint = Some("b".repeat(64)),
                _ => device.fingerprint_provider = Some("machine_v1".into()),
            }
            let error = WindowsStorage::open(&directory.0, &config, &device).unwrap_err();
            assert_eq!(format!("{error}"), "Credential storage failed");
            assert_eq!(format!("{error:?}"), "Credential storage failed");
            assert!(fs::read(&path).unwrap() == original);
        }
        let (config, device) = scope();
        let mut tampered = original.clone();
        *tampered.last_mut().unwrap() ^= 1;
        for invalid in [
            tampered,
            original[..1].to_vec(),
            Vec::new(),
            vec![0; MAX_CIPHERTEXT + 1],
        ] {
            fs::write(&path, &invalid).unwrap();
            assert!(matches!(
                WindowsStorage::open(&directory.0, &config, &device),
                Err(Error::Storage)
            ));
            assert!(fs::read(&path).unwrap() == invalid);
        }
        let mut record: serde_json::Value = serde_json::from_slice(
            &codec::encode(&config, &device, 0, Some(&credential())).unwrap(),
        )
        .unwrap();
        record["format"] = serde_json::json!(99);
        let encrypted = orbit_sdk_native::protect_user_data(
            &serde_json::to_vec(&record).unwrap(),
            &codec::entropy(&config, &device).unwrap(),
        )
        .unwrap();
        fs::write(&path, &encrypted).unwrap();
        assert!(WindowsStorage::open(&directory.0, &config, &device).is_err());
        assert!(fs::read(&path).unwrap() == encrypted);
        fs::remove_file(&path).unwrap();
        assert!(WindowsStorage::open(&directory.0, &config, &device).is_err());
        assert!(!path.exists());

        let interrupted = Directory::new();
        fs::write(interrupted.0.join(LOCK_FILE), []).unwrap();
        assert!(WindowsStorage::open(&interrupted.0, &config, &device).is_err());
        assert!(!interrupted.0.join(DATA_FILE).exists());
    }

    #[test]
    fn native_storage_write_errors_poison_until_reopen_without_plaintext_or_temporary_files() {
        let directory = Directory::new();
        let path = directory.0.join(DATA_FILE);
        for invalidate in [false, true] {
            let storage = open(&directory);
            storage.save(0, credential()).unwrap();
            let original = fs::read(&path).unwrap();
            // Denying delete sharing blocks replacement after temporary flush.
            let held = OpenOptions::new()
                .read(true)
                .share_mode(1)
                .open(&path)
                .unwrap();
            let result = if invalidate {
                storage.invalidate().map(|_| ())
            } else {
                storage.save(0, credential())
            };
            assert!(matches!(result, Err(Error::Storage)));
            drop(held);
            assert!(matches!(storage.load(), Err(Error::Storage)));
            assert!(matches!(storage.version(), Err(Error::Storage)));
            assert!(matches!(storage.save(0, credential()), Err(Error::Storage)));
            assert!(matches!(storage.invalidate(), Err(Error::Storage)));
            assert!(fs::read(&path).unwrap() == original);
            let mut names: Vec<_> = fs::read_dir(&directory.0)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            names.sort();
            assert_eq!(names, [DATA_FILE, LOCK_FILE].map(std::ffi::OsString::from));
            drop(storage);
            let storage = open(&directory);
            assert!(storage.load().unwrap().1.unwrap().credential == credential().credential);
        }
    }

    #[test]
    fn native_storage_serializes_invalidation_and_refuses_generation_overflow() {
        let directory = Directory::new();
        let storage = Arc::new(open(&directory));
        let barrier = Arc::new(Barrier::new(3));
        std::thread::scope(|threads| {
            let saved = threads.spawn(|| {
                barrier.wait();
                storage.save(0, credential())
            });
            let invalidated = threads.spawn(|| {
                barrier.wait();
                storage.invalidate()
            });
            barrier.wait();
            assert!(matches!(
                saved.join().unwrap(),
                Ok(()) | Err(Error::StaleResponse)
            ));
            assert_eq!(invalidated.join().unwrap().unwrap(), 1);
        });
        assert!(storage.load().unwrap().1.is_none());
        drop(storage);
        let (config, device) = scope();
        let ciphertext = orbit_sdk_native::protect_user_data(
            &codec::encode(&config, &device, codec::MAX_GENERATION, Some(&credential())).unwrap(),
            &codec::entropy(&config, &device).unwrap(),
        )
        .unwrap();
        fs::write(directory.0.join(DATA_FILE), &ciphertext).unwrap();
        let storage = open(&directory);
        assert!(matches!(storage.invalidate(), Err(Error::Storage)));
        assert!(matches!(storage.version(), Err(Error::Storage)));
        drop(storage);
        assert_eq!(open(&directory).version().unwrap(), codec::MAX_GENERATION);
    }

    #[test]
    fn native_storage_requires_existing_absolute_local_regular_paths() {
        let directory = Directory::new();
        let (config, device) = scope();
        for path in [
            PathBuf::from("relative"),
            PathBuf::from("C:relative"),
            PathBuf::from(r"\\localhost\share\orbit"),
            directory.0.join("missing"),
            directory.0.join("..").join("unaccepted"),
        ] {
            assert!(matches!(
                WindowsStorage::open(path, &config, &device),
                Err(Error::Storage)
            ));
        }
        fs::create_dir(directory.0.join(DATA_FILE)).unwrap();
        assert!(WindowsStorage::open(&directory.0, &config, &device).is_err());
        fs::remove_dir(directory.0.join(DATA_FILE)).unwrap();
        fs::remove_file(directory.0.join(LOCK_FILE)).unwrap();
        fs::create_dir(directory.0.join(LOCK_FILE)).unwrap();
        assert!(WindowsStorage::open(&directory.0, &config, &device).is_err());
    }
}
