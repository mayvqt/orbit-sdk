//! Explicitly ignored: execute only inside scripts/linux_keyring_session.py.

use super::*;
use crate::storage::codec::{
    self,
    tests::{credential, scope as configuration},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    fs,
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, PermissionsExt},
        net::UnixListener,
    },
    path::PathBuf,
    process::Command,
    time::{Duration, Instant},
};

fn isolated_root() -> PathBuf {
    assert_eq!(
        std::env::var("ORBIT_NATIVE_STORAGE_TEST").as_deref(),
        Ok("1"),
        "Native storage opt-in required"
    );
    assert_ne!(
        rustix::process::geteuid().as_raw(),
        0,
        "Run as the isolated ordinary SDK user"
    );
    let root = PathBuf::from(
        std::env::var_os("ORBIT_KEYRING_FIXTURE").expect("Isolated keyring fixture required"),
    );
    assert!(
        root.parent() == Some(Path::new("/tmp"))
            && root
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("orbit-keyring-session-")
    );
    assert!(root.canonicalize().unwrap() == root);
    for name in ["", "data", "config", "cache", "runtime", "control"] {
        let metadata = fs::symlink_metadata(root.join(name)).unwrap();
        assert!(
            metadata.is_dir()
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.mode() & 0o077 == 0
        );
    }
    for (variable, child) in [
        ("XDG_DATA_HOME", "data"),
        ("XDG_CONFIG_HOME", "config"),
        ("XDG_CACHE_HOME", "cache"),
        ("XDG_RUNTIME_DIR", "runtime"),
        ("GNOME_KEYRING_CONTROL", "control"),
    ] {
        assert!(std::env::var_os(variable).map(PathBuf::from) == Some(root.join(child)));
    }
    assert!(
        std::env::var("DBUS_SESSION_BUS_ADDRESS")
            .unwrap()
            .starts_with("unix:")
    );
    root
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let root = isolated_root();
        let mut bytes = [0; 16];
        aws_lc_rs::rand::fill(&mut bytes).unwrap();
        let path = root.join(format!("rust-storage-{:032x}", u128::from_be_bytes(bytes)));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn open(&self) -> SecretServiceStorage {
        let (config, device) = configuration();
        SecretServiceStorage::open(&self.0, &config, &device).unwrap()
    }

    fn scope(&self) -> String {
        let (config, device) = configuration();
        format::scope(&config, &device, self.0.to_str().unwrap()).unwrap()
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        // The harness removes the entire private keyring, including synthetic
        // items, after the suite. Never route teardown to an ordinary keyring.
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn child(directory: &Directory, mode: &str, bus: Option<&str>) {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "storage::secret_service::native_tests::child_probe",
            "--ignored",
        ])
        .env("_ORBIT_RUST_STORAGE_DIRECTORY", &directory.0)
        .env("_ORBIT_RUST_STORAGE_CHILD", mode);
    if let Some(bus) = bus {
        command.env("DBUS_SESSION_BUS_ADDRESS", bus);
    }
    assert!(
        command.output().unwrap().status.success(),
        "Synthetic storage child failed"
    );
}

#[test]
#[ignore = "private subprocess entry; selected only by the native_ tests"]
fn child_probe() {
    let root = isolated_root();
    let directory = PathBuf::from(
        std::env::var_os("_ORBIT_RUST_STORAGE_DIRECTORY").expect("Synthetic directory required"),
    );
    assert!(directory.parent() == Some(root.as_path()));
    let mode = std::env::var("_ORBIT_RUST_STORAGE_CHILD").expect("Synthetic child mode required");
    let (config, device) = configuration();
    match mode.as_str() {
        "blocked" | "unavailable" => {
            let error = SecretServiceStorage::open(directory, &config, &device).unwrap_err();
            assert_eq!(format!("{error:?}"), "Credential storage failed");
        }
        "invalidate" => {
            let storage = SecretServiceStorage::open(directory, &config, &device).unwrap();
            let (generation, stored) = storage.load().unwrap();
            assert_eq!(generation, 0);
            assert!(stored.unwrap().credential == credential().credential);
            assert_eq!(storage.invalidate().unwrap(), 1);
        }
        "exit-owner" => {
            let storage = SecretServiceStorage::open(directory, &config, &device).unwrap();
            storage.save(0, credential()).unwrap();
            // Verify kernel lease release on process exit without Rust Drop.
            std::process::exit(0);
        }
        "pending-exit" => {
            let storage = SecretServiceStorage::open(directory, &config, &device).unwrap();
            storage.state.lock().unwrap().lease.begin_write().unwrap();
            // Crash after the durable marker, without helper completion or Drop.
            std::process::exit(0);
        }
        "failed-store" | "failed-initial-store" => {
            // The parent seeded this synthetic record through the real service.
            // Construct its known cached state without a lookup so this child's
            // isolated unavailable/hung bus exercises the actual store path.
            let lease = lease::Lease::open(&directory).unwrap();
            let initial = mode == "failed-initial-store";
            assert_eq!(lease.created, initial);
            let mut state = State {
                generation: 0,
                credential: (!initial).then(credential),
                poisoned: false,
                scope: format::scope(&config, &device, &lease.directory).unwrap(),
                config,
                device,
                lease,
            };
            assert!(matches!(
                state.commit(u64::from(!initial), None),
                Err(Error::Storage)
            ));
            assert_eq!(state.generation, 0);
            assert!(state.poisoned && state.credential.is_none());
            let storage = SecretServiceStorage {
                state: std::sync::Mutex::new(state),
            };
            assert!(matches!(storage.load(), Err(Error::Storage)));
            assert!(matches!(storage.version(), Err(Error::Storage)));
            assert!(matches!(storage.save(0, credential()), Err(Error::Storage)));
            assert!(matches!(storage.invalidate(), Err(Error::Storage)));
            assert_eq!(fs::read(directory.join(lease::NAME)).unwrap(), [1]);
        }
        _ => panic!("Unknown synthetic child mode"),
    }
}

#[test]
#[ignore = "requires ORBIT_NATIVE_STORAGE_TEST=1 in linux_keyring_session.py"]
fn native_reopen_process_exit_lease_and_tombstone() {
    let directory = Directory::new();
    child(&directory, "exit-owner", None);
    let storage = directory.open();
    assert!(storage.load().unwrap().1.unwrap().credential == credential().credential);
    child(&directory, "blocked", None);
    storage.save(0, credential()).unwrap();
    child(&directory, "blocked", None);
    drop(storage);
    child(&directory, "invalidate", None);
    let storage = directory.open();
    assert_eq!(storage.version().unwrap(), 1);
    assert!(storage.load().unwrap().1.is_none());
    assert!(matches!(
        storage.save(0, credential()),
        Err(Error::StaleResponse)
    ));
    assert_eq!(storage.version().unwrap(), 1);
    storage.save(1, credential()).unwrap();
    let (config, device) = configuration();
    let encoded = format::encode(&config, &device, 1, Some(&credential())).unwrap();
    let keyrings: Vec<_> = fs::read_dir(isolated_root().join("data/keyrings"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "keyring")
        })
        .collect();
    assert!(!keyrings.is_empty());
    for path in keyrings {
        let disk = fs::read(path).unwrap();
        assert!(!disk.windows(encoded.len()).any(|window| window == encoded));
        assert!(
            !disk
                .windows(43)
                .any(|window| window == credential().credential.as_bytes())
        );
    }
    assert_eq!(storage.invalidate().unwrap(), 2);
    drop(storage);
    let storage = directory.open();
    assert_eq!(storage.version().unwrap(), 2);
    assert!(storage.load().unwrap().1.is_none());
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
    assert_eq!(
        format!("{storage:?}"),
        "SecretServiceStorage { [redacted] }"
    );
}

#[test]
#[ignore = "requires ORBIT_NATIVE_STORAGE_TEST=1 in linux_keyring_session.py"]
fn native_pending_write_crash_and_late_service_completion_never_reopen() {
    let directory = Directory::new();
    let storage = directory.open();
    storage.save(0, credential()).unwrap();
    drop(storage);
    child(&directory, "pending-exit", None);
    let (config, device) = configuration();
    assert_eq!(fs::read(directory.0.join(lease::NAME)).unwrap(), [1]);
    assert!(SecretServiceStorage::open(&directory.0, &config, &device).is_err());
    let key = directory.scope();
    let original = helper::lookup(&key).unwrap().unwrap();
    assert!(
        format::decode(&config, &device, &original)
            .unwrap()
            .1
            .is_some()
    );
    // Model a request already accepted by the service before the owner crashed:
    // even a valid late completion cannot make this pending directory usable.
    helper::store(&key, &format::encode(&config, &device, 1, None).unwrap()).unwrap();
    assert!(SecretServiceStorage::open(&directory.0, &config, &device).is_err());
    assert_eq!(fs::read(directory.0.join(lease::NAME)).unwrap(), [1]);
    let recovery = Directory::new();
    assert!(recovery.open().load().unwrap().1.is_none());
}

#[test]
#[ignore = "requires ORBIT_NATIVE_STORAGE_TEST=1 in linux_keyring_session.py"]
fn native_wrong_scope_corruption_and_missing_state_never_reset() {
    let directory = Directory::new();
    let storage = directory.open();
    storage.save(0, credential()).unwrap();
    drop(storage);
    let (config, device) = configuration();
    let key = directory.scope();
    let original = helper::lookup(&key).unwrap().unwrap();
    for field in 0..5 {
        let (mut other, mut machine) = configuration();
        match field {
            0 => other.issuer.push('/'),
            1 => other.application_id.push('2'),
            2 => other.environment_id.push('2'),
            3 => machine.installation_id.push('2'),
            _ => machine.fingerprint = Some("b".repeat(64)),
        }
        assert!(SecretServiceStorage::open(&directory.0, &other, &machine).is_err());
        assert!(helper::lookup(&key).unwrap().unwrap() == original);
    }
    let other_directory = Directory::new();
    assert!(other_directory.open().load().unwrap().1.is_none());
    for bad in [
        b"not-base64".to_vec(),
        STANDARD
            .encode(vec![b'x'; format::MAX_RECORD + 1])
            .into_bytes(),
    ] {
        // The oversized decoded record still fits the 5464-byte base64 bound.
        helper::store(&key, &bad).unwrap();
        assert!(SecretServiceStorage::open(&directory.0, &config, &device).is_err());
    }
    let mut record: serde_json::Value =
        serde_json::from_slice(&codec::encode(&config, &device, 0, Some(&credential())).unwrap())
            .unwrap();
    record["format"] = serde_json::json!(99);
    helper::store(
        &key,
        STANDARD
            .encode(serde_json::to_vec(&record).unwrap())
            .as_bytes(),
    )
    .unwrap();
    assert!(SecretServiceStorage::open(&directory.0, &config, &device).is_err());
    helper::clear(&key).unwrap();
    assert!(SecretServiceStorage::open(&directory.0, &config, &device).is_err());
    assert!(helper::lookup(&key).unwrap().is_none());
}

#[test]
#[ignore = "requires ORBIT_NATIVE_STORAGE_TEST=1 in linux_keyring_session.py"]
fn native_permissions_removed_lease_and_failed_write_poisoning() {
    let directory = Directory::new();
    let storage = directory.open();
    storage.save(0, credential()).unwrap();
    let path = directory.0.join(lease::NAME);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(matches!(storage.version(), Err(Error::Storage)));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(storage.load(), Err(Error::Storage)));
    drop(storage);
    let storage = directory.open();
    fs::remove_file(&path).unwrap();
    assert!(matches!(storage.invalidate(), Err(Error::Storage)));
    assert!(matches!(storage.save(0, credential()), Err(Error::Storage)));
    drop(storage);
    // Existing keyring state survives the removed lease; it is never overwritten
    // by a fresh tombstone simply because the lease file had to be recreated.
    let storage = directory.open();
    assert!(storage.load().unwrap().1.is_some());
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o750)).unwrap();
    assert!(matches!(storage.load(), Err(Error::Storage)));
    fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(storage.load(), Err(Error::Storage)));
}

#[test]
#[ignore = "requires ORBIT_NATIVE_STORAGE_TEST=1 in linux_keyring_session.py"]
fn native_helper_failure_and_deadline_are_private_and_reaped() {
    let missing = Directory::new();
    let address = format!("unix:path={}", missing.0.join("missing-bus").display());
    child(&missing, "unavailable", Some(&address));
    let (config, device) = configuration();
    assert!(SecretServiceStorage::open(&missing.0, &config, &device).is_err());
    assert!(helper::lookup(&missing.scope()).unwrap().is_none());
    let waiting = Directory::new();
    let path = waiting.0.join("silent-bus");
    let _listener = UnixListener::bind(&path).unwrap();
    let address = format!("unix:path={}", path.display());
    let started = Instant::now();
    child(&waiting, "unavailable", Some(&address));
    assert!(started.elapsed() >= Duration::from_secs(4));
    assert!(started.elapsed() < Duration::from_secs(8));

    let initial = Directory::new();
    let unavailable = format!("unix:path={}", initial.0.join("missing-bus").display());
    child(&initial, "failed-initial-store", Some(&unavailable));
    assert_eq!(fs::read(initial.0.join(lease::NAME)).unwrap(), [1]);
    assert!(SecretServiceStorage::open(&initial.0, &config, &device).is_err());
    assert!(helper::lookup(&initial.scope()).unwrap().is_none());

    for bus in [&unavailable, &address] {
        let pending = Directory::new();
        let storage = pending.open();
        storage.save(0, credential()).unwrap();
        drop(storage);
        let original = helper::lookup(&pending.scope()).unwrap().unwrap();
        let started = Instant::now();
        child(&pending, "failed-store", Some(bus));
        if bus == &address {
            assert!(started.elapsed() >= Duration::from_secs(4));
        }
        assert!(started.elapsed() < Duration::from_secs(8));
        assert_eq!(fs::read(pending.0.join(lease::NAME)).unwrap(), [1]);
        assert!(SecretServiceStorage::open(&pending.0, &config, &device).is_err());
        assert!(helper::lookup(&pending.scope()).unwrap().unwrap() == original);
    }
}
