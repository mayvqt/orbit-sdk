use crate::{Config, Device, Error, Result, Storage, StoredCredential};
use std::{fmt, path::Path};

#[cfg(any(target_os = "linux", test))]
mod format;
#[cfg(target_os = "linux")]
mod helper;
#[cfg(target_os = "linux")]
mod lease;
#[cfg(all(target_os = "linux", test))]
mod native_tests;

/// Explicit Linux Secret Service persistence for one private directory and scope.
///
/// Requires an existing operational keyring and `/usr/bin/secret-tool`; this SDK
/// never installs or unlocks the service. The existing absolute directory and its
/// lifetime lease must belong only to this user. Share this object through `Arc`;
/// Drop releases its lease. Interrupted writes leave a durable nonsecret marker
/// that prevents reopening, even if the keyring later completes the write. Use a
/// new private directory and deliberate online activation to recover. Only
/// activation credentials and metadata persist, not sessions or grants. Every
/// process restart still requires online validation.
pub struct SecretServiceStorage {
    #[cfg(target_os = "linux")]
    state: std::sync::Mutex<State>,
}

impl fmt::Debug for SecretServiceStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretServiceStorage { [redacted] }")
    }
}

impl SecretServiceStorage {
    pub fn open(directory: impl AsRef<Path>, config: &Config, device: &Device) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            // Reject unencodable configuration before touching a lease or service.
            format::encode(config, device, 0, None)?;
            let lease = lease::Lease::open(directory.as_ref())?;
            let scope = format::scope(config, device, &lease.directory)?;
            let mut state = State {
                generation: 0,
                credential: None,
                poisoned: false,
                config: config.clone(),
                device: device.clone(),
                scope,
                lease,
            };
            match helper::lookup(&state.scope)? {
                Some(output) => {
                    let (generation, credential) = format::decode(config, device, &output)?;
                    state.generation = generation;
                    state.credential = credential;
                }
                None if state.lease.created => state.commit(0, None)?,
                None => return Err(Error::Storage),
            }
            state.check()?;
            Ok(Self {
                state: std::sync::Mutex::new(state),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (directory, config, device);
            Err(Error::Storage)
        }
    }
}

#[cfg(target_os = "linux")]
struct State {
    generation: u64,
    credential: Option<StoredCredential>,
    poisoned: bool,
    config: Config,
    device: Device,
    scope: String,
    lease: lease::Lease,
}

#[cfg(target_os = "linux")]
impl State {
    fn poison(&mut self) {
        self.poisoned = true;
        self.credential = None;
    }

    fn check(&mut self) -> Result<()> {
        if self.poisoned || self.lease.verify().is_err() {
            self.poison();
            return Err(Error::Storage);
        }
        Ok(())
    }

    fn commit(&mut self, generation: u64, credential: Option<StoredCredential>) -> Result<()> {
        let result = (|| {
            self.check()?;
            let encoded =
                format::encode(&self.config, &self.device, generation, credential.as_ref())?;
            self.lease.begin_write()?;
            helper::store(&self.scope, &encoded)?;
            self.lease.complete_write()
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

#[cfg(target_os = "linux")]
impl Storage for SecretServiceStorage {
    fn version(&self) -> Result<u64> {
        let mut state = self.state.lock().map_err(|_| Error::Storage)?;
        state.check()?;
        Ok(state.generation)
    }
    fn load(&self) -> Result<(u64, Option<StoredCredential>)> {
        let mut state = self.state.lock().map_err(|_| Error::Storage)?;
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

#[cfg(not(target_os = "linux"))]
impl Storage for SecretServiceStorage {
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::storage::codec::tests::{credential, scope};

    // Synthetic cached state never calls secret-tool: every exercised mutation
    // is rejected before persistence. Only ignored native tests open a keyring.
    fn cached(directory: &lease::tests::Directory) -> SecretServiceStorage {
        let (config, device) = scope();
        SecretServiceStorage {
            state: std::sync::Mutex::new(State {
                generation: 2,
                credential: Some(credential()),
                poisoned: false,
                config,
                device,
                scope: "synthetic_unused_scope".into(),
                lease: lease::Lease::open(&directory.0).unwrap(),
            }),
        }
    }

    #[test]
    fn stale_and_invalid_writes_and_removed_leases_never_authorize() {
        let directory = lease::tests::Directory::new();
        let storage = cached(&directory);
        assert!(matches!(
            storage.save(1, credential()),
            Err(Error::StaleResponse)
        ));
        assert_eq!(storage.version().unwrap(), 2);
        assert!(storage.load().unwrap().1.is_some());
        let mut invalid = credential();
        invalid.credential.clear();
        assert!(matches!(storage.save(2, invalid), Err(Error::Storage)));
        assert!(matches!(storage.load(), Err(Error::Storage)));
        assert!(matches!(storage.version(), Err(Error::Storage)));
        assert!(matches!(storage.invalidate(), Err(Error::Storage)));
        assert!(matches!(storage.save(2, credential()), Err(Error::Storage)));
        assert_eq!(
            format!("{storage:?}"),
            "SecretServiceStorage { [redacted] }"
        );
        drop(storage);
        let storage = cached(&directory);
        std::fs::remove_file(directory.0.join(lease::NAME)).unwrap();
        assert!(matches!(storage.version(), Err(Error::Storage)));
        assert!(storage.state.lock().unwrap().credential.is_none());
    }

    #[test]
    fn generation_overflow_poisoning_does_not_spawn_a_helper() {
        let directory = lease::tests::Directory::new();
        let storage = cached(&directory);
        storage.state.lock().unwrap().generation = crate::storage::codec::MAX_GENERATION;
        assert!(matches!(storage.invalidate(), Err(Error::Storage)));
        assert!(matches!(storage.load(), Err(Error::Storage)));
    }

    #[test]
    fn pending_write_denies_cached_access_and_reopening_before_keyring_access() {
        let directory = lease::tests::Directory::new();
        let storage = cached(&directory);
        storage.state.lock().unwrap().lease.begin_write().unwrap();
        assert!(matches!(storage.load(), Err(Error::Storage)));
        assert!(matches!(storage.version(), Err(Error::Storage)));
        assert!(matches!(storage.save(2, credential()), Err(Error::Storage)));
        assert!(matches!(storage.invalidate(), Err(Error::Storage)));
        assert!(storage.state.lock().unwrap().credential.is_none());
        drop(storage);
        let (config, device) = scope();
        // A pending lease rejects before the constructor can invoke secret-tool.
        assert_eq!(std::fs::read(directory.0.join(lease::NAME)).unwrap(), [1]);
        assert!(matches!(
            SecretServiceStorage::open(&directory.0, &config, &device),
            Err(Error::Storage)
        ));
        assert_eq!(std::fs::read(directory.0.join(lease::NAME)).unwrap(), [1]);
    }
}
