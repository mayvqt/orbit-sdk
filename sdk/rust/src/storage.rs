use crate::{Error, Result};
use std::sync::Mutex;

#[cfg(any(target_os = "windows", target_os = "linux", test))]
mod codec;
mod secret_service;
mod windows;
pub use secret_service::SecretServiceStorage;
pub use windows::WindowsStorage;

/// Sensitive bearer material: deliberately has no Debug or Serialize implementation.
/// Adapters must use OS-protected storage, isolate each access context, and perform
/// version-checked saves atomically with invalidate. Private local Linux storage
/// must enforce ownership, permissions, exclusive leases and durable atomic writes.
#[derive(Clone)]
pub struct StoredCredential {
    pub application_id: String,
    pub environment_id: String,
    pub activation_id: String,
    pub licence_id: String,
    pub installation_id: String,
    pub credential: String,
    pub credential_expires_at: Option<i64>,
    pub fingerprint: Option<String>,
    pub fingerprint_provider: Option<String>,
}
pub trait Storage: Send + Sync {
    /// Atomically read the invalidation version before every protected operation.
    fn version(&self) -> Result<u64>;
    fn load(&self) -> Result<(u64, Option<StoredCredential>)>;
    fn save(&self, version: u64, credential: StoredCredential) -> Result<()>;
    fn invalidate(&self) -> Result<u64>;
}
#[derive(Default)]
pub struct MemoryStorage(Mutex<(u64, Option<StoredCredential>)>);
impl Storage for MemoryStorage {
    fn version(&self) -> Result<u64> {
        self.0
            .lock()
            .map(|state| state.0)
            .map_err(|_| Error::Storage)
    }
    fn load(&self) -> Result<(u64, Option<StoredCredential>)> {
        self.0
            .lock()
            .map(|state| state.clone())
            .map_err(|_| Error::Storage)
    }
    fn save(&self, version: u64, credential: StoredCredential) -> Result<()> {
        let mut state = self.0.lock().map_err(|_| Error::Storage)?;
        if state.0 != version {
            return Err(Error::StaleResponse);
        }
        state.1 = Some(credential);
        Ok(())
    }
    fn invalidate(&self) -> Result<u64> {
        let mut state = self.0.lock().map_err(|_| Error::Storage)?;
        state.0 = state.0.checked_add(1).ok_or(Error::Storage)?;
        state.1 = None;
        Ok(state.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalidation_rejects_a_late_secret_write() {
        let storage = MemoryStorage::default();
        let (version, _) = storage.load().unwrap();
        storage.invalidate().unwrap();
        let secret = StoredCredential {
            application_id: "app".into(),
            environment_id: "test".into(),
            activation_id: "activation".into(),
            licence_id: "licence".into(),
            installation_id: "installation".into(),
            credential: "synthetic".into(),
            credential_expires_at: Some(123),
            fingerprint: None,
            fingerprint_provider: None,
        };
        assert!(matches!(
            storage.save(version, secret),
            Err(Error::StaleResponse)
        ));
        assert!(storage.load().unwrap().1.is_none());
    }
}
