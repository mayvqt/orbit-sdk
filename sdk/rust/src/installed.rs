//! Owned installed-client state. Secret inputs never enter the serialized envelope.
use crate::access::{self, ActivationPrincipal};
use crate::clock::{self, Anchor};
use crate::grants::{self, Expected, Keys};
use crate::{AppKey, Client, Config, Device, Error, Result, Storage, StoredCredential, Transport};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex, atomic::Ordering},
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
#[path = "installed_linux.rs"]
mod platform;
#[cfg(target_os = "windows")]
#[path = "installed_windows.rs"]
mod platform;
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod platform {
    use super::*;
    pub struct Backend;
    impl Backend {
        pub fn open(_: &Path) -> Result<(Self, Option<Vec<u8>>)> {
            Err(Error::Storage)
        }
        pub fn write(&self, _: &[u8]) -> Result<()> {
            Err(Error::Storage)
        }
    }
}

const MAX_BYTES: usize = 64 * 1024;
const MAX_TIME: i64 = 253_402_300_799;
const MAX_GENERATION: u64 = i64::MAX as u64;

const WRITE_PENDING: &[u8] = &[1];
fn check_write_marker(file: &std::fs::File, expected: &[u8]) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    if file.metadata().map_err(|_| Error::Storage)?.len() != expected.len() as u64 {
        return Err(Error::CorruptState);
    }
    let mut file = file;
    file.seek(SeekFrom::Start(0)).map_err(|_| Error::Storage)?;
    let mut marker = [0; 1];
    file.read_exact(&mut marker[..expected.len()])
        .map_err(|_| Error::Storage)?;
    if &marker[..expected.len()] != expected {
        return Err(Error::CorruptState);
    }
    Ok(())
}
fn write_pending_marker(file: &std::fs::File) -> Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    let mut file = file;
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.write_all(WRITE_PENDING))
        .and_then(|()| file.sync_all())
        .map_err(|_| Error::Storage)
}
#[cfg(test)]
#[derive(Default)]
struct WriteFault {
    stage: std::sync::atomic::AtomicU8,
    crash: std::sync::atomic::AtomicBool,
}
#[cfg(test)]
impl WriteFault {
    fn check(&self, stage: u8) -> Result<()> {
        if self.stage.load(Ordering::Relaxed) != stage {
            return Ok(());
        }
        if self.crash.load(Ordering::Relaxed) {
            std::process::exit(42);
        }
        Err(Error::Storage)
    }
}

/// Select automatic, absent, or application-owned machine binding.
#[derive(Clone, Debug, Default)]
pub enum MachineBinding {
    #[default]
    Automatic,
    Disabled,
    Custom {
        fingerprint: String,
        provider: String,
    },
}

/// Optional settings for the installed client. The zero value uses native
/// machine_v1 identity when available and the platform's default state directory.
#[derive(Clone, Debug, Default)]
pub struct Options {
    pub state_directory: Option<PathBuf>,
    pub machine_binding: MachineBinding,
}

fn resolve_binding(
    key: &AppKey,
    binding: &MachineBinding,
) -> Result<(Option<String>, Option<String>)> {
    resolve_binding_with(key, binding, || {
        crate::device::native_fingerprint(key.application_id(), key.environment_id())
    })
}

fn resolve_binding_with<F>(
    _key: &AppKey,
    binding: &MachineBinding,
    native_identity: F,
) -> Result<(Option<String>, Option<String>)>
where
    F: FnOnce() -> Result<String>,
{
    match binding {
        MachineBinding::Automatic => match native_identity() {
            Ok(fingerprint) => Ok((Some(fingerprint), Some("machine_v1".into()))),
            Err(Error::Denied { code, .. }) if code == "device_identity_unavailable" => {
                Ok((None, None))
            }
            Err(error) => Err(error),
        },
        MachineBinding::Disabled => Ok((None, None)),
        MachineBinding::Custom {
            fingerprint,
            provider,
        } => {
            if !valid_fingerprint(fingerprint)
                || !provider.starts_with("custom:")
                || !access::valid_provider(provider)
            {
                return Err(Error::Configuration);
            }
            Ok((Some(fingerprint.clone()), Some(provider.clone())))
        }
    }
}

fn valid_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Scope {
    api_origin: String,
    issuer: String,
    application_id: String,
    environment_id: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Installation {
    id: String,
    #[serde(deserialize_with = "Option::deserialize")]
    fingerprint: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    fingerprint_provider: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    activation_id: String,
    licence_id: String,
    bearer: String,
    #[serde(deserialize_with = "Option::deserialize")]
    expires_at: Option<i64>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    operation_id: String,
    principal_kind: String,
    input_digest: String,
    created_at: i64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cache {
    pub(crate) jws: String,
    pub(crate) jwks: grants::Jwks,
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) licence_expires_at: Option<i64>,
    pub(crate) received_server_time: i64,
    pub(crate) received_wall_time: i64,
    pub(crate) server_high_water: i64,
    pub(crate) wall_high_water: i64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    sdk: String,
    format: u32,
    provider: String,
    scope: Scope,
    installation: Installation,
    generation: u64,
    #[serde(deserialize_with = "Option::deserialize")]
    credential: Option<Credential>,
    #[serde(deserialize_with = "Option::deserialize")]
    pending_activation: Option<Pending>,
    #[serde(deserialize_with = "Option::deserialize")]
    access: Option<Cache>,
}
struct DiskState {
    record: Record,
    backend: Option<platform::Backend>,
    poisoned: bool,
    checkpoint: Instant,
}
pub(crate) struct InstalledStorage(Mutex<DiskState>);

fn provider() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows_dpapi"
    } else {
        "private_file"
    }
}
fn digest(bytes: &[u8]) -> String {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn valid_time(time: i64) -> bool {
    (0..=MAX_TIME).contains(&time)
}
fn valid_expiry(time: Option<i64>) -> bool {
    time.is_none_or(|t| t > 0 && valid_time(t))
}
fn default_path(scope: &Scope) -> Result<PathBuf> {
    let base = if cfg!(target_os = "windows") {
        PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or(Error::Configuration)?).join("Orbit")
    } else if let Some(path) = std::env::var_os("XDG_STATE_HOME") {
        PathBuf::from(path).join("orbit")
    } else {
        PathBuf::from(std::env::var_os("HOME").ok_or(Error::Configuration)?)
            .join(".local/state/orbit")
    };
    if !base.is_absolute() {
        return Err(Error::Configuration);
    }
    Ok(base.join(digest(
        &serde_json::to_vec(&serde_json::to_value(scope).map_err(|_| Error::Configuration)?)
            .map_err(|_| Error::Configuration)?,
    )))
}
impl Record {
    fn config(&self) -> Config {
        Config {
            application_id: self.scope.application_id.clone(),
            environment_id: self.scope.environment_id.clone(),
            issuer: self.scope.issuer.clone(),
        }
    }
    fn device(&self) -> Device {
        Device {
            installation_id: self.installation.id.clone(),
            fingerprint: self.installation.fingerprint.clone(),
            fingerprint_provider: self.installation.fingerprint_provider.clone(),
        }
    }
    fn saved(&self) -> Option<StoredCredential> {
        self.credential.as_ref().map(|c| StoredCredential {
            application_id: self.scope.application_id.clone(),
            environment_id: self.scope.environment_id.clone(),
            activation_id: c.activation_id.clone(),
            licence_id: c.licence_id.clone(),
            installation_id: self.installation.id.clone(),
            credential: c.bearer.clone(),
            credential_expires_at: c.expires_at,
            fingerprint: self.installation.fingerprint.clone(),
            fingerprint_provider: self.installation.fingerprint_provider.clone(),
        })
    }
    fn validate(&self, scope: &Scope, key: &AppKey) -> Result<()> {
        if self.sdk != "orbit.installed-client"
            || self.format != 2
            || self.provider != provider()
            || &self.scope != scope
            || self.scope.issuer != key.issuer()
            || self.scope.application_id != key.application_id()
            || self.scope.environment_id != key.environment_id()
            || self.generation > MAX_GENERATION
            || self.installation.fingerprint.is_some()
                != self.installation.fingerprint_provider.is_some()
            || self
                .installation
                .fingerprint
                .as_deref()
                .is_some_and(|f| !valid_fingerprint(f))
            || self
                .installation
                .fingerprint_provider
                .as_deref()
                .is_some_and(|p| !access::valid_provider(p))
            || !access::valid_configuration(&self.config(), &self.device())
            || self.saved().as_ref().is_some_and(|s| {
                !access::valid_stored_credential(s, &self.config(), &self.device())
                    || !valid_expiry(s.credential_expires_at)
            })
            || self.pending_activation.as_ref().is_some_and(|p| {
                !access::valid_operation_id(&p.operation_id)
                    || !matches!(p.principal_kind.as_str(), "key" | "account")
                    || p.input_digest.len() != 64
                    || !p
                        .input_digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    || !valid_time(p.created_at)
            })
            || self.access.as_ref().is_some_and(|c| {
                self.credential.is_none()
                    || c.jws.len() > 16384
                    || c.jwks.keys.len() != 1
                    || !valid_expiry(c.licence_expires_at)
                    || [
                        c.received_server_time,
                        c.received_wall_time,
                        c.server_high_water,
                        c.wall_high_water,
                    ]
                    .iter()
                    .any(|t| !valid_time(*t))
            })
        {
            return Err(Error::CorruptState);
        }
        Ok(())
    }
}
impl DiskState {
    fn check(&self) -> Result<()> {
        if self.poisoned {
            Err(Error::Storage)
        } else if self.backend.is_none() {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }
    fn commit(&mut self, record: Record) -> Result<()> {
        self.check()?;
        let bytes = serde_json::to_vec(&record).map_err(|_| Error::Storage)?;
        if bytes.len() > MAX_BYTES
            || self
                .backend
                .as_ref()
                .ok_or(Error::Closed)?
                .write(&bytes)
                .is_err()
        {
            self.poisoned = true;
            return Err(Error::Storage);
        }
        self.record = record;
        self.checkpoint = Instant::now();
        Ok(())
    }
}
impl InstalledStorage {
    fn open(
        key: &AppKey,
        fingerprint: Option<String>,
        fingerprint_provider: Option<String>,
        origin: String,
        path: Option<&Path>,
    ) -> Result<Self> {
        let scope = Scope {
            api_origin: origin,
            issuer: key.issuer().to_owned(),
            application_id: key.application_id().to_owned(),
            environment_id: key.environment_id().to_owned(),
        };
        let mut device = Device::new_installation()?;
        device.fingerprint = fingerprint.clone();
        device.fingerprint_provider = fingerprint_provider.clone();
        let mut record = Record {
            sdk: "orbit.installed-client".into(),
            format: 2,
            provider: provider().into(),
            scope: scope.clone(),
            installation: Installation {
                id: device.installation_id,
                fingerprint: device.fingerprint,
                fingerprint_provider: device.fingerprint_provider,
            },
            generation: 0,
            credential: None,
            pending_activation: None,
            access: None,
        };
        if !access::valid_configuration(&record.config(), &record.device())
            || key.issuer().len() > 2048
        {
            return Err(Error::Configuration);
        }
        let directory = path
            .map(Path::to_path_buf)
            .map_or_else(|| default_path(&scope), Ok)?;
        let (backend, bytes) = platform::Backend::open(&directory)?;
        let new = bytes.is_none();
        let mut rebound = false;
        if let Some(bytes) = bytes {
            if bytes.len() > MAX_BYTES {
                return Err(Error::CorruptState);
            }
            record = serde_json::from_slice(&bytes).map_err(|_| Error::CorruptState)?;
            record.validate(&scope, key)?;
            if record.installation.fingerprint != fingerprint
                || record.installation.fingerprint_provider != fingerprint_provider
            {
                let device = Device::new_installation()?;
                record.installation = Installation {
                    id: device.installation_id,
                    fingerprint,
                    fingerprint_provider,
                };
                record.credential = None;
                record.pending_activation = None;
                record.access = None;
                record.generation = record
                    .generation
                    .checked_add(1)
                    .filter(|generation| *generation <= MAX_GENERATION)
                    .ok_or(Error::Storage)?;
                rebound = true;
            }
        }
        let mut state = DiskState {
            record: record.clone(),
            backend: Some(backend),
            poisoned: false,
            checkpoint: Instant::now(),
        };
        if new || rebound {
            state.commit(record)?;
        }
        Ok(Self(Mutex::new(state)))
    }
    fn identity(&self) -> Result<(Config, Device)> {
        let s = self.0.lock().map_err(|_| Error::Storage)?;
        s.check()?;
        Ok((s.record.config(), s.record.device()))
    }
    pub(crate) fn activation_pending(&self) -> Result<bool> {
        let state = self.0.lock().map_err(|_| Error::Storage)?;
        state.check()?;
        Ok(state.record.pending_activation.is_some())
    }
    pub(crate) fn prepare_activation(
        &self,
        principal: ActivationPrincipal<'_>,
        customer_id: Option<&str>,
        previous: Option<&str>,
        operation: &str,
    ) -> Result<(String, u64)> {
        let mut s = self.0.lock().map_err(|_| Error::Storage)?;
        s.check()?;
        let (kind, input) = match principal {
            ActivationPrincipal::Key(k) => ("key", k),
            ActivationPrincipal::Account(l) => ("account", l),
        };
        if match (kind, customer_id) {
            ("key", None) => false,
            ("account", Some(id)) => !access::opaque(id),
            _ => true,
        } {
            return Err(Error::Configuration);
        }
        // serde_json's default map uses sorted keys, including nested scope/installation.
        let data = json!({"scope":s.record.scope,"installation":{"id":s.record.installation.id,"fingerprint":s.record.installation.fingerprint,"fingerprint_provider":s.record.installation.fingerprint_provider},"principal_kind":kind,"licence_input":input,"customer_id":customer_id,"previous_credential":previous,"credential_mode":"persistent"});
        let input_digest = digest(&serde_json::to_vec(&data).map_err(|_| Error::Storage)?);
        let now = clock::wall()?;
        let pending = if let Some(p) = &s.record.pending_activation {
            if p.input_digest != input_digest
                || p.principal_kind != kind
                || (!operation.is_empty() && operation != p.operation_id)
                || now < p.created_at
                || now - p.created_at >= 86400
            {
                return Err(Error::PendingActivation);
            }
            p.clone()
        } else {
            Pending {
                operation_id: if operation.is_empty() {
                    Device::new_installation()?.installation_id
                } else {
                    operation.into()
                },
                principal_kind: kind.into(),
                input_digest,
                created_at: now,
            }
        };
        let id = pending.operation_id.clone();
        let mut record = s.record.clone();
        record.pending_activation = Some(pending);
        record.access = None;
        record.generation = record
            .generation
            .checked_add(1)
            .filter(|v| *v <= MAX_GENERATION)
            .ok_or(Error::Storage)?;
        let generation = record.generation;
        s.commit(record)?;
        Ok((id, generation))
    }
    pub(crate) fn commit_access(
        &self,
        version: u64,
        credential: &StoredCredential,
        cache: Cache,
        activation: bool,
    ) -> Result<()> {
        let mut s = self.0.lock().map_err(|_| Error::Storage)?;
        s.check()?;
        if s.record.generation != version {
            return Err(Error::StaleResponse);
        }
        let mut record = s.record.clone();
        record.credential = Some(Credential {
            activation_id: credential.activation_id.clone(),
            licence_id: credential.licence_id.clone(),
            bearer: credential.credential.clone(),
            expires_at: credential.credential_expires_at,
        });
        record.installation.fingerprint = credential.fingerprint.clone();
        record.installation.fingerprint_provider = credential.fingerprint_provider.clone();
        record.access = Some(cache);
        if activation {
            record.pending_activation = None;
        }
        s.commit(record)
    }
    pub(crate) fn clear_cached(&self, clear_pending: bool, clear_credential: bool) -> Result<u64> {
        let mut s = self.0.lock().map_err(|_| Error::Storage)?;
        s.check()?;
        let mut record = s.record.clone();
        record.access = None;
        if clear_pending {
            record.pending_activation = None;
        }
        if clear_credential {
            record.credential = None;
        }
        record.generation = record
            .generation
            .checked_add(1)
            .filter(|v| *v <= MAX_GENERATION)
            .ok_or(Error::Storage)?;
        let version = record.generation;
        s.commit(record)?;
        Ok(version)
    }
    fn restore(
        &self,
        current_fingerprint: Option<&str>,
        current_fingerprint_provider: Option<&str>,
    ) -> Result<Option<(grants::Claims, Anchor, Keys)>> {
        let s = self.0.lock().map_err(|_| Error::Storage)?;
        s.check()?;
        if s.record.installation.fingerprint.as_deref() != current_fingerprint
            || s.record.installation.fingerprint_provider.as_deref() != current_fingerprint_provider
        {
            return Ok(None);
        }
        let Some(c) = &s.record.access else {
            return Ok(None);
        };
        let saved = s.record.saved().ok_or(Error::CorruptState)?;
        let now = restored_time(c, clock::wall()?)?;
        let keys = Keys::parse(serde_json::to_value(&c.jwks).map_err(|_| Error::CorruptState)?)?;
        let expected = Expected {
            issuer: &s.record.scope.issuer,
            application: &saved.application_id,
            environment: &saved.environment_id,
            licence: Some(&saved.licence_id),
            activation: &saved.activation_id,
            installation: &saved.installation_id,
            fingerprint: saved.fingerprint.as_deref(),
            fingerprint_provider: saved.fingerprint_provider.as_deref(),
            allow_unbound_fingerprint: true,
            credential_expires_at: saved.credential_expires_at,
            licence_expires_at: c.licence_expires_at,
            now: c.received_server_time,
        };
        let claims = grants::verify(&c.jws, &keys, &expected)?;
        if now < claims.nbf || now >= claims.exp || !claims.offline_allowed {
            return Ok(None);
        }
        Ok(Some((claims, Anchor::restored(now, clock::wall()?)?, keys)))
    }
    pub(crate) fn checkpoint(&self, anchor: Option<&Anchor>, force: bool) -> Result<()> {
        let mut s = self.0.lock().map_err(|_| Error::Storage)?;
        s.check()?;
        if !force && s.checkpoint.elapsed() < Duration::from_secs(60) {
            return Ok(());
        }
        let mut record = s.record.clone();
        if let Some(cache) = &mut record.access {
            let Some(anchor) = anchor else {
                record.access = None;
                return s.commit(record);
            };
            let now = anchor.now();
            let wall = clock::wall();
            match (now, wall) {
                (Ok(now), Ok(wall))
                    if now >= cache.server_high_water && wall >= cache.wall_high_water =>
                {
                    cache.server_high_water = now;
                    cache.wall_high_water = wall;
                }
                _ => {
                    record.access = None;
                    s.commit(record)?;
                    return Err(Error::ClockUncertain);
                }
            }
            s.commit(record)?;
        }
        Ok(())
    }
    pub(crate) fn close(&self) {
        if let Ok(mut s) = self.0.lock() {
            s.backend.take();
        }
    }
}
fn restored_time(cache: &Cache, wall: i64) -> Result<i64> {
    if wall < cache.wall_high_water
        || cache.wall_high_water < cache.received_wall_time
        || cache.server_high_water < cache.received_server_time
    {
        return Err(Error::ClockUncertain);
    }
    let wall_progress = cache
        .wall_high_water
        .checked_sub(cache.received_wall_time)
        .ok_or(Error::ClockUncertain)?;
    let server_progress = cache
        .server_high_water
        .checked_sub(cache.received_server_time)
        .ok_or(Error::ClockUncertain)?;
    if wall_progress.abs_diff(server_progress) > 30 {
        return Err(Error::ClockUncertain);
    }
    let elapsed = wall
        .checked_sub(cache.received_wall_time)
        .ok_or(Error::ClockUncertain)?;
    let now = cache
        .received_server_time
        .checked_add(elapsed)
        .ok_or(Error::ClockUncertain)?
        .max(cache.server_high_water);
    if !valid_time(now) {
        return Err(Error::ClockUncertain);
    }
    Ok(now)
}
impl Storage for InstalledStorage {
    fn version(&self) -> Result<u64> {
        let s = self.0.lock().map_err(|_| Error::Storage)?;
        s.check()?;
        Ok(s.record.generation)
    }
    fn load(&self) -> Result<(u64, Option<StoredCredential>)> {
        let s = self.0.lock().map_err(|_| Error::Storage)?;
        s.check()?;
        Ok((s.record.generation, s.record.saved()))
    }
    fn save(&self, version: u64, credential: StoredCredential) -> Result<()> {
        let mut s = self.0.lock().map_err(|_| Error::Storage)?;
        s.check()?;
        if s.record.generation != version {
            return Err(Error::StaleResponse);
        }
        let mut record = s.record.clone();
        record.credential = Some(Credential {
            activation_id: credential.activation_id,
            licence_id: credential.licence_id,
            bearer: credential.credential,
            expires_at: credential.credential_expires_at,
        });
        record.access = None;
        s.commit(record)
    }
    fn invalidate(&self) -> Result<u64> {
        self.clear_cached(false, true)
    }
}
impl Client {
    /// Open the installation state for a public app key.
    pub async fn open(app_key: &str) -> Result<Self> {
        Self::open_with_options(app_key, Options::default()).await
    }

    /// Open with an explicit state directory or machine-binding policy.
    pub async fn open_with_options(app_key: &str, options: Options) -> Result<Self> {
        let key = AppKey::parse(app_key)?;
        let binding = resolve_binding(&key, &options.machine_binding)?;
        let transport = Transport::new(key.api_origin())?;
        Self::open_parsed(key, options, binding, transport).await
    }

    #[cfg(feature = "local-development")]
    pub async fn open_local(app_key: &str) -> Result<Self> {
        Self::open_local_with_options(app_key, Options::default()).await
    }

    #[cfg(feature = "local-development")]
    pub async fn open_local_with_options(app_key: &str, options: Options) -> Result<Self> {
        let key = AppKey::parse_local(app_key)?;
        let binding = resolve_binding(&key, &options.machine_binding)?;
        let transport = Transport::local_loopback(key.api_origin())?;
        Self::open_parsed(key, options, binding, transport).await
    }

    async fn open_parsed(
        key: AppKey,
        options: Options,
        binding: (Option<String>, Option<String>),
        transport: Transport,
    ) -> Result<Self> {
        clock::elapsed_clock()?;
        let storage = Arc::new(InstalledStorage::open(
            &key,
            binding.0.clone(),
            binding.1.clone(),
            transport.canonical_origin(),
            options.state_directory.as_deref(),
        )?);
        let (config, mut device) = storage.identity()?;
        // Identity changes rotate the installation ID and clear saved authority
        // before the client resumes from this record.
        device.fingerprint = binding.0.clone();
        device.fingerprint_provider = binding.1.clone();
        let mut client = Self::with_installed_storage(config, device, transport, storage.clone())?;
        Arc::get_mut(&mut client.0).ok_or(Error::Storage)?.installed = Some(storage.clone());
        match storage.restore(binding.0.as_deref(), binding.1.as_deref()) {
            Ok(Some((claims, anchor, keys))) => {
                *client.0.keys.lock().map_err(|_| Error::Storage)? = keys;
                let mut state = client.0.state.lock().map_err(|_| Error::Storage)?;
                state.claims = Some(claims);
                state.anchor = Some(anchor);
                state.restored = true;
            }
            Ok(None) => {}
            Err(_) => {
                let version = storage.clear_cached(false, false)?;
                client
                    .0
                    .state
                    .lock()
                    .map_err(|_| Error::Storage)?
                    .storage_version = version;
            }
        }
        let has_credential = client
            .0
            .state
            .lock()
            .map_err(|_| Error::Storage)?
            .credential
            .is_some();
        if has_credential && !storage.activation_pending()? {
            let cancel = client.0.transport.owner_cancel.clone();
            match client.refresh_with_cancel(&cancel).await {
                Ok(_) | Err(Error::Transient { .. }) => {}
                Err(error) => {
                    let _ = client.close().await;
                    return Err(error);
                }
            }
        }
        let weak = Arc::downgrade(&client.0);
        let cancel = client.0.transport.owner_cancel.clone();
        let worker = tokio::spawn(async move {
            loop {
                tokio::select! {biased;_=cancel.cancelled()=>break,()=tokio::time::sleep(Duration::from_secs(1))=>{}}
                let Some(inner) = weak.upgrade() else {
                    break;
                };
                let client = Client(inner);
                if client.0.closed.load(Ordering::Acquire) {
                    break;
                }
                let _ = client.refresh_if_needed(&cancel).await;
                if let Ok(state) = client.0.state.lock() {
                    let _ = client
                        .0
                        .installed
                        .as_ref()
                        .expect("installed worker")
                        .checkpoint(state.anchor.as_ref(), false);
                }
            }
        });
        *client.0.worker.lock().map_err(|_| Error::Storage)? = Some(worker);
        Ok(client)
    }
    /// Deliberately abandon an uncertain activation only after reconciling its outcome.
    pub fn resolve_pending_activation(&self) -> Result<()> {
        let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
        let storage = self.0.installed.as_ref().ok_or(Error::Configuration)?;
        state.storage_version = storage.clear_cached(true, false)?;
        state.generation = state.generation.wrapping_add(1);
        state.claims = None;
        state.anchor = None;
        Ok(())
    }
    /// Cancel owned transport and scheduling, settle serialized work, checkpoint, release the lease.
    pub async fn close(&self) -> Result<()> {
        let _close = self.0.close_serial.lock().await;
        if self.0.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.0.transport.owner_cancel.cancel();
        let worker = self.0.worker.lock().map_err(|_| Error::Storage)?.take();
        if let Some(worker) = worker {
            let _ = worker.await;
        }
        let _serial = self.0.serial.lock().await;
        if let Some(storage) = &self.0.installed {
            let checkpoint = self
                .0
                .state
                .lock()
                .map_err(|_| Error::Storage)
                .and_then(|state| storage.checkpoint(state.anchor.as_ref(), true));
            storage.close();
            checkpoint
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Access;
    use crate::Cancellation;
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "orbit-installed-{}",
                Device::new_installation().unwrap().installation_id
            )))
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            if self.0.exists() {
                std::fs::remove_dir_all(&self.0).unwrap();
            }
        }
    }
    #[derive(Clone)]
    struct TestApp {
        api_origin: String,
        application_id: String,
        environment_id: String,
    }
    fn app() -> TestApp {
        TestApp {
            api_origin: "https://orbit.example.test".into(),
            application_id: "app".into(),
            environment_id: "test".into(),
        }
    }
    fn app_key(app: &TestApp) -> AppKey {
        use base64::Engine;
        let origin =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(app.api_origin.as_bytes());
        AppKey::parse(&format!(
            "orbit_app_test_{origin}.{}.{}",
            app.application_id, app.environment_id
        ))
        .unwrap()
    }
    fn test_storage(
        app: &TestApp,
        origin: String,
        path: Option<&Path>,
    ) -> Result<InstalledStorage> {
        InstalledStorage::open(&app_key(app), None, None, origin, path)
    }
    fn store(dir: &Directory) -> InstalledStorage {
        let app = app();
        test_storage(&app, app.api_origin.clone(), Some(&dir.0)).unwrap()
    }
    #[test]
    fn binding_options_default_disable_and_accept_explicit_identity() {
        let key = app_key(&app());
        let machine = "a".repeat(64);
        assert_eq!(
            resolve_binding_with(&key, &MachineBinding::Automatic, || Ok(machine.clone())).unwrap(),
            (Some(machine.clone()), Some("machine_v1".into()))
        );
        assert_eq!(
            resolve_binding_with(&key, &MachineBinding::Disabled, || panic!(
                "must not read identity"
            ))
            .unwrap(),
            (None, None)
        );
        assert_eq!(
            resolve_binding_with(
                &key,
                &MachineBinding::Custom {
                    fingerprint: machine.clone(),
                    provider: "custom:fixture".into(),
                },
                || panic!("custom identity must not read native identity"),
            )
            .unwrap(),
            (Some(machine), Some("custom:fixture".into()))
        );
        assert!(matches!(
            resolve_binding_with(&key, &MachineBinding::Automatic, || Err(Error::Denied {
                code: "device_identity_unavailable".into(),
                request_id: None,
            })),
            Ok((None, None))
        ));
    }

    #[test]
    fn changed_binding_rotates_installation_and_clears_old_authority() {
        let dir = Directory::new();
        let key = app_key(&app());
        let old_fingerprint = "a".repeat(64);
        let old_provider = "custom:old".to_owned();
        let first = InstalledStorage::open(
            &key,
            Some(old_fingerprint),
            Some(old_provider),
            key.api_origin().to_owned(),
            Some(&dir.0),
        )
        .unwrap();
        let old_id = first.identity().unwrap().1.installation_id;
        let (version, _) = first.load().unwrap();
        first
            .save(
                version,
                StoredCredential {
                    application_id: key.application_id().into(),
                    environment_id: key.environment_id().into(),
                    activation_id: "activation".into(),
                    licence_id: "licence".into(),
                    installation_id: old_id.clone(),
                    credential: "a".repeat(43),
                    credential_expires_at: None,
                    fingerprint: Some("a".repeat(64)),
                    fingerprint_provider: Some("custom:old".into()),
                },
            )
            .unwrap();
        first
            .prepare_activation(ActivationPrincipal::Key("pending-key"), None, None, "")
            .unwrap();
        let now = clock::wall().unwrap();
        let corpus: serde_json::Value = serde_json::from_slice(
            &std::fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/sdk/grants.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let mut state = first.0.lock().unwrap();
        let mut record = state.record.clone();
        record.access = Some(Cache {
            jws: "signed-grant".into(),
            jwks: serde_json::from_value(corpus["jwks"].clone()).unwrap(),
            licence_expires_at: None,
            received_server_time: now,
            received_wall_time: now,
            server_high_water: now,
            wall_high_water: now,
        });
        state.commit(record).unwrap();
        drop(state);
        drop(first);

        let reopened = InstalledStorage::open(
            &key,
            Some("b".repeat(64)),
            Some("custom:new".into()),
            key.api_origin().into(),
            Some(&dir.0),
        )
        .unwrap();
        let state = reopened.0.lock().unwrap();
        assert_ne!(state.record.installation.id, old_id);
        assert!(state.record.credential.is_none());
        assert!(state.record.access.is_none());
        assert!(state.record.pending_activation.is_none());
        assert_eq!(
            state.record.installation.fingerprint.as_deref(),
            Some("b".repeat(64).as_str())
        );
        assert_eq!(
            state.record.installation.fingerprint_provider.as_deref(),
            Some("custom:new")
        );
    }
    impl Client {
        async fn open_with_transport(
            app: TestApp,
            state_path: Option<&Path>,
            transport: Transport,
        ) -> Result<Client> {
            Client::open_parsed(
                app_key(&app),
                Options {
                    state_directory: state_path.map(Path::to_path_buf),
                    machine_binding: MachineBinding::Disabled,
                },
                (None, None),
                transport,
            )
            .await
        }
    }
    #[test]
    fn identity_scope_exclusive_lease_and_durable_initialization() {
        let dir = Directory::new();
        let first = store(&dir);
        let identity = first.identity().unwrap().1.installation_id;
        assert!(matches!(
            test_storage(&app(), app().api_origin, Some(&dir.0)),
            Err(Error::InstallationInUse)
        ));
        drop(first);
        let second = store(&dir);
        assert_eq!(identity, second.identity().unwrap().1.installation_id);
        drop(second);
        let mut changed = app();
        changed.application_id = "other".into();
        assert!(matches!(
            test_storage(&changed, changed.api_origin.clone(), Some(&dir.0)),
            Err(Error::CorruptState)
        ));
    }
    #[test]
    fn pending_activation_reuses_only_scoped_same_input_and_survives_reopen() {
        let dir = Directory::new();
        let first = store(&dir);
        let (id, _) = first
            .prepare_activation(
                ActivationPrincipal::Key("synthetic-purchase-key"),
                None,
                None,
                "",
            )
            .unwrap();
        let record = first.0.lock().unwrap().record.clone();
        let bytes = serde_json::to_vec(&record).unwrap();
        assert!(
            !String::from_utf8(bytes)
                .unwrap()
                .contains("synthetic-purchase-key")
        );
        assert!(matches!(
            first.prepare_activation(ActivationPrincipal::Key("different"), None, None, ""),
            Err(Error::PendingActivation)
        ));
        drop(first);
        let second = store(&dir);
        assert_eq!(
            id,
            second
                .prepare_activation(
                    ActivationPrincipal::Key("synthetic-purchase-key"),
                    None,
                    None,
                    ""
                )
                .unwrap()
                .0
        );
        assert!(
            second
                .prepare_activation(
                    ActivationPrincipal::Key("synthetic-purchase-key"),
                    None,
                    Some("a"),
                    ""
                )
                .is_err()
        );
        {
            let mut state = second.0.lock().unwrap();
            state.record.pending_activation.as_mut().unwrap().created_at =
                clock::wall().unwrap() - 86400;
        }
        assert!(matches!(
            second.prepare_activation(
                ActivationPrincipal::Key("synthetic-purchase-key"),
                None,
                None,
                ""
            ),
            Err(Error::PendingActivation)
        ));
        second.clear_cached(true, false).unwrap();
        assert_ne!(
            id,
            second
                .prepare_activation(ActivationPrincipal::Key("different"), None, None, "")
                .unwrap()
                .0
        );
    }
    #[test]
    fn format_two_rejects_unknown_missing_duplicate_and_oversized_fields() {
        let dir = Directory::new();
        let store = store(&dir);
        let record = store.0.lock().unwrap().record.clone();
        let value = serde_json::to_value(&record).unwrap();
        for field in value.as_object().unwrap().keys() {
            let mut invalid = value.clone();
            invalid.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<Record>(invalid).is_err(),
                "{field}"
            );
        }
        for section in ["scope", "installation"] {
            for field in value[section].as_object().unwrap().keys() {
                let mut invalid = value.clone();
                invalid[section].as_object_mut().unwrap().remove(field);
                assert!(
                    serde_json::from_value::<Record>(invalid).is_err(),
                    "{section}.{field}"
                );
            }
        }
        let json = serde_json::to_string(&record).unwrap();
        assert!(
            serde_json::from_str::<Record>(&json.replacen(
                "\"format\":2",
                "\"format\":2,\"format\":2",
                1
            ))
            .is_err()
        );
        assert!(
            serde_json::from_str::<Record>(&json.replacen(
                "\"fingerprint\":null",
                "\"fingerprint\":null,\"fingerprint\":null",
                1
            ))
            .is_err()
        );
        for (field, invalid) in [
            ("unknown", json!(true)),
            ("format", json!(1)),
            ("provider", json!("fallback")),
            ("generation", json!(u64::MAX)),
        ] {
            let mut changed = value.clone();
            changed[field] = invalid;
            assert!(serde_json::from_value::<Record>(changed).map_or(true, |r| {
                r.validate(&record.scope, &app_key(&app())).is_err()
            }));
        }
    }
    #[test]
    fn restored_clock_requires_consistent_nondecreasing_pairs() {
        let corpus: serde_json::Value = serde_json::from_slice(
            &std::fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/sdk/grants.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let cache = Cache {
            jws: "unused".into(),
            jwks: serde_json::from_value(corpus["jwks"].clone()).unwrap(),
            licence_expires_at: None,
            received_server_time: 1000,
            received_wall_time: 2000,
            server_high_water: 1060,
            wall_high_water: 2060,
        };
        assert_eq!(restored_time(&cache, 2100).unwrap(), 1100);
        assert!(restored_time(&cache, 2059).is_err());
        let mut rollback = cache.clone();
        rollback.server_high_water = 999;
        assert!(restored_time(&rollback, 2100).is_err());
        let mut mismatch = cache.clone();
        mismatch.wall_high_water = 2091;
        assert!(restored_time(&mismatch, 2100).is_err());
        assert!(restored_time(&cache, i64::MAX).is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn private_linux_rejects_permissions_links_missing_marker_state_and_renamed_ancestor() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
        let dir = Directory::new();
        let store = store(&dir);
        assert_eq!(std::fs::metadata(&dir.0).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            std::fs::metadata(dir.0.join("orbit-storage.json"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        drop(store);
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(test_storage(&app(), app().api_origin, Some(&dir.0)).is_err());
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::hard_link(dir.0.join("orbit-storage.json"), dir.0.join("alias")).unwrap();
        assert!(test_storage(&app(), app().api_origin, Some(&dir.0)).is_err());
        std::fs::remove_file(dir.0.join("alias")).unwrap();
        std::fs::remove_file(dir.0.join("orbit-storage.json")).unwrap();
        assert!(matches!(
            test_storage(&app(), app().api_origin, Some(&dir.0)),
            Err(Error::CorruptState)
        ));
        symlink("/dev/null", dir.0.join("orbit-storage.json")).unwrap();
        assert!(test_storage(&app(), app().api_origin, Some(&dir.0)).is_err());
        let second = Directory::new();
        let child = second.0.join("child");
        let storage = test_storage(&app(), app().api_origin, Some(&child)).unwrap();
        std::fs::rename(&child, second.0.join("moved")).unwrap();
        std::fs::create_dir(&child).unwrap();
        assert!(
            storage
                .prepare_activation(ActivationPrincipal::Key("key"), None, None, "")
                .is_err()
        );
    }
    #[cfg(feature = "local-development")]
    fn signed_reply(installation: &str, offline: bool, refresh: bool) -> String {
        signed_reply_with_binding(installation, offline, refresh, "none", None)
    }
    #[cfg(feature = "local-development")]
    fn signed_reply_with_binding(
        installation: &str,
        offline: bool,
        refresh: bool,
        binding_mode: &str,
        fingerprint_provider: Option<&str>,
    ) -> String {
        use jsonwebtoken::{Algorithm, EncodingKey, Header};
        jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER
            .install_default()
            .ok();
        let now = clock::wall().unwrap();
        let expires = now + if offline { 3600 } else { 300 };
        let claims = json!({"iss":"https://orbit.example.test","aud":"orbit:app:test","sub":"licence","jti":"installed_fixture","iat":now,"nbf":now,"exp":expires,"application_id":"app","environment_id":"test","activation_id":"activation","installation_id":installation,"binding_mode":"none","policy_version":1,"entitlements":{"export":true},"refresh_after":now+if offline {900}else{60},"offline_allowed":offline,"licence_expires_at":null});
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("orbit-access+jwt".into());
        header.kid = Some("test-key".into());
        let token = jsonwebtoken::encode(
            &header,
            &claims,
            &EncodingKey::from_ec_pem(include_bytes!("../tests/fixtures/es256-test-private.pem"))
                .unwrap(),
        )
        .unwrap();
        let date = time::OffsetDateTime::from_unix_timestamp(now).unwrap();
        let server = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            date.year(),
            u8::from(date.month()),
            date.day(),
            date.hour(),
            date.minute(),
            date.second()
        );
        json!({"activation_id":"activation","installation_id":installation,"credential":if refresh {None}else{Some("a".repeat(43))},"credential_expires_at":null,"grant":token,"server_time":server,"binding_mode":binding_mode,"fingerprint_provider":fingerprint_provider,"licence_expires_at":null,"secret_replay_expired":false}).to_string()
    }
    #[cfg(feature = "local-development")]
    fn jwks() -> serde_json::Value {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/sdk/grants.json");
        let corpus: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        corpus["jwks"].clone()
    }
    #[cfg(feature = "local-development")]
    async fn activated(
        dir: &Directory,
        fixture: &mut crate::transport::tests::Fixture,
        offline: bool,
    ) -> Client {
        let client = Client::open_with_transport(app(), Some(&dir.0), fixture.transport.clone())
            .await
            .unwrap();
        let activate = client.clone();
        let task = tokio::spawn(async move { activate.activate("synthetic-key").await });
        let request = fixture.next().await;
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["credential_mode"], "persistent");
        let installation = body["installation_id"].as_str().unwrap();
        request.respond(200, &signed_reply(installation, offline, false));
        let corpus: serde_json::Value = serde_json::from_slice(
            &std::fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/sdk/grants.json"),
            )
            .unwrap(),
        )
        .unwrap();
        fixture
            .next()
            .await
            .respond(200, &corpus["jwks"].to_string());
        assert_eq!(task.await.unwrap().unwrap().access, Access::Online);
        client
    }
    #[cfg(feature = "local-development")]
    async fn login_fixture_account(
        client: &Client,
        fixture: &mut crate::transport::tests::Fixture,
        username: &str,
    ) {
        let client = client.clone();
        let username_owned = username.to_owned();
        let task = tokio::spawn(async move {
            client
                .login(&username_owned, "account-password-marker")
                .await
        });
        let request = fixture.next().await;
        assert!(request.head.starts_with("POST /api/client/v1/sessions "));
        request.respond(
            200,
            &json!({"customer":{"id":username,"username":username,"email":format!("{username}@example.test"),"suspended":false,"created_at":"2026-01-01T00:00:00Z"},"session":"b".repeat(43),"expires_at":"2030-01-01T00:00:00Z"}).to_string(),
        );
        task.await.unwrap().unwrap();
    }

    #[cfg(feature = "local-development")]
    async fn fail_fixture_login(
        client: &Client,
        fixture: &mut crate::transport::tests::Fixture,
        username: &str,
    ) {
        let client = client.clone();
        let username_owned = username.to_owned();
        let task = tokio::spawn(async move {
            client
                .login(&username_owned, "account-password-marker")
                .await
        });
        fixture.next().await.respond(
            401,
            r#"{"error":{"code":"invalid_credentials","message":"Denied","request_id":"fixture"}}"#,
        );
        assert!(matches!(
            task.await.unwrap(),
            Err(Error::Denied { code, .. }) if code == "invalid_credentials"
        ));
    }

    #[cfg(feature = "local-development")]
    async fn lose_account_activation(
        client: &Client,
        fixture: &mut crate::transport::tests::Fixture,
    ) -> String {
        let client = client.clone();
        let task = tokio::spawn(async move { client.activate_account("licence").await });
        let mut operation = None;
        for _ in 0..3 {
            let request = fixture.next().await;
            assert!(request.head.starts_with("POST /api/client/v1/activations "));
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(body["licence_id"], "licence");
            let current = body["idempotency_key"].as_str().unwrap().to_owned();
            assert!(operation.as_ref().is_none_or(|value| value == &current));
            operation = Some(current);
            request.respond(503, crate::transport::tests::TRANSIENT);
        }
        assert!(matches!(task.await.unwrap(), Err(Error::Transient { .. })));
        operation.unwrap()
    }

    #[cfg(feature = "local-development")]
    fn assert_account_secrets_not_persisted(directory: &Directory) {
        let bytes = std::fs::read(directory.0.join("orbit-storage.json")).unwrap();
        let state = String::from_utf8(bytes).unwrap();
        assert!(!state.contains("account-password-marker"));
        assert!(!state.contains(&"b".repeat(43)));
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn uncertain_account_activation_retries_only_for_the_same_customer() {
        let directory = Directory::new();
        let mut first_fixture = crate::transport::tests::Fixture::new().await;
        let client =
            Client::open_with_transport(app(), Some(&directory.0), first_fixture.transport.clone())
                .await
                .unwrap();
        login_fixture_account(&client, &mut first_fixture, "alice").await;
        let operation = lose_account_activation(&client, &mut first_fixture).await;
        first_fixture.assert_idle();
        client.close().await.unwrap();
        assert_account_secrets_not_persisted(&directory);
        let retry_transport = first_fixture.fresh_transport();
        let client = Client::open_with_transport(app(), Some(&directory.0), retry_transport)
            .await
            .unwrap();
        fail_fixture_login(&client, &mut first_fixture, "alice").await;
        login_fixture_account(&client, &mut first_fixture, "alice").await;
        let activating = client.clone();
        let task = tokio::spawn(async move { activating.activate_account("licence").await });
        let request = first_fixture.next().await;
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["idempotency_key"], operation);
        assert_eq!(body["customer_session"], "b".repeat(43));
        let installation = body["installation_id"].as_str().unwrap();
        request.respond(200, &signed_reply(installation, false, false));
        first_fixture.next().await.respond(200, &jwks().to_string());
        assert_eq!(task.await.unwrap().unwrap().access, Access::Online);
        assert_account_secrets_not_persisted(&directory);
        client.close().await.unwrap();
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn uncertain_account_activation_rejects_a_different_customer_without_request() {
        let directory = Directory::new();
        let mut first_fixture = crate::transport::tests::Fixture::new().await;
        let client =
            Client::open_with_transport(app(), Some(&directory.0), first_fixture.transport.clone())
                .await
                .unwrap();
        login_fixture_account(&client, &mut first_fixture, "alice").await;
        lose_account_activation(&client, &mut first_fixture).await;
        client.close().await.unwrap();
        assert_account_secrets_not_persisted(&directory);
        let retry_transport = first_fixture.fresh_transport();
        let client = Client::open_with_transport(app(), Some(&directory.0), retry_transport)
            .await
            .unwrap();
        login_fixture_account(&client, &mut first_fixture, "bob").await;
        assert!(matches!(
            client.activate_account("licence").await,
            Err(Error::PendingActivation)
        ));
        first_fixture.assert_idle();
        assert_account_secrets_not_persisted(&directory);
        client.close().await.unwrap();
    }
    #[cfg(feature = "local-development")]
    async fn open_with_binding(
        app: TestApp,
        state_path: &Path,
        transport: Transport,
        fingerprint: String,
        provider: String,
    ) -> Result<Client> {
        Client::open_parsed(
            app_key(&app),
            Options {
                state_directory: Some(state_path.to_path_buf()),
                machine_binding: MachineBinding::Custom {
                    fingerprint: fingerprint.clone(),
                    provider: provider.clone(),
                },
            },
            (Some(fingerprint), Some(provider)),
            transport,
        )
        .await
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn runtime_accepts_unbound_claims_only_with_matching_response_provider_and_mode() {
        use crate::transport::tests::Fixture;
        for (mode, provider, accepted) in [
            ("none", Some("custom:fixture"), true),
            ("hwid", Some("custom:fixture"), false),
            ("none", Some("custom:other"), false),
        ] {
            let dir = Directory::new();
            let mut fixture = Fixture::new().await;
            let client = open_with_binding(
                app(),
                &dir.0,
                fixture.transport.clone(),
                "a".repeat(64),
                "custom:fixture".into(),
            )
            .await
            .unwrap();
            let activating = client.clone();
            let task = tokio::spawn(async move { activating.activate("synthetic-key").await });
            let request = fixture.next().await;
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(body["fingerprint_provider"], "custom:fixture");
            request.respond(
                200,
                &signed_reply_with_binding(
                    body["installation_id"].as_str().unwrap(),
                    false,
                    false,
                    mode,
                    provider,
                ),
            );
            if provider == Some("custom:fixture") {
                fixture.next().await.respond(200, &jwks().to_string());
            }
            let result = task.await.unwrap();
            assert_eq!(
                result.is_ok(),
                accepted,
                "mode={mode}, provider={provider:?}"
            );
            if let Err(error) = result {
                assert!(matches!(error, Error::InvalidResponse));
            }
            client.close().await.unwrap();
        }
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn ensure_access_prompts_only_for_missing_activation() {
        use crate::transport::tests::Fixture;
        let dir = Directory::new();
        let mut fixture = Fixture::new().await;
        let client = Client::open_with_transport(app(), Some(&dir.0), fixture.transport.clone())
            .await
            .unwrap();
        let prompted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let callback_prompted = prompted.clone();
        let ensuring = client.clone();
        let task = tokio::spawn(async move {
            ensuring
                .ensure_access("export", || {
                    callback_prompted.store(true, Ordering::Relaxed);
                    Some("synthetic-key".into())
                })
                .await
        });
        let request = fixture.next().await;
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let id = body["idempotency_key"].as_str().unwrap();
        assert!(id.len() >= 16);
        request.respond(
            200,
            &signed_reply(body["installation_id"].as_str().unwrap(), false, false),
        );
        fixture.next().await.respond(200, &jwks().to_string());
        assert_eq!(task.await.unwrap().unwrap().access, Access::Online);
        assert!(prompted.load(Ordering::Relaxed));
        let mut prompted_again = false;
        assert!(matches!(
            client
                .ensure_access("missing", || {
                    prompted_again = true;
                    Some("unexpected-key".into())
                })
                .await,
            Err(Error::FeatureUnavailable)
        ));
        assert!(!prompted_again);
        client.close().await.unwrap();
    }
    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn online_first_restart_transient_offline_and_strict_online() {
        use crate::transport::tests::{Fixture, TRANSIENT};
        for offline in [false, true] {
            let dir = Directory::new();
            let mut fixture = Fixture::new().await;
            let client = activated(&dir, &mut fixture, offline).await;
            let expiry = client.snapshot().unwrap().expires_at;
            client.close().await.unwrap();
            drop(client);
            // Each open owns cancellation independently, even with a supplied transport clone.
            let mut transport = fixture.transport.clone();
            transport.owner_cancel = Cancellation::new();
            let path = dir.0.clone();
            let opening = tokio::spawn(async move {
                Client::open_with_transport(app(), Some(&path), transport).await
            });
            for _ in 0..3 {
                let request = fixture.next().await;
                assert!(request.head.contains("/validate "));
                request.respond(503, TRANSIENT);
            }
            let reopened = opening.await.unwrap().unwrap();
            let mut prompted = false;
            let ensured = reopened
                .ensure_access("export", || {
                    prompted = true;
                    Some("unexpected-key".into())
                })
                .await;
            if offline {
                assert_eq!(ensured.unwrap().access, Access::Offline);
                assert!(!prompted);
                assert_eq!(reopened.snapshot().unwrap().expires_at, expiry);
            } else {
                assert!(matches!(ensured, Err(Error::Transient { .. })));
                assert!(!prompted);
            }
            fixture.assert_idle();
            reopened.close().await.unwrap();
        }
    }
    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn malformed_activation_preserves_retry_identity_and_close_cancels_inflight() {
        use crate::transport::tests::Fixture;
        let dir = Directory::new();
        let mut fixture = Fixture::new().await;
        let client = Client::open_with_transport(app(), Some(&dir.0), fixture.transport.clone())
            .await
            .unwrap();
        let first = client.clone();
        let task = tokio::spawn(async move { first.activate("synthetic").await });
        let request = fixture.next().await;
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let operation = body["idempotency_key"].clone();
        request.respond(200, "{}");
        assert!(matches!(task.await.unwrap(), Err(Error::InvalidResponse)));
        assert!(matches!(
            client.activate("different").await,
            Err(Error::PendingActivation)
        ));
        let second = client.clone();
        let task = tokio::spawn(async move { second.activate("synthetic").await });
        let request = fixture.next().await;
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["idempotency_key"], operation);
        tokio::time::timeout(Duration::from_secs(2), client.close())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            task.await.unwrap(),
            Err(Error::Cancelled) | Err(Error::Closed)
        ));
        assert!(matches!(client.snapshot(), Err(Error::Closed)));
        let reopened =
            test_storage(&app(), fixture.transport.canonical_origin(), Some(&dir.0)).unwrap();
        assert_eq!(
            reopened
                .0
                .lock()
                .unwrap()
                .record
                .pending_activation
                .as_ref()
                .unwrap()
                .operation_id,
            operation.as_str().unwrap()
        );
        drop(request);
    }
    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn close_releases_lease_even_when_checkpoint_fails() {
        let dir = Directory::new();
        let mut fixture = crate::transport::tests::Fixture::new().await;
        let client = activated(&dir, &mut fixture, true).await;
        {
            let mut record = client.0.installed.as_ref().unwrap().0.lock().unwrap();
            record.record.access.as_mut().unwrap().wall_high_water = clock::wall().unwrap() + 120;
        }
        assert!(matches!(client.close().await, Err(Error::ClockUncertain)));
        let reopened =
            test_storage(&app(), fixture.transport.canonical_origin(), Some(&dir.0)).unwrap();
        assert!(reopened.0.lock().unwrap().record.access.is_none());
    }
    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn fresh_persistent_reply_requires_explicit_null_and_external_rebind_is_allowed() {
        use crate::transport::tests::Fixture;
        for expiry in [
            None,
            Some(json!("2030-01-01T00:00:00Z")),
            Some(serde_json::Value::Null),
        ] {
            let dir = Directory::new();
            let mut fixture = Fixture::new().await;
            let client =
                Client::open_with_transport(app(), Some(&dir.0), fixture.transport.clone())
                    .await
                    .unwrap();
            let activating = client.clone();
            let task = tokio::spawn(async move {
                activating
                    .activate_with_previous(
                        "synthetic",
                        Some(&"p".repeat(43)),
                        Some("external_rebind_123"),
                    )
                    .await
            });
            let request = fixture.next().await;
            let input: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(input["previous_credential"], "p".repeat(43));
            let mut reply: serde_json::Value = serde_json::from_str(&signed_reply(
                input["installation_id"].as_str().unwrap(),
                true,
                false,
            ))
            .unwrap();
            let valid = expiry.as_ref().is_some_and(serde_json::Value::is_null);
            if let Some(expiry) = expiry {
                reply["credential_expires_at"] = expiry;
            } else {
                reply
                    .as_object_mut()
                    .unwrap()
                    .remove("credential_expires_at");
            }
            request.respond(200, &reply.to_string());
            if valid {
                let corpus: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(
                        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                            .join("../../contracts/sdk/grants.json"),
                    )
                    .unwrap(),
                )
                .unwrap();
                fixture
                    .next()
                    .await
                    .respond(200, &corpus["jwks"].to_string());
                assert!(task.await.unwrap().is_ok());
                assert!(
                    client
                        .0
                        .installed
                        .as_ref()
                        .unwrap()
                        .0
                        .lock()
                        .unwrap()
                        .record
                        .pending_activation
                        .is_none()
                );
            } else {
                assert!(matches!(task.await.unwrap(), Err(Error::InvalidResponse)));
                assert!(
                    client
                        .0
                        .installed
                        .as_ref()
                        .unwrap()
                        .0
                        .lock()
                        .unwrap()
                        .record
                        .pending_activation
                        .is_some()
                );
            }
            client.close().await.unwrap();
        }
    }
    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn validation_cannot_rotate_persistent_mode_and_denial_clears_durable_authority() {
        use crate::transport::tests::Fixture;
        let dir = Directory::new();
        let mut fixture = Fixture::new().await;
        let client = activated(&dir, &mut fixture, true).await;
        let refreshing = client.clone();
        let task = tokio::spawn(async move { refreshing.refresh().await });
        let request = fixture.next().await;
        let input: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let mut reply: serde_json::Value = serde_json::from_str(&signed_reply(
            input["installation_id"].as_str().unwrap(),
            true,
            true,
        ))
        .unwrap();
        reply["credential"] = json!("b".repeat(43));
        request.respond(200, &reply.to_string());
        assert!(matches!(task.await.unwrap(), Err(Error::InvalidResponse)));
        {
            let store = client.0.installed.as_ref().unwrap().0.lock().unwrap();
            assert!(store.record.access.is_none());
            assert_eq!(
                store.record.credential.as_ref().unwrap().bearer,
                "a".repeat(43)
            );
        }
        let refreshing = client.clone();
        let task = tokio::spawn(async move { refreshing.refresh().await });
        fixture.next().await.respond(
            403,
            r#"{"error":{"code":"licence_revoked","message":"Denied","request_id":"fixture"}}"#,
        );
        assert!(matches!(task.await.unwrap(), Err(Error::Denied { .. })));
        {
            let store = client.0.installed.as_ref().unwrap().0.lock().unwrap();
            assert!(store.record.access.is_none());
            assert!(store.record.credential.is_none());
        }
        client.close().await.unwrap();
    }
    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn protected_checks_do_not_write_state_and_dropped_client_has_no_worker_cycle() {
        let dir = Directory::new();
        let mut fixture = crate::transport::tests::Fixture::new().await;
        let client = activated(&dir, &mut fixture, true).await;
        let storage = client.0.installed.as_ref().unwrap();
        let checkpoint = storage.0.lock().unwrap().checkpoint;
        for _ in 0..20 {
            client.require_access("export").await.unwrap();
        }
        assert_eq!(checkpoint, storage.0.lock().unwrap().checkpoint);
        fixture.assert_idle();
        drop(client);
        let reopened =
            test_storage(&app(), fixture.transport.canonical_origin(), Some(&dir.0)).unwrap();
        assert!(reopened.0.lock().unwrap().record.credential.is_some());
    }
    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn invalid_cached_signature_never_grants_offline_but_keeps_online_recovery_credential() {
        use crate::transport::tests::{Fixture, TRANSIENT};
        let dir = Directory::new();
        let mut fixture = Fixture::new().await;
        let client = activated(&dir, &mut fixture, true).await;
        {
            let storage = client.0.installed.as_ref().unwrap();
            let mut state = storage.0.lock().unwrap();
            let mut record = state.record.clone();
            let cache = record.access.as_mut().unwrap();
            let (unsigned, _) = cache.jws.rsplit_once('.').unwrap();
            use base64::Engine;
            cache.jws = format!(
                "{}.{}",
                unsigned,
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0; 64])
            );
            state.commit(record).unwrap();
        }
        client.close().await.unwrap();
        let mut transport = fixture.transport.clone();
        transport.owner_cancel = Cancellation::new();
        let path = dir.0.clone();
        let opening = tokio::spawn(async move {
            Client::open_with_transport(app(), Some(&path), transport).await
        });
        for _ in 0..3 {
            fixture.next().await.respond(503, TRANSIENT);
        }
        let reopened = opening.await.unwrap().unwrap();
        assert!(matches!(
            reopened.require_access("export").await,
            Err(Error::Transient { .. })
        ));
        let storage = reopened.0.installed.as_ref().unwrap();
        {
            let state = storage.0.lock().unwrap();
            assert!(state.record.access.is_none());
            assert!(state.record.credential.is_some());
        }
        reopened.close().await.unwrap();
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn oversized_or_deleted_established_state_is_not_reinitialized() {
        let dir = Directory::new();
        let storage = store(&dir);
        drop(storage);
        let path = dir.0.join("orbit-storage.json");
        std::fs::write(&path, vec![b' '; MAX_BYTES + 1]).unwrap();
        assert!(matches!(
            test_storage(&app(), app().api_origin, Some(&dir.0)),
            Err(Error::CorruptState)
        ));
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            (MAX_BYTES + 1) as u64
        );
    }
    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn closing_one_client_does_not_cancel_another_cloned_transport() {
        let first_dir = Directory::new();
        let second_dir = Directory::new();
        let mut fixture = crate::transport::tests::Fixture::new().await;
        let first =
            Client::open_with_transport(app(), Some(&first_dir.0), fixture.transport.clone())
                .await
                .unwrap();
        let second = activated(&second_dir, &mut fixture, true).await;
        first.close().await.unwrap();
        let refreshing = second.clone();
        let task = tokio::spawn(async move { refreshing.refresh().await });
        let request = fixture.next().await;
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        request.respond(
            200,
            &signed_reply(body["installation_id"].as_str().unwrap(), true, true),
        );
        assert_eq!(task.await.unwrap().unwrap().access, Access::Online);
        second.close().await.unwrap();
    }
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_rejects_existing_inherited_acl_and_hardlinked_ciphertext_without_repair() {
        let inherited = Directory::new();
        std::fs::create_dir(&inherited.0).unwrap();
        assert!(test_storage(&app(), app().api_origin, Some(&inherited.0)).is_err());
        assert!(!inherited.0.join("orbit-storage.lock").exists());
        let private = Directory::new();
        let storage = store(&private);
        drop(storage);
        let state = private.0.join(orbit_sdk_native::STORAGE_CIPHERTEXT_FILE);
        let original = std::fs::read(&state).unwrap();
        std::fs::hard_link(&state, private.0.join("linked.bin")).unwrap();
        assert!(test_storage(&app(), app().api_origin, Some(&private.0)).is_err());
        assert_eq!(std::fs::read(&state).unwrap(), original);
        std::fs::remove_file(private.0.join("linked.bin")).unwrap();
        let reopened = store(&private);
        assert!(reopened.load().unwrap().1.is_none());
    }
    fn seed_credential(storage: &InstalledStorage) {
        let (config, device) = storage.identity().unwrap();
        storage
            .save(
                0,
                StoredCredential {
                    application_id: config.application_id,
                    environment_id: config.environment_id,
                    activation_id: "activation".into(),
                    licence_id: "licence".into(),
                    installation_id: device.installation_id,
                    credential: "a".repeat(43),
                    credential_expires_at: None,
                    fingerprint: None,
                    fingerprint_provider: None,
                },
            )
            .unwrap();
    }
    fn fault(storage: &InstalledStorage, stage: u8, crash: bool) {
        let state = storage.0.lock().unwrap();
        let fault = &state.backend.as_ref().unwrap().fault;
        fault.stage.store(stage, Ordering::Relaxed);
        fault.crash.store(crash, Ordering::Relaxed);
    }
    #[test]
    fn incomplete_invalidation_rejects_reopen_at_every_failed_write_stage() {
        // After durable fence, temporary flush, replacement flush, and an
        // attempted fence clear. Failure must never make old authority usable.
        for stage in 1..=4 {
            let directory = Directory::new();
            let storage = store(&directory);
            seed_credential(&storage);
            fault(&storage, stage, false);
            assert!(matches!(storage.invalidate(), Err(Error::Storage)));
            assert!(matches!(storage.load(), Err(Error::Storage)));
            drop(storage);
            assert_eq!(
                std::fs::read(directory.0.join("orbit-storage.lock")).unwrap(),
                WRITE_PENDING
            );
            assert!(matches!(
                test_storage(&app(), app().api_origin, Some(&directory.0)),
                Err(Error::CorruptState)
            ));
        }
        let directory = Directory::new();
        let storage = store(&directory);
        seed_credential(&storage);
        storage.invalidate().unwrap();
        drop(storage);
        assert!(
            std::fs::read(directory.0.join("orbit-storage.lock"))
                .unwrap()
                .is_empty()
        );
        assert!(store(&directory).load().unwrap().1.is_none());
    }
    #[test]
    fn write_interruption_child() {
        let Some(path) = std::env::var_os("ORBIT_RUST_WRITE_CRASH_DIRECTORY") else {
            return;
        };
        let stage = std::env::var("ORBIT_RUST_WRITE_CRASH_STAGE")
            .unwrap()
            .parse::<u8>()
            .unwrap();
        let storage = test_storage(&app(), app().api_origin, Some(Path::new(&path))).unwrap();
        fault(&storage, stage, true);
        let _ = storage.invalidate();
        panic!("write crash point was not reached");
    }
    #[test]
    fn process_exit_during_invalidation_leaves_a_durable_recovery_fence() {
        for stage in 1..=3 {
            let directory = Directory::new();
            let storage = store(&directory);
            seed_credential(&storage);
            drop(storage);
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "installed::tests::write_interruption_child",
                    "--nocapture",
                ])
                .env("ORBIT_RUST_WRITE_CRASH_DIRECTORY", &directory.0)
                .env("ORBIT_RUST_WRITE_CRASH_STAGE", stage.to_string())
                .output()
                .unwrap();
            assert_eq!(
                child.status.code(),
                Some(42),
                "crash stage {stage} was not exercised"
            );
            assert_eq!(
                std::fs::read(directory.0.join("orbit-storage.lock")).unwrap(),
                WRITE_PENDING
            );
            assert!(matches!(
                test_storage(&app(), app().api_origin, Some(&directory.0)),
                Err(Error::CorruptState)
            ));
        }
    }
    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn lost_replacement_restart_fences_boot_worker_and_explicit_old_bearer_refresh() {
        let directory = Directory::new();
        let mut fixture = crate::transport::tests::Fixture::new().await;
        let client = activated(&directory, &mut fixture, true).await;
        let cancel = Cancellation::new();
        let cancelling = cancel.clone();
        let replacing = client.clone();
        let task = tokio::spawn(async move {
            replacing
                .activate_with_cancel("replacement-key", "", &cancel)
                .await
        });
        let request = fixture.next().await;
        let input: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let operation = input["idempotency_key"].clone();
        // The server has the replacement request; its committed reply is lost.
        // The old bearer would now be revoked if any unrelated validation ran.
        cancelling.cancel();
        assert!(matches!(task.await.unwrap(), Err(Error::Cancelled)));
        drop(request);
        assert!(matches!(
            client.refresh().await,
            Err(Error::PendingActivation)
        ));
        client.close().await.unwrap();
        let reopened = tokio::time::timeout(
            Duration::from_secs(2),
            Client::open_with_transport(app(), Some(&directory.0), fixture.transport.clone()),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(
            reopened.refresh().await,
            Err(Error::PendingActivation)
        ));
        assert!(matches!(
            reopened.require_access("export").await,
            Err(Error::PendingActivation)
        ));
        tokio::time::sleep(Duration::from_millis(1100)).await;
        fixture.assert_idle();
        {
            let state = reopened.0.installed.as_ref().unwrap().0.lock().unwrap();
            assert_eq!(
                state
                    .record
                    .pending_activation
                    .as_ref()
                    .unwrap()
                    .operation_id,
                operation.as_str().unwrap()
            );
            assert_eq!(
                state.record.credential.as_ref().unwrap().bearer,
                "a".repeat(43)
            );
        }
        let retrying = reopened.clone();
        let task = tokio::spawn(async move { retrying.activate("replacement-key").await });
        let request = fixture.next().await;
        let input: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(input["idempotency_key"], operation);
        let mut reply: serde_json::Value = serde_json::from_str(&signed_reply(
            input["installation_id"].as_str().unwrap(),
            true,
            false,
        ))
        .unwrap();
        reply["credential"] = json!("b".repeat(43));
        request.respond(200, &reply.to_string());
        let corpus: serde_json::Value = serde_json::from_slice(
            &std::fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/sdk/grants.json"),
            )
            .unwrap(),
        )
        .unwrap();
        fixture
            .next()
            .await
            .respond(200, &corpus["jwks"].to_string());
        assert_eq!(task.await.unwrap().unwrap().access, Access::Online);
        {
            let state = reopened.0.installed.as_ref().unwrap().0.lock().unwrap();
            assert!(state.record.pending_activation.is_none());
            assert_eq!(
                state.record.credential.as_ref().unwrap().bearer,
                "b".repeat(43)
            );
        }
        reopened.close().await.unwrap();
    }
}
