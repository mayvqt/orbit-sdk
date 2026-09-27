#[cfg(test)]
use crate::MemoryStorage;
use crate::{
    Cancellation, Error, Result, Storage, StoredCredential, Transport,
    accounts::Session,
    clock::{self, Anchor},
    grants::{self, Claims, Expected, Keys},
    sessions::{self, Expected as SessionExpected, SessionGrant, SessionKeys},
};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

#[derive(Clone)]
pub(crate) struct Config {
    pub application_id: String,
    pub environment_id: String,
    pub issuer: String,
}
#[derive(Clone)]
pub struct Device {
    pub installation_id: String,
    pub fingerprint: Option<String>,
    pub fingerprint_provider: Option<String>,
}
impl Device {
    pub fn new_installation() -> Result<Self> {
        use base64::Engine;
        let mut bytes = [0; 24];
        aws_lc_rs::rand::fill(&mut bytes).map_err(|_| Error::Configuration)?;
        Ok(Self {
            installation_id: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes),
            fingerprint: None,
            fingerprint_provider: None,
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Access {
    Denied,
    Online,
    Offline,
    RefreshRequired,
    Expired,
}
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub access: Access,
    pub entitlements: BTreeMap<String, bool>,
    pub expires_at: Option<std::time::SystemTime>,
    pub next_check_at: Option<std::time::SystemTime>,
    pub credential_expires_at: Option<std::time::SystemTime>,
    pub reauthentication_required: bool,
    pub offline_allowed: bool,
    pub offline_file_mode: bool,
    pub remaining_offline: Duration,
    pub session: Option<SessionMetadata>,
    /// Newer application version reported by the last online check, when
    /// the licence policy offers one.
    pub update_available: Option<String>,
}
impl Snapshot {
    pub fn has_feature(&self, feature: &str) -> bool {
        self.entitlements.get(feature).copied().unwrap_or(false)
    }
}
/// Read-only display metadata for the current connected floating seat.
/// The signed session grant and its identifier are never persisted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionMetadata {
    id: String,
    sequence: u64,
    expires_at: std::time::SystemTime,
    refresh_after: std::time::SystemTime,
}
impl SessionMetadata {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn expires_at(&self) -> std::time::SystemTime {
        self.expires_at
    }
    pub fn refresh_after(&self) -> std::time::SystemTime {
        self.refresh_after
    }
}
pub(crate) struct SessionRuntime {
    pub(crate) metadata: SessionMetadata,
    pub(crate) grant: SessionGrant,
    pub(crate) anchor: Anchor,
    pub(crate) pending_sequence: Option<u64>,
}
pub(crate) struct State {
    pub(crate) generation: u64,
    pub(crate) storage_version: u64,
    pub(crate) account: Option<Session>,
    pub(crate) credential: Option<StoredCredential>,
    pub(crate) claims: Option<Claims>,
    pub(crate) anchor: Option<Anchor>,
    pub(crate) offline: Option<crate::offline::Runtime>,
    pub(crate) session_policy_known: bool,
    pub(crate) session_required: bool,
    pub(crate) session_disabled: bool,
    pub(crate) session: Option<SessionRuntime>,
    pub(crate) pending_session_id: Option<String>,
    pub(crate) pending_session_since: Option<Instant>,
    pub(crate) session_retry_deadline: Option<Instant>,
    pub(crate) session_licence_expires_at: Option<i64>,
    pub(crate) restored: bool,
    pub(crate) update_available: Option<String>,
    transient: bool,
    retry_deadline: Option<Instant>,
    last_failure: Option<Error>,
}
pub(crate) struct Inner {
    pub(crate) config: Config,
    pub(crate) app_key: Option<crate::AppKey>,
    pub(crate) device: Device,
    pub(crate) transport: Transport,
    pub(crate) storage: Arc<dyn Storage>,
    pub(crate) state: Mutex<State>,
    pub(crate) serial: tokio::sync::Mutex<()>,
    pub(crate) keys: Mutex<Keys>,
    pub(crate) session_keys: Mutex<Option<SessionKeys>>,
    pub(crate) offline_keys: Option<Keys>,
    pub(crate) app_version: Option<String>,
    pub(crate) installed: Option<Arc<crate::installed::InstalledStorage>>,
    pub(crate) worker: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub(crate) close_serial: tokio::sync::Mutex<()>,
    pub(crate) closed: std::sync::atomic::AtomicBool,
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.transport.owner_cancel.cancel();
        if let Some(storage) = &self.installed {
            if let Ok(state) = self.state.get_mut() {
                if let Some(offline) = state.offline.as_mut().filter(|item| item.authorized) {
                    let _ = storage.checkpoint_offline(offline, true);
                } else {
                    let _ = storage.checkpoint(state.anchor.as_ref(), true);
                }
            }
            storage.close();
        }
    }
}
#[derive(Clone)]
pub struct Client(pub(crate) Arc<Inner>);
struct SessionAttemptGuard {
    client: Client,
    saved: StoredCredential,
    id: String,
    generation: u64,
    armed: bool,
}
impl Drop for SessionAttemptGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(mut state) = self.client.0.state.lock()
            && state.generation == self.generation
        {
            state.session = None;
            state.pending_session_id = None;
            state.session_disabled = true;
            state.session_retry_deadline = None;
            state.generation = state.generation.wrapping_add(1);
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let client = self.client.clone();
            let saved = self.saved.clone();
            let id = self.id.clone();
            runtime.spawn(async move {
                client.send_session_end_cleanup(&saved, &id).await;
            });
        }
    }
}
#[derive(Clone, Copy)]
pub(crate) enum ActivationPrincipal<'a> {
    Key(&'a str),
    Account(&'a str),
}
#[derive(Deserialize)]
struct Reply {
    activation_id: String,
    installation_id: String,
    credential: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    credential_expires_at: Option<String>,
    grant: Option<String>,
    server_time: String,
    binding_mode: String,
    fingerprint_provider: Option<String>,
    licence_expires_at: Option<String>,
    secret_replay_expired: bool,
    #[serde(default)]
    licence_id: Option<String>,
    #[serde(default)]
    session_required: Option<bool>,
}
enum VerifiedReply {
    Floating {
        credential: StoredCredential,
        licence_expires_at: Option<i64>,
    },
    Ordinary {
        credential: StoredCredential,
        claims: Box<Claims>,
        anchor: Anchor,
        cache: crate::installed::Cache,
    },
}
pub(crate) fn timestamp(value: &str) -> Result<i64> {
    let date = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| Error::InvalidResponse)?;
    if date.nanosecond() != 0 {
        return Err(Error::InvalidResponse);
    }
    Ok(date.unix_timestamp())
}
pub(crate) fn opaque(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}
pub(crate) fn valid_operation_id(value: &str) -> bool {
    (16..=128).contains(&value.len()) && !value.chars().any(char::is_control)
}
fn bearer(value: &str) -> bool {
    value.len() == 43 && opaque(value)
}
pub(crate) fn valid_provider(value: &str) -> bool {
    value == "machine_v1"
        || value.strip_prefix("custom:").is_some_and(|suffix| {
            (1..=48).contains(&suffix.len())
                && suffix.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'_' | b'-' | b'.')
                })
        })
}
pub(crate) fn valid_configuration(config: &Config, device: &Device) -> bool {
    opaque(&config.application_id)
        && opaque(&config.environment_id)
        && !config.issuer.is_empty()
        && opaque(&device.installation_id)
        && device.installation_id.len() >= 16
        && device.fingerprint.is_some() == device.fingerprint_provider.is_some()
        && device
            .fingerprint_provider
            .as_deref()
            .is_none_or(valid_provider)
        && device.fingerprint.as_ref().is_none_or(|f| {
            f.len() == 64
                && f.bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        })
}
pub(crate) fn valid_stored_credential(
    saved: &StoredCredential,
    config: &Config,
    device: &Device,
) -> bool {
    saved.application_id == config.application_id
        && saved.environment_id == config.environment_id
        && saved.installation_id == device.installation_id
        && saved.fingerprint == device.fingerprint
        && saved.fingerprint_provider == device.fingerprint_provider
        && opaque(&saved.activation_id)
        && opaque(&saved.licence_id)
        && bearer(&saved.credential)
}
fn valid_stored_credential_identity(
    saved: &StoredCredential,
    config: &Config,
    device: &Device,
) -> bool {
    saved.application_id == config.application_id
        && saved.environment_id == config.environment_id
        && saved.installation_id == device.installation_id
        && opaque(&saved.activation_id)
        && opaque(&saved.licence_id)
        && bearer(&saved.credential)
}
impl Client {
    #[cfg(test)]
    pub(crate) fn new(config: Config, device: Device, transport: Transport) -> Result<Self> {
        Self::with_storage(
            config,
            device,
            transport,
            Arc::new(MemoryStorage::default()),
        )
    }
    #[cfg(test)]
    pub(crate) fn with_storage(
        config: Config,
        device: Device,
        transport: Transport,
        storage: Arc<dyn Storage>,
    ) -> Result<Self> {
        Self::with_storage_inner(config, device, transport, storage, false)
    }
    pub(crate) fn with_installed_storage(
        config: Config,
        device: Device,
        transport: Transport,
        storage: Arc<dyn Storage>,
    ) -> Result<Self> {
        Self::with_storage_inner(config, device, transport, storage, true)
    }
    fn with_storage_inner(
        config: Config,
        device: Device,
        mut transport: Transport,
        storage: Arc<dyn Storage>,
        allow_binding_change: bool,
    ) -> Result<Self> {
        if !valid_configuration(&config, &device) {
            return Err(Error::Configuration);
        }
        clock::elapsed_clock()?;
        // Cloned transports may share their HTTP connection pool, but each
        // client owns a separate cancellation lifetime.
        transport.owner_cancel = Cancellation::new();
        let (version, credential) = storage.load()?;
        if let Some(saved) = &credential
            && !(if allow_binding_change {
                valid_stored_credential_identity(saved, &config, &device)
            } else {
                valid_stored_credential(saved, &config, &device)
            })
        {
            return Err(Error::Storage);
        }
        Ok(Self(Arc::new(Inner {
            config,
            app_key: None,
            device,
            transport,
            storage,
            state: Mutex::new(State {
                generation: 0,
                storage_version: version,
                account: None,
                credential,
                claims: None,
                anchor: None,
                offline: None,
                session_policy_known: false,
                session_required: false,
                session_disabled: false,
                session: None,
                pending_session_id: None,
                pending_session_since: None,
                session_retry_deadline: None,
                session_licence_expires_at: None,
                restored: false,
                update_available: None,
                transient: false,
                retry_deadline: None,
                last_failure: None,
            }),
            serial: tokio::sync::Mutex::new(()),
            keys: Mutex::new(Keys::default()),
            session_keys: Mutex::new(None),
            offline_keys: None,
            app_version: None,
            installed: None,
            worker: Mutex::new(None),
            close_serial: tokio::sync::Mutex::new(()),
            closed: std::sync::atomic::AtomicBool::new(false),
        })))
    }
    pub fn snapshot(&self) -> Result<Snapshot> {
        let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
        self.sync_storage(&mut state)?;
        self.checked_snapshot_locked(&mut state)
    }
    fn checked_snapshot_locked(&self, state: &mut State) -> Result<Snapshot> {
        if state.session_required {
            return Self::session_snapshot(state);
        }
        if let Some(offline) = state.offline.as_mut().filter(|offline| offline.authorized) {
            let Some(anchor) = &offline.anchor else {
                return Self::offline_snapshot(offline, None);
            };
            match anchor.now_with_wall() {
                Ok((now, wall)) if wall.saturating_add(30) >= offline.saved.wall_high_water => {
                    offline.uncertain = false;
                    return Self::offline_snapshot(offline, Some(now));
                }
                _ => {
                    offline.uncertain = true;
                    return Self::offline_snapshot(offline, None);
                }
            }
        }
        let now = if let Some(anchor) = &state.anchor {
            match anchor.now() {
                Ok(now) => Some(now),
                Err(_) => {
                    state.claims = None;
                    state.anchor = None;
                    state.generation = state.generation.wrapping_add(1);
                    if let Some(storage) = &self.0.installed {
                        state.storage_version = storage.clear_cached(false, false)?;
                    }
                    None
                }
            }
        } else {
            None
        };
        Self::snapshot_state_at(state, now)
    }
    fn snapshot_state(state: &State) -> Result<Snapshot> {
        if state.session_required {
            return Self::session_snapshot(state);
        }
        if let Some(offline) = state.offline.as_ref().filter(|offline| offline.authorized) {
            let now = offline
                .anchor
                .as_ref()
                .and_then(|anchor| anchor.now_with_wall().ok())
                .and_then(|(now, wall)| {
                    (wall.saturating_add(30) >= offline.saved.wall_high_water).then_some(now)
                });
            return Self::offline_snapshot(offline, now);
        }
        let now = state.anchor.as_ref().and_then(|anchor| anchor.now().ok());
        Self::snapshot_state_at(state, now)
    }
    pub(crate) fn offline_snapshot(
        offline: &crate::offline::Runtime,
        now: Option<i64>,
    ) -> Result<Snapshot> {
        let mut snapshot = Snapshot {
            access: Access::Denied,
            entitlements: BTreeMap::new(),
            expires_at: offline
                .verified
                .as_ref()
                .and_then(|claims| crate::accounts::from_unix_seconds(claims.expires_at)),
            next_check_at: None,
            credential_expires_at: None,
            reauthentication_required: false,
            offline_allowed: true,
            offline_file_mode: true,
            remaining_offline: Duration::ZERO,
            session: None,
            update_available: None,
        };
        let (Some(claims), Some(now)) = (&offline.verified, now.filter(|_| !offline.uncertain))
        else {
            return Ok(snapshot);
        };
        if claims.expires_at <= now {
            snapshot.access = Access::Expired;
            return Ok(snapshot);
        }
        snapshot.access = Access::Offline;
        snapshot.entitlements = claims.entitlements.clone();
        snapshot.remaining_offline = Duration::from_secs((claims.expires_at - now) as u64);
        Ok(snapshot)
    }
    fn snapshot_state_at(state: &State, now: Option<i64>) -> Result<Snapshot> {
        let credential_expiry = state
            .credential
            .as_ref()
            .and_then(|value| value.credential_expires_at);
        let mut snapshot = Snapshot {
            access: if state.credential.is_some() {
                Access::RefreshRequired
            } else {
                Access::Denied
            },
            entitlements: BTreeMap::new(),
            expires_at: None,
            next_check_at: None,
            credential_expires_at: credential_expiry
                .map(|value| {
                    crate::accounts::from_unix_seconds(value).ok_or(Error::InvalidResponse)
                })
                .transpose()?,
            reauthentication_required: state.credential.is_none(),
            offline_allowed: false,
            offline_file_mode: false,
            remaining_offline: Duration::ZERO,
            session: None,
            update_available: state.update_available.clone(),
        };
        if let Some(claims) = &state.claims {
            let Some(now) = now else {
                return Ok(snapshot);
            };
            snapshot.expires_at =
                Some(crate::accounts::from_unix_seconds(claims.exp).ok_or(Error::InvalidResponse)?);
            snapshot.next_check_at = Some(
                crate::accounts::from_unix_seconds(claims.refresh_after)
                    .ok_or(Error::InvalidResponse)?,
            );
            snapshot.reauthentication_required =
                credential_expiry.is_some_and(|expiry| expiry <= now + 86400);
            snapshot.offline_allowed = claims.offline_allowed;
            snapshot.access = if state.restored {
                Access::RefreshRequired
            } else if claims.exp <= now {
                Access::Expired
            } else if state.transient {
                if claims.offline_allowed {
                    Access::Offline
                } else {
                    Access::RefreshRequired
                }
            } else if claims.refresh_after <= now {
                Access::RefreshRequired
            } else {
                Access::Online
            };
            if matches!(snapshot.access, Access::Online | Access::Offline) {
                snapshot.entitlements = claims.entitlements.clone();
                if claims.offline_allowed {
                    snapshot.remaining_offline = Duration::from_secs((claims.exp - now) as u64);
                }
            }
        }
        Ok(snapshot)
    }
    /// Start a floating seat when the confirmed licence policy requires one.
    /// Ordinary and long-term offline licences keep their existing access mode.
    pub async fn start_session(&self) -> Result<Snapshot> {
        self.start_session_with_cancel(&self.0.transport.owner_cancel.clone())
            .await
    }
    pub(crate) async fn start_session_with_cancel(
        &self,
        cancel: &Cancellation,
    ) -> Result<Snapshot> {
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        let (known, saved) = {
            let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
            self.sync_storage(&mut state)?;
            if state
                .offline
                .as_ref()
                .is_some_and(|offline| offline.authorized)
            {
                return self.checked_snapshot_locked(&mut state);
            }
            if state.session_required {
                let current = Self::session_snapshot(&state)?;
                if current.access == Access::Online {
                    return Ok(current);
                }
            }
            (state.session_policy_known, state.credential.clone())
        };
        if !known {
            if saved.is_none() {
                return Err(Error::NotActivated);
            }
            self.refresh_with_cancel(cancel).await?;
        }
        let generation = self.generation()?;
        let _serial = tokio::select! {
            guard = self.0.serial.lock() => guard,
            _ = cancel.cancelled() => return Err(Error::Cancelled),
        };
        self.start_session_serialized(cancel, generation, true)
            .await
    }

    async fn start_session_serialized(
        &self,
        cancel: &Cancellation,
        generation: u64,
        explicit: bool,
    ) -> Result<Snapshot> {
        let (saved, id, licence_expiry, body) = {
            let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
            self.sync_storage(&mut state)?;
            if state.generation != generation {
                return Err(Error::StaleResponse);
            }
            if cancel.is_cancelled() {
                return Err(Error::Cancelled);
            }
            if state
                .offline
                .as_ref()
                .is_some_and(|offline| offline.authorized)
            {
                return self.checked_snapshot_locked(&mut state);
            }
            if state.session_policy_known && !state.session_required {
                return Self::snapshot_state(&state);
            }
            if explicit {
                state.session_disabled = false;
                state.session_retry_deadline = None;
            }
            if state.session.is_some() {
                let snapshot = Self::session_snapshot(&state)?;
                if snapshot.access == Access::Online {
                    return Ok(snapshot);
                }
                state.session = None;
                state.pending_session_id = None;
            }
            if state.session_disabled {
                return Err(Error::SessionRequired);
            }
            let saved = state.credential.clone().ok_or(Error::NotActivated)?;
            if state
                .pending_session_since
                .is_some_and(|since| since.elapsed() >= Duration::from_secs(120))
            {
                state.pending_session_id = None;
            }
            let id = match state.pending_session_id.clone() {
                Some(id) => id,
                None => {
                    let id = Device::new_installation()?.installation_id;
                    state.pending_session_id = Some(id.clone());
                    state.pending_session_since = Some(Instant::now());
                    id
                }
            };
            let mut body = self.credential_body(&saved);
            body["session_id"] = json!(id);
            (saved, id, state.session_licence_expires_at, body)
        };

        let mut attempt_guard = SessionAttemptGuard {
            client: self.clone(),
            saved: saved.clone(),
            id: id.clone(),
            generation,
            armed: true,
        };
        let started = clock::Start::capture()?;
        let path = format!(
            "/api/client/v1/activations/{}/sessions",
            saved.activation_id
        );
        let response = self
            .0
            .transport
            .post_with_cancel(&path, &body, true, cancel)
            .await;
        let verified = match response {
            Ok(Some(value)) => {
                self.verify_session_reply(value, &saved, (&id, 1), started, licence_expiry, cancel)
                    .await
            }
            Ok(None) => Err(Error::InvalidResponse),
            Err(error) => Err(error),
        };
        let (outcome, cleanup) = {
            let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
            if let Err(error) = self.sync_storage(&mut state) {
                (Err(error), true)
            } else if state.generation != generation {
                (Err(Error::StaleResponse), true)
            } else if cancel.is_cancelled() {
                state.pending_session_id = None;
                (Err(Error::Cancelled), true)
            } else {
                match verified {
                    Err(error @ Error::Transient { .. }) => {
                        state.session_retry_deadline =
                            Some(Instant::now() + transient_retry_delay());
                        (Err(error), false)
                    }
                    Err(error @ Error::Denied { .. }) => {
                        state.session_retry_deadline = None;
                        if matches!(
                            error.code(),
                            "session_expired" | "session_ended" | "session_sequence_conflict"
                        ) {
                            state.pending_session_id = None;
                        }
                        (Err(error), false)
                    }
                    Err(Error::Cancelled) => {
                        state.pending_session_id = None;
                        (Err(Error::Cancelled), true)
                    }
                    Err(error) => {
                        state.pending_session_id = None;
                        (Err(error), true)
                    }
                    Ok(runtime) => {
                        state.session = Some(runtime);
                        state.pending_session_id = None;
                        state.session_retry_deadline = None;
                        match Self::session_snapshot(&state) {
                            Ok(snapshot) if snapshot.access == Access::Online => {
                                (Ok(snapshot), false)
                            }
                            Ok(_) => {
                                state.session = None;
                                (Err(Error::SessionRequired), true)
                            }
                            Err(error) => {
                                state.session = None;
                                (Err(error), true)
                            }
                        }
                    }
                }
            }
        };
        attempt_guard.armed = false;
        if cleanup {
            self.send_session_end_cleanup(&saved, &id).await;
        }
        outcome
    }

    async fn verify_session_reply(
        &self,
        value: serde_json::Value,
        saved: &StoredCredential,
        expected_session: (&str, u64),
        started: clock::Start,
        licence_expiry: Option<i64>,
        cancel: &Cancellation,
    ) -> Result<SessionRuntime> {
        let (id, sequence) = expected_session;
        let object = value.as_object().ok_or(Error::InvalidResponse)?;
        if object.len() != 5
            || [
                "session_id",
                "sequence",
                "expires_at",
                "server_time",
                "grant",
            ]
            .iter()
            .any(|field| !object.contains_key(*field))
        {
            return Err(Error::InvalidResponse);
        }
        let reply_id = object["session_id"]
            .as_str()
            .ok_or(Error::InvalidResponse)?;
        let reply_sequence = object["sequence"].as_u64().ok_or(Error::InvalidResponse)?;
        let expires = timestamp(
            object["expires_at"]
                .as_str()
                .ok_or(Error::InvalidResponse)?,
        )?;
        let server = timestamp(
            object["server_time"]
                .as_str()
                .ok_or(Error::InvalidResponse)?,
        )?;
        let token = object["grant"].as_str().ok_or(Error::InvalidResponse)?;
        if reply_id != id
            || reply_sequence != sequence
            || !opaque(reply_id)
            || reply_id.len() < 16
            || token.is_empty()
            || token.len() > 16 * 1024
        {
            return Err(Error::InvalidResponse);
        }
        let anchor = Anchor::from_request(server, started);
        let kid = sessions::key_id(token)?;
        let need_keys = self
            .0
            .session_keys
            .lock()
            .map_err(|_| Error::Storage)?
            .as_ref()
            .is_none_or(|keys| !keys.contains(&kid));
        if need_keys {
            let data = self
                .0
                .transport
                .get_with_cancel(
                    &format!(
                        "/.well-known/orbit-jwks.json?application_id={}&environment_id={}",
                        self.0.config.application_id, self.0.config.environment_id
                    ),
                    cancel,
                )
                .await?
                .ok_or(Error::InvalidResponse)?;
            let bytes = serde_json::to_vec(&data).map_err(|_| Error::InvalidResponse)?;
            *self.0.session_keys.lock().map_err(|_| Error::Storage)? = Some(SessionKeys::parse(
                &bytes,
                self.0
                    .app_key
                    .as_ref()
                    .map_or(self.0.config.environment_id.as_str(), |key| {
                        key.environment()
                    }),
            )?);
        }
        let now = anchor.now()?;
        let expected = SessionExpected {
            issuer: &self.0.config.issuer,
            application: &self.0.config.application_id,
            environment: &self.0.config.environment_id,
            licence: Some(&saved.licence_id),
            activation: &saved.activation_id,
            installation: &saved.installation_id,
            fingerprint: saved.fingerprint.as_deref(),
            fingerprint_provider: saved.fingerprint_provider.as_deref(),
            allow_unbound_fingerprint: true,
            credential_expires_at: saved.credential_expires_at,
            licence_expires_at: licence_expiry,
            now,
            session_id: id,
            sequence,
        };
        let keys = self.0.session_keys.lock().map_err(|_| Error::Storage)?;
        let grant = sessions::verify(
            token,
            keys.as_ref().ok_or(Error::InvalidResponse)?,
            &expected,
        )?;
        if grant.expires_at != expires || grant.sequence != sequence || grant.session_id != id {
            return Err(Error::InvalidResponse);
        }
        Ok(SessionRuntime {
            metadata: SessionMetadata {
                id: id.to_owned(),
                sequence,
                expires_at: crate::accounts::from_unix_seconds(expires)
                    .ok_or(Error::InvalidResponse)?,
                refresh_after: crate::accounts::from_unix_seconds(grant.refresh_after)
                    .ok_or(Error::InvalidResponse)?,
            },
            grant,
            anchor,
            pending_sequence: None,
        })
    }

    fn session_body(&self, saved: &StoredCredential) -> serde_json::Value {
        self.credential_body(saved)
    }
    pub(crate) async fn send_session_end_cleanup(&self, saved: &StoredCredential, id: &str) {
        let path = format!(
            "/api/client/v1/activations/{}/sessions/{}/end",
            saved.activation_id, id
        );
        let _ = self
            .0
            .transport
            .post_cleanup(&path, &self.session_body(saved))
            .await;
    }

    /// End the current floating seat after first clearing all local authority.
    pub async fn end_session(&self) -> Result<()> {
        self.end_session_with_cancel(&self.0.transport.owner_cancel.clone())
            .await
    }
    async fn end_session_with_cancel(&self, cancel: &Cancellation) -> Result<()> {
        let (known, saved) = {
            let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
            self.sync_storage(&mut state)?;
            if state
                .offline
                .as_ref()
                .is_some_and(|offline| offline.authorized)
            {
                return Ok(());
            }
            if !state.session_policy_known {
                state.session_disabled = true;
            }
            (state.session_policy_known, state.credential.clone())
        };
        if !known {
            if saved.is_none() {
                return Ok(());
            }
            self.refresh_policy_without_acquire(cancel).await?;
        }
        let (saved, id) = {
            let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
            self.sync_storage(&mut state)?;
            if state.session_policy_known && !state.session_required {
                return Ok(());
            }
            let saved = state.credential.clone().ok_or(Error::NotActivated)?;
            let id = state
                .session
                .as_ref()
                .map(|value| value.metadata.id.clone())
                .or_else(|| state.pending_session_id.clone());
            state.session = None;
            state.pending_session_id = None;
            state.session_disabled = true;
            state.session_retry_deadline = None;
            state.generation = state.generation.wrapping_add(1);
            (saved, id)
        };
        let Some(id) = id else {
            return Ok(());
        };
        let path = format!(
            "/api/client/v1/activations/{}/sessions/{}/end",
            saved.activation_id, id
        );
        let response = self
            .0
            .transport
            .post_with_cancel(&path, &self.session_body(&saved), false, cancel)
            .await?;
        if response.is_some() {
            Err(Error::InvalidResponse)
        } else {
            Ok(())
        }
    }

    pub(crate) async fn renew_session(
        &self,
        cancel: &Cancellation,
        generation: u64,
    ) -> Result<Snapshot> {
        let _serial = tokio::select! { guard=self.0.serial.lock()=>guard, _=cancel.cancelled()=>return Err(Error::Cancelled) };
        let (saved, id, sequence, licence_expiry, body) = {
            let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
            self.sync_storage(&mut state)?;
            if state.generation != generation {
                return Err(Error::StaleResponse);
            }
            let saved = state
                .credential
                .clone()
                .ok_or(Error::ReauthenticationRequired)?;
            let session = state.session.as_mut().ok_or(Error::SessionRequired)?;
            let sequence = session
                .pending_sequence
                .unwrap_or(session.grant.sequence + 1);
            session.pending_sequence = Some(sequence);
            let id = session.metadata.id.clone();
            let mut body = self.session_body(&saved);
            body["sequence"] = json!(sequence);
            (saved, id, sequence, state.session_licence_expires_at, body)
        };
        let mut attempt_guard = SessionAttemptGuard {
            client: self.clone(),
            saved: saved.clone(),
            id: id.clone(),
            generation,
            armed: true,
        };
        let started = clock::Start::capture()?;
        let path = format!(
            "/api/client/v1/activations/{}/sessions/{}/renew",
            saved.activation_id, id
        );
        let response = self
            .0
            .transport
            .post_with_cancel(&path, &body, true, cancel)
            .await;
        let verified = match response {
            Ok(Some(value)) => {
                self.verify_session_reply(
                    value,
                    &saved,
                    (&id, sequence),
                    started,
                    licence_expiry,
                    cancel,
                )
                .await
            }
            Ok(None) => Err(Error::InvalidResponse),
            Err(error) => Err(error),
        };
        attempt_guard.armed = false;
        let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
        self.sync_storage(&mut state)?;
        if state.generation != generation {
            return Err(Error::StaleResponse);
        }
        if cancel.is_cancelled() {
            state.session = None;
            state.session_disabled = true;
            return Err(Error::Cancelled);
        }
        let replacement = match verified {
            Ok(value) => value,
            Err(error @ Error::Transient { .. }) => {
                state.session_retry_deadline = Some(Instant::now() + transient_retry_delay());
                return Err(error);
            }
            Err(error) => {
                state.session = None;
                state.session_disabled = true;
                state.session_retry_deadline = None;
                if error.code() == "session_expired" {
                    state.pending_session_id = None;
                    state.session_disabled = false;
                    state.session_retry_deadline = Some(Instant::now() + transient_retry_delay());
                }
                return Err(error);
            }
        };
        if !state.session.as_ref().is_some_and(|session| {
            session.metadata.id == id && session.pending_sequence == Some(sequence)
        }) {
            return Err(Error::StaleResponse);
        }
        state.session = Some(replacement);
        state.session_retry_deadline = None;
        Self::session_snapshot(&state)
    }

    pub(crate) async fn maintain_session(&self, cancel: &Cancellation) {
        let due = {
            let mut state = match self.0.state.lock() {
                Ok(state) => state,
                Err(_) => return,
            };
            if self.sync_storage(&mut state).is_err()
                || !state.session_required
                || state.session_disabled
            {
                return;
            }
            let retry_set = state.session_retry_deadline.is_some();
            if state
                .session_retry_deadline
                .is_some_and(|deadline| Instant::now() < deadline)
            {
                return;
            }
            let status = state.session.as_ref().map(|session| {
                session
                    .anchor
                    .now()
                    .map(|now| (now, session.grant.expires_at, session.grant.refresh_after))
            });
            match status {
                Some(Ok((now, expires, refresh))) if now < expires && now < refresh => return,
                Some(Ok((now, expires, _))) if now >= expires => {
                    state.session = None;
                    state.pending_session_id = None;
                    state.session_retry_deadline = Some(Instant::now());
                    Some((false, state.generation))
                }
                Some(Err(_)) => {
                    state.session = None;
                    state.pending_session_id = None;
                    state.session_retry_deadline = Some(Instant::now() + transient_retry_delay());
                    state.last_failure = Some(Error::ClockUncertain);
                    None
                }
                Some(_) => Some((true, state.generation)),
                None if retry_set => Some((false, state.generation)),
                None => None,
            }
        };
        if let Some((renew, generation)) = due {
            if renew {
                let _ = self.renew_session(cancel, generation).await;
            } else {
                let _ = self.start_session_with_cancel(cancel).await;
            }
        }
    }
    fn session_snapshot(state: &State) -> Result<Snapshot> {
        let credential_expiry = state
            .credential
            .as_ref()
            .and_then(|value| value.credential_expires_at)
            .and_then(crate::accounts::from_unix_seconds);
        let mut snapshot = Snapshot {
            access: if state.credential.is_some() {
                Access::RefreshRequired
            } else {
                Access::Denied
            },
            entitlements: BTreeMap::new(),
            expires_at: None,
            next_check_at: None,
            credential_expires_at: credential_expiry,
            reauthentication_required: state.credential.is_none(),
            offline_allowed: false,
            offline_file_mode: false,
            remaining_offline: Duration::ZERO,
            session: None,
            update_available: state.update_available.clone(),
        };
        let Some(session) = &state.session else {
            return Ok(snapshot);
        };
        snapshot.session = Some(session.metadata.clone());
        snapshot.expires_at = crate::accounts::from_unix_seconds(session.grant.expires_at);
        snapshot.next_check_at = crate::accounts::from_unix_seconds(session.grant.refresh_after);
        let Ok(now) = session.anchor.now() else {
            return Ok(snapshot);
        };
        if session.grant.expires_at <= now {
            snapshot.access = Access::Expired;
            return Ok(snapshot);
        }
        if state
            .session_licence_expires_at
            .is_some_and(|expires| expires <= now)
        {
            snapshot.access = Access::Expired;
            return Ok(snapshot);
        }
        snapshot.access = Access::Online;
        snapshot.entitlements = session.grant.entitlements.clone();
        Ok(snapshot)
    }
    pub(crate) fn sync_storage(&self, state: &mut State) -> Result<()> {
        if self.0.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(Error::Closed);
        }
        let version = match self.0.storage.version() {
            Ok(version) => version,
            Err(error) => {
                clear(state);
                return Err(error);
            }
        };
        if version != state.storage_version {
            clear(state);
            state.storage_version = version;
        }
        Ok(())
    }
    pub(crate) fn generation(&self) -> Result<u64> {
        let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
        self.sync_storage(&mut state)?;
        Ok(state.generation)
    }
    pub(crate) fn check_generation(&self, generation: u64) -> Result<()> {
        if self.generation()? != generation {
            return Err(Error::StaleResponse);
        }
        Ok(())
    }
    pub fn logout(&self) -> Result<()> {
        let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
        let checkpoint_error = if let (Some(storage), Some(offline)) = (
            &self.0.installed,
            state.offline.as_mut().filter(|item| item.authorized),
        ) {
            storage.checkpoint_offline(offline, true).err()
        } else {
            None
        };
        clear(&mut state);
        state.storage_version = self.0.storage.invalidate()?;
        if let Some(error) = checkpoint_error {
            return Err(error);
        }
        Ok(())
    }
    pub async fn activate(&self, key: &str) -> Result<Snapshot> {
        self.activate_with_cancel(key, "", &self.0.transport.owner_cancel.clone())
            .await
    }
    pub async fn activate_with_id(&self, key: &str, idempotency_key: &str) -> Result<Snapshot> {
        if !valid_operation_id(idempotency_key) {
            return Err(Error::Configuration);
        }
        self.activate_with_cancel(key, idempotency_key, &self.0.transport.owner_cancel.clone())
            .await
    }
    pub async fn activate_with_previous(
        &self,
        key: &str,
        previous_credential: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> Result<Snapshot> {
        if idempotency_key.is_some_and(|id| !valid_operation_id(id)) {
            return Err(Error::Configuration);
        }
        self.activate_as(
            ActivationPrincipal::Key(key),
            previous_credential,
            idempotency_key.unwrap_or(""),
            &self.0.transport.owner_cancel.clone(),
        )
        .await
    }
    pub(crate) async fn activate_with_cancel(
        &self,
        key: &str,
        idempotency_key: &str,
        cancel: &Cancellation,
    ) -> Result<Snapshot> {
        self.activate_as(ActivationPrincipal::Key(key), None, idempotency_key, cancel)
            .await
    }
    pub(crate) async fn activate_as(
        &self,
        principal: ActivationPrincipal<'_>,
        previous_credential: Option<&str>,
        idempotency_key: &str,
        cancel: &Cancellation,
    ) -> Result<Snapshot> {
        let valid_principal = match principal {
            ActivationPrincipal::Key(key) => !key.is_empty() && key.len() <= 256,
            ActivationPrincipal::Account(licence) => opaque(licence),
        };
        if !valid_principal
            || (!idempotency_key.is_empty() && !valid_operation_id(idempotency_key))
            || (!(16..=128).contains(&idempotency_key.len())
                && !(self.0.installed.is_some() && idempotency_key.is_empty()))
        {
            return Err(Error::Configuration);
        }
        let generation = self.generation()?;
        let _serial = tokio::select! {guard=self.0.serial.lock()=>guard,_=cancel.cancelled()=>return Err(Error::Cancelled)};
        self.check_generation(generation)?;
        let (generation, customer_session, operation) = {
            let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
            if state.generation != generation {
                return Err(Error::StaleResponse);
            }
            let (session, customer_id) = match principal {
                ActivationPrincipal::Key(_) => (None, None),
                ActivationPrincipal::Account(_) => {
                    let account = state
                        .account
                        .as_ref()
                        .ok_or(Error::ReauthenticationRequired)?;
                    (
                        Some(account.token.clone()),
                        Some(account.customer_id().to_owned()),
                    )
                }
            };
            let operation = if let Some(storage) = &self.0.installed {
                if let Some(offline) = state.offline.as_mut().filter(|item| item.authorized) {
                    storage.checkpoint_offline(offline, true)?;
                }
                let (operation, version) = storage.prepare_activation(
                    principal,
                    customer_id.as_deref(),
                    previous_credential,
                    idempotency_key,
                )?;
                state.storage_version = version;
                state.generation = state.generation.wrapping_add(1);
                state.claims = None;
                state.anchor = None;
                state.session = None;
                state.pending_session_id = None;
                state.pending_session_since = None;
                state.session_policy_known = false;
                state.session_required = false;
                state.session_disabled = false;
                state.session_retry_deadline = None;
                state.session_licence_expires_at = None;

                if let Some(offline) = state.offline.as_mut() {
                    offline.authorized = false;
                }
                state.restored = false;
                state.transient = false;
                state.retry_deadline = None;
                state.last_failure = None;
                if matches!(principal, ActivationPrincipal::Key(_)) {
                    state.account = None;
                }
                operation
            } else {
                if matches!(principal, ActivationPrincipal::Key(_)) {
                    clear(&mut state);
                } else {
                    clear_access(&mut state);
                }
                state.storage_version = self.0.storage.invalidate()?;
                idempotency_key.to_owned()
            };
            (state.generation, session, operation)
        };
        let mut input = json!({"application_id":self.0.config.application_id,"environment_id":self.0.config.environment_id,
            "installation_id":self.0.device.installation_id,"fingerprint":self.0.device.fingerprint,
            "fingerprint_provider":self.0.device.fingerprint_provider,"previous_credential":previous_credential,"idempotency_key":operation});
        if self.0.installed.is_some() {
            input["credential_mode"] = json!("persistent");
        }
        if let Some(version) = &self.0.app_version {
            input["app_version"] = json!(version);
        }
        let expected_licence = match principal {
            ActivationPrincipal::Key(key) => {
                input["licence_key"] = json!(key);
                None
            }
            ActivationPrincipal::Account(licence) => {
                input["customer_session"] = json!(customer_session);
                input["licence_id"] = json!(licence);
                Some(licence)
            }
        };
        let started = clock::Start::capture()?;
        let response = self
            .0
            .transport
            .post_with_cancel("/api/client/v1/activations", &input, true, cancel)
            .await;
        self.accept_with_licence(
            response,
            generation,
            None,
            started,
            cancel,
            expected_licence,
        )
        .await
    }
    pub async fn refresh(&self) -> Result<Snapshot> {
        self.refresh_with_cancel(&self.0.transport.owner_cancel.clone())
            .await
    }
    pub(crate) async fn refresh_with_cancel(&self, cancel: &Cancellation) -> Result<Snapshot> {
        self.refresh_inner(cancel, false).await
    }
    async fn refresh_policy_without_acquire(&self, cancel: &Cancellation) -> Result<Snapshot> {
        self.refresh_inner_mode(cancel, false, true).await
    }
    pub(crate) async fn refresh_if_needed(&self, cancel: &Cancellation) -> Result<Snapshot> {
        self.refresh_inner(cancel, true).await
    }
    async fn refresh_inner(&self, cancel: &Cancellation, respect_retry: bool) -> Result<Snapshot> {
        self.refresh_inner_mode(cancel, respect_retry, false).await
    }
    async fn refresh_inner_mode(
        &self,
        cancel: &Cancellation,
        respect_retry: bool,
        suppress_session_acquire: bool,
    ) -> Result<Snapshot> {
        let generation = self.generation()?;
        let _serial = tokio::select! {guard=self.0.serial.lock()=>guard,_=cancel.cancelled()=>return Err(Error::Cancelled)};
        self.check_generation(generation)?;
        if let Some(storage) = &self.0.installed
            && storage.activation_pending()?
        {
            // A replacement may already have revoked the old bearer. Its
            // unrelated denial must never resolve the pending activation.
            return Err(Error::PendingActivation);
        }
        if respect_retry {
            let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
            self.sync_storage(&mut state)?;
            if state.generation != generation {
                return Err(Error::StaleResponse);
            }
            if cancel.is_cancelled() {
                return Err(Error::Cancelled);
            }
            let snapshot = Self::snapshot_state(&state)?;
            let retry_due = state
                .retry_deadline
                .is_none_or(|deadline| Instant::now() >= deadline);
            if !matches!(
                snapshot.access,
                Access::RefreshRequired | Access::Expired | Access::Offline
            ) || !retry_due
            {
                if snapshot.access != Access::Offline
                    && let Some(error) = &state.last_failure
                {
                    return Err(error.clone());
                }
                return Ok(snapshot);
            }
        }
        let saved = self
            .0
            .state
            .lock()
            .map_err(|_| Error::Storage)?
            .credential
            .clone()
            .ok_or(Error::ReauthenticationRequired)?;
        let mut body = self.credential_body(&saved);
        if let Some(version) = &self.0.app_version {
            body["app_version"] = json!(version);
        }
        let started = clock::Start::capture()?;
        let response = self
            .0
            .transport
            .post_with_cancel(
                &format!(
                    "/api/client/v1/activations/{}/validate",
                    saved.activation_id
                ),
                &body,
                true,
                cancel,
            )
            .await;
        if suppress_session_acquire {
            self.accept_for_licence(response, generation, Some(saved), started, cancel, None)
                .await
        } else {
            self.accept(response, generation, Some(saved), started, cancel)
                .await
        }
    }
    fn credential_body(&self, saved: &StoredCredential) -> serde_json::Value {
        json!({"application_id":self.0.config.application_id,"environment_id":self.0.config.environment_id,"credential":saved.credential,
            "installation_id":self.0.device.installation_id,"fingerprint":self.0.device.fingerprint,"fingerprint_provider":self.0.device.fingerprint_provider})
    }
    pub async fn deactivate(&self) -> Result<()> {
        self.deactivate_with_cancel("", &self.0.transport.owner_cancel.clone())
            .await
    }
    pub async fn deactivate_with_id(&self, idempotency_key: &str) -> Result<()> {
        if !valid_operation_id(idempotency_key) {
            return Err(Error::Configuration);
        }
        self.deactivate_with_cancel(idempotency_key, &self.0.transport.owner_cancel.clone())
            .await
    }
    pub(crate) async fn deactivate_with_cancel(
        &self,
        requested_id: &str,
        cancel: &Cancellation,
    ) -> Result<()> {
        let generated;
        let idempotency_key = if requested_id.is_empty() {
            let device = Device::new_installation()?;
            generated = device.installation_id;
            generated.as_str()
        } else {
            requested_id
        };
        if !(16..=128).contains(&idempotency_key.len()) {
            return Err(Error::Configuration);
        }
        let saved = {
            let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
            self.sync_storage(&mut state)?;
            let saved = state
                .credential
                .clone()
                .ok_or(Error::ReauthenticationRequired)?;
            // Release the selected activation without discarding a customer
            // login that can select another licence or explicitly sign out.
            clear_access(&mut state);
            state.storage_version = self.0.storage.invalidate()?;
            saved
        };
        let mut body = self.credential_body(&saved);
        body["idempotency_key"] = json!(idempotency_key);
        let response = self
            .0
            .transport
            .post_with_cancel(
                &format!(
                    "/api/client/v1/activations/{}/deactivate",
                    saved.activation_id
                ),
                &body,
                true,
                cancel,
            )
            .await?;
        if response.is_some() {
            return Err(Error::InvalidResponse);
        }
        Ok(())
    }
    pub async fn require_access(&self, feature: &str) -> Result<Snapshot> {
        self.require_access_with_cancel(feature, &self.0.transport.owner_cancel.clone())
            .await
    }
    pub(crate) async fn require_access_with_cancel(
        &self,
        feature: &str,
        cancel: &Cancellation,
    ) -> Result<Snapshot> {
        let (snapshot, session_required, session_disabled, refresh_needed) = {
            let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
            self.sync_storage(&mut state)?;
            if cancel.is_cancelled() {
                return Err(Error::Cancelled);
            }
            let snapshot = self.checked_snapshot_locked(&mut state)?;
            if cancel.is_cancelled() {
                return Err(Error::Cancelled);
            }
            if snapshot.offline_file_mode {
                if snapshot.access == Access::Expired {
                    return Err(crate::offline::expired());
                }
                if snapshot.access != Access::Offline {
                    return Err(Error::ClockUncertain);
                }
                if !snapshot.has_feature(feature) {
                    return Err(Error::FeatureUnavailable);
                }
                return Ok(snapshot);
            }
            let refresh_needed = matches!(
                snapshot.access,
                Access::RefreshRequired | Access::Expired | Access::Offline
            );
            (
                snapshot,
                state.session_required,
                state.session_disabled,
                refresh_needed,
            )
        };
        if snapshot.access == Access::Online {
            let final_snapshot = if session_required {
                let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
                self.sync_storage(&mut state)?;
                if cancel.is_cancelled() {
                    return Err(Error::Cancelled);
                }
                let final_snapshot = self.checked_snapshot_locked(&mut state)?;
                if cancel.is_cancelled() {
                    return Err(Error::Cancelled);
                }
                if final_snapshot.access != Access::Online {
                    return Err(Error::SessionRequired);
                }
                final_snapshot
            } else {
                snapshot
            };
            if !final_snapshot.has_feature(feature) {
                return Err(Error::FeatureUnavailable);
            }
            return Ok(final_snapshot);
        }
        if session_required {
            if session_disabled {
                return Err(Error::SessionRequired);
            }
            let snapshot = self.start_session_with_cancel(cancel).await?;
            if !snapshot.has_feature(feature) {
                return Err(Error::FeatureUnavailable);
            }
            return Ok(snapshot);
        }
        if !refresh_needed {
            return Err(Error::NotActivated);
        }
        let mut refresh_error = None;
        match self.refresh_if_needed(cancel).await {
            Ok(_) => {}
            Err(error @ Error::Transient { .. }) => refresh_error = Some(error),
            Err(error) => return Err(error),
        }
        // The awaited refresh can race logout or external storage invalidation.
        // Synchronize the current generation, then sample native time once and
        // build the decision from that live state.
        let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
        self.sync_storage(&mut state)?;
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        let snapshot = self.checked_snapshot_locked(&mut state)?;
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if !matches!(snapshot.access, Access::Online | Access::Offline) {
            return Err(refresh_error.unwrap_or(Error::NotActivated));
        }
        if !snapshot.entitlements.get(feature).copied().unwrap_or(false) {
            return Err(Error::FeatureUnavailable);
        }
        if state.session_required {
            let final_snapshot = Self::session_snapshot(&state)?;
            if cancel.is_cancelled() {
                return Err(Error::Cancelled);
            }
            if final_snapshot.access != Access::Online {
                return Err(Error::SessionRequired);
            }
            if !final_snapshot.has_feature(feature) {
                return Err(Error::FeatureUnavailable);
            }
            return Ok(final_snapshot);
        }
        Ok(snapshot)
    }
    pub async fn ensure_access<F>(&self, feature: &str, ask_for_key: F) -> Result<Snapshot>
    where
        F: FnOnce() -> Option<String>,
    {
        match self.require_access(feature).await {
            Ok(snapshot) => Ok(snapshot),
            Err(Error::NotActivated) => {
                let Some(key) = ask_for_key().filter(|key| !key.trim().is_empty()) else {
                    return Err(Error::NotActivated);
                };
                let snapshot = self.activate(&key).await?;
                if !matches!(snapshot.access, Access::Online | Access::Offline) {
                    return Err(Error::NotActivated);
                }
                if !snapshot.has_feature(feature) {
                    return Err(Error::FeatureUnavailable);
                }
                Ok(snapshot)
            }
            Err(error) => Err(error),
        }
    }
    async fn accept(
        &self,
        response: Result<Option<serde_json::Value>>,
        generation: u64,
        previous: Option<StoredCredential>,
        started: clock::Start,
        cancel: &Cancellation,
    ) -> Result<Snapshot> {
        self.accept_with_licence(response, generation, previous, started, cancel, None)
            .await
    }
    async fn accept_with_licence(
        &self,
        response: Result<Option<serde_json::Value>>,
        generation: u64,
        previous: Option<StoredCredential>,
        started: clock::Start,
        cancel: &Cancellation,
        expected_licence: Option<&str>,
    ) -> Result<Snapshot> {
        let snapshot = self
            .accept_for_licence(
                response,
                generation,
                previous,
                started,
                cancel,
                expected_licence,
            )
            .await?;
        let should_start = {
            let state = self.0.state.lock().map_err(|_| Error::Storage)?;
            state.session_required && !state.session_disabled && state.session.is_none()
        };
        if should_start {
            let next_generation = self.generation()?;
            self.start_session_serialized(cancel, next_generation, false)
                .await
        } else {
            Ok(snapshot)
        }
    }
    async fn accept_for_licence(
        &self,
        response: Result<Option<serde_json::Value>>,
        generation: u64,
        previous: Option<StoredCredential>,
        started: clock::Start,
        cancel: &Cancellation,
        expected_licence: Option<&str>,
    ) -> Result<Snapshot> {
        self.check_generation(generation)?;
        let (verifying, result) = match response {
            Ok(Some(value)) => (
                true,
                self.verify_reply(value, previous.as_ref(), expected_licence, started, cancel)
                    .await,
            ),
            Ok(None) => (false, Err(Error::InvalidResponse)),
            Err(error) => (false, Err(error)),
        };
        let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
        self.sync_storage(&mut state)?;
        if state.generation != generation {
            return Err(Error::StaleResponse);
        }
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        match result {
            Ok((reply, update_available)) => match reply {
                VerifiedReply::Floating {
                    credential,
                    licence_expires_at,
                } => {
                    let persisted = if let Some(storage) = &self.0.installed {
                        storage.commit_floating(
                            state.storage_version,
                            &credential,
                            previous.is_none(),
                        )
                    } else {
                        self.0
                            .storage
                            .save(state.storage_version, credential.clone())
                    };
                    if let Err(error) = persisted {
                        clear(&mut state);
                        return Err(error);
                    }
                    state.credential = Some(credential);
                    state.claims = None;
                    state.anchor = None;
                    state.session_policy_known = true;
                    state.session_required = true;
                    state.session_licence_expires_at = licence_expires_at;
                    state.update_available = update_available;
                    state.transient = false;
                    state.restored = false;
                    state.retry_deadline = None;
                    state.last_failure = None;
                    Self::snapshot_state(&state)
                }
                VerifiedReply::Ordinary {
                    credential,
                    claims,
                    anchor,
                    cache,
                } => {
                    let persisted = if let Some(storage) = &self.0.installed {
                        storage.commit_access(
                            state.storage_version,
                            &credential,
                            cache,
                            previous.is_none(),
                        )
                    } else {
                        self.0
                            .storage
                            .save(state.storage_version, credential.clone())
                    };
                    if let Err(error) = persisted {
                        clear(&mut state);
                        return Err(error);
                    }
                    state.credential = Some(credential);
                    state.claims = Some(*claims);
                    state.anchor = Some(anchor);
                    state.session_policy_known = true;
                    state.session_required = false;
                    state.session_disabled = false;
                    state.session = None;
                    state.pending_session_id = None;
                    state.session_retry_deadline = None;
                    state.session_licence_expires_at = None;
                    state.update_available = update_available;
                    state.transient = false;
                    state.restored = false;
                    state.retry_deadline = None;
                    state.last_failure = None;
                    Self::snapshot_state(&state)
                }
            },
            Err(error @ Error::Transient { .. }) => {
                if verifying {
                    // Without verification the reply cannot refresh access; retain
                    // only the prior credential and invalidate cached authority.
                    state.generation = state.generation.wrapping_add(1);
                    state.claims = None;
                    state.anchor = None;
                    if let Some(storage) = &self.0.installed {
                        state.storage_version = storage.clear_cached(false, false)?;
                    }
                }
                if state.restored
                    && let Some(storage) = &self.0.installed
                {
                    storage.checkpoint(state.anchor.as_ref(), true)?;
                }
                state.restored = false;
                state.transient = true;
                state.last_failure = Some(error.clone());
                state.retry_deadline = Some(Instant::now() + transient_retry_delay());
                let snapshot = Self::snapshot_state(&state)?;
                if snapshot.access == Access::Offline {
                    Ok(snapshot)
                } else {
                    Err(error)
                }
            }
            Err(Error::Cancelled) => Err(Error::Cancelled),
            Err(error) => {
                if let Some(storage) = &self.0.installed {
                    let definitive = matches!(error, Error::Denied { .. })
                        || (previous.is_none()
                            && matches!(error, Error::AppVersionUnsupported { .. }));
                    state.generation = state.generation.wrapping_add(1);
                    state.claims = None;
                    state.anchor = None;
                    state.session = None;
                    state.pending_session_id = None;
                    state.session_policy_known = false;
                    state.session_required = false;
                    state.session_disabled = false;
                    state.session_retry_deadline = None;
                    state.session_licence_expires_at = None;
                    state.restored = false;
                    state.update_available = None;
                    state.transient = false;
                    state.retry_deadline = Some(Instant::now() + transient_retry_delay());
                    state.last_failure = Some(error.clone());
                    if definitive {
                        state.credential = None;
                        state.account = None;
                    }
                    state.storage_version = storage.clear_cached(definitive, definitive)?;
                } else {
                    clear(&mut state);
                    state.storage_version = self.0.storage.invalidate()?;
                }
                Err(error)
            }
        }
    }
    async fn verify_reply(
        &self,
        value: serde_json::Value,
        previous: Option<&StoredCredential>,
        expected_licence: Option<&str>,
        started: clock::Start,
        cancel: &Cancellation,
    ) -> Result<(VerifiedReply, Option<String>)> {
        let object = value.as_object().ok_or(Error::InvalidResponse)?;
        let update_available = crate::app_version::update_hint(object)?;
        let floating = match object.get("session_required") {
            None if !object.contains_key("licence_id") => false,
            Some(serde_json::Value::Bool(true))
                if object.get("grant") == Some(&serde_json::Value::Null) =>
            {
                true
            }
            _ => return Err(Error::InvalidResponse),
        };
        let reply: Reply = serde_json::from_value(value).map_err(|_| Error::InvalidResponse)?;
        if reply.secret_replay_expired {
            return Err(Error::ReauthenticationRequired);
        }
        if !opaque(&reply.activation_id)
            || reply.installation_id != self.0.device.installation_id
            || reply.fingerprint_provider != self.0.device.fingerprint_provider
            || !matches!(reply.binding_mode.as_str(), "none" | "hwid")
            || (reply.binding_mode == "hwid" && self.0.device.fingerprint.is_none())
        {
            return Err(Error::InvalidResponse);
        }
        let anchor = Anchor::from_request(timestamp(&reply.server_time)?, started);
        let now = anchor.now()?;
        let expiry = reply
            .credential_expires_at
            .as_deref()
            .map(timestamp)
            .transpose()?;
        if expiry.is_some_and(|expiry| expiry <= now || expiry > now.saturating_add(30 * 86400))
            || (previous.is_none() && (self.0.installed.is_some() != expiry.is_none()))
        {
            return Err(Error::InvalidResponse);
        }
        if let Some(previous) = previous
            && (reply.activation_id != previous.activation_id
                || expiry != previous.credential_expires_at
                || reply.credential.is_some())
        {
            return Err(Error::InvalidResponse);
        }
        if floating {
            let licence_id = reply.licence_id.as_deref().ok_or(Error::InvalidResponse)?;
            if !opaque(licence_id)
                || expected_licence.is_some_and(|expected| expected != licence_id)
                || previous.is_some_and(|saved| saved.licence_id != licence_id)
                || reply.grant.is_some()
            {
                return Err(Error::InvalidResponse);
            }
            let credential = reply
                .credential
                .or_else(|| previous.map(|saved| saved.credential.clone()))
                .ok_or(Error::InvalidResponse)?;
            if !bearer(&credential) {
                return Err(Error::InvalidResponse);
            }
            let licence_expires_at = reply
                .licence_expires_at
                .as_deref()
                .map(timestamp)
                .transpose()?;
            return Ok((
                VerifiedReply::Floating {
                    credential: StoredCredential {
                        application_id: self.0.config.application_id.clone(),
                        environment_id: self.0.config.environment_id.clone(),
                        activation_id: reply.activation_id,
                        licence_id: licence_id.to_owned(),
                        installation_id: self.0.device.installation_id.clone(),
                        credential,
                        credential_expires_at: expiry,
                        fingerprint: self.0.device.fingerprint.clone(),
                        fingerprint_provider: self.0.device.fingerprint_provider.clone(),
                    },
                    licence_expires_at,
                },
                update_available,
            ));
        }
        if reply.session_required.is_some() || reply.licence_id.is_some() {
            return Err(Error::InvalidResponse);
        }
        let token = reply.grant.ok_or(Error::InvalidResponse)?;
        let missing = !self
            .0
            .keys
            .lock()
            .map_err(|_| Error::Storage)?
            .contains(&token)?;
        if missing {
            let value = self
                .0
                .transport
                .get_with_cancel(
                    &format!(
                        "/.well-known/orbit-jwks.json?application_id={}&environment_id={}",
                        self.0.config.application_id, self.0.config.environment_id
                    ),
                    cancel,
                )
                .await?
                .ok_or(Error::InvalidResponse)?;
            *self.0.keys.lock().map_err(|_| Error::Storage)? = Keys::parse(value)?;
        }
        let licence_expiry = reply
            .licence_expires_at
            .as_deref()
            .map(timestamp)
            .transpose()?;
        let now = anchor.now()?;
        let expected = Expected {
            issuer: &self.0.config.issuer,
            application: &self.0.config.application_id,
            environment: &self.0.config.environment_id,
            licence: expected_licence.or_else(|| previous.map(|p| p.licence_id.as_str())),
            activation: &reply.activation_id,
            installation: &self.0.device.installation_id,
            fingerprint: self.0.device.fingerprint.as_deref(),
            fingerprint_provider: self.0.device.fingerprint_provider.as_deref(),
            allow_unbound_fingerprint: true,
            credential_expires_at: expiry,
            licence_expires_at: licence_expiry,
            now,
        };
        let claims = grants::verify(
            &token,
            &*self.0.keys.lock().map_err(|_| Error::Storage)?,
            &expected,
        )?;
        if claims.binding_mode != reply.binding_mode {
            return Err(Error::InvalidResponse);
        }
        let credential = reply
            .credential
            .or_else(|| previous.map(|saved| saved.credential.clone()))
            .ok_or(Error::InvalidResponse)?;
        if !bearer(&credential) {
            return Err(Error::InvalidResponse);
        }
        let saved = StoredCredential {
            application_id: self.0.config.application_id.clone(),
            environment_id: self.0.config.environment_id.clone(),
            activation_id: reply.activation_id,
            licence_id: claims.sub.clone(),
            installation_id: self.0.device.installation_id.clone(),
            credential,
            credential_expires_at: expiry,
            fingerprint: self.0.device.fingerprint.clone(),
            fingerprint_provider: self.0.device.fingerprint_provider.clone(),
        };
        let (received_server_time, received_wall_time) = anchor.receipt();
        let jwks = self
            .0
            .keys
            .lock()
            .map_err(|_| Error::Storage)?
            .public_key(&token)?;
        let cache = crate::installed::Cache {
            jws: token,
            jwks: serde_json::from_value(jwks).map_err(|_| Error::InvalidResponse)?,
            licence_expires_at: licence_expiry,
            received_server_time,
            received_wall_time,
            server_high_water: now,
            wall_high_water: clock::wall()?,
        };
        Ok((
            VerifiedReply::Ordinary {
                credential: saved,
                claims: Box::new(claims),
                anchor,
                cache,
            },
            update_available,
        ))
    }
}
pub(crate) fn clear(state: &mut State) {
    clear_access(state);
    state.account = None;
}
fn clear_access(state: &mut State) {
    state.generation = state.generation.wrapping_add(1);
    state.claims = None;
    state.anchor = None;
    state.credential = None;
    state.transient = false;
    state.retry_deadline = None;
    state.restored = false;
    state.last_failure = None;
    state.session_policy_known = false;
    state.session_required = false;
    state.session_disabled = false;
    state.session = None;
    state.pending_session_id = None;
    state.session_retry_deadline = None;
    state.session_licence_expires_at = None;
    state.update_available = None;
    if let Some(offline) = state.offline.as_mut() {
        offline.authorized = false;
    }
}

fn transient_retry_delay() -> Duration {
    let mut entropy = [0_u8; 1];
    if aws_lc_rs::rand::fill(&mut entropy).is_err() {
        return Duration::from_secs(15);
    }
    Duration::from_secs(15 + u64::from(entropy[0] % 30))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "local-development")]
    use crate::transport::tests::Fixture;
    const NOW: i64 = 1_800_000_000;
    fn claims(offline: bool) -> serde_json::Value {
        json!({"iss":"https://orbit.example.test","aud":"orbit:app:test","sub":"licence","jti":"random","iat":NOW,"nbf":NOW,"exp":NOW+300,"application_id":"app","environment_id":"test","activation_id":"activation","installation_id":"installation_1234","binding_mode":"none","policy_version":1,"entitlements":{"export":true},"refresh_after":NOW+60,"offline_allowed":offline})
    }
    fn stored_credential() -> StoredCredential {
        StoredCredential {
            application_id: "app".into(),
            environment_id: "test".into(),
            activation_id: "activation".into(),
            licence_id: "licence".into(),
            installation_id: "installation_1234".into(),
            credential: "a".repeat(43),
            credential_expires_at: Some(NOW + 3600),
            fingerprint: None,
            fingerprint_provider: None,
        }
    }
    fn constructor(provider: Option<&str>, credential: Option<StoredCredential>) -> Result<Client> {
        let storage = Arc::new(MemoryStorage::default());
        if let Some(credential) = credential {
            storage.save(0, credential).unwrap();
        }
        Client::with_storage(
            Config {
                application_id: "app".into(),
                environment_id: "test".into(),
                issuer: "https://orbit.example.test".into(),
            },
            Device {
                installation_id: "installation_1234".into(),
                fingerprint: provider.map(|_| "a".repeat(64)),
                fingerprint_provider: provider.map(str::to_owned),
            },
            Transport::new("https://orbit.example.test").unwrap(),
            storage,
        )
    }
    fn client(offline: bool) -> Client {
        let client = constructor(None, Some(stored_credential())).unwrap();
        {
            let mut state = client.0.state.lock().unwrap();
            state.claims = Some(serde_json::from_value(claims(offline)).unwrap());
            state.anchor = Some(Anchor::from_request(NOW, clock::Start::capture().unwrap()));
        }
        client
    }

    #[test]
    fn transient_retry_delay_stays_within_the_randomized_range() {
        for _ in 0..128 {
            let delay = transient_retry_delay();
            assert!((15..=44).contains(&delay.as_secs()));
            assert_eq!(delay.subsec_nanos(), 0);
        }
    }

    #[test]
    fn constructor_enforces_machine_and_custom_provider_grammar() {
        let maximum = format!("custom:{}", "a".repeat(48));
        for provider in [
            "machine_v1",
            "custom:a",
            "custom:acme.v1",
            "custom:a-b_c.09",
            &maximum,
        ] {
            assert!(constructor(Some(provider), None).is_ok(), "{provider}");
        }
        let too_long = format!("custom:{}", "a".repeat(49));
        for provider in [
            "",
            "machine_v2",
            "MACHINE_V1",
            "custom:",
            "Custom:a",
            "custom:A",
            "custom:a/b",
            "custom:a b",
            "custom:a\nb",
            "custom:é",
            &too_long,
        ] {
            assert!(
                matches!(constructor(Some(provider), None), Err(Error::Configuration)),
                "{provider}"
            );
        }
    }

    #[test]
    fn constructor_rejects_corrupt_stored_identifiers_and_bearers() {
        for invalid in [
            "".to_owned(),
            "../activation".into(),
            "id/validate".into(),
            "id?other=value".into(),
            "id space".into(),
            "é".into(),
            "a".repeat(129),
        ] {
            let mut activation = stored_credential();
            activation.activation_id = invalid.clone();
            assert!(matches!(
                constructor(None, Some(activation)),
                Err(Error::Storage)
            ));
            let mut licence = stored_credential();
            licence.licence_id = invalid;
            assert!(matches!(
                constructor(None, Some(licence)),
                Err(Error::Storage)
            ));
        }
        for invalid in [
            String::new(),
            "a".repeat(42),
            "a".repeat(44),
            format!("{}.", "a".repeat(42)),
            format!("{}/", "a".repeat(42)),
            format!("{}\n", "a".repeat(42)),
            format!("{}é", "a".repeat(41)),
        ] {
            let mut credential = stored_credential();
            credential.credential = invalid;
            assert!(matches!(
                constructor(None, Some(credential)),
                Err(Error::Storage)
            ));
        }
    }

    #[test]
    fn constructor_admits_valid_stored_opaque_credentials() {
        for (activation, licence, bearer) in [
            ("A".into(), "L".into(), "a".repeat(43)),
            (
                "A_-0".repeat(32),
                "L_-9".repeat(32),
                format!("A0_-{}", "a".repeat(39)),
            ),
        ] {
            let mut credential = stored_credential();
            credential.activation_id = activation;
            credential.licence_id = licence;
            credential.credential = bearer;
            let client = constructor(None, Some(credential)).unwrap();
            assert_eq!(client.snapshot().unwrap().access, Access::RefreshRequired);
        }
    }

    #[cfg(feature = "local-development")]
    fn jwks() -> serde_json::Value {
        let path = std::env::var_os("ORBIT_SDK_GRANT_VECTORS")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../contracts/sdk/grants.json")
            });
        let corpus: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        corpus["jwks"].clone()
    }

    #[cfg(feature = "local-development")]
    fn signed_reply(refresh: bool, licence: &str) -> String {
        use jsonwebtoken::{Algorithm, EncodingKey, Header};
        jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER
            .install_default()
            .ok();
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("orbit-access+jwt".into());
        header.kid = Some("test-key".into());
        let mut claims = claims(false);
        claims["sub"] = json!(licence);
        let token = jsonwebtoken::encode(
            &header,
            &claims,
            &EncodingKey::from_ec_pem(include_bytes!("../tests/fixtures/es256-test-private.pem"))
                .unwrap(),
        )
        .unwrap();
        json!({"activation_id":"activation", "installation_id":"installation_1234",
            "credential":if refresh { None } else { Some("b".repeat(43)) },
            "credential_expires_at":"2027-01-15T09:00:00Z", "grant":token,
            "server_time":"2027-01-15T08:00:00Z", "binding_mode":"none",
            "fingerprint_provider":null, "licence_expires_at":null, "secret_replay_expired":false})
        .to_string()
    }

    #[cfg(feature = "local-development")]
    fn reply_with_kid(reply: &str, kid: &str) -> String {
        use base64::Engine;
        let mut reply: serde_json::Value = serde_json::from_str(reply).unwrap();
        let token = reply["grant"].as_str().unwrap();
        let mut parts: Vec<String> = token.split('.').map(str::to_owned).collect();
        let mut header: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[0].as_str())
                .unwrap(),
        )
        .unwrap();
        header["kid"] = json!(kid);
        parts[0] =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        reply["grant"] = json!(parts.join("."));
        reply.to_string()
    }

    #[cfg(feature = "local-development")]
    fn reply_with_invalid_signature(reply: &str) -> String {
        use base64::Engine;
        let mut reply: serde_json::Value = serde_json::from_str(reply).unwrap();
        let token = reply["grant"].as_str().unwrap().to_owned();
        let (unsigned, _) = token.rsplit_once('.').unwrap();
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0_u8; 64]);
        reply["grant"] = json!(format!("{unsigned}.{signature}"));
        reply.to_string()
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn lifecycle_late_activation_validation_and_errors_do_not_restore_or_clear_identity() {
        for refresh in [false, true] {
            for newer_identity in [false, true] {
                for success in [false, true] {
                    let mut fixture = Fixture::new().await;
                    let mut client = client(false);
                    Arc::get_mut(&mut client.0).unwrap().transport = fixture.transport.clone();
                    *client.0.keys.lock().unwrap() = Keys::parse(jwks()).unwrap();
                    let previous_client = client.clone();
                    let previous = tokio::spawn(async move {
                        if refresh {
                            previous_client.refresh().await
                        } else {
                            previous_client
                                .activate_with_id("old-key", "old_operation_123")
                                .await
                        }
                    });
                    let late = fixture.next().await;
                    assert!(late.head.starts_with(if refresh {
                        "POST /api/client/v1/activations/activation/validate "
                    } else {
                        "POST /api/client/v1/activations "
                    }));
                    let newer = if newer_identity {
                        let next = Client::with_storage(
                            client.0.config.clone(),
                            client.0.device.clone(),
                            fixture.transport.clone(),
                            client.0.storage.clone(),
                        )
                        .unwrap();
                        *next.0.keys.lock().unwrap() = Keys::parse(jwks()).unwrap();
                        let next_client = next.clone();
                        let activation = tokio::spawn(async move {
                            next_client
                                .activate_with_id("new-key", "new_operation_123")
                                .await
                        });
                        fixture
                            .next()
                            .await
                            .respond(200, &signed_reply(false, "new_licence"));
                        assert_eq!(activation.await.unwrap().unwrap().access, Access::Online);
                        Some(next)
                    } else {
                        client.logout().unwrap();
                        None
                    };
                    if success {
                        late.respond(200, &signed_reply(refresh, "licence"));
                    } else {
                        late.respond(403, r#"{"error":{"code":"licence_revoked","message":"Denied","request_id":"fixture"}}"#);
                    }
                    assert!(matches!(previous.await.unwrap(), Err(Error::StaleResponse)));
                    assert_eq!(client.snapshot().unwrap().access, Access::Denied);
                    if let Some(newer) = newer {
                        assert_eq!(newer.snapshot().unwrap().access, Access::Online);
                        assert_eq!(
                            newer.0.storage.load().unwrap().1.unwrap().licence_id,
                            "new_licence"
                        );
                    } else {
                        assert!(client.0.storage.load().unwrap().1.is_none());
                    }
                    fixture.assert_idle();
                }
            }
        }
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn lifecycle_activation_retry_keeps_request_and_commits_once() {
        let mut fixture = Fixture::new().await;
        let mut client = client(false);
        Arc::get_mut(&mut client.0).unwrap().transport = fixture.transport.clone();
        *client.0.keys.lock().unwrap() = Keys::parse(jwks()).unwrap();
        let activating_client = client.clone();
        let operation = tokio::spawn(async move {
            activating_client
                .activate_with_previous("key", Some("previous-proof"), Some("retry_operation_123"))
                .await
        });
        let first = fixture.next().await;
        let expected = first.body.clone();
        let body: serde_json::Value = serde_json::from_slice(&expected).unwrap();
        assert_eq!(body["idempotency_key"], "retry_operation_123");
        assert_eq!(body["previous_credential"], "previous-proof");
        first.respond(503, crate::transport::tests::TRANSIENT);
        let retry = fixture.next().await;
        assert_eq!(retry.body, expected);
        retry.respond(200, &signed_reply(false, "licence"));
        assert_eq!(operation.await.unwrap().unwrap().access, Access::Online);
        let (version, credential) = client.0.storage.load().unwrap();
        assert_eq!(version, 1);
        assert_eq!(credential.unwrap().credential, "b".repeat(43));
        fixture.assert_idle();
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn lifecycle_cancelled_or_dropped_activation_cannot_commit_after_key_fetch() {
        for drop_future in [false, true] {
            let mut fixture = Fixture::new().await;
            let mut client = client(false);
            Arc::get_mut(&mut client.0).unwrap().transport = fixture.transport.clone();
            let cancel = Cancellation::new();
            let operation_cancel = cancel.clone();
            let activating_client = client.clone();
            let operation = tokio::spawn(async move {
                activating_client
                    .activate_with_cancel("key", "cancel_operation_123", &operation_cancel)
                    .await
            });
            fixture
                .next()
                .await
                .respond(200, &signed_reply(false, "licence"));
            let keys = fixture.next().await;
            assert!(keys.head.starts_with("GET /.well-known/orbit-jwks.json?"));
            if drop_future {
                operation.abort();
                assert!(operation.await.unwrap_err().is_cancelled());
            } else {
                cancel.cancel();
                assert!(matches!(operation.await.unwrap(), Err(Error::Cancelled)));
            }
            keys.respond(200, &jwks().to_string());
            assert_eq!(client.snapshot().unwrap().access, Access::Denied);
            assert!(client.0.storage.load().unwrap().1.is_none());
            fixture.assert_idle();
        }
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn lifecycle_logout_during_key_fetch_rejects_verified_success() {
        let mut fixture = Fixture::new().await;
        let mut client = client(false);
        Arc::get_mut(&mut client.0).unwrap().transport = fixture.transport.clone();
        let activating_client = client.clone();
        let operation = tokio::spawn(async move {
            activating_client
                .activate_with_id("key", "logout_operation_123")
                .await
        });
        fixture
            .next()
            .await
            .respond(200, &signed_reply(false, "licence"));
        let keys = fixture.next().await;
        client.logout().unwrap();
        keys.respond(200, &jwks().to_string());
        assert!(matches!(
            operation.await.unwrap(),
            Err(Error::StaleResponse)
        ));
        assert_eq!(client.snapshot().unwrap().access, Access::Denied);
        assert!(client.0.storage.load().unwrap().1.is_none());
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn lifecycle_pending_jwks_failure_respects_cancellation_and_invalidation() {
        for race in ["logout", "shared_storage", "cancellation"] {
            let mut fixture = Fixture::new().await;
            let mut client = client(true);
            Arc::get_mut(&mut client.0).unwrap().transport = fixture.transport.clone();
            let cancel = Cancellation::new();
            let operation_cancel = cancel.clone();
            let refreshing = client.clone();
            let operation =
                tokio::spawn(
                    async move { refreshing.refresh_with_cancel(&operation_cancel).await },
                );
            fixture
                .next()
                .await
                .respond(200, &signed_reply(true, "licence"));
            let pending_keys = fixture.next().await;
            assert!(
                pending_keys
                    .head
                    .starts_with("GET /.well-known/orbit-jwks.json?")
            );

            match race {
                "logout" => client.logout().unwrap(),
                "shared_storage" => {
                    client.0.storage.invalidate().unwrap();
                }
                "cancellation" => cancel.cancel(),
                _ => unreachable!(),
            }

            if race == "cancellation" {
                assert!(matches!(operation.await.unwrap(), Err(Error::Cancelled)));
                pending_keys.respond(503, crate::transport::tests::TRANSIENT);
                assert_eq!(client.snapshot().unwrap().access, Access::Online);
                assert!(client.0.storage.load().unwrap().1.is_some());
            } else {
                let mut keys = Some(pending_keys);
                for _ in 0..3 {
                    let request = match keys.take() {
                        Some(request) => request,
                        None => fixture.next().await,
                    };
                    request.respond(503, crate::transport::tests::TRANSIENT);
                }
                assert!(matches!(
                    operation.await.unwrap(),
                    Err(Error::StaleResponse)
                ));
                assert_eq!(client.snapshot().unwrap().access, Access::Denied);
                assert!(client.0.storage.load().unwrap().1.is_none());
            }
            fixture.assert_idle();
        }
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn explicit_empty_or_out_of_range_mutation_ids_do_not_change_state_or_send() {
        let mut fixture = Fixture::new().await;
        let mut client = client(false);
        Arc::get_mut(&mut client.0).unwrap().transport = fixture.transport.clone();
        let before = {
            let state = client.0.state.lock().unwrap();
            (
                state.generation,
                state.credential.as_ref().unwrap().credential.clone(),
            )
        };
        let result = client.activate_with_id("key", "").await;
        assert!(matches!(result, Err(Error::Configuration)));
        assert!(matches!(
            client.activate_with_previous("key", None, Some("")).await,
            Err(Error::Configuration)
        ));
        assert!(matches!(
            client.activate_account_with_id("licence", "").await,
            Err(Error::Configuration)
        ));
        assert!(matches!(
            client
                .activate_account_with_previous("licence", None, Some(""))
                .await,
            Err(Error::Configuration)
        ));
        assert!(matches!(
            client.claim_licence_with_id("purchase-key", "").await,
            Err(Error::Configuration)
        ));
        assert!(matches!(
            client.deactivate_with_id("").await,
            Err(Error::Configuration)
        ));
        let state = client.0.state.lock().unwrap();
        assert_eq!(state.generation, before.0);
        assert_eq!(
            state
                .credential
                .as_ref()
                .map(|value| value.credential.as_str()),
            Some(before.1.as_str())
        );
        drop(state);
        fixture.assert_idle();
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn transient_jwks_failure_preserves_saved_credential_and_successful_retry_recovers() {
        let mut fixture = Fixture::new().await;
        let mut client = constructor(None, Some(stored_credential())).unwrap();
        Arc::get_mut(&mut client.0).unwrap().transport = fixture.transport.clone();
        let prior = client.0.storage.load().unwrap();
        let refreshing = client.clone();
        let operation = tokio::spawn(async move { refreshing.refresh().await });
        fixture
            .next()
            .await
            .respond(200, &signed_reply(true, "licence"));
        for _ in 0..3 {
            let keys = fixture.next().await;
            assert!(keys.head.starts_with("GET /.well-known/orbit-jwks.json?"));
            keys.respond(503, crate::transport::tests::TRANSIENT);
        }
        assert!(matches!(
            operation.await.unwrap(),
            Err(Error::Transient { request_id: Some(ref id), .. }) if id == "fixture"
        ));
        let snapshot = client.snapshot().unwrap();
        assert_eq!(snapshot.access, Access::RefreshRequired);
        assert!(snapshot.entitlements.is_empty());
        assert!(!snapshot.offline_allowed);
        let after_failure = client.0.storage.load().unwrap();
        assert_eq!(after_failure.0, prior.0);
        assert_eq!(
            after_failure.1.unwrap().credential,
            prior.1.unwrap().credential
        );

        let refreshing = client.clone();
        let retry = tokio::spawn(async move { refreshing.refresh().await });
        fixture
            .next()
            .await
            .respond(200, &signed_reply(true, "licence"));
        fixture.next().await.respond(200, &jwks().to_string());
        assert_eq!(retry.await.unwrap().unwrap().access, Access::Online);
        assert_eq!(
            client.0.storage.load().unwrap().1.unwrap().credential,
            stored_credential().credential
        );
        fixture.assert_idle();
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn anchorless_transient_refresh_is_throttled_and_can_retry() {
        let mut fixture = Fixture::new().await;
        let mut client = constructor(None, Some(stored_credential())).unwrap();
        Arc::get_mut(&mut client.0).unwrap().transport = fixture.transport.clone();

        let serial = client.0.serial.lock().await;
        let requiring = client.clone();
        let first = tokio::spawn(async move { requiring.require_access("export").await });
        tokio::task::yield_now().await;
        let requiring = client.clone();
        let queued = tokio::spawn(async move { requiring.require_access("export").await });
        tokio::task::yield_now().await;
        drop(serial);

        let validation = fixture.next().await;
        assert!(validation.head.contains("/activations/activation/validate"));
        let pacing_started = Instant::now();
        validation.respond(503, crate::transport::tests::TRANSIENT);
        for _ in 0..2 {
            let retry = fixture.next().await;
            assert!(retry.head.contains("/activations/activation/validate"));
            retry.respond(503, crate::transport::tests::TRANSIENT);
        }
        assert!(matches!(first.await.unwrap(), Err(Error::Transient { .. })));
        let queued = tokio::time::timeout(Duration::from_secs(1), queued)
            .await
            .expect("queued protected access should finish without another refresh")
            .unwrap();
        assert!(matches!(queued, Err(Error::Transient { .. })));
        let retry_deadline = client.0.state.lock().unwrap().retry_deadline.unwrap();
        assert!(retry_deadline >= pacing_started + Duration::from_secs(15));
        assert_eq!(
            client.0.storage.load().unwrap().1.unwrap().credential,
            stored_credential().credential
        );

        let repeated =
            tokio::time::timeout(Duration::from_secs(1), client.require_access("export"))
                .await
                .expect("access check should return without another refresh");
        assert!(matches!(repeated, Err(Error::Transient { .. })));
        fixture.assert_idle();

        // Explicit refresh bypasses the protected-call retry deadline.
        let refreshing = client.clone();
        let explicit = tokio::spawn(async move { refreshing.refresh().await });
        let validation = fixture.next().await;
        assert!(validation.head.contains("/activations/activation/validate"));
        validation.respond(200, &signed_reply(true, "licence"));
        for _ in 0..3 {
            let keys = fixture.next().await;
            assert!(keys.head.starts_with("GET /.well-known/orbit-jwks.json?"));
            keys.respond(503, crate::transport::tests::TRANSIENT);
        }
        assert!(matches!(
            explicit.await.unwrap(),
            Err(Error::Transient { .. })
        ));

        let repeated =
            tokio::time::timeout(Duration::from_secs(1), client.require_access("export"))
                .await
                .expect("access check should remain paced after the explicit refresh");
        assert!(matches!(repeated, Err(Error::Transient { .. })));
        fixture.assert_idle();

        client.0.state.lock().unwrap().retry_deadline =
            Some(Instant::now() - Duration::from_secs(1));
        let requiring = client.clone();
        let retry = tokio::spawn(async move { requiring.require_access("export").await });
        fixture
            .next()
            .await
            .respond(200, &signed_reply(true, "licence"));
        fixture.next().await.respond(200, &jwks().to_string());
        assert_eq!(retry.await.unwrap().unwrap().access, Access::Online);
        assert!(client.0.state.lock().unwrap().retry_deadline.is_none());
        fixture.assert_idle();
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn failed_anchor_uses_monotonic_retry_deadline() {
        let mut fixture = Fixture::new().await;
        let mut client = client(false);
        Arc::get_mut(&mut client.0).unwrap().transport = fixture.transport.clone();

        let anchor = Anchor::from_request(i64::MAX, clock::Start::capture().unwrap());
        let anchor_deadline = Instant::now() + Duration::from_secs(2);
        while anchor.now().is_ok() && Instant::now() < anchor_deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(anchor.now().is_err());
        client.0.state.lock().unwrap().anchor = Some(anchor);

        let refreshing = client.clone();
        let explicit = tokio::spawn(async move { refreshing.refresh().await });
        let validation = fixture.next().await;
        assert!(validation.head.contains("/activations/activation/validate"));
        let pacing_started = Instant::now();
        validation.respond(503, crate::transport::tests::TRANSIENT);
        for _ in 0..2 {
            fixture
                .next()
                .await
                .respond(503, crate::transport::tests::TRANSIENT);
        }
        assert!(matches!(
            explicit.await.unwrap(),
            Err(Error::Transient { .. })
        ));
        let retry_deadline = client.0.state.lock().unwrap().retry_deadline.unwrap();
        assert!(retry_deadline >= pacing_started + Duration::from_secs(15));

        for _ in 0..2 {
            let outcome = tokio::time::timeout(
                Duration::from_secs(1),
                client.refresh_if_needed(&Cancellation::new()),
            )
            .await
            .expect("invalid anchor fallback should suppress another refresh");
            assert!(matches!(outcome, Err(Error::Transient { .. })));
        }
        fixture.assert_idle();

        for _ in 0..2 {
            assert!(matches!(
                client.require_access("export").await,
                Err(Error::Transient { .. })
            ));
        }
        fixture.assert_idle();
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn transient_jwks_failure_removes_offline_authority_but_keeps_old_credential() {
        let mut fixture = Fixture::new().await;
        let mut client = client(true);
        Arc::get_mut(&mut client.0).unwrap().transport = fixture.transport.clone();
        let prior = client.0.storage.load().unwrap();
        let pacing_started = Instant::now();
        let refreshing = client.clone();
        let operation = tokio::spawn(async move { refreshing.refresh().await });
        fixture
            .next()
            .await
            .respond(200, &signed_reply(true, "licence"));
        for _ in 0..3 {
            let keys = fixture.next().await;
            keys.respond(503, crate::transport::tests::TRANSIENT);
        }
        assert!(matches!(
            operation.await.unwrap(),
            Err(Error::Transient { .. })
        ));
        let retry_deadline = client.0.state.lock().unwrap().retry_deadline.unwrap();
        assert!(retry_deadline >= pacing_started + Duration::from_secs(15));
        assert!(retry_deadline <= Instant::now() + Duration::from_secs(44));
        let snapshot = client.snapshot().unwrap();
        assert_eq!(snapshot.access, Access::RefreshRequired);
        assert!(snapshot.entitlements.is_empty());
        assert!(!snapshot.offline_allowed);
        let after_failure = client.0.storage.load().unwrap();
        assert_eq!(after_failure.0, prior.0);
        assert_eq!(
            after_failure.1.unwrap().credential,
            prior.1.unwrap().credential
        );
        fixture.assert_idle();
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn transient_jwks_failure_does_not_save_initial_activation_credential() {
        let mut fixture = Fixture::new().await;
        let mut client = constructor(None, None).unwrap();
        Arc::get_mut(&mut client.0).unwrap().transport = fixture.transport.clone();
        let activating = client.clone();
        let operation = tokio::spawn(async move {
            activating
                .activate_with_id("key", "initial_operation_123")
                .await
        });
        fixture
            .next()
            .await
            .respond(200, &signed_reply(false, "licence"));
        for _ in 0..3 {
            let keys = fixture.next().await;
            keys.respond(503, crate::transport::tests::TRANSIENT);
        }
        assert!(matches!(
            operation.await.unwrap(),
            Err(Error::Transient { .. })
        ));
        assert_eq!(client.snapshot().unwrap().access, Access::Denied);
        assert!(client.0.storage.load().unwrap().1.is_none());
        fixture.assert_idle();
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn malformed_unknown_and_invalid_grants_remain_terminal() {
        for kind in ["malformed_jwks", "unknown_key", "invalid_signature"] {
            let mut fixture = Fixture::new().await;
            let mut client = client(true);
            Arc::get_mut(&mut client.0).unwrap().transport = fixture.transport.clone();
            if kind == "invalid_signature" {
                *client.0.keys.lock().unwrap() = Keys::parse(jwks()).unwrap();
            }
            let refreshing = client.clone();
            let operation = tokio::spawn(async move { refreshing.refresh().await });
            let reply = signed_reply(true, "licence");
            let reply = if kind == "unknown_key" {
                reply_with_kid(&reply, "unknown-key")
            } else if kind == "invalid_signature" {
                reply_with_invalid_signature(&reply)
            } else {
                reply
            };
            fixture.next().await.respond(200, &reply);
            if kind != "invalid_signature" {
                let keys = fixture.next().await;
                if kind == "malformed_jwks" {
                    keys.respond(200, r#"{"keys":"invalid"}"#);
                } else {
                    keys.respond(200, &jwks().to_string());
                }
            }
            assert!(matches!(
                operation.await.unwrap(),
                Err(Error::InvalidResponse)
            ));
            assert_eq!(client.snapshot().unwrap().access, Access::Denied);
            assert!(client.0.storage.load().unwrap().1.is_none());
            fixture.assert_idle();
        }
    }

    #[tokio::test]
    async fn transient_fallback_requires_policy_and_original_expiry() {
        let online = client(false);
        let offline = client(true);
        for client in [&online, &offline] {
            let result = client
                .accept(
                    Err(Error::Transient {
                        code: Some("service_unavailable".into()),
                        request_id: Some("refresh_reference".into()),
                    }),
                    0,
                    None,
                    clock::Start::capture().unwrap(),
                    &Cancellation::new(),
                )
                .await;
            if Arc::ptr_eq(&client.0, &online.0) {
                assert_eq!(
                    result.as_ref().unwrap_err().request_id(),
                    Some("refresh_reference")
                );
                assert!(matches!(result, Err(Error::Transient { .. })));
                assert_eq!(client.snapshot().unwrap().access, Access::RefreshRequired);
            } else {
                assert_eq!(result.unwrap().access, Access::Offline);
            }
            let mut state = client.0.state.lock().unwrap();
            state.anchor = Some(Anchor::from_request(
                NOW + 3600,
                clock::Start::capture().unwrap(),
            ));
            assert_eq!(
                Client::snapshot_state(&state).unwrap().access,
                Access::Expired
            );
        }
    }
    #[test]
    fn shared_storage_invalidation_clears_cached_access() {
        let client = client(true);
        let snapshot = client.snapshot().unwrap();
        assert_eq!(snapshot.access, Access::Online);
        assert!(snapshot.has_feature("export"));
        assert!(!snapshot.has_feature("missing"));
        client.0.storage.invalidate().unwrap();
        let snapshot = client.snapshot().unwrap();
        assert_eq!(snapshot.access, Access::Denied);
        assert!(!snapshot.has_feature("export"));
    }
    #[tokio::test]
    async fn explicit_denial_tls_failure_and_logout_invalidate_generations() {
        for error in [
            Error::Denied {
                code: "licence_revoked".into(),
                request_id: None,
            },
            Error::InvalidResponse,
            Error::TransportSecurity,
        ] {
            let client = client(true);
            assert!(
                client
                    .accept(
                        Err(error),
                        0,
                        None,
                        clock::Start::capture().unwrap(),
                        &Cancellation::new()
                    )
                    .await
                    .is_err()
            );
            assert_eq!(client.snapshot().unwrap().access, Access::Denied);
            assert!(matches!(
                client
                    .accept(
                        Ok(Some(json!({"grant":"late-success"}))),
                        0,
                        None,
                        clock::Start::capture().unwrap(),
                        &Cancellation::new()
                    )
                    .await,
                Err(Error::StaleResponse)
            ));
        }
        let client = client(true);
        client.logout().unwrap();
        assert!(matches!(
            client
                .accept(
                    Err(Error::transient()),
                    0,
                    None,
                    clock::Start::capture().unwrap(),
                    &Cancellation::new()
                )
                .await,
            Err(Error::StaleResponse)
        ));
        assert_eq!(client.snapshot().unwrap().access, Access::Denied);
    }
}
