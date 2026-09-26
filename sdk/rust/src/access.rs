use crate::{
    Cancellation, Error, MemoryStorage, Result, Storage, StoredCredential, Transport,
    accounts::Session,
    clock::{self, Anchor},
    grants::{self, Claims, Expected, Keys},
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
pub struct Config {
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
    pub expires_at: Option<i64>,
    pub next_check_at: Option<i64>,
    pub credential_expires_at: Option<i64>,
    pub reauthentication_required: bool,
    pub offline_allowed: bool,
    pub remaining_offline_seconds: u64,
}
pub(crate) struct State {
    pub(crate) generation: u64,
    pub(crate) storage_version: u64,
    pub(crate) account: Option<Session>,
    pub(crate) credential: Option<StoredCredential>,
    pub(crate) claims: Option<Claims>,
    pub(crate) anchor: Option<Anchor>,
    pub(crate) restored: bool,
    transient: bool,
    retry_deadline: Option<Instant>,
    last_failure: Option<Error>,
}
pub(crate) struct Inner {
    pub(crate) config: Config,
    device: Device,
    pub(crate) transport: Transport,
    pub(crate) storage: Arc<dyn Storage>,
    pub(crate) state: Mutex<State>,
    pub(crate) serial: tokio::sync::Mutex<()>,
    pub(crate) keys: Mutex<Keys>,
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
                let _ = storage.checkpoint(state.anchor.as_ref(), true);
            }
            storage.close();
        }
    }
}
#[derive(Clone)]
pub struct Client(pub(crate) Arc<Inner>);
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
fn bearer(value: &str) -> bool {
    value.len() == 43 && opaque(value)
}
fn valid_provider(value: &str) -> bool {
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
impl Client {
    pub fn new(config: Config, device: Device, transport: Transport) -> Result<Self> {
        Self::with_storage(
            config,
            device,
            transport,
            Arc::new(MemoryStorage::default()),
        )
    }
    pub fn with_storage(
        config: Config,
        device: Device,
        mut transport: Transport,
        storage: Arc<dyn Storage>,
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
            && !valid_stored_credential(saved, &config, &device)
        {
            return Err(Error::Storage);
        }
        Ok(Self(Arc::new(Inner {
            config,
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
                restored: false,
                transient: false,
                retry_deadline: None,
                last_failure: None,
            }),
            serial: tokio::sync::Mutex::new(()),
            keys: Mutex::new(Keys::default()),
            installed: None,
            worker: Mutex::new(None),
            close_serial: tokio::sync::Mutex::new(()),
            closed: std::sync::atomic::AtomicBool::new(false),
        })))
    }
    pub fn snapshot(&self) -> Result<Snapshot> {
        let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
        self.sync_storage(&mut state)?;
        if state
            .anchor
            .as_ref()
            .is_some_and(|anchor| anchor.now().is_err())
        {
            state.claims = None;
            state.anchor = None;
            state.generation = state.generation.wrapping_add(1);
            if let Some(storage) = &self.0.installed {
                state.storage_version = storage.clear_cached(false, false)?;
            }
        }
        Self::snapshot_state(&state)
    }
    fn snapshot_state(state: &State) -> Result<Snapshot> {
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
            credential_expires_at: credential_expiry,
            reauthentication_required: state.credential.is_none(),
            offline_allowed: false,
            remaining_offline_seconds: 0,
        };
        if let (Some(claims), Some(anchor)) = (&state.claims, &state.anchor) {
            let now = match anchor.now() {
                Ok(now) => now,
                Err(_) => return Ok(snapshot),
            };
            snapshot.expires_at = Some(claims.exp);
            snapshot.next_check_at = Some(claims.refresh_after);
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
                    snapshot.remaining_offline_seconds = (claims.exp - now) as u64;
                }
            }
        }
        Ok(snapshot)
    }
    pub(crate) fn sync_storage(&self, state: &mut State) -> Result<()> {
        if self.0.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(Error::Closed);
        }
        let version = self.0.storage.version()?;
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
        clear(&mut state);
        state.storage_version = self.0.storage.invalidate()?;
        Ok(())
    }
    pub async fn activate(
        &self,
        key: &str,
        idempotency_key: &str,
        cancel: &Cancellation,
    ) -> Result<Snapshot> {
        self.activate_with_previous(key, None, idempotency_key, cancel)
            .await
    }
    pub async fn activate_with_previous(
        &self,
        key: &str,
        previous_credential: Option<&str>,
        idempotency_key: &str,
        cancel: &Cancellation,
    ) -> Result<Snapshot> {
        self.activate_as(
            ActivationPrincipal::Key(key),
            previous_credential,
            idempotency_key,
            cancel,
        )
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
            let session = match principal {
                ActivationPrincipal::Key(_) => None,
                ActivationPrincipal::Account(_) => Some(
                    state
                        .account
                        .as_ref()
                        .ok_or(Error::ReauthenticationRequired)?
                        .token
                        .clone(),
                ),
            };
            let operation = if let Some(storage) = &self.0.installed {
                let (operation, version) =
                    storage.prepare_activation(principal, previous_credential, idempotency_key)?;
                state.storage_version = version;
                state.generation = state.generation.wrapping_add(1);
                state.claims = None;
                state.anchor = None;
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
            .post("/api/client/v1/activations", &input, true, cancel)
            .await;
        self.accept_for_licence(
            response,
            generation,
            None,
            started,
            cancel,
            expected_licence,
        )
        .await
    }
    pub async fn refresh(&self, cancel: &Cancellation) -> Result<Snapshot> {
        self.refresh_inner(cancel, false).await
    }
    pub(crate) async fn refresh_if_needed(&self, cancel: &Cancellation) -> Result<Snapshot> {
        self.refresh_inner(cancel, true).await
    }
    async fn refresh_inner(&self, cancel: &Cancellation, respect_retry: bool) -> Result<Snapshot> {
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
                if self.0.installed.is_some()
                    && snapshot.access != Access::Offline
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
        let body = self.credential_body(&saved);
        let started = clock::Start::capture()?;
        let response = self
            .0
            .transport
            .post(
                &format!(
                    "/api/client/v1/activations/{}/validate",
                    saved.activation_id
                ),
                &body,
                true,
                cancel,
            )
            .await;
        self.accept(response, generation, Some(saved), started, cancel)
            .await
    }
    fn credential_body(&self, saved: &StoredCredential) -> serde_json::Value {
        json!({"application_id":self.0.config.application_id,"environment_id":self.0.config.environment_id,"credential":saved.credential,
            "installation_id":self.0.device.installation_id,"fingerprint":self.0.device.fingerprint,"fingerprint_provider":self.0.device.fingerprint_provider})
    }
    pub async fn deactivate(&self, idempotency_key: &str, cancel: &Cancellation) -> Result<()> {
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
            .post(
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
    pub async fn require_access(&self, feature: &str, cancel: &Cancellation) -> Result<Snapshot> {
        let snapshot = self.snapshot()?;
        let snapshot = if matches!(
            snapshot.access,
            Access::RefreshRequired | Access::Expired | Access::Offline
        ) {
            match self.refresh_if_needed(cancel).await {
                Ok(value) => value,
                Err(error @ Error::Transient { .. }) => {
                    let snapshot = self.snapshot()?;
                    if self.0.installed.is_some() && snapshot.access != Access::Offline {
                        return Err(error);
                    }
                    snapshot
                }
                Err(error) => return Err(error),
            }
        } else {
            snapshot
        };
        if !matches!(snapshot.access, Access::Online | Access::Offline) {
            return Err(Error::Denied {
                code: "access_unavailable".into(),
                request_id: None,
            });
        }
        if !snapshot.entitlements.get(feature).copied().unwrap_or(false) {
            return Err(Error::Denied {
                code: "feature_unavailable".into(),
                request_id: None,
            });
        }
        Ok(snapshot)
    }
    async fn accept(
        &self,
        response: Result<Option<serde_json::Value>>,
        generation: u64,
        previous: Option<StoredCredential>,
        started: clock::Start,
        cancel: &Cancellation,
    ) -> Result<Snapshot> {
        self.accept_for_licence(response, generation, previous, started, cancel, None)
            .await
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
            Ok((credential, claims, anchor, cache)) => {
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
                state.claims = Some(claims);
                state.anchor = Some(anchor);
                state.transient = false;
                state.restored = false;
                state.retry_deadline = None;
                state.last_failure = None;
                Self::snapshot_state(&state)
            }
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
                    let definitive = matches!(error, Error::Denied { .. });
                    state.generation = state.generation.wrapping_add(1);
                    state.claims = None;
                    state.anchor = None;
                    state.restored = false;
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
    ) -> Result<(StoredCredential, Claims, Anchor, crate::installed::Cache)> {
        let reply: Reply = serde_json::from_value(value).map_err(|_| Error::InvalidResponse)?;
        if reply.secret_replay_expired {
            return Err(Error::ReauthenticationRequired);
        }
        if !opaque(&reply.activation_id)
            || reply.installation_id != self.0.device.installation_id
            || reply.fingerprint_provider != self.0.device.fingerprint_provider
            || reply.binding_mode
                != if self.0.device.fingerprint.is_some() {
                    "hwid"
                } else {
                    "none"
                }
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
                .get(
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
            credential_expires_at: expiry,
            licence_expires_at: licence_expiry,
            now,
        };
        let claims = grants::verify(
            &token,
            &*self.0.keys.lock().map_err(|_| Error::Storage)?,
            &expected,
        )?;
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
        Ok((saved, claims, anchor, cache))
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
                            previous_client.refresh(&Cancellation::new()).await
                        } else {
                            previous_client
                                .activate("old-key", "old_operation_123", &Cancellation::new())
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
                                .activate("new-key", "new_operation_123", &Cancellation::new())
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
                .activate_with_previous(
                    "key",
                    Some("previous-proof"),
                    "retry_operation_123",
                    &Cancellation::new(),
                )
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
                    .activate("key", "cancel_operation_123", &operation_cancel)
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
                .activate("key", "logout_operation_123", &Cancellation::new())
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
                tokio::spawn(async move { refreshing.refresh(&operation_cancel).await });
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
    async fn transient_jwks_failure_preserves_saved_credential_and_successful_retry_recovers() {
        let mut fixture = Fixture::new().await;
        let mut client = constructor(None, Some(stored_credential())).unwrap();
        Arc::get_mut(&mut client.0).unwrap().transport = fixture.transport.clone();
        let prior = client.0.storage.load().unwrap();
        let refreshing = client.clone();
        let operation = tokio::spawn(async move { refreshing.refresh(&Cancellation::new()).await });
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
        let retry = tokio::spawn(async move { refreshing.refresh(&Cancellation::new()).await });
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
        let first = tokio::spawn(async move {
            requiring
                .require_access("export", &Cancellation::new())
                .await
        });
        tokio::task::yield_now().await;
        let requiring = client.clone();
        let queued = tokio::spawn(async move {
            requiring
                .require_access("export", &Cancellation::new())
                .await
        });
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
        assert!(matches!(
            first.await.unwrap(),
            Err(Error::Denied { ref code, .. }) if code == "access_unavailable"
        ));
        let queued = tokio::time::timeout(Duration::from_secs(1), queued)
            .await
            .expect("queued protected access should finish without another refresh")
            .unwrap();
        assert!(matches!(
            queued,
            Err(Error::Denied { ref code, .. }) if code == "access_unavailable"
        ));
        let retry_deadline = client.0.state.lock().unwrap().retry_deadline.unwrap();
        assert!(retry_deadline >= pacing_started + Duration::from_secs(15));
        assert_eq!(
            client.0.storage.load().unwrap().1.unwrap().credential,
            stored_credential().credential
        );

        let repeated = tokio::time::timeout(
            Duration::from_secs(1),
            client.require_access("export", &Cancellation::new()),
        )
        .await
        .expect("access check should return without another refresh");
        assert!(matches!(repeated, Err(Error::Denied { .. })));
        fixture.assert_idle();

        // Explicit refresh bypasses the protected-call retry deadline.
        let refreshing = client.clone();
        let explicit = tokio::spawn(async move { refreshing.refresh(&Cancellation::new()).await });
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

        let repeated = tokio::time::timeout(
            Duration::from_secs(1),
            client.require_access("export", &Cancellation::new()),
        )
        .await
        .expect("access check should remain paced after the explicit refresh");
        assert!(matches!(repeated, Err(Error::Denied { .. })));
        fixture.assert_idle();

        client.0.state.lock().unwrap().retry_deadline =
            Some(Instant::now() - Duration::from_secs(1));
        let requiring = client.clone();
        let retry = tokio::spawn(async move {
            requiring
                .require_access("export", &Cancellation::new())
                .await
        });
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
        let explicit = tokio::spawn(async move { refreshing.refresh(&Cancellation::new()).await });
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
            let snapshot = tokio::time::timeout(
                Duration::from_secs(1),
                client.refresh_if_needed(&Cancellation::new()),
            )
            .await
            .expect("invalid anchor fallback should suppress another refresh")
            .unwrap();
            assert_eq!(snapshot.access, Access::RefreshRequired);
        }
        fixture.assert_idle();

        for _ in 0..2 {
            assert!(matches!(
                client.require_access("export", &Cancellation::new()).await,
                Err(Error::Denied { .. })
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
        let operation = tokio::spawn(async move { refreshing.refresh(&Cancellation::new()).await });
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
                .activate("key", "initial_operation_123", &Cancellation::new())
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
            let operation =
                tokio::spawn(async move { refreshing.refresh(&Cancellation::new()).await });
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
        assert_eq!(client.snapshot().unwrap().access, Access::Online);
        client.0.storage.invalidate().unwrap();
        assert_eq!(client.snapshot().unwrap().access, Access::Denied);
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
