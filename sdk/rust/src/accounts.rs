use crate::{
    Cancellation, Client, Error, Result, Snapshot,
    access::{self, ActivationPrincipal},
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize)]
pub struct Customer {
    pub id: String,
    pub username: String,
    pub email: String,
    pub suspended: bool,
    pub created_at: String,
}

/// Safe account metadata. Successful login does not authorize protected work.
#[derive(Clone, Debug)]
pub struct Account {
    pub customer: Customer,
    pub expires_at: String,
}

/// Sensitive, opaque login proof held only in memory, with redacted debugging.
/// Possession establishes neither current session validity nor licensed access.
#[derive(Clone)]
pub struct CustomerSessionProof {
    token: String,
}

impl std::fmt::Debug for CustomerSessionProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CustomerSessionProof([REDACTED])")
    }
}

impl CustomerSessionProof {
    /// Return the sensitive `Bearer <token>` Authorization header value.
    /// Send it only to your own trusted HTTPS backend, which must verify the
    /// session online with Orbit. Never send it to arbitrary URLs, log it or
    /// persist it. This value does not itself authorize licensed work.
    pub fn authorization_header(&self) -> String {
        format!("Bearer {}", self.token)
    }
}

/// Customer sessions never enter a Storage adapter or a serializable public type.
#[derive(Clone)]
pub(crate) struct Session {
    pub(crate) token: String,
    account: Account,
}

#[derive(Deserialize)]
struct LoginReply {
    customer: Customer,
    session: String,
    expires_at: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OwnedLicence {
    pub id: String,
    pub policy_name: String,
    pub state: String,
    pub expiry_mode: String,
    pub first_used_at: Option<String>,
    pub expires_at: Option<String>,
    pub duration_seconds: Option<i64>,
    pub device_limit: i32,
    pub hwid_locked: bool,
    pub offline_allowed: bool,
    pub offline_seconds: i32,
    pub entitlements: BTreeMap<String, bool>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OwnedLicences {
    pub items: Vec<OwnedLicence>,
    pub next_cursor: Option<String>,
}

/// Borrowed input is sent once and is never retained by the SDK.
pub struct Registration<'a> {
    pub licence_key: &'a str,
    pub username: &'a str,
    pub email: &'a str,
    pub password: &'a str,
}

/// Narrow resend proof retained in memory; deliberately not Debug or Serialize.
pub struct PendingRegistration {
    pub accepted: bool,
    pub expires_at: String,
    resend_credential: String,
    application_id: String,
    environment_id: String,
}

#[derive(Deserialize)]
struct RegistrationReply {
    accepted: bool,
    resend_credential: String,
    expires_at: String,
}

#[derive(Deserialize)]
struct Accepted {
    accepted: bool,
}

impl Client {
    pub fn account(&self) -> Result<Option<Account>> {
        let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
        self.sync_storage(&mut state)?;
        Ok(state
            .account
            .as_ref()
            .map(|session| session.account.clone()))
    }

    /// Copy the locally held login proof after synchronizing storage invalidation.
    /// The receiving trusted backend must verify current session validity online;
    /// this method does not establish validity or licensed access.
    pub fn customer_session_proof(&self) -> Result<CustomerSessionProof> {
        let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
        self.sync_storage(&mut state)?;
        let session = state
            .account
            .as_ref()
            .ok_or(Error::ReauthenticationRequired)?;
        Ok(CustomerSessionProof {
            token: session.token.clone(),
        })
    }

    pub async fn login(
        &self,
        username: &str,
        password: &str,
        cancel: &Cancellation,
    ) -> Result<Account> {
        if username.is_empty() || username.len() > 128 || password.len() > 256 {
            return Err(Error::Configuration);
        }
        let generation = self.generation()?;
        let _serial = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(Error::Cancelled),
            guard = self.0.serial.lock() => guard,
        };
        let generation = {
            let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
            self.sync_storage(&mut state)?;
            if state.generation != generation {
                return Err(Error::StaleResponse);
            }
            access::clear(&mut state);
            state.storage_version = self.0.storage.invalidate()?;
            state.generation
        };
        let response = self
            .0
            .transport
            .post(
                "/api/client/v1/sessions",
                &self.account_body(json!({"username": username, "password": password})),
                false,
                cancel,
            )
            .await;
        let reply: LoginReply = self.finish_account(decode(response), generation, cancel)?;
        let valid = access::opaque(&reply.customer.id)
            && !reply.customer.suspended
            && (3..=32).contains(&reply.customer.username.len())
            && reply
                .customer
                .username
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
            && !reply.customer.email.is_empty()
            && reply.customer.email.len() <= 254
            && bearer(&reply.session)
            && access::timestamp(&reply.customer.created_at).is_ok()
            && access::timestamp(&reply.expires_at).is_ok();
        if !valid {
            return self.finish_account(Err(Error::InvalidResponse), generation, cancel);
        }
        let account = Account {
            customer: reply.customer,
            expires_at: reply.expires_at,
        };
        let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
        self.sync_storage(&mut state)?;
        if state.generation != generation {
            return Err(Error::StaleResponse);
        }
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        state.account = Some(Session {
            token: reply.session,
            account: account.clone(),
        });
        Ok(account)
    }

    pub async fn activate_account(
        &self,
        licence_id: &str,
        idempotency_key: &str,
        cancel: &Cancellation,
    ) -> Result<Snapshot> {
        self.activate_account_with_previous(licence_id, None, idempotency_key, cancel)
            .await
    }

    pub async fn activate_account_with_previous(
        &self,
        licence_id: &str,
        previous_credential: Option<&str>,
        idempotency_key: &str,
        cancel: &Cancellation,
    ) -> Result<Snapshot> {
        self.activate_as(
            ActivationPrincipal::Account(licence_id),
            previous_credential,
            idempotency_key,
            cancel,
        )
        .await
    }

    /// Local state is cleared when this method is called, even if its returned
    /// future is dropped. Only a successful await confirms remote revocation.
    pub fn logout_account<'a>(
        &'a self,
        cancel: &'a Cancellation,
    ) -> impl std::future::Future<Output = Result<()>> + 'a {
        let prepared = (|| -> Result<Option<Session>> {
            let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
            let session = state.account.take();
            access::clear(&mut state);
            state.storage_version = self.0.storage.invalidate()?;
            Ok(session)
        })();
        async move {
            let Some(session) = prepared? else {
                return Ok(());
            };
            let response = self
                .0
                .transport
                .delete_bearer(
                    &self.account_path("/api/client/v1/sessions/current", None),
                    &session.token,
                    cancel,
                )
                .await?;
            if response.is_some() {
                return Err(Error::InvalidResponse);
            }
            Ok(())
        }
    }

    pub async fn owned_licences(
        &self,
        after: Option<&str>,
        cancel: &Cancellation,
    ) -> Result<OwnedLicences> {
        if after.is_some_and(|cursor| !access::opaque(cursor)) {
            return Err(Error::Configuration);
        }
        let generation = self.generation()?;
        let _serial = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(Error::Cancelled),
            guard = self.0.serial.lock() => guard,
        };
        let session = self.customer_session(generation)?;
        let response = self
            .0
            .transport
            .get_bearer(
                &self.account_path("/api/client/v1/licences", after),
                &session.token,
                cancel,
            )
            .await;
        let result = decode::<OwnedLicences>(response).and_then(|page| {
            if page.items.len() > 100
                || page
                    .next_cursor
                    .as_deref()
                    .is_some_and(|value| !access::opaque(value))
            {
                return Err(Error::InvalidResponse);
            }
            for licence in &page.items {
                check_licence(licence)?;
            }
            Ok(page)
        });
        self.finish_account(result, generation, cancel)
    }

    pub async fn claim_licence(
        &self,
        licence_key: &str,
        idempotency_key: &str,
        cancel: &Cancellation,
    ) -> Result<OwnedLicence> {
        if licence_key.is_empty()
            || licence_key.len() > 256
            || !(16..=128).contains(&idempotency_key.len())
        {
            return Err(Error::Configuration);
        }
        self.account_post(
            "/api/client/v1/licence-claims",
            json!({"licence_key": licence_key, "idempotency_key": idempotency_key}),
            true,
            |licence| {
                check_licence(&licence)?;
                Ok(licence)
            },
            cancel,
        )
        .await
    }

    pub async fn request_email_change(
        &self,
        password: &str,
        email: &str,
        cancel: &Cancellation,
    ) -> Result<()> {
        if password.len() > 256 || email.len() > 254 {
            return Err(Error::Configuration);
        }
        self.account_post(
            "/api/client/v1/email-changes",
            json!({"password": password, "email": email}),
            false,
            accepted,
            cancel,
        )
        .await
        .map(|_| ())
    }

    pub async fn register(
        &self,
        input: Registration<'_>,
        cancel: &Cancellation,
    ) -> Result<PendingRegistration> {
        if input.licence_key.is_empty()
            || input.licence_key.len() > 256
            || input.username.len() > 128
            || input.email.len() > 254
            || input.password.len() > 256
            || input.password.chars().count() < 8
        {
            return Err(Error::Configuration);
        }
        let reply: RegistrationReply = decode(
            self.0
                .transport
                .post(
                    "/api/client/v1/registrations",
                    &self.account_body(
                        json!({"licence_key": input.licence_key, "username": input.username,
                "email": input.email, "password": input.password}),
                    ),
                    false,
                    cancel,
                )
                .await,
        )?;
        if !reply.accepted || !bearer(&reply.resend_credential) {
            return Err(Error::InvalidResponse);
        }
        access::timestamp(&reply.expires_at)?;
        Ok(PendingRegistration {
            accepted: reply.accepted,
            expires_at: reply.expires_at,
            resend_credential: reply.resend_credential,
            application_id: self.0.config.application_id.clone(),
            environment_id: self.0.config.environment_id.clone(),
        })
    }

    pub async fn resend_registration(
        &self,
        pending: &PendingRegistration,
        cancel: &Cancellation,
    ) -> Result<()> {
        if pending.application_id != self.0.config.application_id
            || pending.environment_id != self.0.config.environment_id
        {
            return Err(Error::Configuration);
        }
        accepted(decode(
            self.0
                .transport
                .post(
                    "/api/client/v1/registrations/resend",
                    &self.account_body(json!({"resend_credential": pending.resend_credential})),
                    false,
                    cancel,
                )
                .await,
        )?)?;
        Ok(())
    }

    pub async fn request_password_recovery(
        &self,
        email: &str,
        cancel: &Cancellation,
    ) -> Result<()> {
        if email.len() > 254 {
            return Err(Error::Configuration);
        }
        accepted(decode(
            self.0
                .transport
                .post(
                    "/api/client/v1/password-recovery",
                    &self.account_body(json!({"email": email})),
                    false,
                    cancel,
                )
                .await,
        )?)?;
        Ok(())
    }

    fn account_body(&self, mut body: Value) -> Value {
        body["application_id"] = json!(self.0.config.application_id);
        body["environment_id"] = json!(self.0.config.environment_id);
        body
    }

    fn account_path(&self, route: &str, after: Option<&str>) -> String {
        let mut path = format!(
            "{route}?application_id={}&environment_id={}",
            self.0.config.application_id, self.0.config.environment_id
        );
        if let Some(after) = after {
            path.push_str(&format!("&after={after}"));
        }
        path
    }

    fn customer_session(&self, generation: u64) -> Result<Session> {
        let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
        self.sync_storage(&mut state)?;
        if state.generation != generation {
            return Err(Error::StaleResponse);
        }
        state.account.clone().ok_or(Error::ReauthenticationRequired)
    }

    async fn account_post<T: DeserializeOwned>(
        &self,
        path: &str,
        mut body: Value,
        retry_safe: bool,
        validate: fn(T) -> Result<T>,
        cancel: &Cancellation,
    ) -> Result<T> {
        let generation = self.generation()?;
        let _serial = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(Error::Cancelled),
            guard = self.0.serial.lock() => guard,
        };
        let session = self.customer_session(generation)?;
        body["customer_session"] = json!(session.token);
        let response = self
            .0
            .transport
            .post(path, &self.account_body(body), retry_safe, cancel)
            .await;
        self.finish_account(decode(response).and_then(validate), generation, cancel)
    }

    fn finish_account<T>(
        &self,
        result: Result<T>,
        generation: u64,
        cancel: &Cancellation,
    ) -> Result<T> {
        let mut state = self.0.state.lock().map_err(|_| Error::Storage)?;
        self.sync_storage(&mut state)?;
        if state.generation != generation {
            return Err(Error::StaleResponse);
        }
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if result.as_ref().is_err_and(|error| {
            !matches!(error, Error::Transient { .. } | Error::Cancelled)
                && !matches!(error, Error::Denied { code, .. } if code == "session_expired")
        }) {
            access::clear(&mut state);
            state.storage_version = self.0.storage.invalidate()?;
        }
        result
    }
}

fn decode<T: DeserializeOwned>(response: Result<Option<Value>>) -> Result<T> {
    serde_json::from_value(response?.ok_or(Error::InvalidResponse)?)
        .map_err(|_| Error::InvalidResponse)
}

fn accepted(value: Accepted) -> Result<Accepted> {
    if !value.accepted {
        return Err(Error::InvalidResponse);
    }
    Ok(value)
}

fn bearer(value: &str) -> bool {
    value.len() == 43 && access::opaque(value)
}

fn check_licence(licence: &OwnedLicence) -> Result<()> {
    if !access::opaque(&licence.id)
        || !(1..=100).contains(&licence.device_limit)
        || licence.entitlements.len() > 64
        || licence.policy_name.chars().count() > 80
    {
        return Err(Error::InvalidResponse);
    }
    for date in [&licence.first_used_at, &licence.expires_at]
        .into_iter()
        .flatten()
    {
        access::timestamp(date)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "local-development")]
    use crate::transport::tests::{Fixture, TRANSIENT};
    use crate::{Access, Config, Device, MemoryStorage, Storage, StoredCredential, Transport};
    use std::sync::Arc;

    fn client() -> Client {
        let storage = Arc::new(MemoryStorage::default());
        storage
            .save(
                0,
                StoredCredential {
                    application_id: "app".into(),
                    environment_id: "test".into(),
                    activation_id: "activation".into(),
                    licence_id: "licence".into(),
                    installation_id: "installation_1234".into(),
                    credential: "s".repeat(43),
                    credential_expires_at: 2_000_000_000,
                    fingerprint: None,
                    fingerprint_provider: None,
                },
            )
            .unwrap();
        let client = Client::with_storage(
            Config {
                application_id: "app".into(),
                environment_id: "test".into(),
                issuer: "https://orbit.example.test".into(),
            },
            Device {
                installation_id: "installation_1234".into(),
                fingerprint: None,
                fingerprint_provider: None,
            },
            Transport::new("https://orbit.example.test").unwrap(),
            storage,
        )
        .unwrap();
        client.0.state.lock().unwrap().account = Some(Session {
            token: "a".repeat(43),
            account: Account {
                customer: Customer {
                    id: "customer".into(),
                    username: "alice".into(),
                    email: "alice@example.test".into(),
                    suspended: false,
                    created_at: "2026-01-01T00:00:00Z".into(),
                },
                expires_at: "2026-01-02T00:00:00Z".into(),
            },
        });
        client
    }
    #[test]
    fn logout_clears_before_await_and_rejects_late_account_results() {
        let client = client();
        let generation = client.generation().unwrap();
        let cancel = Cancellation::new();
        let logout = client.logout_account(&cancel);
        assert!(client.account().unwrap().is_none());
        assert_eq!(client.snapshot().unwrap().access, Access::Denied);
        drop(logout);
        assert!(matches!(
            client.finish_account(Ok(()), generation, &cancel),
            Err(Error::StaleResponse)
        ));
    }
    #[test]
    fn shared_storage_logout_invalidates_account_metadata_and_callbacks() {
        let client = client();
        let generation = client.generation().unwrap();
        client.0.storage.invalidate().unwrap();
        assert!(matches!(
            client.finish_account(Ok(()), generation, &Cancellation::new()),
            Err(Error::StaleResponse)
        ));
        assert!(client.account().unwrap().is_none());
        assert_eq!(client.snapshot().unwrap().access, Access::Denied);
        assert!(client.0.storage.load().unwrap().1.is_none());
    }

    #[cfg(feature = "local-development")]
    fn login_reply(username: &str) -> String {
        json!({"customer":{"id":username,"username":username,"email":format!("{username}@example.test"),
            "suspended":false,"created_at":"2026-01-01T00:00:00Z"},"session":"b".repeat(43),
            "expires_at":"2026-01-02T00:00:00Z"}).to_string()
    }

    #[cfg(feature = "local-development")]
    struct ProofStorage {
        inner: Arc<dyn Storage>,
        writes: std::sync::atomic::AtomicUsize,
    }

    #[cfg(feature = "local-development")]
    impl Storage for ProofStorage {
        fn version(&self) -> Result<u64> {
            self.inner.version()
        }
        fn load(&self) -> Result<(u64, Option<StoredCredential>)> {
            self.inner.load()
        }
        fn save(&self, version: u64, credential: StoredCredential) -> Result<()> {
            self.writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.save(version, credential)
        }
        fn invalidate(&self) -> Result<u64> {
            self.writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.invalidate()
        }
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn customer_session_proof_is_explicit_redacted_and_locally_invalidated() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        for shared_storage in [false, true] {
            let mut fixture = Fixture::new().await;
            let mut client = client();
            let storage = Arc::new(ProofStorage {
                inner: client.0.storage.clone(),
                writes: AtomicUsize::new(0),
            });
            let inner = Arc::get_mut(&mut client.0).unwrap();
            inner.transport = fixture.transport.clone();
            inner.storage = storage.clone();
            client.0.state.lock().unwrap().account = None;
            assert!(matches!(
                client.customer_session_proof(),
                Err(Error::ReauthenticationRequired)
            ));
            assert_eq!(storage.writes.load(Ordering::SeqCst), 0);
            fixture.assert_idle();

            let login_client = client.clone();
            let login = tokio::spawn(async move {
                login_client
                    .login("alice", "password", &Cancellation::new())
                    .await
            });
            fixture.next().await.respond(200, &login_reply("alice"));
            login.await.unwrap().unwrap();
            let writes = storage.writes.load(Ordering::SeqCst);
            let token = "b".repeat(43);
            let proof = client.customer_session_proof().unwrap();
            assert!(proof.authorization_header() == format!("Bearer {token}"));
            for redacted in [format!("{proof:?}"), format!("{:#?}", proof.clone())] {
                assert_eq!(redacted, "CustomerSessionProof([REDACTED])");
            }
            let account = client.account().unwrap().unwrap();
            assert!(!format!("{account:?}").contains(&token));
            assert!(!format!("{account:#?}").contains(&token));
            assert_eq!(storage.writes.load(Ordering::SeqCst), writes);
            fixture.assert_idle();

            if shared_storage {
                storage.invalidate().unwrap();
            } else {
                client.logout().unwrap();
            }
            let writes = storage.writes.load(Ordering::SeqCst);
            assert!(matches!(
                client.customer_session_proof(),
                Err(Error::ReauthenticationRequired)
            ));
            assert_eq!(storage.writes.load(Ordering::SeqCst), writes);
            assert!(client.account().unwrap().is_none());
            fixture.assert_idle();
        }
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn lifecycle_late_login_and_error_cannot_replace_newer_identity() {
        for newer_identity in [false, true] {
            for success in [false, true] {
                let mut fixture = Fixture::new().await;
                let mut client = client();
                Arc::get_mut(&mut client.0).unwrap().transport = fixture.transport.clone();
                let old_client = client.clone();
                let old_login = tokio::spawn(async move {
                    old_client
                        .login("alice", "password", &Cancellation::new())
                        .await
                });
                let late = fixture.next().await;
                let newer = if newer_identity {
                    let next = Client::with_storage(
                        client.0.config.clone(),
                        Device {
                            installation_id: "installation_1234".into(),
                            fingerprint: None,
                            fingerprint_provider: None,
                        },
                        fixture.transport.clone(),
                        client.0.storage.clone(),
                    )
                    .unwrap();
                    let next_client = next.clone();
                    let next_login = tokio::spawn(async move {
                        next_client
                            .login("bob", "password", &Cancellation::new())
                            .await
                    });
                    fixture.next().await.respond(200, &login_reply("bob"));
                    assert_eq!(next_login.await.unwrap().unwrap().customer.username, "bob");
                    Some(next)
                } else {
                    client.logout().unwrap();
                    None
                };
                if success {
                    late.respond(200, &login_reply("alice"));
                } else {
                    late.respond(401, r#"{"error":{"code":"invalid_credentials","message":"Denied","request_id":"fixture"}}"#);
                }
                assert!(matches!(
                    old_login.await.unwrap(),
                    Err(Error::StaleResponse)
                ));
                assert!(client.account().unwrap().is_none());
                assert_eq!(client.snapshot().unwrap().access, Access::Denied);
                if let Some(newer) = newer {
                    assert_eq!(newer.account().unwrap().unwrap().customer.username, "bob");
                }
                fixture.assert_idle();
            }
        }
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn lifecycle_shared_logout_invalidates_login_waiting_for_lock() {
        use std::{
            future::Future,
            task::{Context, Poll, Waker},
            time::Duration,
        };
        let mut fixture = Fixture::new().await;
        let mut client = client();
        Arc::get_mut(&mut client.0).unwrap().transport = fixture.transport.clone();
        let guard = client.0.serial.lock().await;
        let cancel = Cancellation::new();
        let mut login = Box::pin(client.login("bob", "password", &cancel));
        assert!(matches!(
            login.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ));
        client.0.storage.invalidate().unwrap();
        drop(guard);
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), login)
                .await
                .unwrap(),
            Err(Error::StaleResponse)
        ));
        assert!(client.account().unwrap().is_none());
        assert_eq!(client.snapshot().unwrap().access, Access::Denied);
        fixture.assert_idle();
    }

    #[tokio::test]
    async fn lifecycle_shared_logout_invalidates_account_before_deactivation() {
        let client = client();
        client.0.storage.invalidate().unwrap();
        let cancel = Cancellation::new();
        cancel.cancel();
        let _ = client.deactivate("deactivate_operation_123", &cancel).await;
        assert!(client.account().unwrap().is_none());
        assert_eq!(client.snapshot().unwrap().access, Access::Denied);
        assert!(client.0.storage.load().unwrap().1.is_none());
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn lifecycle_account_mutations_without_idempotency_are_never_retried() {
        for route in [
            "sessions",
            "registrations",
            "registrations/resend",
            "password-recovery",
            "email-changes",
            "sessions/current",
        ] {
            let mut fixture = Fixture::new().await;
            let mut client = client();
            Arc::get_mut(&mut client.0).unwrap().transport = fixture.transport.clone();
            let operation = tokio::spawn(async move {
                let cancel = Cancellation::new();
                match route {
                    "sessions" => client.login("alice", "password", &cancel).await.map(|_| ()),
                    "registrations" => client
                        .register(
                            Registration {
                                licence_key: "key",
                                username: "alice",
                                email: "alice@example.test",
                                password: "password",
                            },
                            &cancel,
                        )
                        .await
                        .map(|_| ()),
                    "registrations/resend" => {
                        client
                            .resend_registration(
                                &PendingRegistration {
                                    accepted: true,
                                    expires_at: "2026-01-02T00:00:00Z".into(),
                                    resend_credential: "c".repeat(43),
                                    application_id: "app".into(),
                                    environment_id: "test".into(),
                                },
                                &cancel,
                            )
                            .await
                    }
                    "password-recovery" => {
                        client
                            .request_password_recovery("alice@example.test", &cancel)
                            .await
                    }
                    "email-changes" => {
                        client
                            .request_email_change("password", "new@example.test", &cancel)
                            .await
                    }
                    "sessions/current" => client.logout_account(&cancel).await,
                    _ => unreachable!(),
                }
            });
            let request = fixture.next().await;
            assert!(request.head.contains(&format!(" /api/client/v1/{route}")));
            request.respond(503, TRANSIENT);
            assert!(
                matches!(
                    tokio::time::timeout(std::time::Duration::from_secs(2), operation)
                        .await
                        .unwrap()
                        .unwrap(),
                    Err(Error::Transient { .. })
                ),
                "{route}"
            );
            fixture.assert_idle();
        }
    }
    #[test]
    fn ordinary_login_expiry_preserves_activation_but_revocation_clears_it() {
        let client = client();
        let generation = client.generation().unwrap();
        let cancel = Cancellation::new();
        assert!(
            client
                .finish_account::<()>(
                    Err(Error::Denied {
                        code: "session_expired".into(),
                        request_id: None,
                    }),
                    generation,
                    &cancel
                )
                .is_err()
        );
        assert_eq!(client.snapshot().unwrap().access, Access::RefreshRequired);
        assert!(
            client
                .finish_account::<()>(
                    Err(Error::Denied {
                        code: "invalid_credentials".into(),
                        request_id: None,
                    }),
                    generation,
                    &cancel
                )
                .is_err()
        );
        assert_eq!(client.snapshot().unwrap().access, Access::Denied);
        assert!(client.account().unwrap().is_none());
    }
}
