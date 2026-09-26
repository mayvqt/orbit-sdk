use crate::{Client, Error};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// Copyable diagnostic metadata, never authentication or authorization proof.
#[derive(Clone, Debug, Serialize)]
pub struct SupportSummary {
    pub application_id: String,
    pub environment_id: String,
    pub code: String,
    pub request_id: Option<String>,
    /// Local Unix seconds, or None when unavailable; not an access clock.
    pub timestamp: Option<i64>,
}

impl std::fmt::Display for SupportSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&serde_json::to_string(self).map_err(|_| std::fmt::Error)?)
    }
}

impl Client {
    /// Build safe support metadata from this error and configured public scope.
    /// Does not read access, account, device or storage state or contact Orbit.
    pub fn support_summary(&self, error: &Error) -> SupportSummary {
        SupportSummary {
            application_id: self.0.config.application_id.clone(),
            environment_id: self.0.config.environment_id.clone(),
            code: error.safe_code().to_owned(),
            request_id: error.request_id().map(str::to_owned),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|duration| i64::try_from(duration.as_secs()).ok()),
        }
    }
}

pub(crate) fn valid_request_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

pub(crate) fn valid_code(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

impl Error {
    /// Validated server correlation reference, absent for local failures.
    pub fn request_id(&self) -> Option<&str> {
        match self {
            Self::Transient { request_id, .. } | Self::Denied { request_id, .. } => request_id
                .as_deref()
                .filter(|value| valid_request_id(value)),
            _ => None,
        }
    }

    pub(crate) fn transient() -> Self {
        Self::Transient {
            code: None,
            request_id: None,
        }
    }

    fn safe_code(&self) -> &str {
        match self {
            Self::Denied { code, .. } if valid_code(code) => code,
            Self::Transient {
                code: Some(code), ..
            } if valid_code(code) => code,
            Self::Configuration => "configuration",
            Self::Cancelled => "cancelled",
            Self::Transient { .. } => "transient",
            Self::Denied { .. } => "denied",
            Self::InvalidResponse => "invalid_response",
            Self::TransportSecurity => "transport_security",
            Self::ReauthenticationRequired => "reauthentication_required",
            Self::StaleResponse => "stale_response",
            Self::Storage => "storage",
            Self::ClockUncertain => "clock_uncertain",
            Self::InstallationInUse => "installation_in_use",
            Self::CorruptState => "corrupt_state",
            Self::PendingActivation => "pending_activation",
            Self::Closed => "closed",
        }
    }

    pub(crate) fn guidance(&self) -> Option<&'static str> {
        Some(match self.safe_code() {
            "invalid_credentials"
            | "credential_expired"
            | "credential_revoked"
            | "reauthentication_required" => {
                "Authenticate again with your licence key or customer account."
            }
            "session_expired" | "session_revoked" => "Sign in again to continue.",
            "licence_expired" => {
                "Your licence has expired. Contact application support to renew it."
            }
            "licence_suspended" => "Your licence is suspended. Contact application support.",
            "licence_revoked" => "Your licence was revoked. Contact application support.",
            "device_limit_reached" => {
                "The device limit is reached. Release an existing device or contact application support."
            }
            "device_mismatch" | "device_identity_unavailable" => {
                "This device could not be verified. Contact application support."
            }
            "reset_cooldown" => "Device changes are temporarily limited. Wait before trying again.",
            "application_maintenance" => {
                "The application is under maintenance. Try again after maintenance ends."
            }
            "rate_limited" => "Too many requests. Wait before trying again.",
            "service_unavailable" => "Orbit is temporarily unavailable. Try again later.",
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, Device, MemoryStorage, Result, Storage, StoredCredential, Transport};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };

    #[derive(Default)]
    struct UnavailableStorage {
        inner: MemoryStorage,
        blocked: AtomicBool,
    }
    impl Storage for UnavailableStorage {
        fn version(&self) -> Result<u64> {
            panic!("support summary read storage")
        }
        fn load(&self) -> Result<(u64, Option<StoredCredential>)> {
            assert!(
                !self.blocked.load(Ordering::SeqCst),
                "support summary loaded storage"
            );
            self.inner.load()
        }
        fn save(&self, _: u64, _: StoredCredential) -> Result<()> {
            panic!("support summary wrote storage")
        }
        fn invalidate(&self) -> Result<u64> {
            panic!("support summary invalidated storage")
        }
    }

    #[test]
    fn summary_is_serializable_and_independent_of_state_and_storage() {
        let storage = Arc::new(UnavailableStorage::default());
        let client = Client::with_storage(
            Config {
                application_id: "app".into(),
                environment_id: "test".into(),
                issuer: "https://orbit.example.test".into(),
            },
            Device {
                installation_id: "private_installation_1234".into(),
                fingerprint: None,
                fingerprint_provider: None,
            },
            Transport::new("https://orbit.example.test").unwrap(),
            storage.clone(),
        )
        .unwrap();
        storage.blocked.store(true, Ordering::SeqCst);
        let locked = client.0.state.lock().unwrap();
        let (sender, receiver) = mpsc::channel();
        let copy = client.clone();
        let worker = std::thread::spawn(move || {
            sender
                .send(copy.support_summary(&Error::Denied {
                    code: "licence_expired".into(),
                    request_id: Some("Req_A-9".into()),
                }))
                .unwrap();
        });
        let summary = receiver.recv_timeout(std::time::Duration::from_secs(1));
        drop(locked);
        worker.join().unwrap();
        let summary = summary.expect("support summary waited for access state");
        let value = serde_json::to_value(&summary).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 5);
        assert_eq!(value["application_id"], "app");
        assert_eq!(value["environment_id"], "test");
        assert_eq!(value["code"], "licence_expired");
        assert_eq!(value["request_id"], "Req_A-9");
        assert!(value["timestamp"].as_i64().is_some_and(|time| time >= 0));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&summary.to_string()).unwrap(),
            value
        );
        assert!(!summary.to_string().contains("private_installation"));

        for error in [
            Error::Denied {
                code: "synthetic-secret\n".into(),
                request_id: Some("secret/token".into()),
            },
            Error::Transient {
                code: Some("X".repeat(129)),
                request_id: Some("a".repeat(65)),
            },
            Error::Denied {
                code: "é".into(),
                request_id: Some("é".into()),
            },
            Error::transient(),
            Error::Storage,
            Error::Cancelled,
        ] {
            let summary = client.support_summary(&error);
            assert!(valid_code(&summary.code));
            assert!(summary.request_id.is_none());
            assert!(error.request_id().is_none());
            assert!(!format!("{error} {error:?}").contains("synthetic-secret"));
            assert!(!summary.to_string().contains("synthetic-secret"));
        }
        assert_eq!(
            client.support_summary(&Error::transient()).code,
            "transient"
        );
        for code in ["future_error".to_owned(), "a".repeat(128)] {
            let error = Error::Denied {
                code: code.clone(),
                request_id: None,
            };
            assert_eq!(client.support_summary(&error).code, code);
            assert_eq!(
                error.to_string(),
                "Orbit denied access. Contact application support."
            );
        }
    }

    #[test]
    fn guidance_uses_fixed_text_for_known_codes() {
        for (code, guidance) in [
            (
                "invalid_credentials",
                "Authenticate again with your licence key or customer account.",
            ),
            ("session_expired", "Sign in again to continue."),
            (
                "licence_expired",
                "Your licence has expired. Contact application support to renew it.",
            ),
            (
                "licence_suspended",
                "Your licence is suspended. Contact application support.",
            ),
            (
                "licence_revoked",
                "Your licence was revoked. Contact application support.",
            ),
            (
                "device_limit_reached",
                "The device limit is reached. Release an existing device or contact application support.",
            ),
            (
                "device_mismatch",
                "This device could not be verified. Contact application support.",
            ),
            (
                "reset_cooldown",
                "Device changes are temporarily limited. Wait before trying again.",
            ),
            (
                "application_maintenance",
                "The application is under maintenance. Try again after maintenance ends.",
            ),
        ] {
            let error = Error::Denied {
                code: code.into(),
                request_id: Some("reference".into()),
            };
            assert_eq!(error.to_string(), guidance);
            assert_eq!(format!("{error:?}"), guidance);
        }
    }
}
