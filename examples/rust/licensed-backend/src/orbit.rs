use crate::config::{Config, opaque};
use orbit_sdk::{Cancellation, Transport};
use reqwest::{Client, StatusCode, Url};
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub enum Failure {
    Authentication,
    Denied,
    Unavailable,
}

pub struct Orbit {
    sessions: Transport,
    client: Client,
    current: String,
    decision: Url,
    config: Config,
}

#[derive(Deserialize)]
struct Subject {
    customer_id: String,
    application_id: String,
    environment_id: String,
    expires_at: String,
}

#[derive(Deserialize)]
struct Decision {
    allowed: bool,
    reason: String,
    checked_at: String,
}

impl Orbit {
    pub fn new(config: Config) -> Result<Self, &'static str> {
        // Reuse the SDK's strict origin parsing and explicit loopback-only opt-in.
        let sessions = if config.local_development {
            #[cfg(feature = "local-development")]
            {
                Transport::local_loopback(&config.orbit_origin)
            }
            #[cfg(not(feature = "local-development"))]
            {
                return Err("Local transport requires the local-development build feature");
            }
        } else {
            Transport::new(&config.orbit_origin)
        }
        .map_err(|_| "Invalid Orbit origin")?;
        let mut decision = Url::parse(&config.orbit_origin).map_err(|_| "Invalid Orbit origin")?;
        decision.set_path("/api/management/v1/licence-decisions");
        decision
            .query_pairs_mut()
            .append_pair("application_id", &config.application_id)
            .append_pair("environment_id", &config.environment_id);
        let current = format!(
            "/api/client/v1/sessions/current?application_id={}&environment_id={}",
            config.application_id, config.environment_id
        );
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(!config.local_development)
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| "Cannot configure Orbit transport")?;
        Ok(Self {
            sessions,
            client,
            current,
            decision,
            config,
        })
    }

    pub async fn authorize(
        &self,
        token: &str,
        licence: &str,
        activation: &str,
    ) -> Result<String, Failure> {
        let value = self
            .sessions
            .get_bearer(&self.current, token, &Cancellation::new())
            .await
            .map_err(|error| match error {
                orbit_sdk::Error::Denied { code, .. }
                    if matches!(code.as_str(), "invalid_credentials" | "session_expired") =>
                {
                    Failure::Authentication
                }
                orbit_sdk::Error::Denied { .. } => Failure::Denied,
                _ => Failure::Unavailable,
            })?
            .ok_or(Failure::Unavailable)?;
        let subject: Subject = serde_json::from_value(value).map_err(|_| Failure::Unavailable)?;
        let expiry = OffsetDateTime::parse(&subject.expires_at, &Rfc3339)
            .map_err(|_| Failure::Unavailable)?;
        if subject.application_id != self.config.application_id
            || subject.environment_id != self.config.environment_id
            || !opaque(&subject.customer_id)
        {
            return Err(Failure::Unavailable);
        }
        if expiry <= OffsetDateTime::now_utc() {
            return Err(Failure::Authentication);
        }
        // Client-selected resource IDs are selectors only. Orbit enforces their
        // ownership against the authenticated subject and the fixed export feature.
        let mut response = self
            .client
            .post(self.decision.clone())
            .bearer_auth(&self.config.management_credential)
            .json(&json!({"licence_id":licence,"activation_id":activation,
                "customer_id":subject.customer_id,"entitlement":"export"}))
            .send()
            .await
            .map_err(|_| Failure::Unavailable)?;
        if matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND
        ) {
            return Err(Failure::Denied);
        }
        if response.status() != StatusCode::OK {
            return Err(Failure::Unavailable);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Failure::Unavailable)? {
            if body.len() + chunk.len() > 16 * 1024 {
                return Err(Failure::Unavailable);
            }
            body.extend_from_slice(&chunk);
        }
        let decision: Decision = serde_json::from_slice(&body).map_err(|_| Failure::Unavailable)?;
        if OffsetDateTime::parse(&decision.checked_at, &Rfc3339).is_err() {
            return Err(Failure::Unavailable);
        }
        if !decision.allowed || decision.reason != "allowed" {
            return Err(Failure::Denied);
        }
        Ok(subject.customer_id)
    }
}
