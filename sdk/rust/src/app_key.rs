use crate::{Error, Result, transport};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// Parsed public app key for one Orbit application and environment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppKey {
    api_origin: String,
    application_id: String,
    environment_id: String,
    environment: AppEnvironment,
}

/// The deployment selected by an app key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppEnvironment {
    Test,
    Live,
}

impl AppEnvironment {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Test => "test",
            Self::Live => "live",
        }
    }
}

impl AppKey {
    /// Parse the public app key copied from Orbit's Integration page.
    pub fn parse(raw: &str) -> Result<Self> {
        Self::parse_with(raw, false)
    }

    #[cfg(feature = "local-development")]
    pub(crate) fn parse_local(raw: &str) -> Result<Self> {
        Self::parse_with(raw, true)
    }

    fn parse_with(raw: &str, local: bool) -> Result<Self> {
        let value = raw.trim();
        if value.is_empty() || value.len() > 512 {
            return Err(Error::Configuration);
        }
        let (environment, rest) = if let Some(rest) = value.strip_prefix("orbit_app_test_") {
            (AppEnvironment::Test, rest)
        } else if let Some(rest) = value.strip_prefix("orbit_app_live_") {
            (AppEnvironment::Live, rest)
        } else {
            return Err(Error::Configuration);
        };
        let mut parts = rest.split('.');
        let encoded_origin = parts.next().ok_or(Error::Configuration)?;
        let application_id = parts.next().ok_or(Error::Configuration)?;
        let environment_id = parts.next().ok_or(Error::Configuration)?;
        if parts.next().is_some() {
            return Err(Error::Configuration);
        }
        let origin_bytes = URL_SAFE_NO_PAD
            .decode(encoded_origin)
            .map_err(|_| Error::Configuration)?;
        if URL_SAFE_NO_PAD.encode(&origin_bytes) != encoded_origin {
            return Err(Error::Configuration);
        }
        let api_origin = String::from_utf8(origin_bytes).map_err(|_| Error::Configuration)?;
        if api_origin.ends_with('/') {
            return Err(Error::Configuration);
        }
        if local {
            transport::validate_local_origin(&api_origin)?;
        } else {
            transport::origin(&api_origin, "https")?;
        }
        if !crate::access::opaque(application_id) || !crate::access::opaque(environment_id) {
            return Err(Error::Configuration);
        }
        Ok(Self {
            api_origin,
            application_id: application_id.to_owned(),
            environment_id: environment_id.to_owned(),
            environment,
        })
    }

    pub fn api_origin(&self) -> &str {
        &self.api_origin
    }

    pub fn issuer(&self) -> &str {
        &self.api_origin
    }

    pub fn application_id(&self) -> &str {
        &self.application_id
    }

    pub fn environment_id(&self) -> &str {
        &self.environment_id
    }

    pub fn environment(&self) -> &'static str {
        self.environment.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::{fs, path::PathBuf};

    #[derive(Deserialize)]
    struct Corpus {
        format_version: u32,
        cases: Vec<Case>,
    }

    #[derive(Deserialize)]
    struct Case {
        name: String,
        key: String,
        valid: bool,
        api_origin: Option<String>,
        issuer: Option<String>,
        application_id: Option<String>,
        environment_id: Option<String>,
        environment: Option<String>,
    }

    #[test]
    fn shared_app_key_vectors() {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/sdk/app-keys.json");
        let corpus: Corpus = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(corpus.format_version, 1);
        assert_eq!(corpus.cases.len(), 27);
        for case in corpus.cases {
            let parsed = AppKey::parse(&case.key);
            assert_eq!(parsed.is_ok(), case.valid, "{}", case.name);
            if let Ok(parsed) = parsed {
                assert_eq!(
                    Some(parsed.api_origin()),
                    case.api_origin.as_deref(),
                    "{}",
                    case.name
                );
                assert_eq!(
                    Some(parsed.issuer()),
                    case.issuer.as_deref(),
                    "{}",
                    case.name
                );
                assert_eq!(
                    Some(parsed.application_id()),
                    case.application_id.as_deref(),
                    "{}",
                    case.name
                );
                assert_eq!(
                    Some(parsed.environment_id()),
                    case.environment_id.as_deref(),
                    "{}",
                    case.name
                );
                assert_eq!(
                    Some(parsed.environment()),
                    case.environment.as_deref(),
                    "{}",
                    case.name
                );
            }
        }
    }

    #[cfg(feature = "local-development")]
    #[test]
    fn local_app_keys_require_loopback_literal_and_default_parser_rejects_http() {
        let key = |origin: &str| {
            format!(
                "orbit_app_test_{}.app.test",
                URL_SAFE_NO_PAD.encode(origin.as_bytes())
            )
        };
        assert!(AppKey::parse(&key("http://127.0.0.1:8080")).is_err());
        assert!(AppKey::parse_local(&key("http://127.0.0.1:8080")).is_ok());
        assert!(AppKey::parse_local(&key("http://localhost:8080")).is_err());
    }
}
