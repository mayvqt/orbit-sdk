use crate::{AppKey, Error, Result, access::Device, clock::Anchor, grants::Keys};
use aws_lc_rs::digest::{self, SHA256};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, Validation, decode};
use serde::{Deserialize, Serialize, de};
use std::time::Instant;
use std::{collections::BTreeMap, fmt};

const MAX_FILE: usize = 16 * 1024;
pub(crate) const MAX_SEQUENCE: u64 = 9_007_199_254_740_991;
const MAX_TIME: i64 = 253_402_300_799;
const MAX_LIFETIME: i64 = 366 * 86_400;

#[derive(Clone, Debug, Serialize)]
pub struct OfflineRequest {
    pub format: &'static str,
    pub version: u8,
    pub app_key: String,
    pub installation_id: String,
    pub fingerprint: Option<String>,
    pub fingerprint_provider: Option<String>,
}
pub(crate) fn request(key: &AppKey, device: &Device) -> OfflineRequest {
    use base64::Engine;
    let prefix = if key.environment() == "live" {
        "orbit_app_live_"
    } else {
        "orbit_app_test_"
    };
    OfflineRequest {
        format: "orbit-offline-request",
        version: 1,
        app_key: format!(
            "{prefix}{}.{}.{}",
            URL_SAFE_NO_PAD.encode(key.api_origin()),
            key.application_id(),
            key.environment_id()
        ),
        installation_id: device.installation_id.clone(),
        fingerprint: device.fingerprint.clone(),
        fingerprint_provider: device.fingerprint_provider.clone(),
    }
}

#[derive(Debug)]
pub(crate) struct Verified {
    pub(crate) issuance_id: String,
    pub(crate) issued_at: i64,
    pub(crate) expires_at: i64,
    pub(crate) sequence: u64,
    pub(crate) entitlements: BTreeMap<String, bool>,
    pub(crate) content_digest: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Persisted {
    #[serde(deserialize_with = "Option::deserialize")]
    pub(crate) jws: Option<String>,
    pub(crate) sequence: u64,
    pub(crate) issuance_id: String,
    pub(crate) content_digest: String,
    pub(crate) verified_at: i64,
    pub(crate) time_high_water: i64,
    pub(crate) wall_high_water: i64,
}
pub(crate) struct Runtime {
    pub(crate) verified: Option<Verified>,
    pub(crate) anchor: Option<Anchor>,
    pub(crate) saved: Persisted,
    pub(crate) authorized: bool,
    pub(crate) uncertain: bool,
    pub(crate) last_checkpoint: Instant,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    ver: u64,
    iss: String,
    aud: String,
    sub: String,
    jti: String,
    iat: i64,
    nbf: i64,
    exp: i64,
    application_id: String,
    environment_id: String,
    activation_id: String,
    installation_id: String,
    sequence: u64,
    binding_mode: String,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default)]
    fingerprint_provider: Option<String>,
    policy_version: i32,
    #[serde(deserialize_with = "entitlements")]
    entitlements: BTreeMap<String, bool>,
    #[serde(default)]
    licence_expires_at: Option<i64>,
}
fn entitlements<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, bool>, D::Error> {
    struct Entries;
    impl<'de> de::Visitor<'de> for Entries {
        type Value = BTreeMap<String, bool>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("bounded unique offline entitlements")
        }
        fn visit_map<A: de::MapAccess<'de>>(
            self,
            mut entries: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut result = BTreeMap::new();
            while let Some((name, enabled)) = entries.next_entry::<String, bool>()? {
                if name.is_empty()
                    || name.len() > 64
                    || !name.as_bytes()[0].is_ascii_lowercase()
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                    || result.len() >= 64
                    || result.insert(name, enabled).is_some()
                {
                    return Err(de::Error::custom("invalid offline entitlements"));
                }
            }
            Ok(result)
        }
    }
    deserializer.deserialize_map(Entries)
}

pub(crate) fn parse_keys(bytes: &[u8], environment: &str) -> Result<Keys> {
    let prefix = if environment == "live" {
        "offline-live-"
    } else {
        "offline-test-"
    };
    Keys::parse_offline(bytes, prefix)
}
fn canonical(value: &str) -> Result<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Error::InvalidResponse)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(Error::InvalidResponse);
    }
    Ok(bytes)
}
fn opaque(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn error(code: &str) -> Error {
    Error::Denied {
        code: code.into(),
        request_id: None,
    }
}
pub(crate) fn verify(
    raw: &[u8],
    keys: &Keys,
    key: &AppKey,
    device: &Device,
    now: i64,
    minimum_sequence: u64,
) -> Result<Verified> {
    if raw.is_empty() || raw.len() > MAX_FILE {
        return Err(Error::InvalidResponse);
    }
    let raw = std::str::from_utf8(raw).map_err(|_| Error::InvalidResponse)?;
    let token = raw.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n' | '\u{b}' | '\u{c}'));
    let mut parts = token.split('.');
    let (Some(header_part), Some(payload_part), Some(sig_part), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::InvalidResponse);
    };
    let header_bytes = canonical(header_part)?;
    let header: Header =
        serde_json::from_slice(&header_bytes).map_err(|_| Error::InvalidResponse)?;
    let prefix = if key.environment() == "live" {
        "offline-live-"
    } else {
        "offline-test-"
    };
    if header.alg != "ES256"
        || header.typ != "orbit-offline+jwt"
        || !header.kid.starts_with(prefix)
        || header.kid.len() == prefix.len()
        || !header
            .kid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        || canonical(sig_part)?.len() != 64
    {
        return Err(Error::InvalidResponse);
    }
    let payload_bytes = canonical(payload_part)?;
    let value: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| Error::InvalidResponse)?;
    let claims: Claims =
        serde_json::from_slice(&payload_bytes).map_err(|_| Error::InvalidResponse)?;
    let object = value.as_object().ok_or(Error::InvalidResponse)?;
    if object
        .get("licence_expires_at")
        .is_some_and(|value| value.as_i64().is_none())
    {
        return Err(Error::InvalidResponse);
    }
    let bound = match claims.binding_mode.as_str() {
        "none" => {
            !object.contains_key("fingerprint") && !object.contains_key("fingerprint_provider")
        }
        "hwid" => {
            object.contains_key("fingerprint")
                && object.contains_key("fingerprint_provider")
                && device.fingerprint.as_deref() == claims.fingerprint.as_deref()
                && device.fingerprint_provider.as_deref() == claims.fingerprint_provider.as_deref()
                && claims.fingerprint.is_some()
                && claims.fingerprint_provider.is_some()
        }
        _ => false,
    };
    let audience = format!(
        "orbit-offline:{}:{}",
        key.application_id(),
        key.environment_id()
    );
    if claims.ver != 1
        || claims.iss != key.issuer()
        || claims.aud != audience
        || !opaque(&claims.sub, 1, 128)
        || !opaque(&claims.jti, 1, 128)
        || claims.application_id != key.application_id()
        || claims.environment_id != key.environment_id()
        || !opaque(&claims.activation_id, 1, 128)
        || claims.installation_id != device.installation_id
        || !opaque(&claims.installation_id, 16, 128)
        || claims.sequence < minimum_sequence
        || claims.sequence < 1
        || claims.sequence > MAX_SEQUENCE
        || claims.policy_version < 1
        || claims.iat < 0
        || claims.iat > MAX_TIME
        || claims.nbf != claims.iat
        || claims.iat > now.saturating_add(30)
        || claims.exp <= now
        || claims.exp <= claims.iat
        || claims.exp > MAX_TIME
        || claims.exp - claims.iat > MAX_LIFETIME
        || claims
            .licence_expires_at
            .is_some_and(|expiry| expiry < claims.exp || expiry > MAX_TIME)
        || !bound
    {
        return Err(Error::InvalidResponse);
    }
    let decoding_key = keys
        .decoding_key(&header.kid)
        .ok_or(Error::InvalidResponse)?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.leeway = 0;
    decode::<Claims>(token, decoding_key, &validation).map_err(|_| Error::InvalidResponse)?;
    let canonical = serde_json::to_vec(&value).map_err(|_| Error::InvalidResponse)?;
    let digest = digest::digest(&SHA256, &canonical);
    let content_digest = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    Ok(Verified {
        issuance_id: claims.jti,
        issued_at: claims.iat,
        expires_at: claims.exp,
        sequence: claims.sequence,
        entitlements: claims.entitlements,
        content_digest,
    })
}
pub(crate) fn stale() -> Error {
    error("offline_sequence")
}
pub(crate) fn expired() -> Error {
    error("offline_file_expired")
}

#[cfg(test)]
#[path = "offline_vectors.rs"]
pub(crate) mod vectors;
