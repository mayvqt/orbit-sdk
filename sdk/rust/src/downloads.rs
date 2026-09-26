//! Seller-side verification of short-lived protected-download tickets.
//!
//! This module performs no HTTP requests and never follows token-provided URLs.

use crate::{AppKey, Error, Result, grants::Keys, transport};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, Validation, decode};
use serde::Deserialize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_BYTES: usize = 16 * 1024;
const MAX_TIME: i64 = 253_402_300_799;

/// Immutable trusted configuration for a seller's protected endpoint.
pub struct DownloadTicketVerifier {
    app: AppKey,
    endpoint: String,
    keys: Keys,
}

/// Verified artifact metadata. The compact ticket is never retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DownloadTicket {
    licence_id: String,
    release_id: String,
    artifact_id: String,
    sha256: String,
    byte_length: u64,
    ticket_id: String,
    issued_at: SystemTime,
    expires_at: SystemTime,
}

impl DownloadTicket {
    pub fn licence_id(&self) -> &str {
        &self.licence_id
    }
    pub fn release_id(&self) -> &str {
        &self.release_id
    }
    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn byte_length(&self) -> u64 {
        self.byte_length
    }
    pub fn ticket_id(&self) -> &str {
        &self.ticket_id
    }
    pub fn issued_at(&self) -> SystemTime {
        self.issued_at
    }
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }
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
    release_id: String,
    artifact_id: String,
    sha256: String,
    byte_length: u64,
}

impl DownloadTicketVerifier {
    /// Parse a public app key, exact protected HTTPS endpoint, and copied,
    /// environment-scoped connected-purpose JWKS bytes.
    pub fn new(app_key: &str, endpoint: &str, trusted_jwks: &[u8]) -> Result<Self> {
        let app = AppKey::parse(app_key)?;
        if !valid_endpoint(endpoint) {
            return Err(Error::Configuration);
        }
        let keys = Keys::parse_connected(trusted_jwks, app.environment())
            .map_err(|_| Error::Configuration)?;
        Ok(Self {
            app,
            endpoint: endpoint.to_owned(),
            keys,
        })
    }

    /// Verify against the current system clock.
    pub fn verify(&self, token: &str) -> Result<DownloadTicket> {
        self.verify_at(token, SystemTime::now())
    }

    /// Verify against an explicit instant for trusted-clock integrations and
    /// deterministic testing. A caller must not derive it from the request.
    pub fn verify_at(&self, token: &str, now: SystemTime) -> Result<DownloadTicket> {
        verify(self, token, now)
    }
}

fn valid_endpoint(value: &str) -> bool {
    if value.is_empty() || value.len() > 2048 || !value.is_ascii() || !value.starts_with("https://")
    {
        return false;
    }
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte <= 0x20 || byte == 0x7f || b"\\?#<>\"{}|^`".contains(&byte) {
            return false;
        }
        if byte == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 2;
        }
        index += 1;
    }
    transport::download_endpoint(value).is_ok()
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

fn opaque(value: &str) -> bool {
    crate::access::opaque(value)
}

fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn unix_time(seconds: i64) -> Result<SystemTime> {
    if !(0..=MAX_TIME).contains(&seconds) {
        return Err(Error::InvalidResponse);
    }
    UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds as u64))
        .ok_or(Error::InvalidResponse)
}

fn verify(
    verifier: &DownloadTicketVerifier,
    token: &str,
    now: SystemTime,
) -> Result<DownloadTicket> {
    if token.is_empty() || token.len() > MAX_BYTES || !token.is_ascii() {
        return Err(Error::InvalidResponse);
    }
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::InvalidResponse);
    };
    let header: Header =
        serde_json::from_slice(&canonical(header)?).map_err(|_| Error::InvalidResponse)?;
    if header.alg != "ES256" || header.typ != "orbit-download+jwt" || !opaque(&header.kid) {
        return Err(Error::InvalidResponse);
    }
    let key = verifier
        .keys
        .decoding_key(&header.kid)
        .ok_or(Error::InvalidResponse)?;
    let _payload_bytes = canonical(payload)?;
    let signature = canonical(signature)?;
    if signature.len() != 64 {
        return Err(Error::InvalidResponse);
    }
    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.leeway = 0;
    validation.set_audience(&[&verifier.endpoint]);
    validation.set_issuer(&[verifier.app.issuer()]);
    validation.set_required_spec_claims(&["exp", "nbf", "iat", "iss", "aud", "sub"]);
    let verified = decode::<Claims>(token, key, &validation)
        .map_err(|_| Error::InvalidResponse)?
        .claims;
    let issued_at = unix_time(verified.iat)?;
    let expires_at = unix_time(verified.exp)?;
    if now
        .duration_since(UNIX_EPOCH)
        .ok()
        .is_none_or(|value| value > Duration::from_secs(MAX_TIME as u64))
        || verified.ver != 1
        || !opaque(&verified.sub)
        || !opaque(&verified.jti)
        || verified.iss != verifier.app.issuer()
        || verified.aud != verifier.endpoint
        || verified.application_id != verifier.app.application_id()
        || verified.environment_id != verifier.app.environment_id()
        || !opaque(&verified.application_id)
        || !opaque(&verified.environment_id)
        || !opaque(&verified.release_id)
        || !opaque(&verified.artifact_id)
        || !lower_hex(&verified.sha256, 64)
        || verified.byte_length == 0
        || verified.byte_length > 9_007_199_254_740_991
        || verified.nbf != verified.iat
        || verified.exp <= verified.iat
        || verified.exp - verified.iat > 120
        || issued_at
            > now
                .checked_add(Duration::from_secs(30))
                .ok_or(Error::InvalidResponse)?
        || expires_at <= now
    {
        return Err(Error::InvalidResponse);
    }
    Ok(DownloadTicket {
        licence_id: verified.sub,
        release_id: verified.release_id,
        artifact_id: verified.artifact_id,
        sha256: verified.sha256,
        byte_length: verified.byte_length,
        ticket_id: verified.jti,
        issued_at,
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_json::{Map, Value};
    use std::{fs, path::PathBuf, sync::Arc, thread};

    #[derive(Deserialize)]
    struct Corpus {
        format_version: u32,
        jwks: Value,
        expected: ExpectedVector,
        cases: Vec<Case>,
    }
    #[derive(Clone, Deserialize)]
    struct ExpectedVector {
        app_key: String,
        endpoint: String,
        now: i64,
    }
    #[derive(Deserialize)]
    struct Case {
        name: String,
        token: String,
        valid: bool,
        expected: Option<Map<String, Value>>,
        jwks: Option<Value>,
    }

    fn corpus() -> Corpus {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/sdk/download-tickets.json");
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    fn configure_keys(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }

    #[test]
    fn shared_download_ticket_vectors() {
        let corpus = corpus();
        assert_eq!(corpus.format_version, 1);
        assert_eq!(corpus.cases.len(), 110);
        for case in corpus.cases {
            let mut expected = corpus.expected.clone();
            if let Some(overrides) = case.expected {
                for (name, value) in overrides {
                    match name.as_str() {
                        "app_key" => expected.app_key = value.as_str().unwrap_or("").to_owned(),
                        "endpoint" => expected.endpoint = value.as_str().unwrap_or("").to_owned(),
                        "now" => expected.now = value.as_i64().unwrap_or(-1),
                        _ => panic!("unexpected ticket vector override {name}"),
                    }
                }
            }
            let jwks = configure_keys(case.jwks.as_ref().unwrap_or(&corpus.jwks));
            let verifier =
                DownloadTicketVerifier::new(&expected.app_key, &expected.endpoint, &jwks);
            let now = (expected.now >= 0)
                .then(|| UNIX_EPOCH.checked_add(Duration::from_secs(expected.now as u64)))
                .flatten();
            let accepted = verifier
                .and_then(|verifier| {
                    now.ok_or(Error::InvalidResponse)
                        .and_then(|instant| verifier.verify_at(&case.token, instant))
                })
                .is_ok();
            assert_eq!(accepted, case.valid, "{}", case.name);
        }
    }

    #[test]
    fn copied_trusted_keys_and_32_concurrent_verifications() {
        let corpus = corpus();
        let mut keys = configure_keys(&corpus.jwks);
        let verifier = Arc::new(
            DownloadTicketVerifier::new(&corpus.expected.app_key, &corpus.expected.endpoint, &keys)
                .unwrap(),
        );
        keys.fill(b' ');
        let token = corpus.cases[0].token.clone();
        let now = UNIX_EPOCH + Duration::from_secs(corpus.expected.now as u64);
        let threads: Vec<_> = (0..32)
            .map(|_| {
                let verifier = Arc::clone(&verifier);
                let token = token.clone();
                thread::spawn(move || verifier.verify_at(&token, now).unwrap())
            })
            .collect();
        for thread in threads {
            let ticket = thread.join().unwrap();
            assert_eq!(ticket.byte_length(), 1024);
            assert_eq!(ticket.release_id(), "release_1");
            assert_eq!(
                ticket.issued_at(),
                UNIX_EPOCH + Duration::from_secs(corpus.expected.now as u64)
            );
            assert_eq!(
                ticket.expires_at(),
                UNIX_EPOCH + Duration::from_secs(corpus.expected.now as u64 + 120)
            );
        }
    }

    #[test]
    fn endpoint_configuration_is_bounded_and_strict() {
        let corpus = corpus();
        for endpoint in [
            "http://downloads.example.test/file",
            "https://user@downloads.example.test/file",
            "https://@downloads.example.test/file",
            "https:///downloads.example.test/file",
            "https://downloads.example.test/file?",
            "https://downloads.example.test/file#fragment",
            "https://downloads.example.test/%zz",
            "https://%64ownloads.example.test/file",
            "https://downloads.example.test:/file",
            "https://downloads.example.test:abc/file",
            "https://downloads.example.test:65536/file",
            "https://downloads.example.test:0/file",
            "https://:443/file",
            "https://[2001:db8::1/file",
            "https://downloads.example.test/a\\b",
            "https://downloads.example.test/has space",
        ] {
            assert!(
                DownloadTicketVerifier::new(
                    &corpus.expected.app_key,
                    endpoint,
                    &configure_keys(&corpus.jwks)
                )
                .is_err()
            );
        }
        let too_long = format!("https://downloads.example.test/{}", "a".repeat(2048));
        assert!(
            DownloadTicketVerifier::new(
                &corpus.expected.app_key,
                &too_long,
                &configure_keys(&corpus.jwks)
            )
            .is_err()
        );
        let endpoint_prefix = "https://downloads.example.test/";
        let exact_limit = format!(
            "{endpoint_prefix}{}",
            "a".repeat(2048 - endpoint_prefix.len())
        );
        assert!(
            DownloadTicketVerifier::new(
                &corpus.expected.app_key,
                &exact_limit,
                &configure_keys(&corpus.jwks)
            )
            .is_ok()
        );
        for endpoint in [
            "https://downloads.example.test:8443/file",
            "https://[2001:db8::1]:8443/file",
        ] {
            assert!(
                DownloadTicketVerifier::new(
                    &corpus.expected.app_key,
                    endpoint,
                    &configure_keys(&corpus.jwks)
                )
                .is_ok(),
                "rejected valid endpoint {endpoint}"
            );
        }
    }
}
