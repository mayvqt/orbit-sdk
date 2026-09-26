//! Internal verification for connected floating-session grants.
//!
//! This verifier is crate-private so the public SDK does not expose a
//! caller-selectable JWT purpose.

use crate::{
    Error, Result,
    access::{self, valid_provider},
    grants::Keys,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, Validation, decode};
use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use std::{collections::BTreeMap, fmt};

const MAX_BYTES: usize = 16 * 1024;
const MAX_TIME: i64 = 253_402_300_799;
const MAX_SEQUENCE: u64 = 9_007_199_254_740_991;

pub(crate) struct SessionKeys(Keys);

impl SessionKeys {
    pub(crate) fn parse(data: &[u8], environment: &str) -> Result<Self> {
        Ok(Self(Keys::parse_connected(data, environment)?))
    }
}

pub(crate) struct Expected<'a> {
    pub(crate) issuer: &'a str,
    pub(crate) application: &'a str,
    pub(crate) environment: &'a str,
    pub(crate) licence: Option<&'a str>,
    pub(crate) activation: &'a str,
    pub(crate) installation: &'a str,
    pub(crate) fingerprint: Option<&'a str>,
    pub(crate) fingerprint_provider: Option<&'a str>,
    pub(crate) allow_unbound_fingerprint: bool,
    pub(crate) credential_expires_at: Option<i64>,
    pub(crate) licence_expires_at: Option<i64>,
    pub(crate) now: i64,
    pub(crate) session_id: &'a str,
    pub(crate) sequence: u64,
}

#[derive(Clone)]
pub(crate) struct SessionGrant {
    pub(crate) session_id: String,
    pub(crate) sequence: u64,
    pub(crate) licence_id: String,
    pub(crate) activation_id: String,
    pub(crate) installation_id: String,
    pub(crate) ticket_id: String,
    pub(crate) issued_at: i64,
    pub(crate) expires_at: i64,
    pub(crate) refresh_after: i64,
    pub(crate) licence_expires_at: Option<i64>,
    pub(crate) policy_version: i32,
    pub(crate) entitlements: BTreeMap<String, bool>,
}

impl fmt::Debug for SessionGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionGrant(<verified>)")
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
struct Claims {
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
    binding_mode: String,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default)]
    fingerprint_provider: Option<String>,
    policy_version: i32,
    #[serde(deserialize_with = "crate::grants::entitlements")]
    entitlements: BTreeMap<String, bool>,
    refresh_after: i64,
    offline_allowed: bool,
    #[serde(default)]
    licence_expires_at: Option<i64>,
    session_id: String,
    session_sequence: u64,
}

/// A JSON value that rejects duplicate keys at every object depth. Parsing
/// into `serde_json::Value` alone would silently keep only the last value.
struct UniqueJson(Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UniqueJsonVisitor;

        impl<'de> Visitor<'de> for UniqueJsonVisitor {
            type Value = UniqueJson;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON without duplicate object keys")
            }

            fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::from(value)))
            }

            fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::from(value)))
            }

            fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(|number| UniqueJson(Value::Number(number)))
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::String(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::String(value)))
            }

            fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::Null))
            }

            fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::Null))
            }

            fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(UniqueJson(value)) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(UniqueJson(Value::Array(values)))
            }

            fn visit_map<A>(self, mut object: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = serde_json::Map::new();
                while let Some(key) = object.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate JSON object key"));
                    }
                    let UniqueJson(value) = object.next_value()?;
                    values.insert(key, value);
                }
                Ok(UniqueJson(Value::Object(values)))
            }
        }

        deserializer.deserialize_any(UniqueJsonVisitor)
    }
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

pub(crate) fn verify(
    token: &str,
    keys: &SessionKeys,
    expected: &Expected<'_>,
) -> Result<SessionGrant> {
    if token.is_empty()
        || token.len() > MAX_BYTES
        || !token.is_ascii()
        || !(0..=MAX_TIME).contains(&expected.now)
        || !access::opaque(expected.session_id)
        || expected.session_id.len() < 16
        || !(1..=MAX_SEQUENCE).contains(&expected.sequence)
        || expected.fingerprint.is_some() != expected.fingerprint_provider.is_some()
        || !access::opaque(expected.application)
        || !access::opaque(expected.environment)
        || !access::opaque(expected.activation)
        || !access::opaque(expected.installation)
        || expected
            .licence
            .is_some_and(|licence| !access::opaque(licence))
    {
        return Err(Error::InvalidResponse);
    }
    let mut parts = token.split('.');
    let (Some(header_part), Some(payload_part), Some(signature_part), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::InvalidResponse);
    };
    let header: Header =
        serde_json::from_slice(&canonical(header_part)?).map_err(|_| Error::InvalidResponse)?;
    if header.alg != "ES256" || header.typ != "orbit-session+jwt" || !access::opaque(&header.kid) {
        return Err(Error::InvalidResponse);
    }
    let payload = canonical(payload_part)?;
    if canonical(signature_part)?.len() != 64 {
        return Err(Error::InvalidResponse);
    }
    let UniqueJson(value) = serde_json::from_slice(&payload).map_err(|_| Error::InvalidResponse)?;
    let object = value.as_object().ok_or(Error::InvalidResponse)?;
    let known = [
        "iss",
        "aud",
        "sub",
        "jti",
        "iat",
        "nbf",
        "exp",
        "application_id",
        "environment_id",
        "activation_id",
        "installation_id",
        "binding_mode",
        "fingerprint",
        "fingerprint_provider",
        "policy_version",
        "entitlements",
        "refresh_after",
        "offline_allowed",
        "licence_expires_at",
        "session_id",
        "session_sequence",
    ];
    if object.keys().any(|field| {
        known
            .iter()
            .any(|name| field != name && field.eq_ignore_ascii_case(name))
    }) {
        return Err(Error::InvalidResponse);
    }
    let no_fingerprint_claims =
        !object.contains_key("fingerprint") && !object.contains_key("fingerprint_provider");
    let key = keys
        .0
        .decoding_key(&header.kid)
        .ok_or(Error::InvalidResponse)?;
    let audience = format!(
        "orbit-session:{}:{}",
        expected.application, expected.environment
    );
    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.leeway = 0;
    validation.set_audience(&[&audience]);
    validation.set_issuer(&[expected.issuer]);
    validation.set_required_spec_claims(&["exp", "nbf", "iat", "iss", "aud", "sub"]);
    let claims = decode::<Claims>(token, key, &validation)
        .map_err(|_| Error::InvalidResponse)?
        .claims;
    let bound = match claims.binding_mode.as_str() {
        "none" => {
            no_fingerprint_claims
                && (expected.fingerprint.is_none() && expected.fingerprint_provider.is_none()
                    || expected.allow_unbound_fingerprint
                        && expected.fingerprint.is_some()
                        && expected.fingerprint_provider.is_some())
        }
        "hwid" => {
            expected.fingerprint.is_some()
                && expected.fingerprint_provider.is_some()
                && claims.fingerprint.as_deref() == expected.fingerprint
                && claims.fingerprint_provider.as_deref() == expected.fingerprint_provider
                && claims
                    .fingerprint
                    .as_deref()
                    .is_some_and(|value| lower_hex(value, 64))
                && claims
                    .fingerprint_provider
                    .as_deref()
                    .is_some_and(valid_provider)
        }
        _ => false,
    };
    if claims.iss != expected.issuer
        || claims.aud != audience
        || !access::opaque(&claims.sub)
        || expected.licence.is_some_and(|value| value != claims.sub)
        || !access::opaque(&claims.jti)
        || !access::opaque(&claims.application_id)
        || !access::opaque(&claims.environment_id)
        || !access::opaque(&claims.activation_id)
        || !access::opaque(&claims.installation_id)
        || claims.application_id != expected.application
        || claims.environment_id != expected.environment
        || claims.activation_id != expected.activation
        || claims.installation_id != expected.installation
        || claims.session_id != expected.session_id
        || claims.session_sequence != expected.sequence
        || !bound
        || claims.policy_version < 1
        || claims.offline_allowed
        || !(0..=MAX_TIME).contains(&claims.iat)
        || claims.nbf != claims.iat
        || claims.iat > expected.now.saturating_add(30)
        || !(0..=MAX_TIME).contains(&claims.exp)
        || claims.exp <= expected.now
        || claims.exp <= claims.iat
        || claims.exp.saturating_sub(claims.iat) > 120
        || claims
            .licence_expires_at
            .is_some_and(|expiry| !(0..=MAX_TIME).contains(&expiry))
        || expected
            .credential_expires_at
            .is_some_and(|expiry| claims.exp > expiry)
        || claims.licence_expires_at != expected.licence_expires_at
        || claims
            .licence_expires_at
            .is_some_and(|expiry| claims.exp > expiry)
        || !(0..=MAX_TIME).contains(&claims.refresh_after)
        || claims.refresh_after <= claims.iat
        || claims.refresh_after > claims.exp
        || claims.refresh_after > claims.iat.saturating_add(75)
        || (claims.refresh_after < claims.iat.saturating_add(45)
            && claims.refresh_after != claims.exp)
    {
        return Err(Error::InvalidResponse);
    }
    Ok(SessionGrant {
        session_id: claims.session_id,
        sequence: claims.session_sequence,
        licence_id: claims.sub,
        activation_id: claims.activation_id,
        installation_id: claims.installation_id,
        ticket_id: claims.jti,
        issued_at: claims.iat,
        expires_at: claims.exp,
        refresh_after: claims.refresh_after,
        licence_expires_at: claims.licence_expires_at,
        policy_version: claims.policy_version,
        entitlements: claims.entitlements,
    })
}

fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
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
        expected: Value,
        cases: Vec<Case>,
    }
    #[derive(Deserialize)]
    struct Case {
        name: String,
        token: String,
        valid: bool,
        expected: Option<Map<String, Value>>,
        jwks: Option<Value>,
    }
    #[derive(Deserialize)]
    struct ExpectedVector {
        issuer: String,
        application: String,
        environment: String,
        licence: Option<String>,
        activation: String,
        installation: String,
        fingerprint: Option<String>,
        fingerprint_provider: Option<String>,
        allow_unbound_fingerprint: Option<bool>,
        credential_expires_at: Option<i64>,
        licence_expires_at: Option<i64>,
        now: Value,
        session_id: String,
        sequence: Value,
        key_environment: String,
    }

    fn corpus() -> Corpus {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/sdk/session-grants.json");
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    fn run_vector(token: &str, jwks: &[u8], expected: &ExpectedVector) -> Result<SessionGrant> {
        let keys = SessionKeys::parse(jwks, &expected.key_environment)?;
        let now = expected.now.as_i64().unwrap_or(-1);
        let sequence = expected.sequence.as_u64().unwrap_or(0);
        let expected = Expected {
            issuer: &expected.issuer,
            application: &expected.application,
            environment: &expected.environment,
            licence: expected.licence.as_deref(),
            activation: &expected.activation,
            installation: &expected.installation,
            fingerprint: expected.fingerprint.as_deref(),
            fingerprint_provider: expected.fingerprint_provider.as_deref(),
            allow_unbound_fingerprint: expected.allow_unbound_fingerprint.unwrap_or(false),
            credential_expires_at: expected.credential_expires_at,
            licence_expires_at: expected.licence_expires_at,
            now,
            session_id: &expected.session_id,
            sequence,
        };
        verify(token, &keys, &expected)
    }

    #[test]
    fn shared_session_grant_vectors() {
        let corpus = corpus();
        assert_eq!(corpus.format_version, 1);
        assert_eq!(corpus.cases.len(), 184);
        for case in corpus.cases {
            let mut value = corpus.expected.as_object().unwrap().clone();
            if let Some(overrides) = case.expected {
                value.extend(overrides);
            }
            let expected: ExpectedVector = serde_json::from_value(Value::Object(value)).unwrap();
            let jwks = serde_json::to_vec(case.jwks.as_ref().unwrap_or(&corpus.jwks)).unwrap();
            let accepted = run_vector(&case.token, &jwks, &expected).is_ok();
            assert_eq!(accepted, case.valid, "{}", case.name);
        }
    }

    #[test]
    fn signed_claim_identifiers_remain_bounded_with_matching_context() {
        let corpus = corpus();
        let parts: Vec<_> = corpus.cases[0].token.split('.').collect();
        let base: Value = serde_json::from_slice(&canonical(parts[1]).unwrap()).unwrap();
        let jwks = serde_json::to_vec(&corpus.jwks).unwrap();
        for (claim, context) in [
            ("application_id", "application"),
            ("environment_id", "environment"),
            ("activation_id", "activation"),
            ("installation_id", "installation"),
        ] {
            for invalid in ["a".repeat(129), "invalid/id".to_owned()] {
                let mut claims = base.clone();
                claims[claim] = Value::String(invalid.clone());
                let mut expected = corpus.expected.clone();
                expected[context] = Value::String(invalid);
                let token = sign_review_payload(parts[0], &serde_json::to_vec(&claims).unwrap());
                let expected = serde_json::from_value(expected).unwrap();
                assert!(
                    run_vector(&token, &jwks, &expected).is_err(),
                    "accepted malformed {claim}"
                );
            }
        }
    }

    #[test]
    fn duplicate_unknown_claims_are_rejected() {
        let corpus = corpus();
        let parts: Vec<_> = corpus.cases[0].token.split('.').collect();
        let payload = String::from_utf8(canonical(parts[1]).unwrap()).unwrap();
        let payload = format!(
            "{},\"metadata\":1,\"metadata\":2}}",
            &payload[..payload.len() - 1]
        );
        let token = sign_review_payload(parts[0], payload.as_bytes());
        let expected = serde_json::from_value(corpus.expected.clone()).unwrap();
        assert!(
            run_vector(
                &token,
                &serde_json::to_vec(&corpus.jwks).unwrap(),
                &expected
            )
            .is_err()
        );

        // Build a fresh copy of the original payload without its closing brace.
        let original = String::from_utf8(canonical(parts[1]).unwrap()).unwrap();
        let valid_payload = format!(
            "{},\"metadata\":{{\"nested\":{{\"first\":1,\"second\":2}}}}}}",
            &original[..original.len() - 1]
        );
        let valid_token = sign_review_payload(parts[0], valid_payload.as_bytes());
        let expected = serde_json::from_value(corpus.expected.clone()).unwrap();
        assert!(
            run_vector(
                &valid_token,
                &serde_json::to_vec(&corpus.jwks).unwrap(),
                &expected
            )
            .is_ok()
        );

        let nested_duplicate = format!(
            "{},\"metadata\":{{\"nested\":{{\"first\":1,\"first\":2}}}}}}",
            &original[..original.len() - 1]
        );
        let nested_token = sign_review_payload(parts[0], nested_duplicate.as_bytes());
        assert!(
            run_vector(
                &nested_token,
                &serde_json::to_vec(&corpus.jwks).unwrap(),
                &expected
            )
            .is_err()
        );
    }

    fn sign_review_payload(header: &str, payload: &[u8]) -> String {
        jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER
            .install_default()
            .ok();
        let input = format!("{header}.{}", URL_SAFE_NO_PAD.encode(payload));
        let key = jsonwebtoken::EncodingKey::from_ec_pem(include_bytes!(
            "../tests/fixtures/es256-test-private.pem"
        ))
        .unwrap();
        let signature =
            jsonwebtoken::crypto::sign(input.as_bytes(), &key, Algorithm::ES256).unwrap();
        format!("{input}.{signature}")
    }

    #[test]
    fn copied_keys_and_32_concurrent_verifications() {
        let corpus = corpus();
        let expected: ExpectedVector = serde_json::from_value(corpus.expected.clone()).unwrap();
        let mut jwks = serde_json::to_vec(&corpus.jwks).unwrap();
        let keys = Arc::new(SessionKeys::parse(&jwks, &expected.key_environment).unwrap());
        jwks.fill(b' ');
        let now = expected.now.as_i64().unwrap();
        let context = Arc::new(expected);
        let token = corpus.cases[0].token.clone();
        let threads: Vec<_> = (0..32)
            .map(|_| {
                let keys = Arc::clone(&keys);
                let expected = Arc::clone(&context);
                let token = token.clone();
                thread::spawn(move || {
                    let expected = Expected {
                        issuer: &expected.issuer,
                        application: &expected.application,
                        environment: &expected.environment,
                        licence: expected.licence.as_deref(),
                        activation: &expected.activation,
                        installation: &expected.installation,
                        fingerprint: expected.fingerprint.as_deref(),
                        fingerprint_provider: expected.fingerprint_provider.as_deref(),
                        allow_unbound_fingerprint: expected
                            .allow_unbound_fingerprint
                            .unwrap_or(false),
                        credential_expires_at: expected.credential_expires_at,
                        licence_expires_at: expected.licence_expires_at,
                        now,
                        session_id: &expected.session_id,
                        sequence: expected.sequence.as_u64().unwrap(),
                    };
                    verify(&token, &keys, &expected).unwrap()
                })
            })
            .collect();
        for thread in threads {
            assert_eq!(thread.join().unwrap().sequence, 1);
        }
    }
}
