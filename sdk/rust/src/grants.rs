use crate::{Error, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, de};
use std::{collections::BTreeMap, fmt};

#[cfg(test)]
#[path = "grant_vectors.rs"]
mod vectors;

#[cfg(test)]
#[path = "grant_mutations.rs"]
mod mutations;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}
#[derive(Clone, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub jti: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    pub application_id: String,
    pub environment_id: String,
    pub activation_id: String,
    pub installation_id: String,
    pub binding_mode: String,
    pub fingerprint: Option<String>,
    pub fingerprint_provider: Option<String>,
    pub policy_version: i32,
    #[serde(deserialize_with = "entitlements")]
    pub entitlements: BTreeMap<String, bool>,
    pub refresh_after: i64,
    pub offline_allowed: bool,
    pub licence_expires_at: Option<i64>,
}
fn entitlements<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, bool>, D::Error> {
    struct Entries;
    impl<'de> de::Visitor<'de> for Entries {
        type Value = BTreeMap<String, bool>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("bounded unique boolean entitlements")
        }
        fn visit_map<A: de::MapAccess<'de>>(
            self,
            mut entries: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut map = BTreeMap::new();
            while let Some((key, value)) = entries.next_entry::<String, bool>()? {
                if key.is_empty()
                    || key.len() > 64
                    || !key.as_bytes()[0].is_ascii_lowercase()
                    || !key
                        .bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
                    || map.len() == 64
                    || map.insert(key, value).is_some()
                {
                    return Err(de::Error::custom("invalid entitlements"));
                }
            }
            Ok(map)
        }
    }
    deserializer.deserialize_map(Entries)
}
#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Jwk {
    kty: String,
    crv: String,
    alg: String,
    #[serde(rename = "use")]
    purpose: String,
    kid: String,
    x: String,
    y: String,
}
#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Jwks {
    pub(crate) keys: Vec<Jwk>,
}
#[derive(Default)]
pub struct Keys(BTreeMap<String, DecodingKey>, BTreeMap<String, Jwk>);
impl Keys {
    pub fn parse(value: serde_json::Value) -> Result<Self> {
        let jwks: Jwks = serde_json::from_value(value).map_err(|_| Error::InvalidResponse)?;
        if jwks.keys.is_empty() || jwks.keys.len() > 8 {
            return Err(Error::InvalidResponse);
        }
        let mut keys = BTreeMap::new();
        let mut public_keys = BTreeMap::new();
        for key in jwks.keys {
            if key.kty != "EC"
                || key.crv != "P-256"
                || key.alg != "ES256"
                || key.purpose != "sig"
                || key.kid.is_empty()
                || key.kid.len() > 128
                || !key.kid.is_ascii()
                || canonical(&key.x)?.len() != 32
                || canonical(&key.y)?.len() != 32
            {
                return Err(Error::InvalidResponse);
            }
            let public = DecodingKey::from_ec_components(&key.x, &key.y)
                .map_err(|_| Error::InvalidResponse)?;
            public_keys.insert(key.kid.clone(), key.clone());
            if keys.insert(key.kid, public).is_some() {
                return Err(Error::InvalidResponse);
            }
        }
        Ok(Self(keys, public_keys))
    }
    pub(crate) fn public_key(&self, token: &str) -> Result<serde_json::Value> {
        let key = self
            .1
            .get(&header(token)?.kid)
            .ok_or(Error::InvalidResponse)?;
        serde_json::to_value(Jwks {
            keys: vec![key.clone()],
        })
        .map_err(|_| Error::InvalidResponse)
    }
    pub fn contains(&self, token: &str) -> Result<bool> {
        Ok(self.0.contains_key(&header(token)?.kid))
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
fn header(token: &str) -> Result<Header> {
    if token.len() > 16384 {
        return Err(Error::InvalidResponse);
    }
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 || canonical(parts[2])?.len() != 64 {
        return Err(Error::InvalidResponse);
    }
    let header: Header =
        serde_json::from_slice(&canonical(parts[0])?).map_err(|_| Error::InvalidResponse)?;
    canonical(parts[1])?;
    if header.alg != "ES256" || header.typ != "orbit-access+jwt" || header.kid.len() > 128 {
        return Err(Error::InvalidResponse);
    }
    Ok(header)
}
pub struct Expected<'a> {
    pub issuer: &'a str,
    pub application: &'a str,
    pub environment: &'a str,
    pub licence: Option<&'a str>,
    pub activation: &'a str,
    pub installation: &'a str,
    pub fingerprint: Option<&'a str>,
    pub fingerprint_provider: Option<&'a str>,
    pub credential_expires_at: Option<i64>,
    pub licence_expires_at: Option<i64>,
    pub now: i64,
}
pub fn verify(token: &str, keys: &Keys, expected: &Expected<'_>) -> Result<Claims> {
    jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER
        .install_default()
        .ok();
    let header = header(token)?;
    let key = keys.0.get(&header.kid).ok_or(Error::InvalidResponse)?;
    let audience = format!("orbit:{}:{}", expected.application, expected.environment);
    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.leeway = 0;
    validation.set_audience(&[&audience]);
    validation.set_issuer(&[expected.issuer]);
    validation.set_required_spec_claims(&["exp", "nbf", "iat", "iss", "aud", "sub"]);
    let claims: Claims = decode::<Claims>(token, key, &validation)
        .map_err(|_| Error::InvalidResponse)?
        .claims;
    let allowance = if claims.offline_allowed { 86400 } else { 300 };
    let (refresh_min, refresh_max) =
        if expected.credential_expires_at.is_none() && claims.offline_allowed {
            (675, 1125)
        } else {
            (45, 75)
        };
    let bound = match (expected.fingerprint, expected.fingerprint_provider) {
        (None, None) => {
            claims.binding_mode == "none"
                && claims.fingerprint.is_none()
                && claims.fingerprint_provider.is_none()
        }
        (Some(fingerprint), Some(provider)) => {
            claims.binding_mode == "hwid"
                && claims.fingerprint.as_deref() == Some(fingerprint)
                && claims.fingerprint_provider.as_deref() == Some(provider)
        }
        _ => false,
    };
    if claims.iss != expected.issuer
        || claims.aud != audience
        || claims.sub.is_empty()
        || claims.sub.len() > 128
        || expected.licence.is_some_and(|id| id != claims.sub)
        || claims.jti.is_empty()
        || claims.jti.len() > 128
        || claims.application_id != expected.application
        || claims.environment_id != expected.environment
        || claims.activation_id != expected.activation
        || claims.installation_id != expected.installation
        || !bound
        || claims.policy_version < 1
        || claims.iat < 0
        || claims.nbf != claims.iat
        || claims.iat > expected.now.saturating_add(30)
        || claims.iat < expected.now.saturating_sub(30)
        || claims.exp <= expected.now
        || claims.exp <= claims.iat
        || claims.exp > claims.iat.saturating_add(allowance)
        || expected
            .credential_expires_at
            .is_some_and(|expiry| claims.exp > expiry)
        || claims.licence_expires_at != expected.licence_expires_at
        || claims
            .licence_expires_at
            .is_some_and(|expiry| claims.exp > expiry)
        || claims.refresh_after <= claims.iat
        || claims.refresh_after > claims.exp
        || claims.refresh_after > claims.iat.saturating_add(refresh_max)
        || (claims.refresh_after < claims.iat.saturating_add(refresh_min)
            && claims.refresh_after != claims.exp)
    {
        return Err(Error::InvalidResponse);
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};
    use serde::Serialize;
    const NOW: i64 = 1_800_000_000;
    pub(super) const PRIVATE: &[u8] = include_bytes!("../tests/fixtures/es256-test-private.pem");
    pub(super) fn claims() -> serde_json::Value {
        serde_json::json!({"iss":"https://orbit.example.test","aud":"orbit:app:test","sub":"licence","jti":"random",
            "iat":NOW,"nbf":NOW,"exp":NOW+300,"application_id":"app","environment_id":"test","activation_id":"activation",
            "installation_id":"installation","binding_mode":"none","policy_version":1,"entitlements":{"export":true},"refresh_after":NOW+60,"offline_allowed":false})
    }
    fn keys() -> Keys {
        Keys(
            BTreeMap::from([(
                "test-key".into(),
                DecodingKey::from_ec_pem(include_bytes!("../tests/fixtures/es256-test-public.pem"))
                    .unwrap(),
            )]),
            BTreeMap::new(),
        )
    }
    pub(super) fn expected() -> Expected<'static> {
        Expected {
            issuer: "https://orbit.example.test",
            application: "app",
            environment: "test",
            licence: Some("licence"),
            activation: "activation",
            installation: "installation",
            fingerprint: None,
            fingerprint_provider: None,
            credential_expires_at: Some(NOW + 3600),
            licence_expires_at: None,
            now: NOW,
        }
    }
    pub(super) fn sign<T: Serialize>(value: &T, header: Option<Header>) -> String {
        jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER
            .install_default()
            .ok();
        let mut default = Header::new(Algorithm::ES256);
        default.typ = Some("orbit-access+jwt".into());
        default.kid = Some("test-key".into());
        jsonwebtoken::encode(
            &header.unwrap_or(default),
            value,
            &EncodingKey::from_ec_pem(PRIVATE).unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn valid_grant_and_policy_caps() {
        let verified = verify(&sign(&claims(), None), &keys(), &expected()).unwrap();
        assert!(verified.entitlements["export"]);
        let mut offline = claims();
        offline["offline_allowed"] = true.into();
        offline["exp"] = (NOW + 900).into();
        assert!(verify(&sign(&offline, None), &keys(), &expected()).is_ok());
        let mut timed = expected();
        timed.licence_expires_at = Some(NOW + 250);
        assert!(verify(&sign(&claims(), None), &keys(), &timed).is_err());
    }
    #[test]
    fn scope_types_lifetime_and_missing_claims_fail_closed() {
        for (name, value) in [
            ("iss", json!("https://evil.test")),
            ("aud", json!("orbit:app:live")),
            ("sub", json!("other")),
            ("application_id", json!("other")),
            ("environment_id", json!("live")),
            ("activation_id", json!("other")),
            ("installation_id", json!("other")),
            ("binding_mode", json!("unknown")),
            ("policy_version", json!(0)),
            ("offline_allowed", json!("true")),
            ("exp", json!(NOW)),
            ("exp", json!(NOW + 301)),
            ("iat", json!(NOW + 31)),
            ("nbf", json!(NOW + 1)),
            ("refresh_after", json!(NOW + 76)),
            ("refresh_after", json!(NOW + 44)),
            ("entitlements", json!({"Export":true})),
            ("entitlements", json!({"export":"true"})),
            ("licence_expires_at", json!(NOW + 200)),
        ] {
            let mut value2 = claims();
            value2[name] = value;
            assert!(
                verify(&sign(&value2, None), &keys(), &expected()).is_err(),
                "{name}"
            );
        }
        for field in [
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
            "policy_version",
            "entitlements",
            "refresh_after",
            "offline_allowed",
        ] {
            let mut value = claims();
            value.as_object_mut().unwrap().remove(field);
            assert!(
                verify(&sign(&value, None), &keys(), &expected()).is_err(),
                "{field}"
            );
        }
    }
    use serde_json::json;
    #[test]
    fn bad_signatures_untrusted_headers_duplicates_and_algorithms() {
        let token = sign(&claims(), None);
        let mut changed = token.as_bytes().to_vec();
        let start = token.rfind('.').unwrap() + 1;
        changed[start] = if changed[start] == b'A' { b'B' } else { b'A' };
        assert!(verify(std::str::from_utf8(&changed).unwrap(), &keys(), &expected()).is_err());
        for kind in ["kid", "typ", "crit", "jku"] {
            let mut h = Header::new(Algorithm::ES256);
            h.typ = Some("orbit-access+jwt".into());
            h.kid = Some("test-key".into());
            match kind {
                "kid" => h.kid = Some("live-key".into()),
                "typ" => h.typ = Some("JWT".into()),
                "crit" => h.crit = Some(vec!["unknown".into()]),
                _ => h.jku = Some("https://evil.test".into()),
            }
            assert!(verify(&sign(&claims(), Some(h)), &keys(), &expected()).is_err());
        }
        for token in ["", "a.b.c", "a.b.c.d", "eyJhbGciOiJub25lIn0.e30."] {
            assert!(verify(token, &keys(), &expected()).is_err());
        }
        #[derive(Clone)]
        struct Duplicate;
        impl Serialize for Duplicate {
            fn serialize<S: serde::Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                use serde::ser::SerializeMap;
                let mut map = serializer.serialize_map(None)?;
                for (key, value) in claims().as_object().unwrap() {
                    map.serialize_entry(key, value)?;
                }
                map.serialize_entry("exp", &(NOW + 300))?;
                map.end()
            }
        }
        assert!(verify(&sign(&Duplicate, None), &keys(), &expected()).is_err());
        let duplicate = serde_json::to_string(&claims())
            .unwrap()
            .replace("\"export\":true", "\"export\":true,\"export\":false");
        assert!(serde_json::from_str::<Claims>(&duplicate).is_err());
        assert!(
            serde_json::from_str::<Header>(
                r#"{"alg":"ES256","alg":"HS256","typ":"orbit-access+jwt","kid":"test-key"}"#
            )
            .is_err()
        );
    }
}
