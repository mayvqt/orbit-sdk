use super::*;
use crate::Device;
use serde::{Deserialize, Serialize, Serializer, ser::SerializeMap};
use serde_json::Value;
use std::{fs, path::PathBuf};

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
    jwks: Option<Value>,
    expected: Option<Value>,
}

#[test]
fn shared_offline_file_vectors() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/sdk/offline-files.json");
    let corpus: Corpus = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(corpus.format_version, 1);
    assert_eq!(corpus.cases.len(), 104);
    for case in &corpus.cases {
        let mut expected = corpus.expected.clone();
        if let Some(overrides) = &case.expected {
            for (key, value) in overrides.as_object().unwrap() {
                expected[key] = value.clone();
            }
        }
        let app = AppKey::parse(expected["app_key"].as_str().unwrap()).unwrap();
        let mut device = Device {
            installation_id: expected["installation_id"].as_str().unwrap().into(),
            fingerprint: None,
            fingerprint_provider: None,
        };
        if let Some(value) = expected["fingerprint"].as_str() {
            device.fingerprint = Some(value.into())
        }
        if let Some(value) = expected["fingerprint_provider"].as_str() {
            device.fingerprint_provider = Some(value.into())
        }
        let jwks = case.jwks.as_ref().unwrap_or(&corpus.jwks);
        let bytes = serde_json::to_vec(jwks).unwrap();
        let parsed = parse_keys(&bytes, app.environment()).and_then(|keys| {
            verify(
                case.token.as_bytes(),
                &keys,
                &app,
                &device,
                expected["now"].as_i64().unwrap(),
                expected["minimum_sequence"].as_u64().unwrap(),
            )
        });
        assert_eq!(
            parsed.is_ok(),
            case.valid,
            "offline vector {}: {parsed:?}",
            case.name
        );
    }

    let app = AppKey::parse(corpus.expected["app_key"].as_str().unwrap()).unwrap();
    let device = Device {
        installation_id: corpus.expected["installation_id"].as_str().unwrap().into(),
        fingerprint: None,
        fingerprint_provider: None,
    };
    let jwks = serde_json::to_vec(&corpus.jwks).unwrap();
    let keys = parse_keys(&jwks, app.environment()).unwrap();
    let first_case = &corpus.cases[0];
    let first = verify(
        first_case.token.as_bytes(),
        &keys,
        &app,
        &device,
        corpus.expected["now"].as_i64().unwrap(),
        corpus.expected["minimum_sequence"].as_u64().unwrap(),
    )
    .unwrap();
    assert_eq!(
        first.content_digest,
        "8aed1c86dab86f56c744802ee68650041ddc12e8d56bb6d73c2f40049424740a"
    );
    let reordered = reordered_token(&first_case.token, false);
    let reordered = verify(
        reordered.as_bytes(),
        &keys,
        &app,
        &device,
        corpus.expected["now"].as_i64().unwrap(),
        corpus.expected["minimum_sequence"].as_u64().unwrap(),
    )
    .unwrap();
    assert_eq!(reordered.content_digest, first.content_digest);
    assert_eq!(reordered.issuance_id, first.issuance_id);
    assert_eq!(reordered.sequence, first.sequence);
    let changed = reordered_token(&first_case.token, true);
    let changed = verify(
        changed.as_bytes(),
        &keys,
        &app,
        &device,
        corpus.expected["now"].as_i64().unwrap(),
        corpus.expected["minimum_sequence"].as_u64().unwrap(),
    )
    .unwrap();
    assert_eq!(changed.issuance_id, first.issuance_id);
    assert_eq!(changed.sequence, first.sequence);
    assert_ne!(changed.content_digest, first.content_digest);

    let mut bad_keys = corpus.jwks.clone();
    bad_keys["keys"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "kty":"EC","crv":"P-256","alg":"ES256","use":"sig",
            "kid":"offline-test-retained-invalid-point",
            "x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        }));
    assert!(parse_keys(&serde_json::to_vec(&bad_keys).unwrap(), "test").is_err());

    let exact_keys = serde_json::to_vec(&corpus.jwks).unwrap();
    let mut exact_keys = exact_keys.clone();
    exact_keys.resize(16 * 1024, b' ');
    assert!(parse_keys(&exact_keys, "test").is_ok());
    exact_keys.push(b' ');
    assert!(parse_keys(&exact_keys, "test").is_err());
    assert!(parse_keys(br#"{"keys":[],"keys":[]}"#, "test").is_err());

    let mut exact_file = first_case.token.as_bytes().to_vec();
    exact_file.resize(16 * 1024, b' ');
    assert!(
        verify(
            &exact_file,
            &keys,
            &app,
            &device,
            corpus.expected["now"].as_i64().unwrap(),
            corpus.expected["minimum_sequence"].as_u64().unwrap(),
        )
        .is_ok()
    );
    exact_file.push(b' ');
    assert!(
        verify(
            &exact_file,
            &keys,
            &app,
            &device,
            corpus.expected["now"].as_i64().unwrap(),
            corpus.expected["minimum_sequence"].as_u64().unwrap(),
        )
        .is_err()
    );
}

struct ReverseObject(Value);
impl Serialize for ReverseObject {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let object = self.0.as_object().expect("JWT claims object");
        let mut map = serializer.serialize_map(Some(object.len()))?;
        for (key, value) in object.iter().rev() {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

pub(crate) fn reordered_token(token: &str, change: bool) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    let parts: Vec<_> = token.split('.').collect();
    let mut claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    if change {
        claims["entitlements"]["export"] = Value::Bool(false);
    }
    let pem = fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/es256-test-private.pem"),
    )
    .unwrap();
    let key = EncodingKey::from_ec_pem(&pem).unwrap();
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("orbit-offline+jwt".into());
    header.kid = Some("offline-test-fixture".into());
    encode(&header, &ReverseObject(claims), &key).unwrap()
}
