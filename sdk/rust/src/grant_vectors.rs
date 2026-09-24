//! Identical fixed signed inputs for every SDK; no wall clock or server dependency.
use super::{Expected, Keys, verify};
use serde::Deserialize;
use serde_json::Value;
use std::path::PathBuf;

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
    expected: Option<Value>,
    jwks: Option<Value>,
}

#[test]
fn shared_grant_vectors() {
    let path = std::env::var_os("ORBIT_SDK_GRANT_VECTORS")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/sdk/grants.json")
        });
    let corpus: Corpus = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(corpus.format_version, 1);
    assert!(!corpus.cases.is_empty());
    for case in corpus.cases {
        let mut expected = corpus.expected.clone();
        if let Some(overrides) = case.expected {
            expected
                .as_object_mut()
                .unwrap()
                .extend(overrides.as_object().unwrap().clone());
        }
        let text = |name: &str| expected[name].as_str().unwrap();
        let number = |name: &str| expected[name].as_i64().unwrap();
        let binding = Expected {
            issuer: text("issuer"),
            application: text("application"),
            environment: text("environment"),
            licence: expected["licence"].as_str(),
            activation: text("activation"),
            installation: text("installation"),
            fingerprint: expected["fingerprint"].as_str(),
            fingerprint_provider: expected["fingerprint_provider"].as_str(),
            credential_expires_at: number("credential_expires_at"),
            licence_expires_at: expected["licence_expires_at"].as_i64(),
            now: number("now"),
        };
        let actual = Keys::parse(case.jwks.unwrap_or_else(|| corpus.jwks.clone()))
            .and_then(|keys| verify(&case.token, &keys, &binding));
        assert_eq!(actual.is_ok(), case.valid, "grant vector: {}", case.name);
    }
}
