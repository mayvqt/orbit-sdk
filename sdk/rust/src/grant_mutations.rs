//! Bounded deterministic parser mutation regressions, separate from runtime code.

use super::tests::{PRIVATE, claims, expected, sign};
use super::*;
use jsonwebtoken::EncodingKey;
use serde_json::json;

fn mutation_fixture() -> (String, serde_json::Value) {
    // Reuse the fixed cross-SDK signature, including the exported-kit path.
    // Signing a fresh fixture would randomize the signature mutation corpus.
    let path = std::env::var_os("ORBIT_SDK_GRANT_VECTORS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../contracts/sdk/grants.json")
        });
    let corpus: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let case = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "strict-valid")
        .unwrap();
    assert_eq!(case["valid"], true);
    (
        case["token"].as_str().unwrap().to_owned(),
        corpus["jwks"].clone(),
    )
}

fn replace_segment(parts: &[&str], index: usize, value: &str) -> String {
    let mut changed = [parts[0], parts[1], parts[2]];
    changed[index] = value;
    changed.join(".")
}

fn sign_json_bytes(header: &[u8], payload: &[u8]) -> String {
    jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER
        .install_default()
        .ok();
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let signature = jsonwebtoken::crypto::sign(
        message.as_bytes(),
        &EncodingKey::from_ec_pem(PRIVATE).unwrap(),
        Algorithm::ES256,
    )
    .unwrap();
    format!("{message}.{signature}")
}

fn next_mutation_byte(state: &mut u32) -> u8 {
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    (*state >> 24) as u8
}

#[test]
fn grant_mutations_reject_each_changed_encoded_and_decoded_byte() {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let (token, jwks) = mutation_fixture();
    let keys = Keys::parse(jwks).unwrap();
    let expected = expected();
    assert!(token.len() <= 1024, "Keep the mutation fixture bounded");
    assert!(verify(&token, &keys, &expected).is_ok());
    let parts: Vec<_> = token.split('.').collect();
    for (part, original) in parts.iter().enumerate() {
        let mut encoded = original.as_bytes().to_vec();
        for index in 0..encoded.len() {
            let old = encoded[index];
            let ordinal = ALPHABET.iter().position(|byte| *byte == old).unwrap();
            // One legal-alphabet change plus one illegal byte at every
            // position of all three segments, including unused pad bits.
            for byte in [ALPHABET[(ordinal + 1) % ALPHABET.len()], b'!'] {
                encoded[index] = byte;
                let changed = replace_segment(&parts, part, std::str::from_utf8(&encoded).unwrap());
                assert_ne!(changed, token);
                assert!(
                    verify(&changed, &keys, &expected).is_err(),
                    "encoded part {part}, byte {index}"
                );
            }
            encoded[index] = old;
        }
        let mut decoded = URL_SAFE_NO_PAD.decode(original).unwrap();
        for index in 0..decoded.len() {
            decoded[index] ^= 1;
            let changed = replace_segment(&parts, part, &URL_SAFE_NO_PAD.encode(&decoded));
            assert_ne!(changed, token);
            assert!(
                verify(&changed, &keys, &expected).is_err(),
                "decoded part {part}, byte {index}"
            );
            decoded[index] ^= 1;
        }
    }
}

#[test]
fn grant_mutations_reject_truncation_segments_encodings_and_oversize() {
    let (token, jwks) = mutation_fixture();
    let keys = Keys::parse(jwks).unwrap();
    let expected = expected();
    // Both payloads remain correctly signed and semantically valid; only
    // the second exceeds the compact-token byte limit.
    let mut padded = claims();
    padded["padding"] = "x".repeat(11_000).into();
    let within_limit = sign(&padded, None);
    assert!(within_limit.len() <= 16_384);
    assert!(verify(&within_limit, &keys, &expected).is_ok());
    padded["padding"] = "x".repeat(12_288).into();
    let oversized = sign(&padded, None);
    assert!(oversized.len() > 16_384 && oversized.len() <= 20_000);
    assert!(verify(&oversized, &keys, &expected).is_err());
    for end in 0..token.len() {
        assert!(
            verify(&token[..end], &keys, &expected).is_err(),
            "token cut {end}"
        );
    }
    for malformed in [
        "".to_owned(),
        ".".to_owned(),
        "..".to_owned(),
        "a.b.c.d".to_owned(),
        format!(".{token}"),
        format!("{token}."),
        format!("{token}\n"),
        "A".repeat(16_385),
    ] {
        assert!(verify(&malformed, &keys, &expected).is_err());
    }
    let parts: Vec<_> = token.split('.').collect();
    for part in 0..3 {
        for malformed in [
            String::new(),
            format!("{}=", parts[part]),
            format!(" {}", parts[part]),
            format!("{}\n", parts[part]),
            format!("{}+", parts[part]),
        ] {
            assert!(verify(&replace_segment(&parts, part, &malformed), &keys, &expected).is_err());
        }
        let mut bytes = parts[part].as_bytes().to_vec();
        bytes[0] = 0xff;
        let lossy = String::from_utf8_lossy(&bytes);
        assert!(verify(&replace_segment(&parts, part, &lossy), &keys, &expected).is_err());
    }
}

#[test]
fn grant_mutations_reject_signed_invalid_json_and_duplicate_security_fields() {
    let (token, jwks) = mutation_fixture();
    let keys = Keys::parse(jwks).unwrap();
    let expected = expected();
    let parts: Vec<_> = token.split('.').collect();
    let header = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
    let mut all_claims = claims();
    for name in ["fingerprint", "fingerprint_provider", "licence_expires_at"] {
        all_claims[name] = serde_json::Value::Null;
    }
    let payload = serde_json::to_vec(&all_claims).unwrap();
    assert!(verify(&sign_json_bytes(&header, &payload), &keys, &expected).is_ok());
    // These have a real signature, so malformed JSON cannot pass merely
    // because a stale signature was rejected before deserialization.
    let deep = format!("{}0{}", "[".repeat(129), "]".repeat(129));
    for malformed in [b"{".as_slice(), b"null", b"[]", b"\xff", deep.as_bytes()] {
        assert!(verify(&sign_json_bytes(malformed, &payload), &keys, &expected).is_err());
        assert!(verify(&sign_json_bytes(&header, malformed), &keys, &expected).is_err());
    }
    let header_text = std::str::from_utf8(&header).unwrap();
    let parsed_header: serde_json::Value = serde_json::from_slice(&header).unwrap();
    for name in ["alg", "typ", "kid"] {
        let duplicate = format!(
            "{},\"{name}\":{}}}",
            &header_text[..header_text.len() - 1],
            parsed_header[name]
        );
        assert!(
            verify(
                &sign_json_bytes(duplicate.as_bytes(), &payload),
                &keys,
                &expected
            )
            .is_err()
        );
    }
    let payload_text = std::str::from_utf8(&payload).unwrap();
    for (name, value) in all_claims.as_object().unwrap() {
        let duplicate = format!(
            "{},\"{name}\":{value}}}",
            &payload_text[..payload_text.len() - 1]
        );
        assert!(
            verify(
                &sign_json_bytes(&header, duplicate.as_bytes()),
                &keys,
                &expected
            )
            .is_err(),
            "duplicate {name}"
        );
    }
    for value in ["true", "false"] {
        let duplicate = payload_text.replace(
            "\"export\":true",
            &format!("\"export\":true,\"export\":{value}"),
        );
        assert_ne!(duplicate, payload_text);
        assert!(
            verify(
                &sign_json_bytes(&header, duplicate.as_bytes()),
                &keys,
                &expected
            )
            .is_err()
        );
    }
}

#[test]
fn grant_mutations_bounded_arbitrary_text_fails_closed_without_panics() {
    const CASES: usize = 2048;
    const MAX_BYTES: usize = 4096;
    const ALPHABET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.= \n{}[]\"";
    let (token, jwks) = mutation_fixture();
    let keys = Keys::parse(jwks).unwrap();
    let expected = expected();
    let mut state = 0x6772_616e_u32;
    for case in 0..CASES {
        let length = case * 2053 % (MAX_BYTES + 1);
        let text: String = (0..length)
            .map(|_| ALPHABET[usize::from(next_mutation_byte(&mut state)) % ALPHABET.len()] as char)
            .collect();
        let actual = verify(&text, &keys, &expected);
        assert_eq!(actual.is_ok(), text == token, "arbitrary token {case}");
    }
}

fn assert_accepted_jwks_metadata(value: serde_json::Value) {
    let Ok(parsed) = Keys::parse(value.clone()) else {
        return;
    };
    let entries = value["keys"].as_array().unwrap();
    assert!((1..=8).contains(&entries.len()));
    assert_eq!(parsed.0.len(), entries.len());
    let mut ids = std::collections::BTreeSet::new();
    for key in entries {
        assert_eq!(key.as_object().unwrap().len(), 7);
        for (name, expected) in [
            ("kty", "EC"),
            ("crv", "P-256"),
            ("alg", "ES256"),
            ("use", "sig"),
        ] {
            assert_eq!(key[name], expected);
        }
        let id = key["kid"].as_str().unwrap();
        assert!(!id.is_empty() && id.len() <= 128 && id.is_ascii());
        assert!(ids.insert(id));
        assert!(parsed.0.contains_key(id));
        for coordinate in ["x", "y"] {
            let encoded = key[coordinate].as_str().unwrap();
            let decoded = URL_SAFE_NO_PAD.decode(encoded).unwrap();
            assert_eq!(decoded.len(), 32);
            assert_eq!(URL_SAFE_NO_PAD.encode(decoded), encoded);
        }
    }
    // Legal changed IDs/coordinates need not be rejected by a key parser;
    // possession of those public bytes does not validate any signed grant.
}

#[test]
fn jwks_mutations_reject_invalid_metadata_types_duplicates_and_bounds() {
    let (_, jwks) = mutation_fixture();
    assert!(Keys::parse(jwks.clone()).is_ok());
    for value in [
        json!(null),
        json!(true),
        json!(0),
        json!("keys"),
        json!([]),
        json!({}),
        json!({"keys": null}),
        json!({"keys": []}),
    ] {
        assert!(Keys::parse(value).is_err());
    }
    let nine: Vec<_> = (0..9)
        .map(|index| {
            let mut key = jwks["keys"][0].clone();
            key["kid"] = format!("test-key-{index}").into();
            key
        })
        .collect();
    assert!(Keys::parse(json!({"keys": &nine[..8]})).is_ok());
    assert!(Keys::parse(json!({"keys": nine})).is_err());
    for name in ["kty", "crv", "alg", "use", "kid", "x", "y"] {
        let mut missing = jwks.clone();
        missing["keys"][0].as_object_mut().unwrap().remove(name);
        assert!(Keys::parse(missing).is_err(), "missing {name}");
        for value in [json!(null), json!(true), json!(0), json!([]), json!({})] {
            let mut wrong_type = jwks.clone();
            wrong_type["keys"][0][name] = value;
            assert!(Keys::parse(wrong_type).is_err(), "type of {name}");
        }
    }
    for (name, value) in [
        ("kty", "RSA".to_owned()),
        ("crv", "P-384".to_owned()),
        ("alg", "none".to_owned()),
        ("use", "enc".to_owned()),
        ("kid", String::new()),
        ("kid", "k".repeat(129)),
        ("kid", "clé".to_owned()),
    ] {
        let mut changed = jwks.clone();
        changed["keys"][0][name] = value.into();
        assert!(Keys::parse(changed).is_err(), "metadata {name}");
    }
    for name in ["x", "y"] {
        let original = jwks["keys"][0][name].as_str().unwrap();
        for value in [
            String::new(),
            "!".to_owned(),
            format!("{original}="),
            URL_SAFE_NO_PAD.encode([0; 31]),
            URL_SAFE_NO_PAD.encode([0; 33]),
            URL_SAFE_NO_PAD.encode([0; 3072]),
        ] {
            let mut changed = jwks.clone();
            changed["keys"][0][name] = value.into();
            assert!(Keys::parse(changed).is_err(), "coordinate {name}");
        }
    }
    let key = jwks["keys"][0].clone();
    assert!(Keys::parse(json!({"keys": [key.clone(), key]})).is_err());
    for name in ["d", "unexpected"] {
        let mut changed = jwks.clone();
        changed["keys"][0][name] = json!("rejected synthetic field");
        assert!(Keys::parse(changed).is_err());
    }
}

#[test]
fn jwks_mutations_bounded_json_corpus_does_not_panic_or_accept_invalid_metadata() {
    const CASES: usize = 2048;
    const MAX_BYTES: usize = 4096;
    let (_, jwks) = mutation_fixture();
    let original = serde_json::to_vec(&jwks).unwrap();
    assert!(original.len() <= 1024);
    for end in 0..original.len() {
        assert!(
            serde_json::from_slice::<serde_json::Value>(&original[..end]).is_err(),
            "JWKS cut {end}"
        );
    }
    for index in 0..original.len() {
        for mask in [1, 0x80] {
            let mut changed = original.clone();
            changed[index] ^= mask;
            // Keys::parse accepts an already decoded Value. Invalid UTF-8,
            // syntax and excessive JSON depth stop at that existing boundary.
            if let Ok(value) = serde_json::from_slice(&changed) {
                assert_accepted_jwks_metadata(value);
            }
            if let Ok(value) = serde_json::from_str(&String::from_utf8_lossy(&changed)) {
                assert_accepted_jwks_metadata(value);
            }
        }
    }
    let deep = format!("{}0{}", "[".repeat(129), "]".repeat(129));
    assert!(serde_json::from_str::<serde_json::Value>(&deep).is_err());
    let mut state = 0x6a77_6b73_u32;
    for case in 0..CASES {
        let length = case * 2053 % (MAX_BYTES + 1);
        let bytes: Vec<_> = (0..length)
            .map(|_| next_mutation_byte(&mut state))
            .collect();
        if let Ok(value) = serde_json::from_slice(&bytes) {
            assert_accepted_jwks_metadata(value);
        }
        if let Ok(value) = serde_json::from_str(&String::from_utf8_lossy(&bytes)) {
            assert_accepted_jwks_metadata(value);
        }
        // Another 1,024 cases always reach Keys::parse: arbitrary bounded
        // strings in typed JWK fields, including legal changed metadata.
        if case % 2 == 0 {
            let names = ["kty", "crv", "alg", "use", "kid", "x", "y"];
            let mut changed = jwks.clone();
            let field = names[(case / 2) % names.len()];
            changed["keys"][0][field] = String::from_utf8_lossy(&bytes[..bytes.len().min(128)])
                .into_owned()
                .into();
            assert_accepted_jwks_metadata(changed);
        }
    }
}
