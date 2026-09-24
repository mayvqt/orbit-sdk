//! Private bounded persistence format. Never serialize the public bearer type.

use crate::{Config, Device, Error, Result, StoredCredential, access};
use aws_lc_rs::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};

pub(super) const MAX_PLAINTEXT: usize = 32 * 1024;
pub(super) const MAX_GENERATION: u64 = i64::MAX as u64;
const SDK: &str = "orbit.rust.storage";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    sdk: String,
    format: u32,
    generation: u64,
    issuer: String,
    application_id: String,
    environment_id: String,
    installation_id: String,
    #[serde(deserialize_with = "Option::deserialize")]
    fingerprint: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    fingerprint_provider: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    credential: Option<Credential>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    activation_id: String,
    licence_id: String,
    bearer: String,
    expires_at: i64,
}

pub(super) fn entropy(config: &Config, device: &Device) -> Result<[u8; 32]> {
    if !access::valid_configuration(config, device) {
        return Err(Error::Configuration);
    }
    let mut digest = Context::new(&SHA256);
    digest.update(b"orbit.sdk.storage.v1\0");
    for value in [
        &config.issuer,
        &config.application_id,
        &config.environment_id,
        &device.installation_id,
    ] {
        // Bound caller-supplied scope before private encoding as well as reads.
        if value.len() > MAX_PLAINTEXT {
            return Err(Error::Storage);
        }
        digest.update(&(value.len() as u32).to_be_bytes());
        digest.update(value.as_bytes());
    }
    Ok(digest.finish().as_ref().try_into().expect("SHA-256 length"))
}

pub(super) fn encode(
    config: &Config,
    device: &Device,
    generation: u64,
    credential: Option<&StoredCredential>,
) -> Result<Vec<u8>> {
    entropy(config, device)?;
    if generation > MAX_GENERATION
        || credential.is_some_and(|value| !access::valid_stored_credential(value, config, device))
    {
        return Err(Error::Storage);
    }
    let record = Record {
        sdk: SDK.into(),
        format: 1,
        generation,
        issuer: config.issuer.clone(),
        application_id: config.application_id.clone(),
        environment_id: config.environment_id.clone(),
        installation_id: device.installation_id.clone(),
        fingerprint: device.fingerprint.clone(),
        fingerprint_provider: device.fingerprint_provider.clone(),
        credential: credential.map(|value| Credential {
            activation_id: value.activation_id.clone(),
            licence_id: value.licence_id.clone(),
            bearer: value.credential.clone(),
            expires_at: value.credential_expires_at,
        }),
    };
    let bytes = serde_json::to_vec(&record).map_err(|_| Error::Storage)?;
    if bytes.len() > MAX_PLAINTEXT {
        return Err(Error::Storage);
    }
    Ok(bytes)
}

pub(super) fn decode(
    config: &Config,
    device: &Device,
    bytes: &[u8],
) -> Result<(u64, Option<StoredCredential>)> {
    entropy(config, device)?;
    if bytes.len() > MAX_PLAINTEXT {
        return Err(Error::Storage);
    }
    let record: Record = serde_json::from_slice(bytes).map_err(|_| Error::Storage)?;
    if record.sdk != SDK
        || record.format != 1
        || record.generation > MAX_GENERATION
        || record.issuer != config.issuer
        || record.application_id != config.application_id
        || record.environment_id != config.environment_id
        || record.installation_id != device.installation_id
        || record.fingerprint != device.fingerprint
        || record.fingerprint_provider != device.fingerprint_provider
    {
        return Err(Error::Storage);
    }
    let credential = record.credential.map(|value| StoredCredential {
        application_id: record.application_id,
        environment_id: record.environment_id,
        installation_id: record.installation_id,
        activation_id: value.activation_id,
        licence_id: value.licence_id,
        credential: value.bearer,
        credential_expires_at: value.expires_at,
        fingerprint: record.fingerprint,
        fingerprint_provider: record.fingerprint_provider,
    });
    if credential
        .as_ref()
        .is_some_and(|value| !access::valid_stored_credential(value, config, device))
    {
        return Err(Error::Storage);
    }
    Ok((record.generation, credential))
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use serde_json::{Value, json};

    pub(in crate::storage) fn scope() -> (Config, Device) {
        (
            Config {
                issuer: "https://example.test".into(),
                application_id: "app".into(),
                environment_id: "test".into(),
            },
            Device {
                installation_id: "synthetic_installation".into(),
                fingerprint: Some("a".repeat(64)),
                fingerprint_provider: Some("custom:synthetic".into()),
            },
        )
    }

    pub(in crate::storage) fn credential() -> StoredCredential {
        let (config, device) = scope();
        StoredCredential {
            application_id: config.application_id,
            environment_id: config.environment_id,
            activation_id: "synthetic_activation".into(),
            licence_id: "synthetic_licence".into(),
            installation_id: device.installation_id,
            credential: "s".repeat(43),
            credential_expires_at: 1234,
            fingerprint: device.fingerprint,
            fingerprint_provider: device.fingerprint_provider,
        }
    }

    #[test]
    fn credential_and_tombstone_roundtrip_preserve_generation() {
        let (config, device) = scope();
        let saved = credential();
        let bytes = encode(&config, &device, MAX_GENERATION, Some(&saved)).unwrap();
        let (generation, decoded) = decode(&config, &device, &bytes).unwrap();
        assert_eq!(generation, MAX_GENERATION);
        let decoded = decoded.unwrap();
        assert!(decoded.credential == saved.credential);
        assert!(access::valid_stored_credential(&decoded, &config, &device));
        assert_eq!(decoded.credential_expires_at, saved.credential_expires_at);
        let empty = encode(&config, &device, 9, None).unwrap();
        let (generation, decoded) = decode(&config, &device, &empty).unwrap();
        assert_eq!(generation, 9);
        assert!(decoded.is_none());
        assert!(encode(&config, &device, MAX_GENERATION + 1, None).is_err());
    }

    #[test]
    fn private_codec_rejects_unknown_missing_duplicate_and_malformed_fields() {
        let (config, device) = scope();
        let bytes = encode(&config, &device, 0, Some(&credential())).unwrap();
        let original: Value = serde_json::from_slice(&bytes).unwrap();
        for (field, value) in [
            ("sdk", json!("orbit.other.storage")),
            ("format", json!(2)),
            ("generation", json!(-1)),
            ("generation", json!(MAX_GENERATION + 1)),
            ("generation", json!(1.5)),
            ("generation", json!("1")),
            ("unknown", json!(true)),
            ("credential", json!([])),
        ] {
            let mut invalid = original.clone();
            invalid[field] = value;
            assert!(decode(&config, &device, &serde_json::to_vec(&invalid).unwrap()).is_err());
        }
        for field in original.as_object().unwrap().keys() {
            let mut invalid = original.clone();
            invalid.as_object_mut().unwrap().remove(field);
            assert!(decode(&config, &device, &serde_json::to_vec(&invalid).unwrap()).is_err());
        }
        for (field, value) in [
            ("bearer", json!("s".repeat(42))),
            ("bearer", json!("/".repeat(43))),
            ("activation_id", json!("")),
            ("licence_id", json!("invalid id")),
            ("expires_at", json!(null)),
            ("unknown", json!(true)),
        ] {
            let mut invalid = original.clone();
            invalid["credential"][field] = value;
            assert!(decode(&config, &device, &serde_json::to_vec(&invalid).unwrap()).is_err());
        }
        let mut duplicate = bytes.clone();
        duplicate.pop();
        duplicate.extend_from_slice(b",\"format\":1}");
        for invalid in [
            &duplicate[..],
            &bytes[..bytes.len() - 1],
            &[0xff][..],
            &vec![b' '; MAX_PLAINTEXT + 1][..],
        ] {
            assert!(decode(&config, &device, invalid).is_err());
        }
        let mut appended = bytes;
        appended.extend_from_slice(b"{}");
        assert!(decode(&config, &device, &appended).is_err());
    }

    #[test]
    fn scope_and_fingerprint_mismatches_fail_without_resetting() {
        let (config, device) = scope();
        let bytes = encode(&config, &device, 0, None).unwrap();
        for field in [
            "issuer",
            "application_id",
            "environment_id",
            "installation_id",
            "fingerprint",
            "fingerprint_provider",
        ] {
            let mut invalid: Value = serde_json::from_slice(&bytes).unwrap();
            invalid[field] = json!("different");
            assert!(decode(&config, &device, &serde_json::to_vec(&invalid).unwrap()).is_err());
        }
        let mut invalid = credential();
        invalid.application_id = "different".into();
        assert!(encode(&config, &device, 0, Some(&invalid)).is_err());
        let mut invalid_device = device.clone();
        invalid_device.fingerprint_provider = Some("custom:UPPER".into());
        assert!(entropy(&config, &invalid_device).is_err());
        let mut oversized = config;
        oversized.issuer = "i".repeat(MAX_PLAINTEXT + 1);
        assert!(encode(&oversized, &device, 0, None).is_err());
    }

    #[test]
    fn entropy_uses_exact_domain_and_big_endian_length_framing() {
        let (mut config, mut device) = scope();
        config.issuer = "i".into();
        config.application_id = "ab".into();
        config.environment_id = "c".into();
        device.installation_id = "installation_123".into();
        let expected = aws_lc_rs::digest::digest(
            &SHA256,
            b"orbit.sdk.storage.v1\0\0\0\0\x01i\0\0\0\x02ab\0\0\0\x01c\0\0\0\x10installation_123",
        );
        let first = entropy(&config, &device).unwrap();
        assert_eq!(first.as_slice(), expected.as_ref());
        config.application_id = "a".into();
        config.environment_id = "bc".into();
        assert_ne!(first, entropy(&config, &device).unwrap());
        config.issuer.push('/');
        let changed_issuer = entropy(&config, &device).unwrap();
        device.installation_id.push('4');
        assert_ne!(changed_issuer, entropy(&config, &device).unwrap());
    }
}
