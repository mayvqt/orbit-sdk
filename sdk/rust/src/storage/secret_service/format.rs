//! The Secret Service transport representation of the existing private codec.

use crate::{Config, Device, Error, Result, StoredCredential, storage::codec};
use aws_lc_rs::digest::{Context, SHA256};
use base64::{Engine, engine::general_purpose::STANDARD};

pub(super) const MAX_RECORD: usize = 4096;
pub(super) const MAX_BASE64: usize = 5464;
pub(super) const MAX_STDOUT: usize = MAX_BASE64 + 1;

pub(super) fn scope(config: &Config, device: &Device, directory: &str) -> Result<String> {
    let entropy = codec::entropy(config, device)?;
    let length: u32 = directory.len().try_into().map_err(|_| Error::Storage)?;
    let mut digest = Context::new(&SHA256);
    digest.update(b"orbit.sdk.secret-service.v1\0");
    digest.update(&4_u32.to_be_bytes());
    digest.update(b"rust");
    digest.update(&entropy);
    digest.update(&length.to_be_bytes());
    digest.update(directory.as_bytes());
    Ok(digest
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub(super) fn encode(
    config: &Config,
    device: &Device,
    generation: u64,
    credential: Option<&StoredCredential>,
) -> Result<Vec<u8>> {
    let record = codec::encode(config, device, generation, credential)?;
    if record.len() > MAX_RECORD {
        return Err(Error::Storage);
    }
    Ok(STANDARD.encode(record).into_bytes())
}

pub(super) fn decode(
    config: &Config,
    device: &Device,
    output: &[u8],
) -> Result<(u64, Option<StoredCredential>)> {
    if output.len() > MAX_STDOUT {
        return Err(Error::Storage);
    }
    let encoded = output.strip_suffix(b"\n").unwrap_or(output);
    if encoded.is_empty() || encoded.len() > MAX_BASE64 {
        return Err(Error::Storage);
    }
    let decoded = STANDARD.decode(encoded).map_err(|_| Error::Storage)?;
    if decoded.len() > MAX_RECORD || STANDARD.encode(&decoded).as_bytes() != encoded {
        return Err(Error::Storage);
    }
    codec::decode(config, device, &decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::codec::tests::{credential, scope as config};

    #[test]
    fn private_record_base64_is_canonical_and_accepts_only_one_optional_lf() {
        let (config, device) = config();
        let encoded = encode(&config, &device, 7, Some(&credential())).unwrap();
        let (generation, stored) = decode(&config, &device, &encoded).unwrap();
        assert_eq!(generation, 7);
        assert!(stored.unwrap().credential == credential().credential);
        let mut line = encoded.clone();
        line.push(b'\n');
        assert!(decode(&config, &device, &line).is_ok());
        for ending in [b"\n\n".as_slice(), b"\r\n", b" ", b"\t"] {
            let mut bad = encoded.clone();
            bad.extend_from_slice(ending);
            assert!(decode(&config, &device, &bad).is_err());
        }
        for bad in [
            Vec::new(),
            b"Zg".to_vec(),
            b"Zh==".to_vec(),
            b" Zg==".to_vec(),
            vec![b'A'; MAX_STDOUT + 1],
            STANDARD.encode(vec![0; MAX_RECORD + 1]).into_bytes(),
        ] {
            assert!(decode(&config, &device, &bad).is_err());
        }
        let mut too_large = config.clone();
        too_large.issuer = "x".repeat(MAX_RECORD);
        assert!(encode(&too_large, &device, 0, None).is_err());
    }

    #[test]
    fn item_scope_binds_sdk_entropy_and_length_framed_utf8_directory() {
        let (config, device) = config();
        let directory = "/tmp/private-α";
        let mut input = b"orbit.sdk.secret-service.v1\0\0\0\0\x04rust".to_vec();
        input.extend_from_slice(&codec::entropy(&config, &device).unwrap());
        input.extend_from_slice(&(directory.len() as u32).to_be_bytes());
        input.extend_from_slice(directory.as_bytes());
        let expected: String = aws_lc_rs::digest::digest(&SHA256, &input)
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let original = scope(&config, &device, directory).unwrap();
        assert_eq!(original, expected);
        assert_ne!(original, scope(&config, &device, "/tmp/private-β").unwrap());
        let mut other = config;
        other.issuer.push('/');
        assert_ne!(original, scope(&other, &device, directory).unwrap());
    }

    #[test]
    fn maximum_record_accepts_5464_base64_bytes_and_one_lf() {
        let (mut config, device) = config();
        config.issuer = "x".into();
        let initial = codec::encode(&config, &device, 0, None).unwrap().len();
        config.issuer = "x".repeat(MAX_RECORD - initial + 1);
        assert_eq!(
            codec::encode(&config, &device, 0, None).unwrap().len(),
            MAX_RECORD
        );
        let mut encoded = encode(&config, &device, 0, None).unwrap();
        assert_eq!(encoded.len(), MAX_BASE64);
        assert!(decode(&config, &device, &encoded).unwrap().1.is_none());
        encoded.push(b'\n');
        assert_eq!(encoded.len(), MAX_STDOUT);
        assert!(decode(&config, &device, &encoded).unwrap().1.is_none());
        encoded.push(b'\n');
        assert!(decode(&config, &device, &encoded).is_err());
    }
}
