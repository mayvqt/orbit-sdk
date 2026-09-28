//! Local helpers: randomness, file digests and argument parsing.

use crate::app::Failure;
use aws_lc_rs::{digest, rand::SecureRandom};
use std::{fs::File, io::Read, path::Path};

pub fn random_hex(bytes: usize) -> Result<String, Failure> {
    let mut buffer = vec![0_u8; bytes];
    aws_lc_rs::rand::SystemRandom::new()
        .fill(&mut buffer)
        .map_err(|_| Failure::Other("system randomness is unavailable".into()))?;
    Ok(hex(&buffer))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A fresh idempotency key for one invocation.
pub fn idempotency_key() -> Result<String, Failure> {
    Ok(format!("orbit-cli-{}", random_hex(16)?))
}

/// The service accepts 16 to 128 printable ASCII characters.
pub fn valid_idempotency_key(value: &str) -> bool {
    (16..=128).contains(&value.len()) && value.bytes().all(|b| (b'!'..=b'~').contains(&b))
}

pub struct Digest {
    pub byte_length: u64,
    pub sha256: String,
}

/// Exact length and lowercase SHA-256 of a file, read in bounded chunks.
pub fn digest_file(path: &Path) -> Result<Digest, Failure> {
    let failure = |error: std::io::Error| Failure::Other(format!("{}: {error}", path.display()));
    let mut file = File::open(path).map_err(failure)?;
    if !file.metadata().map_err(failure)?.is_file() {
        return Err(Failure::Usage(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    let mut context = digest::Context::new(&digest::SHA256);
    let mut buffer = vec![0_u8; 1 << 16];
    let mut byte_length = 0_u64;
    loop {
        let read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(failure(error)),
        };
        context.update(&buffer[..read]);
        byte_length += read as u64;
    }
    if byte_length == 0 {
        return Err(Failure::Usage(format!("{} is empty", path.display())));
    }
    Ok(Digest {
        byte_length,
        sha256: hex(context.finish().as_ref()),
    })
}

/// Parse `30d`, `12h`, `90m`, `3600s` or a bare number of seconds.
pub fn duration_seconds(value: &str) -> Result<i64, Failure> {
    let invalid = || Failure::Usage(format!("invalid duration `{value}`; use for example 30d"));
    let (digits, unit) = match value.char_indices().last() {
        Some((index, c)) if c.is_ascii_alphabetic() => (&value[..index], c),
        _ => (value, 's'),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    let multiplier = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3_600,
        'd' => 86_400,
        _ => return Err(invalid()),
    };
    digits
        .parse::<i64>()
        .ok()
        .and_then(|n| n.checked_mul(multiplier))
        .filter(|n| *n > 0)
        .ok_or_else(invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_matches_known_values_across_chunks() {
        let dir = crate::config::tests::temp_dir();
        let small = dir.join("abc");
        std::fs::write(&small, b"abc").unwrap();
        let d = digest_file(&small).unwrap();
        assert_eq!(d.byte_length, 3);
        assert_eq!(
            d.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let large = dir.join("large");
        std::fs::write(&large, vec![b'a'; 1_000_000]).unwrap();
        let d = digest_file(&large).unwrap();
        assert_eq!(d.byte_length, 1_000_000);
        assert_eq!(
            d.sha256,
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
        let empty = dir.join("empty");
        std::fs::write(&empty, b"").unwrap();
        assert!(matches!(digest_file(&empty), Err(Failure::Usage(_))));
        assert!(matches!(
            digest_file(&dir),
            Err(Failure::Usage(_) | Failure::Other(_))
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn durations() {
        assert_eq!(duration_seconds("30d").unwrap(), 2_592_000);
        assert_eq!(duration_seconds("12h").unwrap(), 43_200);
        assert_eq!(duration_seconds("90m").unwrap(), 5_400);
        assert_eq!(duration_seconds("3600s").unwrap(), 3_600);
        assert_eq!(duration_seconds("60").unwrap(), 60);
        for bad in ["", "d", "0d", "-1d", "1w", "1.5d", "99999999999999999999d"] {
            assert!(duration_seconds(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn idempotency_keys() {
        let key = idempotency_key().unwrap();
        assert!(valid_idempotency_key(&key));
        assert_ne!(key, idempotency_key().unwrap());
        assert!(!valid_idempotency_key("short"));
        assert!(!valid_idempotency_key("has a space in the key"));
    }
}
