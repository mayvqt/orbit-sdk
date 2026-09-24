use crate::{Error, Result, access::opaque};
use aws_lc_rs::digest::{self, SHA256};

/// Derive the application-scoped `machine_v1` digest without exporting the OS ID.
pub fn machine_fingerprint(
    application_id: &str,
    environment_id: &str,
    os_family: &str,
    machine_id: &str,
) -> Result<String> {
    check_scope(application_id, environment_id)?;
    if !matches!(os_family, "linux" | "windows") {
        return Err(Error::Configuration);
    }
    let normalized = machine_id
        .trim_matches([' ', '\t', '\n', '\r', '\u{b}', '\u{c}'])
        .replace('-', "")
        .to_ascii_lowercase();
    if normalized.len() != 32
        || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit())
        || normalized.bytes().all(|byte| byte == b'0')
        || normalized.bytes().all(|byte| byte == b'f')
    {
        return Err(unavailable());
    }
    let input =
        format!("orbit-machine-v1\n{application_id}\n{environment_id}\n{os_family}\n{normalized}");
    Ok(digest::digest(&SHA256, input.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Read the native machine identity and return only its scoped `machine_v1` digest.
/// Unavailable identity fails closed; no random fallback or subprocess is used.
pub fn native_fingerprint(application_id: &str, environment_id: &str) -> Result<String> {
    check_scope(application_id, environment_id)?;
    #[cfg(target_os = "linux")]
    {
        let source = std::fs::File::open("/etc/machine-id").map_err(|_| unavailable())?;
        let identity = read_machine_id(source)?;
        machine_fingerprint(application_id, environment_id, "linux", &identity)
    }
    #[cfg(target_os = "windows")]
    {
        let identity = orbit_sdk_native::machine_uuid().ok_or_else(unavailable)?;
        machine_fingerprint(application_id, environment_id, "windows", &identity)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Err(unavailable())
    }
}

fn check_scope(application_id: &str, environment_id: &str) -> Result<()> {
    if opaque(application_id) && opaque(environment_id) {
        Ok(())
    } else {
        Err(Error::Configuration)
    }
}

fn unavailable() -> Error {
    Error::Denied {
        code: "device_identity_unavailable".into(),
        request_id: None,
    }
}

#[cfg(target_os = "linux")]
fn read_machine_id(source: impl std::io::Read) -> Result<String> {
    use std::io::Read;

    let mut bytes = Vec::new();
    source
        .take(257)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable())?;
    if bytes.len() > 256 {
        return Err(unavailable());
    }
    String::from_utf8(bytes).map_err(|_| unavailable())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires an independently calculated ORBIT_NATIVE_FINGERPRINT_EXPECTED on the native host"]
    fn native_fingerprint_matches_os_identity() {
        let expected = std::env::var("ORBIT_NATIVE_FINGERPRINT_EXPECTED")
            .unwrap_or_else(|_| panic!("ORBIT_NATIVE_FINGERPRINT_EXPECTED is required"));
        let valid_digest = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        assert!(
            valid_digest(&expected),
            "ORBIT_NATIVE_FINGERPRINT_EXPECTED must contain 64 lowercase hex characters"
        );
        let first = native_fingerprint("native_test_app", "native_test_env")
            .expect("native machine identity must be available");
        let repeated = native_fingerprint("native_test_app", "native_test_env")
            .expect("native machine identity must remain available");
        assert!(
            first == expected,
            "native fingerprint differs from OS identity"
        );
        assert!(repeated == first, "native fingerprint is unstable");
        for (application, environment) in [
            ("native_other_app", "native_test_env"),
            ("native_test_app", "native_other_env"),
        ] {
            let scoped = native_fingerprint(application, environment)
                .expect("native machine identity must be available for another scope");
            assert!(
                valid_digest(&scoped),
                "native fingerprint has invalid encoding"
            );
            assert!(
                scoped != expected,
                "native fingerprint did not isolate its scope"
            );
        }
    }

    #[test]
    fn machine_fingerprint_matches_shared_golden_framing() {
        // Literal preimages match Go/C# and fix separators and the absent final newline.
        for (application, environment, family, identity, preimage) in [
            (
                "app",
                "test",
                "linux",
                "00112233445566778899aabbccddeeff",
                "orbit-machine-v1\napp\ntest\nlinux\n00112233445566778899aabbccddeeff",
            ),
            (
                "app",
                "test",
                "linux",
                " \t\r\n00112233-4455-6677-8899-AABBCCDDEEFF\u{b}\u{c} ",
                "orbit-machine-v1\napp\ntest\nlinux\n00112233445566778899aabbccddeeff",
            ),
            (
                "app",
                "test",
                "windows",
                "00112233-4455-6677-8899-AABBCCDDEEFF",
                "orbit-machine-v1\napp\ntest\nwindows\n00112233445566778899aabbccddeeff",
            ),
            (
                "other_app",
                "live",
                "linux",
                "0123456789ABCDEF0123456789ABCDEF",
                "orbit-machine-v1\nother_app\nlive\nlinux\n0123456789abcdef0123456789abcdef",
            ),
        ] {
            let expected: String = digest::digest(&SHA256, preimage.as_bytes())
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            assert_eq!(
                machine_fingerprint(application, environment, family, identity).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn machine_fingerprint_rejects_unavailable_identity() {
        for identity in [
            "",
            "00000000000000000000000000000000",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "00112233445566778899aabbccddeef",
            "00112233445566778899aabbccddeeff00",
            "00112233445566778899aabbccddeefg",
            "00112233 445566778899aabbccddeeff",
            "\u{a0}00112233445566778899aabbccddeeff",
        ] {
            assert!(
                matches!(machine_fingerprint("app", "test", "linux", identity),
                Err(Error::Denied { code, .. }) if code == "device_identity_unavailable")
            );
        }
    }

    #[test]
    fn machine_fingerprint_rejects_invalid_scope_before_native_access() {
        for (application, environment, family) in [
            ("app\nother", "test", "linux"),
            ("app", "test/live", "linux"),
            ("", "test", "linux"),
            ("app", "", "linux"),
            ("äpp", "test", "linux"),
            ("app", "test", "Linux"),
            ("app", "test", "macos"),
        ] {
            assert!(matches!(
                machine_fingerprint(
                    application,
                    environment,
                    family,
                    "00112233445566778899aabbccddeeff"
                ),
                Err(Error::Configuration)
            ));
        }
        let too_long = "a".repeat(129);
        for (application, environment) in [
            ("app\nother", "test"),
            ("app", "test/live"),
            (too_long.as_str(), "test"),
            ("app", too_long.as_str()),
        ] {
            assert!(matches!(
                native_fingerprint(application, environment),
                Err(Error::Configuration)
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_identity_read_is_bounded_and_rejects_read_or_encoding_errors() {
        let identity = "00112233445566778899aabbccddeeff";
        let padded = format!("{identity}{}", " ".repeat(224));
        assert_eq!(read_machine_id(padded.as_bytes()).unwrap(), padded);
        for bytes in [format!("{padded} ").into_bytes(), vec![0xff]] {
            assert!(matches!(read_machine_id(bytes.as_slice()),
                Err(Error::Denied { code, .. }) if code == "device_identity_unavailable"));
        }
        struct FailedRead;
        impl std::io::Read for FailedRead {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("synthetic read failure"))
            }
        }
        assert!(matches!(read_machine_id(FailedRead),
            Err(Error::Denied { code, .. }) if code == "device_identity_unavailable"));
    }
}
