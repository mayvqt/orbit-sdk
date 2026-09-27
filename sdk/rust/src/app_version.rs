use crate::{Error, Result};
use serde_json::{Map, Value};

const LANGUAGE: &str = "rust";

/// Reports whether `value` is a valid application or SDK version.
pub(crate) fn valid(value: &str) -> bool {
    if value.is_empty() || value.len() > 32 {
        return false;
    }
    let (rest, build) = match value.split_once('+') {
        Some((rest, build)) => (rest, Some(build)),
        None => (value, None),
    };
    let (core, pre) = match rest.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (rest, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() <= 4
        && parts.iter().all(|part| numeric(part))
        && pre.is_none_or(|pre| {
            pre.split('.').all(|part| {
                identifier(part) && (!part.bytes().all(|c| c.is_ascii_digit()) || numeric(part))
            })
        })
        && build.is_none_or(|build| build.split('.').all(identifier))
}

fn numeric(part: &str) -> bool {
    !part.is_empty()
        && part.bytes().all(|c| c.is_ascii_digit())
        && (part == "0" || !part.starts_with('0'))
}

fn identifier(part: &str) -> bool {
    !part.is_empty() && part.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
}

/// Validates an application-supplied version before any request uses it.
pub(crate) fn configured(value: Option<&str>) -> Result<Option<String>> {
    match value {
        Some(value) if !valid(value) => Err(Error::Configuration),
        value => Ok(value.map(str::to_owned)),
    }
}

/// `Orbit-Client` header value, or `None` when a part is outside the grammar.
pub(crate) fn client_header(language: &str, sdk_version: &str, platform: &str) -> Option<String> {
    let language_ok = (1..=16).contains(&language.len())
        && language.as_bytes()[0].is_ascii_lowercase()
        && language
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
    let platform_ok = (1..=32).contains(&platform.len())
        && platform.as_bytes()[0].is_ascii_alphanumeric()
        && platform.bytes().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'.' | b'-')
        });
    let header = format!("{language}/{sdk_version} ({platform})");
    (language_ok && platform_ok && valid(sdk_version) && header.len() <= 128).then_some(header)
}

/// This SDK's `Orbit-Client` header value.
pub(crate) fn this_client() -> String {
    let platform: String = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
        .bytes()
        .map(|c| match c.to_ascii_lowercase() {
            c @ (b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-') => char::from(c),
            _ => '_',
        })
        .take(32)
        .collect();
    client_header(LANGUAGE, env!("CARGO_PKG_VERSION"), &platform)
        .or_else(|| client_header(LANGUAGE, env!("CARGO_PKG_VERSION"), "unknown"))
        .unwrap_or_else(|| format!("{LANGUAGE}/0 (unknown)"))
}

/// Parses the optional `update_available` hint of an activation or validation reply.
pub(crate) fn update_hint(reply: &Map<String, Value>) -> Result<Option<String>> {
    let Some(hint) = reply.get("update_available") else {
        return Ok(None);
    };
    match hint.get("version") {
        Some(Value::String(version)) if hint.is_object() && valid(version) => {
            Ok(Some(version.clone()))
        }
        _ => Err(Error::InvalidResponse),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn vectors() -> Value {
        let path =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contracts/sdk/app-versions.json");
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn app_version_grammar_matches_shared_vectors() {
        for case in vectors()["app_versions"].as_array().unwrap() {
            let value = case["value"].as_str().unwrap();
            assert_eq!(valid(value), case["valid"].as_bool().unwrap(), "{value:?}");
            assert_eq!(configured(Some(value)).is_ok(), valid(value), "{value:?}");
        }
        assert!(matches!(configured(None), Ok(None)));
    }

    #[test]
    fn client_header_matches_shared_vectors() {
        for case in vectors()["client_headers"].as_array().unwrap() {
            let actual = client_header(
                case["language"].as_str().unwrap(),
                case["sdk_version"].as_str().unwrap(),
                case["platform"].as_str().unwrap(),
            );
            assert_eq!(actual.as_deref(), case["header"].as_str(), "{case}");
        }
        let header = this_client();
        let (prefix, platform) = header.split_once(" (").unwrap();
        assert_eq!(
            prefix,
            format!("rust/{}", env!("CARGO_PKG_VERSION")),
            "{header}"
        );
        let platform = platform.strip_suffix(')').unwrap();
        assert_eq!(
            client_header("rust", env!("CARGO_PKG_VERSION"), platform).as_deref(),
            Some(header.as_str())
        );
    }

    #[test]
    fn update_hint_matches_shared_vectors() {
        for case in vectors()["update_available"].as_array().unwrap() {
            let mut reply = Map::new();
            if let Some(value) = case.get("value") {
                reply.insert("update_available".into(), value.clone());
            }
            let parsed = update_hint(&reply);
            if case["valid"].as_bool().unwrap() {
                assert_eq!(parsed.ok().flatten().as_deref(), case["version"].as_str());
            } else {
                assert!(matches!(parsed, Err(Error::InvalidResponse)), "{case}");
            }
        }
    }
}
