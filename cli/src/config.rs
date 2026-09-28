//! Saved credential profiles in a private per-user file.

use crate::app::{Env, Failure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
};

pub const FILE_NAME: &str = "credentials.json";

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Store {
    pub profiles: BTreeMap<String, Profile>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub token: String,
    pub application_id: String,
    pub environment_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_url: Option<String>,
}

impl fmt::Debug for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Profile")
            .field("token", &redact(&self.token))
            .field("application_id", &self.application_id)
            .field("environment_id", &self.environment_id)
            .field("api_url", &self.api_url)
            .finish()
    }
}

/// Management tokens have the exact shape the Orbit service accepts.
pub fn valid_token(value: &str) -> bool {
    value.len() == 52
        && value.starts_with("orb_mgmt_")
        && value[9..]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A display form that never reveals more than the token's last four characters.
pub fn redact(token: &str) -> String {
    if valid_token(token) {
        format!("orb_mgmt_…{}", &token[48..])
    } else {
        "(invalid token)".into()
    }
}

pub fn valid_profile_name(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The per-user directory holding the credential file.
pub fn directory(env: &dyn Env) -> Result<PathBuf, Failure> {
    let absolute = |name: &str| {
        env.var(name)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    if let Some(dir) = absolute("ORBIT_CONFIG_DIR") {
        return Ok(dir);
    }
    let base = if cfg!(windows) {
        absolute("APPDATA")
    } else if cfg!(target_os = "macos") {
        absolute("HOME").map(|home| home.join("Library").join("Application Support"))
    } else {
        absolute("XDG_CONFIG_HOME").or_else(|| absolute("HOME").map(|home| home.join(".config")))
    };
    base.map(|dir| dir.join(if cfg!(windows) { "Orbit" } else { "orbit" }))
        .ok_or_else(|| {
            Failure::Other("cannot find your configuration directory; set ORBIT_CONFIG_DIR".into())
        })
}

pub fn load(dir: &Path) -> Result<Store, Failure> {
    let path = dir.join(FILE_NAME);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Store::default()),
        Err(error) => return Err(io_failure(&path, &error)),
    };
    if !metadata.file_type().is_file() {
        return Err(Failure::Other(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    check_private(&path, &metadata)?;
    let bytes = fs::read(&path).map_err(|error| io_failure(&path, &error))?;
    serde_json::from_slice(&bytes).map_err(|_| {
        Failure::Other(format!(
            "{} is not a valid credentials file",
            path.display()
        ))
    })
}

#[cfg(unix)]
fn check_private(path: &Path, metadata: &fs::Metadata) -> Result<(), Failure> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(Failure::Other(format!(
            "{} is accessible by other users (mode {mode:03o}); run `chmod 600 {}`",
            path.display(),
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(_: &Path, _: &fs::Metadata) -> Result<(), Failure> {
    Ok(())
}

/// Replace the credential file atomically with a new owner-only file.
pub fn save(dir: &Path, store: &Store) -> Result<(), Failure> {
    create_dir(dir)?;
    let path = dir.join(FILE_NAME);
    if store.profiles.is_empty() {
        return match fs::remove_file(&path) {
            Err(error) if error.kind() != ErrorKind::NotFound => Err(io_failure(&path, &error)),
            _ => Ok(()),
        };
    }
    let mut bytes = serde_json::to_vec_pretty(store)
        .map_err(|_| Failure::Other("cannot encode credentials".into()))?;
    bytes.push(b'\n');
    let temporary = dir.join(format!(".{FILE_NAME}.{}.tmp", crate::files::random_hex(8)?));
    let written = write_new(&temporary, &bytes).and_then(|()| fs::rename(&temporary, &path));
    if let Err(error) = written {
        let _ = fs::remove_file(&temporary);
        return Err(io_failure(&path, &error));
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn create_dir(dir: &Path) -> Result<(), Failure> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir).map_err(|error| io_failure(dir, &error))
}

fn io_failure(path: &Path, error: &std::io::Error) -> Failure {
    Failure::Other(format!("{}: {error}", path.display()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const TOKEN: &str = "orb_mgmt_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1234";

    pub fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "orbit-cli-{}",
            crate::files::random_hex(8).unwrap()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn profile() -> Profile {
        Profile {
            token: TOKEN.into(),
            application_id: "app_1".into(),
            environment_id: "env_1".into(),
            api_url: None,
        }
    }

    #[test]
    fn token_shape_matches_service() {
        assert_eq!(TOKEN.len(), 52);
        assert!(valid_token(TOKEN));
        assert!(!valid_token(&TOKEN[..51]));
        assert!(!valid_token(&TOKEN.replace("orb_mgmt_", "orb_mgnt_")));
        assert!(!valid_token(&TOKEN.replace('A', "+")));
    }

    #[test]
    fn redaction_keeps_only_the_suffix() {
        assert_eq!(redact(TOKEN), "orb_mgmt_…1234");
        assert_eq!(redact("orb_mgmt_short"), "(invalid token)");
        let debug = format!("{:?}", profile());
        assert!(!debug.contains(TOKEN));
        assert!(debug.contains("orb_mgmt_…1234"));
    }

    #[test]
    fn save_and_load_round_trip_and_remove_when_empty() {
        let dir = temp_dir().join("nested");
        let mut store = Store::default();
        store.profiles.insert("default".into(), profile());
        save(&dir, &store).unwrap();
        let loaded = load(&dir).unwrap();
        assert_eq!(loaded.profiles["default"].token, TOKEN);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir.join(FILE_NAME)), 0o600);
            assert_eq!(mode(&dir), 0o700);
        }
        assert_eq!(
            fs::read_dir(&dir).unwrap().count(),
            1,
            "no temporary file left"
        );
        save(&dir, &Store::default()).unwrap();
        assert!(!dir.join(FILE_NAME).exists());
        assert!(load(&dir).unwrap().profiles.is_empty());
        fs::remove_dir_all(dir.parent().unwrap()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn refuses_group_or_world_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir();
        let mut store = Store::default();
        store.profiles.insert("default".into(), profile());
        save(&dir, &store).unwrap();
        let path = dir.join(FILE_NAME);
        for mode in [0o640, 0o604] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            let Err(Failure::Other(message)) = load(&dir) else {
                panic!("readable file accepted")
            };
            assert!(message.contains("chmod 600"), "{message}");
            assert!(!message.contains(TOKEN));
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_file() {
        let dir = temp_dir();
        fs::write(dir.join("target"), "{}").unwrap();
        std::os::unix::fs::symlink(dir.join("target"), dir.join(FILE_NAME)).unwrap();
        assert!(load(&dir).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn profile_names_are_plain() {
        assert!(valid_profile_name("live-shop_2"));
        assert!(!valid_profile_name(""));
        assert!(!valid_profile_name("../x"));
    }
}
