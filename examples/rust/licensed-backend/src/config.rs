use serde::Deserialize;
use std::{fs::File, io::Read, path::Path};

/// Server configuration only. Never embed this file in a desktop/web client.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub orbit_origin: String,
    pub application_id: String,
    pub environment_id: String,
    pub management_credential: String,
    pub port: u16,
    #[serde(default)]
    pub local_development: bool,
}

pub fn opaque(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

pub fn load(path: &Path) -> Result<Config, &'static str> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| "Cannot open configuration")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("Configuration must be a private regular file");
    }
    let file = File::open(path).map_err(|_| "Cannot open configuration")?;
    let metadata = file
        .metadata()
        .map_err(|_| "Cannot inspect configuration")?;
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err("Invalid configuration file");
    }
    private_permissions(&metadata)?;
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read configuration")?;
    if bytes.len() > 4096 {
        return Err("Configuration is too large");
    }
    let config: Config = serde_json::from_slice(&bytes).map_err(|_| "Invalid configuration")?;
    if !opaque(&config.application_id)
        || !opaque(&config.environment_id)
        || config.management_credential.len() != 52
        || !config.management_credential.starts_with("orb_mgmt_")
        || !opaque(&config.management_credential[9..])
    {
        return Err("Invalid scope or management credential");
    }
    Ok(config)
}

#[cfg(unix)]
fn private_permissions(metadata: &std::fs::Metadata) -> Result<(), &'static str> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err("Configuration permissions must exclude group and other access");
    }
    Ok(())
}

#[cfg(not(unix))]
fn private_permissions(_: &std::fs::Metadata) -> Result<(), &'static str> {
    Err("This server example requires Unix private-file permissions")
}
