//! Seller-hosted update metadata and verified, atomic direct downloads.
use crate::{
    Client, Error, Result, access,
    limits::{self, MAX_INTEGER, date, exact, integer, text},
};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryMode {
    Public,
    Protected,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Artifact {
    pub id: String,
    pub release_id: String,
    pub platform: String,
    pub architecture: String,
    pub filename: String,
    pub byte_length: u64,
    pub sha256: String,
    pub delivery_mode: DeliveryMode,
    pub url: String,
    pub required_feature: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub id: String,
    pub channel: String,
    pub version: String,
    pub notes: String,
    pub release_number: u64,
    pub created_at: SystemTime,
    pub published_at: SystemTime,
    pub artifacts: Vec<Artifact>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update {
    pub release: Release,
    pub artifact: Artifact,
}
#[derive(Clone, Debug, Default)]
pub struct UpdateOptions {
    pub channel: Option<String>,
    pub platform: Option<String>,
    pub architecture: Option<String>,
}
/// A short-lived capability held only in memory; never persist or log it.
#[derive(Clone)]
pub struct DownloadAuthorization {
    artifact: Artifact,
    ticket: Option<String>,
    expires_at: Option<SystemTime>,
    cancel: crate::Cancellation,
}
impl std::fmt::Debug for DownloadAuthorization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[Orbit download authorization redacted]")
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub struct DownloadOptions {
    pub replace_existing: bool,
}
fn target(value: &str) -> bool {
    (1..=32).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}
fn options(options: UpdateOptions) -> Result<(String, String, String)> {
    let channel = options.channel.unwrap_or_else(|| "stable".into());
    let platform = match options.platform {
        Some(v) => v,
        None => match std::env::consts::OS {
            "linux" => "linux",
            "windows" => "windows",
            "macos" => "macos",
            _ => return Err(Error::Configuration),
        }
        .into(),
    };
    let architecture = match options.architecture {
        Some(v) => v,
        None => match std::env::consts::ARCH {
            "x86_64" => "x64",
            "aarch64" => "arm64",
            "x86" => "x86",
            _ => return Err(Error::Configuration),
        }
        .into(),
    };
    if !target(&channel) || !target(&platform) || !target(&architecture) {
        return Err(Error::Configuration);
    }
    Ok((channel, platform, architecture))
}
fn delivery_url(value: &str, protected: bool) -> bool {
    if protected {
        return crate::downloads::valid_endpoint(value);
    }
    if value.len() > 2048
        || !value.starts_with("https://")
        || value
            .bytes()
            .any(|b| b <= 32 || b >= 127 || b == b'\\' || b == b'#')
    {
        return false;
    }
    crate::downloads::valid_endpoint(value.split('?').next().unwrap_or(""))
        && reqwest::Url::parse(value).is_ok_and(|url| {
            url.username().is_empty() && url.password().is_none() && url.fragment().is_none()
        })
}
fn artifact(value: &Value) -> Result<Artifact> {
    exact(
        value,
        &[
            "id",
            "release_id",
            "platform",
            "architecture",
            "filename",
            "byte_length",
            "sha256",
            "delivery_mode",
            "url",
            "required_feature",
        ],
    )?;
    let id = text(value, "id")?;
    let release_id = text(value, "release_id")?;
    let platform = text(value, "platform")?;
    let architecture = text(value, "architecture")?;
    let filename = text(value, "filename")?;
    let sha256 = text(value, "sha256")?;
    let length = integer(value, "byte_length")?;
    let mode = match text(value, "delivery_mode")? {
        "public" => DeliveryMode::Public,
        "protected" => DeliveryMode::Protected,
        _ => return Err(Error::InvalidResponse),
    };
    let url = text(value, "url")?;
    let feature = match &value["required_feature"] {
        Value::Null => None,
        Value::String(v) if limits::name(v) => Some(v.clone()),
        _ => return Err(Error::InvalidResponse),
    };
    if !access::opaque(id)
        || !access::opaque(release_id)
        || !target(platform)
        || !target(architecture)
        || filename.is_empty()
        || filename.len() > 255
        || matches!(filename, "." | "..")
        || filename.contains(['/', '\\'])
        || filename.chars().any(char::is_control)
        || length == 0
        || sha256.len() != 64
        || !sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !delivery_url(url, mode == DeliveryMode::Protected)
    {
        return Err(Error::InvalidResponse);
    }
    Ok(Artifact {
        id: id.into(),
        release_id: release_id.into(),
        platform: platform.into(),
        architecture: architecture.into(),
        filename: filename.into(),
        byte_length: length,
        sha256: sha256.into(),
        delivery_mode: mode,
        url: url.into(),
        required_feature: feature,
    })
}
impl Client {
    /// Default channel stable; exact current desktop target with no fallback.
    pub async fn check_for_updates(&self, installed_release_number: u64) -> Result<Option<Update>> {
        self.check_for_updates_with(installed_release_number, UpdateOptions::default())
            .await
    }
    pub async fn check_for_updates_with(
        &self,
        installed: u64,
        options_: UpdateOptions,
    ) -> Result<Option<Update>> {
        if installed > MAX_INTEGER {
            return Err(Error::Configuration);
        }
        let (channel, platform, architecture) = options(options_)?;
        let value=self.online_service("/updates",json!({"channel":channel,"platform":platform,"architecture":architecture,"installed_release_number":installed})).await?;
        exact(&value, &["release", "artifact"])?;
        if value["release"].is_null() && value["artifact"].is_null() {
            return Ok(None);
        }
        let artifact = artifact(&value["artifact"])?;
        let release = &value["release"];
        exact(
            release,
            &[
                "id",
                "channel",
                "version",
                "notes",
                "release_number",
                "state",
                "created_at",
                "published_at",
                "artifacts",
            ],
        )?;
        let id = text(release, "id")?;
        let version = text(release, "version")?;
        let notes = text(release, "notes")?;
        let number = integer(release, "release_number")?;
        let artifacts = release["artifacts"]
            .as_array()
            .ok_or(Error::InvalidResponse)?;
        if id != artifact.release_id
            || text(release, "channel")? != channel
            || text(release, "state")? != "published"
            || version.is_empty()
            || version.len() > 64
            || notes.len() > 8192
            || number <= installed
            || artifact.platform != platform
            || artifact.architecture != architecture
            || artifacts.len() != 1
            || self::artifact(&artifacts[0])? != artifact
        {
            return Err(Error::InvalidResponse);
        }
        let release = Release {
            id: id.into(),
            channel,
            version: version.into(),
            notes: notes.into(),
            release_number: number,
            created_at: date(release, "created_at")?,
            published_at: date(release, "published_at")?,
            artifacts: vec![artifact.clone()],
        };
        Ok(Some(Update { release, artifact }))
    }
    pub async fn authorize_download(
        &self,
        release_id: &str,
        artifact_id: &str,
    ) -> Result<DownloadAuthorization> {
        if !access::opaque(release_id) || !access::opaque(artifact_id) {
            return Err(Error::Configuration);
        }
        let value = self
            .online_service(
                "/downloads/authorize",
                json!({"release_id":release_id,"artifact_id":artifact_id}),
            )
            .await?;
        exact(&value, &["artifact", "ticket", "expires_at"])?;
        let artifact = artifact(&value["artifact"])?;
        if artifact.id != artifact_id || artifact.release_id != release_id {
            return Err(Error::InvalidResponse);
        }
        let (ticket, expires_at) = match artifact.delivery_mode {
            DeliveryMode::Public => {
                if !value["ticket"].is_null() || !value["expires_at"].is_null() {
                    return Err(Error::InvalidResponse);
                }
                (None, None)
            }
            DeliveryMode::Protected => {
                let ticket = text(&value, "ticket")?;
                if ticket.is_empty()
                    || ticket.len() > 16 * 1024
                    || ticket.bytes().any(|b| b <= 32 || b >= 127)
                {
                    return Err(Error::InvalidResponse);
                }
                (Some(ticket.into()), Some(date(&value, "expires_at")?))
            }
        };
        Ok(DownloadAuthorization {
            artifact,
            ticket,
            expires_at,
            cancel: self.0.transport.owner_cancel.clone(),
        })
    }
}
struct StagedFile {
    file: Option<File>,
    path: PathBuf,
}
impl Drop for StagedFile {
    fn drop(&mut self) {
        self.file.take();
        let _ = fs::remove_file(&self.path);
    }
}
impl StagedFile {
    fn new(destination: &Path) -> Result<Self> {
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let id = crate::Device::new_installation()?.installation_id;
        let path = parent.join(format!(".orbit-download-{id}"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path).map_err(|_| Error::Storage)?;
        Ok(Self {
            file: Some(file),
            path,
        })
    }
}
impl DownloadAuthorization {
    pub fn artifact(&self) -> &Artifact {
        &self.artifact
    }
    pub fn expires_at(&self) -> Option<SystemTime> {
        self.expires_at
    }
    /// Verify exact bytes into an atomic destination. Dropping the future aborts
    /// the transfer and removes its temporary file. Never executes an installer.
    pub async fn download(&self, destination: impl AsRef<Path>, max_size: u64) -> Result<()> {
        self.download_with(destination, max_size, DownloadOptions::default())
            .await
    }
    pub async fn download_with(
        &self,
        destination: impl AsRef<Path>,
        max_size: u64,
        options: DownloadOptions,
    ) -> Result<()> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(1800))
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
            .build()
            .map_err(|_| Error::Configuration)?;
        tokio::select! {result=self.download_using(destination.as_ref(),max_size,options,&client)=>result,_=self.cancel.cancelled()=>Err(Error::Cancelled)}
    }
    async fn download_using(
        &self,
        destination: &Path,
        max_size: u64,
        options: DownloadOptions,
        client: &reqwest::Client,
    ) -> Result<()> {
        if max_size == 0
            || max_size > MAX_INTEGER
            || self.artifact.byte_length > max_size
            || destination.as_os_str().is_empty()
        {
            return Err(Error::Configuration);
        }
        if self
            .expires_at
            .is_some_and(|time| time <= SystemTime::now())
        {
            return Err(Error::Denied {
                code: "download_authorization_expired".into(),
                request_id: None,
            });
        }
        if !options.replace_existing {
            match fs::symlink_metadata(destination) {
                Ok(_) => return Err(Error::Configuration),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(Error::Storage),
            }
        }
        let mut stage = StagedFile::new(destination)?;
        let mut current = self.artifact.url.clone();
        let mut response = None;
        for redirects in 0..=5 {
            if !delivery_url(&current, false) {
                return Err(Error::TransportSecurity);
            }
            let mut request = client
                .get(&current)
                .header(reqwest::header::ACCEPT_ENCODING, "identity");
            if redirects == 0
                && let Some(ticket) = &self.ticket
            {
                request = request.bearer_auth(ticket);
            }
            let result = request.send().await.map_err(|_| Error::TransportSecurity)?;
            if matches!(result.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
                if redirects == 5 {
                    return Err(Error::InvalidResponse);
                }
                let location = result
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .ok_or(Error::InvalidResponse)?
                    .to_str()
                    .map_err(|_| Error::InvalidResponse)?;
                // Reject raw userinfo/whitespace before URL normalization.
                if location.bytes().any(|b| b <= 32 || b >= 127 || b == b'\\')
                    || location.contains('#')
                {
                    return Err(Error::TransportSecurity);
                }
                if location.starts_with("//") && !delivery_url(&format!("https:{location}"), false)
                {
                    return Err(Error::TransportSecurity);
                }
                if location.starts_with("https://") && !delivery_url(location, false) {
                    return Err(Error::TransportSecurity);
                }
                current = result
                    .url()
                    .join(location)
                    .map_err(|_| Error::InvalidResponse)?
                    .to_string();
                continue;
            }
            response = Some(result);
            break;
        }
        let mut response = response.ok_or(Error::InvalidResponse)?;
        if response.status().as_u16() != 200
            || response
                .content_length()
                .is_some_and(|size| size != self.artifact.byte_length || size > max_size)
            || response
                .headers()
                .get(reqwest::header::CONTENT_ENCODING)
                .is_some_and(|v| v.as_bytes() != b"identity")
        {
            return Err(Error::InvalidResponse);
        }
        let mut hash = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
        let mut size = 0u64;
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::InvalidResponse)? {
            size = size
                .checked_add(chunk.len() as u64)
                .ok_or(Error::InvalidResponse)?;
            if size > max_size || size > self.artifact.byte_length {
                return Err(Error::InvalidResponse);
            }
            hash.update(&chunk);
            stage
                .file
                .as_mut()
                .ok_or(Error::Storage)?
                .write_all(&chunk)
                .map_err(|_| Error::Storage)?;
        }
        let digest = hash.finish();
        let actual: String = digest
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        if size != self.artifact.byte_length || actual != self.artifact.sha256 {
            return Err(Error::InvalidResponse);
        }
        stage
            .file
            .as_ref()
            .ok_or(Error::Storage)?
            .sync_all()
            .map_err(|_| Error::Storage)?;
        stage.file.take();
        if self.cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if options.replace_existing {
            fs::rename(&stage.path, destination)
        } else {
            fs::hard_link(&stage.path, destination)
        }
        .map_err(|_| Error::Storage)?;
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader},
        process::{Child, Command, Stdio},
    };
    struct Fixture {
        child: Child,
        url: String,
        directory: PathBuf,
        client: reqwest::Client,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
    impl Fixture {
        fn new() -> Self {
            let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
            let mut child = Command::new("python3")
                .arg(base.join("download_server.py"))
                .arg(base.join("download-test-cert.pem"))
                .arg(base.join("download-test-key.pem"))
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut line = String::new();
            BufReader::new(child.stdout.take().unwrap())
                .read_line(&mut line)
                .unwrap();
            let port: u16 = line.trim().parse().unwrap();
            let cert = reqwest::Certificate::from_pem(
                &fs::read(base.join("download-test-cert.pem")).unwrap(),
            )
            .unwrap();
            let client = reqwest::Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .add_root_certificate(cert)
                .build()
                .unwrap();
            let directory = std::env::temp_dir().join(format!(
                "orbit-download-{}",
                crate::Device::new_installation().unwrap().installation_id
            ));
            fs::create_dir(&directory).unwrap();
            Self {
                child,
                url: format!("https://127.0.0.1:{port}"),
                directory,
                client,
            }
        }
        fn authorization(&self, path: &str, protected: bool) -> DownloadAuthorization {
            let digest =
                aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b"verified seller bytes");
            DownloadAuthorization {
                artifact: Artifact {
                    id: "artifact".into(),
                    release_id: "release".into(),
                    platform: "linux".into(),
                    architecture: "x64".into(),
                    filename: "update.bin".into(),
                    byte_length: 21,
                    sha256: digest.as_ref().iter().map(|b| format!("{b:02x}")).collect(),
                    delivery_mode: if protected {
                        DeliveryMode::Protected
                    } else {
                        DeliveryMode::Public
                    },
                    url: format!("{}{path}", self.url),
                    required_feature: None,
                },
                ticket: protected.then(|| "synthetic.ticket.proof".into()),
                expires_at: protected.then(|| SystemTime::now() + Duration::from_secs(60)),
                cancel: crate::Cancellation::new(),
            }
        }
    }
    #[tokio::test]
    async fn tls_stream_redirects_are_credential_free_and_failures_are_atomic() {
        let fixture = Fixture::new();
        let destination = fixture.directory.join("artifact");
        let auth = fixture.authorization("/start", true);
        auth.download_using(
            &destination,
            100,
            DownloadOptions::default(),
            &fixture.client,
        )
        .await
        .unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"verified seller bytes");
        assert!(
            auth.download_using(
                &destination,
                100,
                DownloadOptions::default(),
                &fixture.client
            )
            .await
            .is_err()
        );
        for path in [
            "/wrong",
            "/short",
            "/oversize",
            "/encoded",
            "/loop",
            "/http",
        ] {
            let bad = fixture.authorization(path, false);
            assert!(
                bad.download_using(
                    &destination,
                    100,
                    DownloadOptions {
                        replace_existing: true
                    },
                    &fixture.client
                )
                .await
                .is_err(),
                "{path}"
            );
            assert_eq!(fs::read(&destination).unwrap(), b"verified seller bytes");
            assert_eq!(fs::read_dir(&fixture.directory).unwrap().count(), 1);
        }
        assert!(
            auth.download(fixture.directory.join("untrusted"), 100)
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn dropping_download_future_removes_partial_file() {
        let fixture = Fixture::new();
        let destination = fixture.directory.join("artifact");
        let auth = fixture.authorization("/blocked", false);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(300),
                auth.download_using(
                    &destination,
                    100,
                    DownloadOptions::default(),
                    &fixture.client
                )
            )
            .await
            .is_err()
        );
        assert_eq!(fs::read_dir(&fixture.directory).unwrap().count(), 0);
    }
}

#[cfg(all(test, feature = "local-development"))]
mod service_tests {
    use super::*;
    #[tokio::test]
    async fn discovery_rejects_other_targets_and_authorization_is_separate() {
        for wrong_target in [false, true] {
            let mut fixture = crate::transport::tests::Fixture::new().await;
            let client = crate::limits::tests::client(fixture.transport.clone());
            let checking = client.clone();
            let task = tokio::spawn(async move {
                checking
                    .check_for_updates_with(
                        1,
                        UpdateOptions {
                            platform: Some("linux".into()),
                            architecture: Some("x64".into()),
                            ..UpdateOptions::default()
                        },
                    )
                    .await
            });
            let request = fixture.next().await;
            let input: Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(input["channel"], "stable");
            assert_eq!(input["platform"], "linux");
            assert_eq!(input["architecture"], "x64");
            assert_eq!(input["credential"], "a".repeat(43));
            let artifact = json!({"id":"artifact","release_id":"release","platform":"linux","architecture":if wrong_target {"arm64"}else{"x64"},"filename":"update.bin","byte_length":1,"sha256":"0".repeat(64),"delivery_mode":"public","url":"https://seller.example.test/file","required_feature":null});
            let release = json!({"id":"release","channel":"stable","version":"1.2","notes":"notes","release_number":2,"state":"published","created_at":"2026-09-27T00:00:00Z","published_at":"2026-09-27T00:00:00Z","artifacts":[artifact.clone()]});
            request.respond(
                200,
                &json!({"release":release,"artifact":artifact}).to_string(),
            );
            if wrong_target {
                assert!(matches!(task.await.unwrap(), Err(Error::InvalidResponse)));
                continue;
            }
            let update = task.await.unwrap().unwrap().unwrap();
            assert_eq!(update.release.version, "1.2");
            let task =
                tokio::spawn(async move { client.authorize_download("release", "artifact").await });
            fixture.next().await.respond(
                200,
                &json!({"artifact":artifact,"ticket":null,"expires_at":null}).to_string(),
            );
            let authorization = task.await.unwrap().unwrap();
            assert_eq!(authorization.artifact().id, "artifact");
            assert!(authorization.expires_at().is_none());
            fixture.assert_idle();
        }
    }
}
