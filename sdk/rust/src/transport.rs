use crate::{Error, Result};
use reqwest::{Client, Method, Url, header};
use serde::Deserialize;
use serde_json::Value;
use std::{
    error::Error as _,
    io::{self, Write},
    time::Duration,
};
use tokio::{sync::watch, time::Instant};

const MAX_BYTES: usize = 64 * 1024;
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const CLIENT_PREFIX: &str = "/api/client/v1/";
const JWKS_PATH: &str = "/.well-known/orbit-jwks.json";

#[derive(Clone)]
pub struct Cancellation {
    state: watch::Sender<bool>,
}

impl Cancellation {
    pub fn new() -> Self {
        let (state, _) = watch::channel(false);
        Self { state }
    }

    pub fn cancel(&self) {
        self.state.send_replace(true);
    }

    pub fn is_cancelled(&self) -> bool {
        *self.state.borrow()
    }

    pub async fn cancelled(&self) {
        let mut receiver = self.state.subscribe();
        loop {
            if *receiver.borrow_and_update() {
                return;
            }
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }
}

impl Default for Cancellation {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct Transport {
    client: Client,
    base: Url,
}

impl Transport {
    pub fn new(base: &str) -> Result<Self> {
        let base = origin(base, "https")?;
        let client = client_builder()
            .https_only(true)
            .build()
            .map_err(|_| Error::Configuration)?;
        Ok(Self { client, base })
    }

    #[cfg(feature = "local-development")]
    pub fn local_loopback(base: &str) -> Result<Self> {
        let parsed = origin(base, "http")?;
        let authority = origin_authority(base)?;
        let host = if let Some(ipv6) = authority.strip_prefix('[') {
            ipv6.split_once(']')
                .map(|(host, _)| host)
                .ok_or(Error::Configuration)?
        } else {
            authority
                .split_once(':')
                .map_or(authority, |(host, _)| host)
        };
        // Parse the supplied literal, not a DNS name or a URL-normalized numeric
        // hostname. This also excludes shorthand and integer IPv4 spellings.
        if !host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
        {
            return Err(Error::Configuration);
        }
        let client = client_builder()
            .no_proxy()
            .build()
            .map_err(|_| Error::Configuration)?;
        Ok(Self {
            client,
            base: parsed,
        })
    }

    pub async fn get(&self, path: &str, cancel: &Cancellation) -> Result<Option<Value>> {
        self.request(Method::GET, path, None, None, true, cancel)
            .await
    }

    pub async fn get_bearer(
        &self,
        path: &str,
        bearer: &str,
        cancel: &Cancellation,
    ) -> Result<Option<Value>> {
        if !matches!(
            path.split('?').next(),
            Some("/api/client/v1/licences" | "/api/client/v1/sessions/current")
        ) {
            return Err(Error::Configuration);
        }
        self.request(Method::GET, path, None, Some(bearer), true, cancel)
            .await
    }

    pub async fn delete_bearer(
        &self,
        path: &str,
        bearer: &str,
        cancel: &Cancellation,
    ) -> Result<Option<Value>> {
        if path.split('?').next() != Some("/api/client/v1/sessions/current") {
            return Err(Error::Configuration);
        }
        self.request(Method::DELETE, path, None, Some(bearer), false, cancel)
            .await
    }

    pub async fn post(
        &self,
        path: &str,
        body: &Value,
        retry_safe: bool,
        cancel: &Cancellation,
    ) -> Result<Option<Value>> {
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        let mut encoded = LimitedBody(Vec::new());
        serde_json::to_writer(&mut encoded, body).map_err(|_| Error::Configuration)?;
        self.request(
            Method::POST,
            path,
            Some(encoded.0),
            None,
            retry_safe,
            cancel,
        )
        .await
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        bearer: Option<&str>,
        retry_safe: bool,
        cancel: &Cancellation,
    ) -> Result<Option<Value>> {
        if cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        let url = self.endpoint(path)?;
        let authorization = bearer
            .map(|token| {
                if token.is_empty()
                    || token.len() > 256
                    || !token
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
                {
                    return Err(Error::Configuration);
                }
                let mut value = header::HeaderValue::from_str(&format!("Bearer {token}"))
                    .map_err(|_| Error::Configuration)?;
                value.set_sensitive(true);
                Ok(value)
            })
            .transpose()?;
        // Dropping this entire future interrupts connection work, streaming
        // body reads and retry sleeps. Cancellation takes priority over success.
        let result = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(Error::Cancelled),
            result = tokio::time::timeout(
                OPERATION_TIMEOUT,
                self.retry(method, url, body.as_deref(), authorization.as_ref(), retry_safe),
            ) => result.unwrap_or(Err(Error::transient())),
        };
        if cancel.is_cancelled() {
            Err(Error::Cancelled)
        } else {
            result
        }
    }

    fn endpoint(&self, path: &str) -> Result<Url> {
        let (route, query) = path
            .split_once('?')
            .map_or((path, None), |(route, query)| (route, Some(query)));
        if path.len() > 2048
            || !(route.starts_with(CLIENT_PREFIX) || route == JWKS_PATH)
            || path.contains("//")
            || path.contains(['\\', '#'])
            || path.chars().any(|c| c.is_control() || c.is_whitespace())
            || (query.is_some()
                && !matches!(
                    route,
                    JWKS_PATH | "/api/client/v1/licences" | "/api/client/v1/sessions/current"
                ))
        {
            return Err(Error::Configuration);
        }
        let url = self.base.join(path).map_err(|_| Error::Configuration)?;
        if url.origin() != self.base.origin() || url.path() != route || url.fragment().is_some() {
            return Err(Error::Configuration);
        }
        if query.is_some() {
            let pairs: Vec<_> = url.query_pairs().collect();
            let with_cursor = route == "/api/client/v1/licences" && pairs.len() == 3;
            if (pairs.len() != 2 && !with_cursor)
                || pairs[0].0 != "application_id"
                || pairs[1].0 != "environment_id"
                || (with_cursor && pairs[2].0 != "after")
                || pairs.iter().any(|(_, value)| {
                    value.is_empty()
                        || value.len() > 128
                        || !value
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
                })
            {
                return Err(Error::Configuration);
            }
        }
        Ok(url)
    }

    async fn retry(
        &self,
        method: Method,
        url: Url,
        body: Option<&[u8]>,
        authorization: Option<&header::HeaderValue>,
        retry_safe: bool,
    ) -> Result<Option<Value>> {
        let started = Instant::now();
        for attempt in 0..=2 {
            let failure = match self
                .attempt(method.clone(), url.clone(), body, authorization)
                .await
            {
                Ok(result) => return Ok(result),
                Err(failure) => failure,
            };
            if !retry_safe || attempt == 2 || !matches!(failure.error, Error::Transient { .. }) {
                return Err(failure.error);
            }
            let mut entropy = [0_u8; 1];
            aws_lc_rs::rand::fill(&mut entropy).map_err(|_| Error::TransportSecurity)?;
            let backoff = Duration::from_millis((250 + u64::from(entropy[0])) << attempt);
            let delay = backoff.max(failure.retry_after.unwrap_or(Duration::ZERO));
            let remaining = OPERATION_TIMEOUT.saturating_sub(started.elapsed());
            if delay >= remaining {
                return Err(failure.error);
            }
            tokio::time::sleep(delay).await;
        }
        Err(Error::transient())
    }

    async fn attempt(
        &self,
        method: Method,
        url: Url,
        body: Option<&[u8]>,
        authorization: Option<&header::HeaderValue>,
    ) -> std::result::Result<Option<Value>, AttemptFailure> {
        let mut request = self
            .client
            .request(method, url)
            .header(header::ACCEPT, "application/json");
        if let Some(authorization) = authorization {
            request = request.header(header::AUTHORIZATION, authorization.clone());
        }
        if let Some(body) = body {
            request = request
                .header(header::CONTENT_TYPE, "application/json")
                .body(body.to_vec());
        }
        let mut response = request.send().await.map_err(AttemptFailure::transport)?;
        let status = response.status();
        let retry_after = response
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
            .map(|value| Duration::from_secs(value.parse::<u64>().unwrap_or(u64::MAX)));
        if response
            .content_length()
            .is_some_and(|length| length > MAX_BYTES as u64)
        {
            return Err(AttemptFailure::invalid());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(AttemptFailure::transport)? {
            if chunk.len() > MAX_BYTES - bytes.len() {
                return Err(AttemptFailure::invalid());
            }
            bytes.extend_from_slice(&chunk);
        }
        if status.as_u16() == 204 {
            return if bytes.is_empty() {
                Ok(None)
            } else {
                Err(AttemptFailure::invalid())
            };
        }
        if status.is_success() {
            return serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| AttemptFailure::invalid());
        }
        if matches!(status.as_u16(), 502..=504) && !has_orbit_error_member(&bytes) {
            return Err(AttemptFailure {
                error: Error::transient(),
                retry_after,
            });
        }
        if !matches!(status.as_u16(), 401 | 403 | 404 | 409 | 422 | 429)
            && !status.is_server_error()
        {
            return Err(AttemptFailure::invalid());
        }
        // Parse the error envelope directly, so duplicate required fields do not
        // disappear into a generic JSON map before this security classification.
        let envelope: ErrorEnvelope =
            serde_json::from_slice(&bytes).map_err(|_| AttemptFailure::invalid())?;
        let error = envelope.error;
        if !crate::diagnostics::valid_code(&error.code)
            || error.message.is_empty()
            || !crate::diagnostics::valid_request_id(&error.request_id)
        {
            return Err(AttemptFailure::invalid());
        }
        Err(AttemptFailure {
            error: if (status.as_u16() == 429 && error.code == "rate_limited")
                || (status.as_u16() == 503 && error.code == "service_unavailable")
            {
                Error::Transient {
                    code: Some(error.code),
                    request_id: Some(error.request_id),
                }
            } else {
                Error::Denied {
                    code: error.code,
                    request_id: Some(error.request_id),
                }
            },
            retry_after,
        })
    }
}

fn client_builder() -> reqwest::ClientBuilder {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(3))
        .timeout(ATTEMPT_TIMEOUT)
}

fn origin_authority(base: &str) -> Result<&str> {
    if base.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(Error::Configuration);
    }
    let (_, rest) = base.split_once("://").ok_or(Error::Configuration)?;
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.is_empty() || authority.contains(['/', '\\', '@', '?', '#']) {
        return Err(Error::Configuration);
    }
    Ok(authority)
}

fn origin(base: &str, scheme: &str) -> Result<Url> {
    origin_authority(base)?;
    let parsed = Url::parse(base).map_err(|_| Error::Configuration)?;
    if parsed.scheme() != scheme
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(Error::Configuration);
    }
    Ok(parsed)
}

struct LimitedBody(Vec<u8>);

impl Write for LimitedBody {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_BYTES - self.0.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "request_too_large",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Deserialize)]
struct ErrorEnvelope {
    error: ErrorDescription,
}

#[derive(Deserialize)]
struct ErrorDescription {
    code: String,
    message: String,
    request_id: String,
}

fn has_orbit_error_member(bytes: &[u8]) -> bool {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|value| value.as_object().map(|object| object.contains_key("error")))
        .unwrap_or(false)
}

struct AttemptFailure {
    error: Error,
    retry_after: Option<Duration>,
}

impl AttemptFailure {
    fn invalid() -> Self {
        Self {
            error: Error::InvalidResponse,
            retry_after: None,
        }
    }

    fn transport(error: reqwest::Error) -> Self {
        let mut transient = error.is_timeout();
        let mut source = error.source();
        // A generic connection error is insufficient evidence of an outage: it
        // also wraps certificate and TLS failures. Only concrete OS failures or
        // timeout signals are eligible for retries and offline fallback.
        while let Some(cause) = source {
            if let Some(io) = cause.downcast_ref::<io::Error>() {
                transient |= matches!(
                    io.kind(),
                    io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::NetworkUnreachable
                        | io::ErrorKind::HostUnreachable
                );
            }
            source = cause.source();
        }
        Self {
            error: if transient {
                Error::transient()
            } else {
                Error::TransportSecurity
            },
            retry_after: None,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[cfg(feature = "local-development")]
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::{mpsc, oneshot},
        task::{JoinHandle, JoinSet},
    };

    #[cfg(feature = "local-development")]
    pub(crate) struct Fixture {
        pub(crate) transport: Transport,
        requests: mpsc::UnboundedReceiver<Request>,
        server: JoinHandle<()>,
    }

    #[cfg(feature = "local-development")]
    pub(crate) struct Request {
        pub(crate) head: String,
        pub(crate) body: Vec<u8>,
        response: oneshot::Sender<String>,
    }

    #[cfg(feature = "local-development")]
    impl Request {
        pub(crate) fn respond(self, status: u16, body: &str) {
            self.respond_after(status, body, None);
        }

        fn respond_after(self, status: u16, body: &str, retry_after: Option<u64>) {
            self.respond_as(status, "application/json", body, retry_after);
        }

        fn respond_unstructured(self, status: u16, body: &str) {
            self.respond_as(status, "text/html", body, None);
        }

        fn respond_as(self, status: u16, content_type: &str, body: &str, retry_after: Option<u64>) {
            let retry = retry_after
                .map(|seconds| format!("Retry-After: {seconds}\r\n"))
                .unwrap_or_default();
            // A cancelled client may already have closed its connection.
            let _ = self.response.send(format!(
                "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n{retry}\r\n{body}",
                body.len()
            ));
        }
    }

    #[cfg(feature = "local-development")]
    impl Fixture {
        pub(crate) async fn new() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let transport =
                Transport::local_loopback(&format!("http://{}", listener.local_addr().unwrap()))
                    .unwrap();
            let (requests, receiver) = mpsc::unbounded_channel();
            let server = tokio::spawn(async move {
                let mut connections = JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let (mut stream, _) = accepted.unwrap();
                            let requests = requests.clone();
                            connections.spawn(async move {
                                let mut bytes = Vec::new();
                                let header_end = loop {
                                    let mut chunk = [0; 1024];
                                    let read = stream.read(&mut chunk).await.unwrap();
                                    if read == 0 { return; }
                                    bytes.extend_from_slice(&chunk[..read]);
                                    assert!(bytes.len() <= MAX_BYTES + 4096);
                                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                                        break end + 4;
                                    }
                                };
                                let head = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
                                let length = head.lines().find_map(|line| {
                                    let (name, value) = line.split_once(':')?;
                                    name.eq_ignore_ascii_case("content-length")
                                        .then(|| value.trim().parse::<usize>().unwrap())
                                }).unwrap_or(0);
                                assert!(length <= MAX_BYTES);
                                while bytes.len() - header_end < length {
                                    let mut chunk = [0; 1024];
                                    let read = stream.read(&mut chunk).await.unwrap();
                                    if read == 0 { return; }
                                    bytes.extend_from_slice(&chunk[..read]);
                                }
                                let (response, reply) = oneshot::channel();
                                if requests.send(Request {
                                    head, body: bytes[header_end..].to_vec(), response,
                                }).is_err() { return; }
                                if let Ok(response) = reply.await {
                                    let _ = stream.write_all(response.as_bytes()).await;
                                }
                            });
                        },
                        completed = connections.join_next(), if !connections.is_empty() => {
                            completed.unwrap().unwrap();
                        },
                    }
                }
            });
            Self {
                transport,
                requests: receiver,
                server,
            }
        }

        pub(crate) async fn next(&mut self) -> Request {
            tokio::time::timeout(Duration::from_secs(5), self.requests.recv())
                .await
                .unwrap()
                .unwrap()
        }

        pub(crate) fn assert_idle(&mut self) {
            assert!(self.requests.try_recv().is_err());
        }
    }

    #[cfg(feature = "local-development")]
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    #[cfg(feature = "local-development")]
    pub(crate) const TRANSIENT: &str = r#"{"error":{"code":"service_unavailable","message":"Unavailable","request_id":"fixture"}}"#;

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn lifecycle_retry_status_and_malformed_responses() {
        for (status, body, attempts, expected) in [
            (
                429,
                r#"{"error":{"code":"rate_limited","message":"Limited","request_id":"fixture"}}"#,
                3,
                "transient",
            ),
            (503, TRANSIENT, 3, "transient"),
            (500, TRANSIENT, 1, "denied"),
            (429, TRANSIENT, 1, "denied"),
            (
                503,
                r#"{"error":{"code":"licence_revoked","message":"Denied","request_id":"fixture"}}"#,
                1,
                "denied",
            ),
            (
                503,
                r#"{"error":{"code":"future_error","message":"Unknown","request_id":"fixture"}}"#,
                1,
                "denied",
            ),
            (
                401,
                r#"{"error":{"code":"invalid_credentials","message":"Denied","request_id":"fixture"}}"#,
                1,
                "denied",
            ),
            (
                403,
                r#"{"error":{"code":"licence_revoked","message":"Denied","request_id":"fixture"}}"#,
                1,
                "denied",
            ),
            (
                409,
                r#"{"error":{"code":"future_error","message":"Denied","request_id":"fixture"}}"#,
                1,
                "denied",
            ),
            (502, "<html>Bad Gateway</html>", 3, "gateway"),
            (503, "upstream unavailable", 3, "gateway"),
            (504, "gateway timeout", 3, "gateway"),
            (429, "upstream unavailable", 1, "invalid"),
            (500, "upstream unavailable", 1, "invalid"),
            (
                503,
                r#"{"error":{"code":"service_unavailable","code":"licence_revoked","message":"Denied","request_id":"fixture"}}"#,
                1,
                "invalid",
            ),
            (200, "invalid-json", 1, "invalid"),
        ] {
            let mut fixture = Fixture::new().await;
            let transport = fixture.transport.clone();
            let operation = tokio::spawn(async move {
                transport
                    .get("/.well-known/orbit-jwks.json", &Cancellation::new())
                    .await
            });
            for _ in 0..attempts {
                let request = fixture.next().await;
                if expected == "gateway" {
                    request.respond_unstructured(status, body);
                } else {
                    request.respond(status, body);
                }
            }
            let result = tokio::time::timeout(Duration::from_secs(2), operation)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                result.as_ref().err().and_then(Error::request_id),
                if matches!(expected, "transient" | "denied") {
                    Some("fixture")
                } else {
                    None
                }
            );
            assert!(
                match expected {
                    "transient" | "gateway" => matches!(result, Err(Error::Transient { .. })),
                    "denied" => matches!(result, Err(Error::Denied { .. })),
                    _ => matches!(result, Err(Error::InvalidResponse)),
                },
                "status {status}: {result:?}"
            );
            fixture.assert_idle();
        }
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn unstructured_gateway_does_not_retry_unsafe_operation() {
        let mut fixture = Fixture::new().await;
        let transport = fixture.transport.clone();
        let operation = tokio::spawn(async move {
            transport
                .post(
                    "/api/client/v1/sessions",
                    &serde_json::json!({}),
                    false,
                    &Cancellation::new(),
                )
                .await
        });
        fixture.next().await.respond(502, "Bad Gateway");
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), operation)
                .await
                .unwrap()
                .unwrap(),
            Err(Error::Transient { .. })
        ));
        fixture.assert_idle();
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn error_request_ids_are_strict_and_retained_on_http_failures() {
        for (request_id, valid) in [
            (serde_json::json!("A-a_0"), true),
            (serde_json::json!("_"), true),
            (serde_json::json!("a".repeat(64)), true),
            (serde_json::json!(""), false),
            (serde_json::json!("a".repeat(65)), false),
            (serde_json::json!("a b"), false),
            (serde_json::json!("a/b"), false),
            (serde_json::json!("a\nb"), false),
            (serde_json::json!("é"), false),
            (serde_json::Value::Null, false),
            (serde_json::json!(123), false),
        ] {
            for (status, code) in [(403, "licence_expired"), (503, "service_unavailable")] {
                let mut fixture = Fixture::new().await;
                let transport = fixture.transport.clone();
                let operation = tokio::spawn(async move {
                    transport
                        .post(
                            "/api/client/v1/sessions",
                            &serde_json::json!({}),
                            false,
                            &Cancellation::new(),
                        )
                        .await
                });
                let body = serde_json::json!({"error": {"code": code, "message": "synthetic-secret", "request_id": request_id}}).to_string();
                fixture.next().await.respond(status, &body);
                let error = operation.await.unwrap().unwrap_err();
                if valid {
                    assert_eq!(error.request_id(), request_id.as_str());
                    match &error {
                        Error::Denied { code: actual, .. } => {
                            assert_eq!(status, 403);
                            assert_eq!(actual, code);
                        }
                        Error::Transient { code: actual, .. } => {
                            assert_eq!(status, 503);
                            assert_eq!(actual.as_deref(), Some(code));
                        }
                        _ => panic!("valid HTTP metadata lost classification"),
                    }
                } else {
                    assert!(matches!(error, Error::InvalidResponse));
                    assert!(error.request_id().is_none());
                }
                assert!(!format!("{error} {error:?}").contains("synthetic-secret"));
                fixture.assert_idle();
            }
        }
        assert!(Error::transient().request_id().is_none());
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn lifecycle_retry_keeps_body_and_one_operation_deadline() {
        let mut fixture = Fixture::new().await;
        let transport = fixture.transport.clone();
        let body =
            serde_json::json!({"licence_key":"synthetic", "idempotency_key":"same_operation_123"});
        let expected = serde_json::to_vec(&body).unwrap();
        let started = Instant::now();
        let operation = tokio::spawn(async move {
            transport
                .post(
                    "/api/client/v1/activations",
                    &body,
                    true,
                    &Cancellation::new(),
                )
                .await
        });
        let first = fixture.next().await;
        assert!(
            first
                .head
                .starts_with("POST /api/client/v1/activations HTTP/1.1\r\n")
        );
        assert_eq!(first.body, expected);
        first.respond_after(503, TRANSIENT, Some(16));
        let second = tokio::time::timeout(Duration::from_secs(20), fixture.requests.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.body, expected);
        second.respond_after(503, TRANSIENT, Some(16));
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), operation)
                .await
                .unwrap()
                .unwrap(),
            Err(Error::Transient { .. })
        ));
        assert!(started.elapsed() < OPERATION_TIMEOUT);
        fixture.assert_idle();
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn lifecycle_cancellation_stops_retries() {
        let mut fixture = Fixture::new().await;
        let transport = fixture.transport.clone();
        let cancel = Cancellation::new();
        let operation_cancel = cancel.clone();
        let operation = tokio::spawn(async move {
            transport
                .get("/.well-known/orbit-jwks.json", &operation_cancel)
                .await
        });
        fixture.next().await.respond_after(503, TRANSIENT, Some(20));
        cancel.cancel();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), operation)
                .await
                .unwrap()
                .unwrap(),
            Err(Error::Cancelled)
        ));
        fixture.assert_idle();
    }

    #[cfg(feature = "local-development")]
    #[tokio::test]
    async fn lifecycle_tls_failure_is_never_retried() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let transport = Transport {
            client: client_builder()
                .no_proxy()
                .https_only(true)
                .build()
                .unwrap(),
            base: Url::parse(&format!("https://{}", listener.local_addr().unwrap())).unwrap(),
        };
        let operation = tokio::spawn(async move {
            transport
                .get("/.well-known/orbit-jwks.json", &Cancellation::new())
                .await
        });
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut hello = [0; 4096];
        assert!(stream.read(&mut hello).await.unwrap() > 0);
        stream
            .write_all(b"HTTP/1.1 400 Not TLS\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        drop(stream);
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), operation)
                .await
                .unwrap()
                .unwrap(),
            Err(Error::TransportSecurity)
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }
    #[test]
    fn origin_and_route_do_not_redirect_bearers() {
        for url in [
            "http://example.test",
            "https://user:password@example.test",
            "https://example.test/path",
            "https://example.test?query=1",
            "https://example.test/#fragment",
        ] {
            assert!(Transport::new(url).is_err());
        }
        let client = Transport::new("https://orbit.example.test").unwrap();
        for path in [
            "//evil.test/api/client/v1/x",
            "https://evil.test/api/client/v1/x",
            "/api/client/v1/../../admin",
            "/api/client/v1/%2e%2e/admin",
            "/api/client/v1/x?credential=secret",
            "/api/client/v1/x#fragment",
        ] {
            assert!(client.endpoint(path).is_err());
        }
        assert!(
            client
                .endpoint("/.well-known/orbit-jwks.json?application_id=app&environment_id=test")
                .is_ok()
        );
        #[cfg(feature = "local-development")]
        for url in [
            "http://localhost:8080",
            "http://192.168.1.1",
            "http://2130706433",
            "http://127.1",
        ] {
            assert!(Transport::local_loopback(url).is_err());
        }
    }
    #[tokio::test]
    async fn cancellation_settles_without_sending() {
        let cancel = Cancellation::new();
        cancel.cancel();
        cancel.cancelled().await;
        let client = Transport::new("https://orbit.example.test").unwrap();
        assert!(matches!(
            client.get("/.well-known/orbit-jwks.json", &cancel).await,
            Err(Error::Cancelled)
        ));
    }
}
