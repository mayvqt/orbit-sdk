//! Whole-invocation tests against a local mock of the management API. Request
//! bodies are compared exactly because the service rejects unknown fields.

use crate::{
    app::{Env, Io, run},
    config::tests::{TOKEN, temp_dir},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    path::PathBuf,
    thread::JoinHandle,
};

struct Recorded {
    method: String,
    path: String,
    query: Vec<(String, String)>,
    headers: HashMap<String, String>,
    body: Value,
}

struct Server {
    url: String,
    handle: JoinHandle<Vec<Recorded>>,
}

impl Server {
    /// Answer each connection in turn with the next canned status and body.
    fn start(responses: Vec<(u16, &'static str)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let mut recorded = Vec::new();
            listener.set_nonblocking(true).unwrap();
            for (status, body) in responses {
                // Stop waiting when the command sends fewer requests than expected.
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                let stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break Some(stream),
                        Err(_) if std::time::Instant::now() < deadline => {
                            std::thread::sleep(std::time::Duration::from_millis(5));
                        }
                        Err(_) => break None,
                    }
                };
                let Some(stream) = stream else { break };
                stream.set_nonblocking(false).unwrap();
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap().to_owned();
                let target = parts.next().unwrap().to_owned();
                let mut headers = HashMap::new();
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).unwrap();
                    let header = header.trim_end();
                    if header.is_empty() {
                        break;
                    }
                    let (name, value) = header.split_once(':').unwrap();
                    headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
                }
                let length = headers
                    .get("content-length")
                    .map_or(0, |v| v.parse().unwrap());
                let mut bytes = vec![0; length];
                reader.read_exact(&mut bytes).unwrap();
                let url = reqwest::Url::parse(&format!("http://h{target}")).unwrap();
                recorded.push(Recorded {
                    method,
                    path: url.path().to_owned(),
                    query: url.query_pairs().into_owned().collect(),
                    headers,
                    body: if bytes.is_empty() {
                        Value::Null
                    } else {
                        serde_json::from_slice(&bytes).unwrap()
                    },
                });
                let mut stream = reader.into_inner();
                write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
            recorded
        });
        Self { url, handle }
    }

    fn finish(self) -> Vec<Recorded> {
        self.handle.join().unwrap()
    }
}

struct TestEnv(HashMap<&'static str, String>);

impl Env for TestEnv {
    fn var(&self, name: &str) -> Option<String> {
        self.0.get(name).cloned()
    }
}

impl TestEnv {
    fn new(config: &std::path::Path) -> Self {
        Self(HashMap::from([(
            "ORBIT_CONFIG_DIR",
            config.display().to_string(),
        )]))
    }

    fn api(server: &Server) -> (Self, PathBuf) {
        let dir = temp_dir();
        let mut env = Self::new(&dir);
        env.0.insert("ORBIT_API_URL", server.url.clone());
        env.0.insert("ORBIT_MANAGEMENT_TOKEN", TOKEN.into());
        env.0.insert("ORBIT_APPLICATION_ID", "app_1".into());
        env.0.insert("ORBIT_ENVIRONMENT_ID", "env_1".into());
        (env, dir)
    }
}

struct Outcome {
    status: u8,
    out: String,
    err: String,
}

fn invoke(env: &TestEnv, args: &[&str], stdin: &str) -> Outcome {
    let mut input = stdin.as_bytes();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let status = run(
        std::iter::once("orbit").chain(args.iter().copied()),
        env,
        &mut Io {
            stdin: &mut input,
            stdin_terminal: false,
            out: &mut out,
            err: &mut err,
        },
    );
    Outcome {
        status,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
    }
}

/// Run one command against one canned response and return its request.
fn exchange(args: &[&str], status: u16, body: &'static str) -> (Outcome, Recorded) {
    let server = Server::start(vec![(status, body)]);
    let (env, dir) = TestEnv::api(&server);
    let outcome = invoke(&env, args, "");
    let mut requests = server.finish();
    std::fs::remove_dir_all(dir).unwrap();
    assert_eq!(requests.len(), 1);
    (outcome, requests.remove(0))
}

fn assert_scoped(request: &Recorded, method: &str, path: &str) {
    assert_eq!(request.method, method);
    assert_eq!(request.path, path);
    assert_eq!(request.headers["authorization"], format!("Bearer {TOKEN}"));
    assert_eq!(request.query[0], ("application_id".into(), "app_1".into()));
    assert_eq!(request.query[1], ("environment_id".into(), "env_1".into()));
}

fn generated_key(request: &Recorded) -> String {
    let key = request.body["idempotency_key"].as_str().unwrap().to_owned();
    assert!(key.starts_with("orbit-cli-") && key.len() == 42, "{key}");
    key
}

const LICENCE: &str = r#"{"id":"lic_1","status":"enabled","state":"active","policy_name":"Pro","key_suffix":"ABCD","entitlements":{"export":true,"beta":false},"reference":"order-7","note":"old note","expires_at":null}"#;

#[test]
fn credentials_set_show_and_remove() {
    let dir = temp_dir();
    let env = TestEnv::new(&dir);
    let set = invoke(
        &env,
        &[
            "--profile",
            "shop",
            "--application-id",
            "app_1",
            "--environment-id",
            "env_1",
            "credentials",
            "set",
        ],
        &format!("{TOKEN}\n"),
    );
    assert_eq!(set.status, 0, "{}", set.err);
    assert!(!set.out.contains(TOKEN));
    let file = std::fs::read_to_string(dir.join("credentials.json")).unwrap();
    assert!(file.contains(TOKEN));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("credentials.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    let show = invoke(&env, &["--profile", "shop", "credentials", "show"], "");
    assert_eq!(show.status, 0, "{}", show.err);
    assert!(!show.out.contains(TOKEN));
    assert!(show.out.contains("orb_mgmt_…1234"));
    assert!(show.out.contains("app_1"));
    let json = invoke(
        &env,
        &["--profile", "shop", "--json", "credentials", "show"],
        "",
    );
    let value: Value = serde_json::from_str(&json.out).unwrap();
    assert_eq!(value["token"], "orb_mgmt_…1234");
    assert_eq!(value["api_url"], "https://orbit.mayvie.dev");

    let missing = invoke(&env, &["credentials", "show"], "");
    assert_eq!(missing.status, 1);
    let bad = invoke(
        &env,
        &[
            "--application-id",
            "a",
            "--environment-id",
            "e",
            "credentials",
            "set",
        ],
        "not-a-token\n",
    );
    assert_eq!(bad.status, 2);
    assert!(!bad.err.contains("not-a-token"));
    let argv = invoke(&env, &["credentials", "set", TOKEN], "");
    assert_eq!(argv.status, 2);

    let remove = invoke(&env, &["--profile", "shop", "credentials", "remove"], "");
    assert_eq!(remove.status, 0, "{}", remove.err);
    assert!(!dir.join("credentials.json").exists());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn saved_profile_supplies_token_scope_and_url() {
    let server = Server::start(vec![(200, "[]")]);
    let dir = temp_dir();
    let env = TestEnv::new(&dir);
    let set = invoke(
        &env,
        &[
            "--api-url",
            &server.url,
            "--application-id",
            "app_1",
            "--environment-id",
            "env_1",
            "credentials",
            "set",
        ],
        TOKEN,
    );
    assert_eq!(set.status, 0, "{}", set.err);
    let list = invoke(&env, &["policies", "list"], "");
    assert_eq!(list.status, 0, "{}", list.err);
    assert_eq!(list.out, "No results.\n");
    let requests = server.finish();
    assert_scoped(&requests[0], "GET", "/api/management/v1/policies");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn missing_token_is_a_usage_error() {
    let dir = temp_dir();
    let outcome = invoke(&TestEnv::new(&dir), &["licences", "show", "lic_1"], "");
    assert_eq!(outcome.status, 2);
    assert!(
        outcome.err.contains("orbit credentials set"),
        "{}",
        outcome.err
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn licence_search_sends_body_and_renders_table() {
    let (outcome, request) = exchange(
        &["licences", "list", "--query", "order-7", "--status", "all"],
        200,
        r#"{"items":[{"id":"lic_1","key_suffix":"ABCD","policy_name":"Pro","state":"active","expires_at":null,"reference":"order-7"}],"next_cursor":"cur_2"}"#,
    );
    assert_scoped(&request, "POST", "/api/management/v1/licences/search");
    assert_eq!(request.body, json!({"query": "order-7", "status": "all"}));
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert!(outcome.out.starts_with("ID     KEY_SUFFIX  POLICY_NAME"));
    assert!(outcome.out.contains("lic_1  ABCD"));
    assert!(outcome.out.ends_with("More results: --after cur_2\n"));
}

#[test]
fn json_output_is_the_response_unchanged() {
    let (outcome, request) = exchange(&["--json", "licences", "show", "lic/1"], 200, LICENCE);
    assert_scoped(&request, "GET", "/api/management/v1/licences/lic%2F1");
    assert_eq!(outcome.out, format!("{LICENCE}\n"));
}

#[test]
fn status_changes() {
    for (args, status) in [
        (
            &["suspend", "lic_1", "--reason", "chargeback"][..],
            "suspended",
        ),
        (
            &["reinstate", "lic_1", "--reason", "chargeback"][..],
            "enabled",
        ),
        (
            &["revoke", "lic_1", "--reason", "chargeback", "--yes"][..],
            "revoked",
        ),
    ] {
        let args: Vec<&str> = std::iter::once("licences")
            .chain(args.iter().copied())
            .collect();
        let (outcome, request) = exchange(&args, 200, LICENCE);
        assert_eq!(outcome.status, 0, "{}", outcome.err);
        assert_scoped(&request, "POST", "/api/management/v1/licences/lic_1/status");
        assert_eq!(
            request.body,
            json!({"status": status, "reason": "chargeback"})
        );
    }
    let dir = temp_dir();
    let env = TestEnv::new(&dir);
    let unconfirmed = invoke(&env, &["licences", "revoke", "lic_1", "--reason", "x"], "");
    assert_eq!(unconfirmed.status, 2);
    let no_reason = invoke(&env, &["licences", "suspend", "lic_1"], "");
    assert_eq!(no_reason.status, 2);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn extension_uses_generated_or_supplied_idempotency_key() {
    let (outcome, request) = exchange(
        &[
            "licences", "extend", "lic_1", "--by", "30d", "--reason", "renewal",
        ],
        200,
        LICENCE,
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert_scoped(
        &request,
        "POST",
        "/api/management/v1/licences/lic_1/extensions",
    );
    let key = generated_key(&request);
    assert_eq!(
        request.body,
        json!({"seconds": 2_592_000, "reason": "renewal", "idempotency_key": key})
    );
    let (_, request) = exchange(
        &[
            "--idempotency-key",
            "renewal-order-7-2026",
            "licences",
            "extend",
            "lic_1",
            "--by",
            "12h",
            "--reason",
            "renewal",
        ],
        200,
        LICENCE,
    );
    assert_eq!(request.body["idempotency_key"], "renewal-order-7-2026");
    assert_eq!(request.body["seconds"], 43_200);
}

#[test]
fn entitlements_merge_with_current_values() {
    let server = Server::start(vec![(200, LICENCE), (200, LICENCE)]);
    let (env, dir) = TestEnv::api(&server);
    let outcome = invoke(
        &env,
        &[
            "licences",
            "entitlements",
            "lic_1",
            "--enable",
            "beta",
            "--disable",
            "export",
            "--enable",
            "sync",
            "--reason",
            "upgrade",
        ],
        "",
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    let requests = server.finish();
    assert_scoped(&requests[0], "GET", "/api/management/v1/licences/lic_1");
    assert_scoped(
        &requests[1],
        "POST",
        "/api/management/v1/licences/lic_1/entitlements",
    );
    assert_eq!(
        requests[1].body,
        json!({"entitlements": {"beta": true, "export": false, "sync": true}, "reason": "upgrade"})
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn annotation_keeps_the_unchanged_field() {
    let server = Server::start(vec![(200, LICENCE), (200, LICENCE)]);
    let (env, dir) = TestEnv::api(&server);
    let outcome = invoke(
        &env,
        &[
            "licences", "annotate", "lic_1", "--note", "new", "--reason", "support",
        ],
        "",
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    let requests = server.finish();
    assert_scoped(
        &requests[1],
        "POST",
        "/api/management/v1/licences/lic_1/annotations",
    );
    assert_eq!(
        requests[1].body,
        json!({"reference": "order-7", "note": "new", "reason": "support"})
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn devices_and_resets() {
    let (outcome, request) = exchange(
        &["licences", "devices", "lic_1", "--after", "act_1"],
        200,
        r#"{"items":[{"id":"act_2","installation_id":"ins_1","active":true,"fingerprint_provider":null,"fingerprint_suffix":"a1b2c3","created_at":"2026-01-01T00:00:00Z","last_seen_at":"2026-01-02T00:00:00Z"}],"next_cursor":null}"#,
    );
    assert_scoped(&request, "GET", "/api/management/v1/licences/lic_1/devices");
    assert_eq!(request.query[2], ("after".into(), "act_1".into()));
    assert!(outcome.out.contains("act_2  ins_1"));

    let (outcome, request) = exchange(
        &[
            "licences",
            "reset-device",
            "lic_1",
            "act_2",
            "--reason",
            "new laptop",
        ],
        204,
        "",
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert_eq!(outcome.out, "Device released.\n");
    assert_scoped(
        &request,
        "POST",
        "/api/management/v1/licences/lic_1/device-resets",
    );
    let key = generated_key(&request);
    assert_eq!(
        request.body,
        json!({"activation_id": "act_2", "override_cooldown": false, "reason": "new laptop", "idempotency_key": key})
    );
}

#[test]
fn issue_and_key_replacement_print_keys() {
    let issued = r#"{"licences":[],"keys":[{"licence_id":"lic_1","key":"ORB-KEY-1"}],"secret_replay_expired":false}"#;
    let (outcome, request) = exchange(
        &[
            "licences",
            "issue",
            "--policy",
            "pol_1",
            "--quantity",
            "2",
            "--reference",
            "order-7",
        ],
        200,
        issued,
    );
    assert_scoped(&request, "POST", "/api/management/v1/licences");
    let key = generated_key(&request);
    assert_eq!(
        request.body,
        json!({"policy_id": "pol_1", "quantity": 2, "reference": "order-7", "note": "", "idempotency_key": key})
    );
    assert!(
        outcome.out.contains("lic_1       ORB-KEY-1"),
        "{}",
        outcome.out
    );

    let (outcome, request) = exchange(
        &["licences", "replace-key", "lic_1", "--reason", "leaked"],
        200,
        issued,
    );
    assert_scoped(
        &request,
        "POST",
        "/api/management/v1/licences/lic_1/key-replacements",
    );
    let key = generated_key(&request);
    assert_eq!(
        request.body,
        json!({"reason": "leaked", "idempotency_key": key})
    );
    assert!(outcome.out.contains("ORB-KEY-1"));
}

#[test]
fn floating_sessions() {
    let (_, request) = exchange(
        &[
            "licences", "sessions", "lic_1", "--state", "active", "--limit", "10",
        ],
        200,
        r#"{"items":[],"next_cursor":null}"#,
    );
    assert_scoped(
        &request,
        "GET",
        "/api/management/v1/licences/lic_1/sessions",
    );
    assert_eq!(
        request.query[2..],
        [
            ("state".into(), "active".into()),
            ("limit".into(), "10".into())
        ]
    );
    let (outcome, request) = exchange(
        &[
            "licences",
            "end-session",
            "lic_1",
            "ses_1",
            "--reason",
            "stuck",
        ],
        204,
        "",
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert_scoped(
        &request,
        "POST",
        "/api/management/v1/licences/lic_1/sessions/ses_1/end",
    );
    let key = generated_key(&request);
    assert_eq!(
        request.body,
        json!({"reason": "stuck", "idempotency_key": key})
    );
}

#[test]
fn offline_file_is_written() {
    let server = Server::start(vec![(
        201,
        r#"{"file":"SIGNED-FILE","issuance_id":"iss_1","licence_id":"lic_1","activation_id":"act_1","installation_id":"ins_1","sequence":1,"issued_at":"2026-01-01T00:00:00Z","expires_at":"2026-07-01T00:00:00Z"}"#,
    )]);
    let (env, dir) = TestEnv::api(&server);
    let request_file = dir.join("request.json");
    let request_json = json!({"format": "orbit-offline-request", "version": 1, "app_key": "orbit_app_test_x", "installation_id": "ins_1", "fingerprint": null, "fingerprint_provider": null});
    std::fs::write(&request_file, request_json.to_string()).unwrap();
    let output = dir.join("licence.orbit");
    let outcome = invoke(
        &env,
        &[
            "licences",
            "offline-file",
            "lic_1",
            "--request",
            request_file.to_str().unwrap(),
            "--duration",
            "180d",
            "--output",
            output.to_str().unwrap(),
        ],
        "",
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert_eq!(std::fs::read_to_string(&output).unwrap(), "SIGNED-FILE");
    let requests = server.finish();
    assert_scoped(
        &requests[0],
        "POST",
        "/api/management/v1/licences/lic_1/offline-files",
    );
    let key = generated_key(&requests[0]);
    assert_eq!(
        requests[0].body,
        json!({"request": request_json, "duration_seconds": 15_552_000, "idempotency_key": key})
    );
    std::fs::remove_dir_all(dir).unwrap();
}

const RELEASE: &str = r#"{"id":"rel_1","channel":"stable","version":"2.4.0","notes":"Fixes","release_number":null,"state":"draft","created_at":"2026-01-01T00:00:00Z","published_at":null,"artifacts":[]}"#;

#[test]
fn release_lifecycle_requests() {
    let (outcome, request) = exchange(
        &["releases", "list", "--channel", "beta", "--limit", "5"],
        200,
        r#"{"items":[{"id":"rel_1","channel":"beta","version":"2.4.0","state":"draft","release_number":null,"published_at":null,"artifacts":[{}]}],"next_cursor":null}"#,
    );
    assert_scoped(&request, "GET", "/api/management/v1/releases");
    assert_eq!(
        request.query[2..],
        [
            ("channel".into(), "beta".into()),
            ("limit".into(), "5".into())
        ]
    );
    assert!(
        outcome
            .out
            .contains("rel_1  beta     2.4.0    draft  -               1"),
        "{}",
        outcome.out
    );

    let (outcome, request) = exchange(
        &[
            "releases",
            "create",
            "--version",
            "2.4.0",
            "--notes",
            "Fixes",
        ],
        201,
        RELEASE,
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert_scoped(&request, "POST", "/api/management/v1/releases");
    let key = generated_key(&request);
    assert_eq!(
        request.body,
        json!({"channel": "stable", "version": "2.4.0", "notes": "Fixes", "idempotency_key": key})
    );

    for action in ["publish", "unpublish"] {
        let (outcome, request) = exchange(&["releases", action, "rel_1"], 200, RELEASE);
        assert_eq!(outcome.status, 0, "{}", outcome.err);
        assert_scoped(
            &request,
            "POST",
            &format!("/api/management/v1/releases/rel_1/{action}"),
        );
        let key = generated_key(&request);
        assert_eq!(request.body, json!({"idempotency_key": key}));
    }

    let (outcome, request) = exchange(&["releases", "remove-artifact", "rel_1", "art_1"], 204, "");
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    assert_scoped(
        &request,
        "DELETE",
        "/api/management/v1/releases/rel_1/artifacts/art_1",
    );
    let key = generated_key(&request);
    assert_eq!(request.body, json!({"idempotency_key": key}));
}

#[test]
fn release_edit_replaces_complete_metadata() {
    let server = Server::start(vec![(200, RELEASE), (200, RELEASE)]);
    let (env, dir) = TestEnv::api(&server);
    let outcome = invoke(
        &env,
        &["releases", "edit", "rel_1", "--version", "2.4.1"],
        "",
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    let requests = server.finish();
    assert_scoped(&requests[1], "PATCH", "/api/management/v1/releases/rel_1");
    let key = generated_key(&requests[1]);
    assert_eq!(
        requests[1].body,
        json!({"channel": "stable", "version": "2.4.1", "notes": "Fixes", "idempotency_key": key})
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn artifact_length_and_digest_come_from_the_file() {
    let server = Server::start(vec![(
        201,
        r#"{"id":"art_1","release_id":"rel_1","platform":"linux","architecture":"x86_64","filename":"app.tar.gz","byte_length":3,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","delivery_mode":"public","url":"https://downloads.example.com/app.tar.gz","required_feature":null}"#,
    )]);
    let (env, dir) = TestEnv::api(&server);
    let file = dir.join("app.tar.gz");
    std::fs::write(&file, b"abc").unwrap();
    let args = |url: &'static str| {
        vec![
            "releases".to_owned(),
            "add-artifact".into(),
            "rel_1".into(),
            file.display().to_string(),
            "--url".into(),
            url.into(),
            "--platform".into(),
            "linux".into(),
            "--arch".into(),
            "x86_64".into(),
        ]
    };
    let https = args("https://downloads.example.com/app.tar.gz");
    let outcome = invoke(
        &env,
        &https.iter().map(String::as_str).collect::<Vec<_>>(),
        "",
    );
    assert_eq!(outcome.status, 0, "{}", outcome.err);
    let requests = server.finish();
    assert_scoped(
        &requests[0],
        "POST",
        "/api/management/v1/releases/rel_1/artifacts",
    );
    let key = generated_key(&requests[0]);
    assert_eq!(
        requests[0].body,
        json!({
            "platform": "linux",
            "architecture": "x86_64",
            "filename": "app.tar.gz",
            "byte_length": 3,
            "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "delivery_mode": "public",
            "url": "https://downloads.example.com/app.tar.gz",
            "required_feature": null,
            "idempotency_key": key,
        })
    );
    let plain = args("http://downloads.example.com/app");
    let plain = invoke(
        &env,
        &plain.iter().map(String::as_str).collect::<Vec<_>>(),
        "",
    );
    assert_eq!(plain.status, 2);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn api_errors_report_code_and_retry_key() {
    let (outcome, _) = exchange(
        &["licences", "show", "lic_1"],
        404,
        r#"{"error":{"code":"not_found","message":"Not found.","request_id":"req_1"}}"#,
    );
    assert_eq!(outcome.status, 1);
    assert_eq!(
        outcome.err,
        "orbit: not_found: Not found. (HTTP 404, request req_1)\n"
    );
    let (outcome, request) = exchange(
        &["releases", "publish", "rel_1"],
        503,
        r#"{"error":{"code":"service_unavailable","message":"Try again.","request_id":"req_2"}}"#,
    );
    assert_eq!(outcome.status, 1);
    let key = generated_key(&request);
    assert!(
        outcome.err.contains(&format!("--idempotency-key {key}")),
        "{}",
        outcome.err
    );
    assert!(!outcome.err.contains(TOKEN));
}

#[test]
fn command_definitions_are_consistent() {
    use clap::CommandFactory;
    crate::args::Cli::command().debug_assert();
}
