//! Opt-in signed-client evidence; never suspends a machine itself.

use crate::transport::tests::{Fixture, TRANSIENT};
use crate::{Access, Cancellation, Client, Config, Device, Error, Snapshot, clock};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;
use std::{
    io::{self, Write},
    time::Duration,
};

const LIFETIME: Duration = Duration::from_secs(30);

fn awake_clock() -> Duration {
    #[cfg(target_os = "windows")]
    {
        orbit_sdk_native::awake_clock()
    }
    #[cfg(target_os = "linux")]
    {
        let value = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
        assert!(value.tv_sec >= 0 && (0..1_000_000_000).contains(&value.tv_nsec));
        Duration::new(value.tv_sec as u64, value.tv_nsec as u32)
    }
}

fn timestamp(seconds: i64) -> String {
    let value = time::OffsetDateTime::from_unix_timestamp(seconds).unwrap();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        value.year(),
        u8::from(value.month()),
        value.day(),
        value.hour(),
        value.minute(),
        value.second()
    )
}

fn reply(offline: bool) -> String {
    jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER
        .install_default()
        .ok();
    let now = clock::wall().unwrap();
    let expires = now + LIFETIME.as_secs() as i64;
    let claims = json!({"iss":"https://orbit.example.test", "aud":"orbit:app:test",
        "sub":"licence", "jti":"sleep_fixture", "iat":now, "nbf":now, "exp":expires,
        "application_id":"app", "environment_id":"test", "activation_id":"activation",
        "installation_id":"installation_1234", "binding_mode":"none", "fingerprint":null,
        "fingerprint_provider":null, "policy_version":1, "entitlements":{"export":true},
        "refresh_after":expires, "offline_allowed":offline, "licence_expires_at":null});
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("orbit-access+jwt".into());
    header.kid = Some("test-key".into());
    let key = EncodingKey::from_ec_pem(include_bytes!("../tests/fixtures/es256-test-private.pem"))
        .unwrap();
    let token = jsonwebtoken::encode(&header, &claims, &key).unwrap();
    json!({"activation_id":"activation", "installation_id":"installation_1234",
        "credential":"s".repeat(43), "credential_expires_at":timestamp(now + 86400),
        "grant":token, "server_time":timestamp(now), "binding_mode":"none",
        "fingerprint_provider":null, "licence_expires_at":null, "secret_replay_expired":false})
    .to_string()
}

fn assert_expired(snapshot: Snapshot) {
    assert_eq!(snapshot.access, Access::Expired);
    assert!(snapshot.entitlements.is_empty());
    assert_eq!(snapshot.remaining_offline_seconds, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ORBIT_NATIVE_GRANT_SUSPEND_TEST=1 and actual native sleep for at least 45 seconds"]
async fn native_grant_expires_across_suspend() {
    assert_eq!(
        std::env::var("ORBIT_NATIVE_GRANT_SUSPEND_TEST").as_deref(),
        Ok("1")
    );
    let vectors = std::env::var_os("ORBIT_SDK_GRANT_VECTORS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../contracts/sdk/grants.json")
        });
    let corpus: serde_json::Value =
        serde_json::from_slice(&std::fs::read(vectors).unwrap()).unwrap();
    let jwks = corpus["jwks"].to_string();
    let cancel = Cancellation::new();
    let mut contexts = Vec::new();
    for offline in [false, true] {
        let fixture = Fixture::new().await;
        let client = Client::new(
            Config {
                application_id: "app".into(),
                environment_id: "test".into(),
                issuer: "https://orbit.example.test".into(),
            },
            Device {
                installation_id: "installation_1234".into(),
                fingerprint: None,
                fingerprint_provider: None,
            },
            fixture.transport.clone(),
        )
        .unwrap();
        contexts.push((offline, client, fixture));
    }
    let active_start = awake_clock();
    let elapsed_start = clock::elapsed_clock().unwrap();
    for (offline, client, fixture) in &mut contexts {
        let operation = client.activate("synthetic licence", "sleep_operation_1234", &cancel);
        let serve = async {
            let activation = fixture.next().await;
            assert!(
                activation
                    .head
                    .starts_with("POST /api/client/v1/activations ")
            );
            activation.respond(200, &reply(*offline));
            let keys = fixture.next().await;
            assert!(keys.head.starts_with("GET /.well-known/orbit-jwks.json?"));
            keys.respond(200, &jwks);
        };
        let (accepted, ()) = tokio::join!(operation, serve);
        let accepted = accepted.unwrap();
        assert_eq!(accepted.access, Access::Online);
        assert_eq!(accepted.offline_allowed, *offline);
    }
    // From here the fixture can only return transient failures; no signing or
    // successful activation/refresh response is reachable after READY.
    for (_, client, fixture) in &mut contexts {
        assert_eq!(
            client
                .require_access("export", &cancel)
                .await
                .unwrap()
                .access,
            Access::Online
        );
        fixture.assert_idle();
    }
    println!(
        "READY: strict-online and offline-allowed grants accepted; refresh blocked. Suspend immediately for at least 45 seconds, then press Enter after resume."
    );
    io::stdout().flush().unwrap();
    assert!(
        io::stdin().read_line(&mut String::new()).unwrap() > 0,
        "EOF is not a resume acknowledgement"
    );
    let elapsed = clock::elapsed_clock()
        .unwrap()
        .checked_sub(elapsed_start)
        .unwrap();
    let active = awake_clock().checked_sub(active_start).unwrap();
    let slept = elapsed
        .checked_sub(active)
        .expect("Native elapsed clock moved backwards");
    assert!(
        slept >= Duration::from_secs(45),
        "At least 45 seconds of actual native sleep required"
    );
    assert!(
        active < LIFETIME,
        "Too much awake time; expiry during sleep was not established"
    );
    for (_, client, fixture) in &mut contexts {
        assert_expired(client.snapshot().unwrap());
        let denied = client.require_access("export", &cancel);
        tokio::pin!(denied);
        let mut blocked = 0;
        let result = loop {
            tokio::select! {
                result = &mut denied => break result,
                request = fixture.next() => {
                    assert!(request.head.starts_with("POST /api/client/v1/activations/activation/validate "));
                    blocked += 1;
                    request.respond(503, TRANSIENT);
                }
            }
        };
        assert!(
            matches!(result, Err(Error::Denied { ref code, .. }) if code == "access_unavailable")
        );
        assert!(
            blocked > 0,
            "Expired protected access did not attempt its blocked refresh"
        );
        assert_expired(client.snapshot().unwrap());
        fixture.assert_idle();
    }
    println!(
        "PASS: both signed grants expired during native sleep; access and entitlements denied. elapsed={elapsed:?}, awake={active:?}, sleep={slept:?}"
    );
}
