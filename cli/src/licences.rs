//! `orbit licences`.

use crate::{
    app::{Ctx, Failure, Result},
    args::{Licences, SearchStatus, SessionState},
    files,
    output::{fields, next_page, table},
    policies,
};
use serde_json::{Map, Value, json};
use std::io::Write;

const LICENCE_FIELDS: &[&str] = &[
    "id",
    "status",
    "state",
    "policy_name",
    "policy_version",
    "policy_id",
    "key_suffix",
    "key_generation",
    "expiry_mode",
    "duration_seconds",
    "first_used_at",
    "expires_at",
    "device_limit",
    "hwid_locked",
    "concurrent_session_limit",
    "offline_allowed",
    "entitlements",
    "reference",
    "note",
    "customer_id",
    "created_at",
    "transfer_retry_at",
];

fn licence(out: &mut dyn Write, value: &Value) -> std::io::Result<()> {
    fields(out, value, LICENCE_FIELDS)
}

/// Print newly disclosed keys; Orbit returns them only to this response.
fn keys(out: &mut dyn Write, value: &Value) -> std::io::Result<()> {
    if value["secret_replay_expired"] == Value::Bool(true) {
        return writeln!(
            out,
            "These keys were returned by the original request and are no longer available."
        );
    }
    let rows = value["keys"].as_array().cloned().unwrap_or_default();
    table(out, &["licence_id", "key"], &rows)?;
    writeln!(out, "Store these keys now; Orbit does not show them again.")
}

fn status(ctx: &mut Ctx, id: &str, status: &str, reason: String) -> Result<()> {
    let response = ctx.api()?.post(
        &["licences", id, "status"],
        &json!({"status": status, "reason": reason}),
    )?;
    ctx.emit(&response, licence)
}

pub fn run(ctx: &mut Ctx, command: Licences) -> Result<()> {
    match command {
        Licences::List {
            query,
            status,
            after,
        } => {
            let mut body = json!({"query": query});
            if let Some(status) = status {
                body["status"] = json!(match status {
                    SearchStatus::Active => "active",
                    SearchStatus::Revoked => "revoked",
                    SearchStatus::All => "all",
                });
            }
            if let Some(after) = after {
                body["after"] = json!(after);
            }
            let response = ctx.api()?.post(&["licences", "search"], &body)?;
            ctx.emit(&response, |out, page| {
                let rows = page["items"].as_array().cloned().unwrap_or_default();
                table(
                    out,
                    &[
                        "id",
                        "key_suffix",
                        "policy_name",
                        "state",
                        "expires_at",
                        "reference",
                    ],
                    &rows,
                )?;
                next_page(out, page)
            })
        }
        Licences::ChangePolicy {
            policy,
            reason,
            yes,
            licences,
        } => policies::change(ctx, &policy, &reason.reason, yes, licences),
        Licences::Show { licence: id } => {
            let response = ctx.api()?.get(&["licences", &id], &[])?;
            ctx.emit(&response, licence)
        }
        Licences::Issue {
            policy,
            quantity,
            reference,
            note,
        } => {
            let api = ctx.api()?;
            let body = json!({
                "policy_id": policy,
                "quantity": quantity,
                "reference": reference,
                "note": note,
                "idempotency_key": ctx.idempotency_key()?,
            });
            let response = api.post(&["licences"], &body)?;
            ctx.emit(&response, keys)
        }
        Licences::Suspend { licence, reason } => status(ctx, &licence, "suspended", reason.reason),
        Licences::Reinstate { licence, reason } => status(ctx, &licence, "enabled", reason.reason),
        Licences::Revoke {
            licence,
            reason,
            yes,
        } => {
            if !yes {
                return Err(Failure::Usage(
                    "revocation cannot be undone; add --yes to confirm".into(),
                ));
            }
            status(ctx, &licence, "revoked", reason.reason)
        }
        Licences::Extend {
            licence: id,
            by,
            reason,
        } => {
            let seconds = files::duration_seconds(&by)?;
            let api = ctx.api()?;
            let body = json!({
                "seconds": seconds,
                "reason": reason.reason,
                "idempotency_key": ctx.idempotency_key()?,
            });
            let response = api.post(&["licences", &id, "extensions"], &body)?;
            ctx.emit(&response, licence)
        }
        Licences::Entitlements {
            licence: id,
            enable,
            disable,
            reason,
        } => {
            if enable.is_empty() && disable.is_empty() {
                return Err(Failure::Usage("pass --enable or --disable".into()));
            }
            if let Some(name) = enable.iter().find(|n| disable.contains(n)) {
                return Err(Failure::Usage(format!(
                    "`{name}` is both enabled and disabled"
                )));
            }
            let api = ctx.api()?;
            // The API replaces the whole map, so start from the current values.
            let current = api.get(&["licences", &id], &[])?.json()?;
            let mut entitlements = current["entitlements"]
                .as_object()
                .cloned()
                .unwrap_or_else(Map::new);
            for (names, on) in [(enable, true), (disable, false)] {
                for name in names {
                    entitlements.insert(name, Value::Bool(on));
                }
            }
            let response = api.post(
                &["licences", &id, "entitlements"],
                &json!({"entitlements": entitlements, "reason": reason.reason}),
            )?;
            ctx.emit(&response, licence)
        }
        Licences::Annotate {
            licence: id,
            reference,
            note,
            reason,
        } => {
            if reference.is_none() && note.is_none() {
                return Err(Failure::Usage("pass --reference or --note".into()));
            }
            let api = ctx.api()?;
            // Both fields are replaced, so keep the one that is not changing.
            let (reference, note) = match (reference, note) {
                (Some(reference), Some(note)) => (reference, note),
                (reference, note) => {
                    let current = api.get(&["licences", &id], &[])?.json()?;
                    let keep = |name: &str| current[name].as_str().unwrap_or_default().to_owned();
                    (
                        reference.unwrap_or_else(|| keep("reference")),
                        note.unwrap_or_else(|| keep("note")),
                    )
                }
            };
            let response = api.post(
                &["licences", &id, "annotations"],
                &json!({"reference": reference, "note": note, "reason": reason.reason}),
            )?;
            ctx.emit(&response, licence)
        }
        Licences::Devices { licence: id, after } => {
            let query: Vec<(&str, &str)> = after.iter().map(|a| ("after", a.as_str())).collect();
            let response = ctx.api()?.get(&["licences", &id, "devices"], &query)?;
            ctx.emit(&response, |out, page| {
                let rows = page["items"].as_array().cloned().unwrap_or_default();
                table(
                    out,
                    &[
                        "id",
                        "installation_id",
                        "active",
                        "fingerprint_provider",
                        "fingerprint_suffix",
                        "last_seen_at",
                    ],
                    &rows,
                )?;
                next_page(out, page)
            })
        }
        Licences::ResetDevice {
            licence: id,
            activation,
            reason,
        } => {
            let api = ctx.api()?;
            let body = json!({
                "activation_id": activation,
                "override_cooldown": false,
                "reason": reason.reason,
                "idempotency_key": ctx.idempotency_key()?,
            });
            api.post(&["licences", &id, "device-resets"], &body)?;
            ctx.done("Device released.")
        }
        Licences::ReplaceKey {
            licence: id,
            reason,
        } => {
            let api = ctx.api()?;
            let body = json!({
                "reason": reason.reason,
                "idempotency_key": ctx.idempotency_key()?,
            });
            let response = api.post(&["licences", &id, "key-replacements"], &body)?;
            ctx.emit(&response, keys)
        }
        Licences::Sessions {
            licence: id,
            state,
            limit,
            after,
        } => {
            let limit = limit.map(|l| l.to_string());
            let mut query = Vec::new();
            if let Some(state) = state {
                query.push((
                    "state",
                    match state {
                        SessionState::Active => "active",
                        SessionState::Ended => "ended",
                        SessionState::Expired => "expired",
                    },
                ));
            }
            if let Some(limit) = &limit {
                query.push(("limit", limit));
            }
            if let Some(after) = &after {
                query.push(("after", after));
            }
            let response = ctx.api()?.get(&["licences", &id, "sessions"], &query)?;
            ctx.emit(&response, |out, page| {
                let rows = page["items"].as_array().cloned().unwrap_or_default();
                table(
                    out,
                    &[
                        "session_id",
                        "activation_id",
                        "state",
                        "renewed_at",
                        "expires_at",
                        "ended_at",
                    ],
                    &rows,
                )?;
                next_page(out, page)
            })
        }
        Licences::EndSession {
            licence: id,
            session,
            reason,
        } => {
            let api = ctx.api()?;
            let body = json!({
                "reason": reason.reason,
                "idempotency_key": ctx.idempotency_key()?,
            });
            api.post(&["licences", &id, "sessions", &session, "end"], &body)?;
            ctx.done("Session ended.")
        }
        Licences::OfflineFile {
            licence: id,
            request,
            duration,
            output,
        } => {
            let duration_seconds = files::duration_seconds(&duration)?;
            let bytes = std::fs::read(&request)
                .map_err(|e| Failure::Other(format!("{}: {e}", request.display())))?;
            let request_json: Value = serde_json::from_slice(&bytes).map_err(|_| {
                Failure::Usage(format!(
                    "{} is not an offline request file",
                    request.display()
                ))
            })?;
            if output.exists() {
                return Err(Failure::Usage(format!(
                    "{} already exists",
                    output.display()
                )));
            }
            let api = ctx.api()?;
            let body = json!({
                "request": request_json,
                "duration_seconds": duration_seconds,
                "idempotency_key": ctx.idempotency_key()?,
            });
            let response = api.post(&["licences", &id, "offline-files"], &body)?;
            let issued = response.json()?;
            let file = issued["file"]
                .as_str()
                .ok_or_else(|| Failure::Other("the API response has no file".into()))?;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&output)
                .and_then(|mut f| f.write_all(file.as_bytes()).and_then(|()| f.sync_all()))
                .map_err(|e| Failure::Other(format!("{}: {e}", output.display())))?;
            ctx.emit(&response, |out, value| {
                fields(
                    out,
                    value,
                    &[
                        "issuance_id",
                        "activation_id",
                        "installation_id",
                        "sequence",
                        "issued_at",
                        "expires_at",
                    ],
                )?;
                writeln!(out, "Wrote {}.", output.display())
            })
        }
    }
}
