//! `orbit policies` and `orbit licences change-policy`.

use crate::{
    app::{Ctx, Failure, Result},
    args::{Expiry, Policies, PolicyTerms},
    files,
    output::{cell, fields, table},
};
use serde_json::{Map, Value, json};
use std::io::{BufRead, Read, Write};

const POLICY_FIELDS: &[&str] = &[
    "id",
    "name",
    "version",
    "expiry_mode",
    "duration_seconds",
    "fixed_expires_at",
    "device_limit",
    "hwid_locked",
    "offline_allowed",
    "offline_seconds",
    "offline_file_seconds",
    "concurrent_session_limit",
    "entitlements",
    "usage_limits",
    "resource_limits",
    "created_at",
];

/// The policy fields that creating a policy accepts.
const TERMS: &[&str] = &[
    "name",
    "expiry_mode",
    "duration_seconds",
    "fixed_expires_at",
    "device_limit",
    "hwid_locked",
    "offline_allowed",
    "offline_seconds",
    "offline_file_seconds",
    "concurrent_session_limit",
    "usage_limits",
    "resource_limits",
    "entitlements",
];

/// Licence terms a policy change shows, each with a `previous_` counterpart.
const CHANGED_TERMS: &[&str] = &[
    "expires_at",
    "duration_seconds",
    "device_limit",
    "hwid_locked",
    "entitlements",
    "concurrent_session_limit",
    "offline_allowed",
];

/// Most licences one policy-change request accepts.
const BATCH: usize = 100;

pub fn run(ctx: &mut Ctx, command: Policies) -> Result<()> {
    match command {
        Policies::List => {
            let response = ctx.api()?.get(&["policies"], &[])?;
            ctx.emit(&response, |out, value| {
                let rows = value.as_array().cloned().unwrap_or_default();
                table(
                    out,
                    &["id", "name", "version", "expiry_mode", "device_limit"],
                    &rows,
                )
            })
        }
        Policies::Create(terms) => create(ctx, *terms),
    }
}

/// Parse `--entitlement NAME` or `NAME=true|false`.
fn entitlement(value: &str) -> Result<(String, bool)> {
    let (name, on) = match value.split_once('=') {
        None => (value, true),
        Some((name, "true")) => (name, true),
        Some((name, "false")) => (name, false),
        Some(_) => {
            return Err(Failure::Usage(format!(
                "invalid entitlement `{value}`; use NAME, NAME=true or NAME=false"
            )));
        }
    };
    if name.is_empty() {
        return Err(Failure::Usage("entitlement names cannot be empty".into()));
    }
    Ok((name.to_owned(), on))
}

/// Policy fields the flags set, parsed before any request.
struct Changes {
    fields: Vec<(&'static str, Value)>,
    add: Vec<(String, bool)>,
    remove: Vec<String>,
}

fn changes(flags: PolicyTerms) -> Result<Changes> {
    let mut fields = Vec::new();
    if let Some(name) = flags.name {
        fields.push(("name", json!(name)));
    }
    if let Some(expiry) = flags.expiry {
        fields.push((
            "expiry_mode",
            json!(match expiry {
                Expiry::Perpetual => "perpetual",
                Expiry::Fixed => "fixed",
                Expiry::FirstActivation => "first_activation",
            }),
        ));
        // A copied lifetime or end date belongs only to its own expiry mode.
        if expiry != Expiry::FirstActivation {
            fields.push(("duration_seconds", Value::Null));
        }
        if expiry != Expiry::Fixed {
            fields.push(("fixed_expires_at", Value::Null));
        }
    }
    if let Some(duration) = flags.duration {
        fields.push((
            "duration_seconds",
            json!(files::duration_seconds(&duration)?),
        ));
    }
    if let Some(expires_at) = flags.expires_at {
        fields.push(("fixed_expires_at", json!(expires_at)));
    }
    if let Some(limit) = flags.device_limit {
        fields.push(("device_limit", json!(limit)));
    }
    if let Some(locked) = flags.hwid_locked {
        fields.push(("hwid_locked", json!(locked)));
    }
    if let Some(offline) = flags.offline {
        fields.push(("offline_allowed", json!(offline)));
        if !offline {
            fields.push(("offline_seconds", json!(0)));
        }
    }
    if let Some(allowance) = flags.offline_allowance {
        fields.push((
            "offline_seconds",
            json!(files::duration_seconds(&allowance)?),
        ));
    }
    if let Some(allowance) = flags.offline_file_allowance {
        let seconds = if allowance == "0" {
            0
        } else {
            files::duration_seconds(&allowance)?
        };
        fields.push(("offline_file_seconds", json!(seconds)));
    }
    if let Some(sessions) = flags.concurrent_sessions {
        fields.push(("concurrent_session_limit", json!(sessions)));
    }
    let add = flags
        .entitlement
        .iter()
        .map(|value| entitlement(value))
        .collect::<Result<Vec<_>>>()?;
    if let Some((name, _)) = add
        .iter()
        .find(|(n, _)| flags.remove_entitlement.contains(n))
    {
        return Err(Failure::Usage(format!(
            "`{name}` is both added and removed"
        )));
    }
    Ok(Changes {
        fields,
        add,
        remove: flags.remove_entitlement,
    })
}

impl Changes {
    fn apply(self, terms: &mut Map<String, Value>) -> Result<()> {
        for (name, value) in self.fields {
            terms.insert(name.into(), value);
        }
        let mut entitlements = terms
            .get("entitlements")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        for name in self.remove {
            if entitlements.remove(&name).is_none() {
                return Err(Failure::Usage(format!(
                    "the policy has no entitlement `{name}` to remove"
                )));
            }
        }
        for (name, on) in self.add {
            entitlements.insert(name, Value::Bool(on));
        }
        terms.insert("entitlements".into(), Value::Object(entitlements));
        Ok(())
    }
}

fn create(ctx: &mut Ctx, flags: PolicyTerms) -> Result<()> {
    let mut terms = Map::new();
    if flags.from.is_none() {
        let missing: Vec<&str> = [
            ("--name", flags.name.is_none()),
            ("--expiry", flags.expiry.is_none()),
            ("--device-limit", flags.device_limit.is_none()),
            ("--hwid-locked", flags.hwid_locked.is_none()),
        ]
        .into_iter()
        .filter_map(|(flag, absent)| absent.then_some(flag))
        .collect();
        if !missing.is_empty() {
            return Err(Failure::Usage(format!(
                "pass {}, or start from an existing policy with --from",
                missing.join(", ")
            )));
        }
        let defaults = json!({
            "duration_seconds": null,
            "fixed_expires_at": null,
            "offline_allowed": false,
            "offline_seconds": 0,
            "offline_file_seconds": 0,
            "concurrent_session_limit": 0,
            "usage_limits": {},
            "resource_limits": {},
            "entitlements": {},
        });
        if let Value::Object(defaults) = defaults {
            terms = defaults;
        }
    }
    let from = flags.from.clone();
    let changes = changes(flags)?;
    let api = ctx.api()?;
    if let Some(id) = from {
        let policies = api.get(&["policies"], &[])?.json()?;
        let policy = policies
            .as_array()
            .and_then(|list| list.iter().find(|p| p["id"] == id.as_str()))
            .ok_or_else(|| {
                Failure::Other(format!(
                    "policy `{id}` is not one of this environment's 100 most recent policy versions"
                ))
            })?;
        terms = TERMS
            .iter()
            .map(|name| ((*name).to_owned(), policy[*name].clone()))
            .collect();
    }
    changes.apply(&mut terms)?;
    let response = api.post(&["policies"], &Value::Object(terms))?;
    ctx.emit(&response, |out, value| fields(out, value, POLICY_FIELDS))
}

fn items(page: &Value) -> &[Value] {
    page["items"].as_array().map_or(&[], Vec::as_slice)
}

/// Combine batch responses into one response of the same shape.
fn merged(pages: &[Value]) -> Value {
    let first = pages.first().cloned().unwrap_or_else(|| json!({}));
    json!({
        "policy_id": first["policy_id"],
        "policy_name": first["policy_name"],
        "policy_version": first["policy_version"],
        "items": pages.iter().flat_map(items).cloned().collect::<Vec<_>>(),
    })
}

fn policy_label(name: &Value, version: &Value) -> String {
    format!("{} version {}", cell(name), cell(version))
}

/// Print each licence's terms as `previous -> new`, or once when unchanged.
fn render_preview(out: &mut dyn Write, preview: &Value) -> std::io::Result<()> {
    let target = policy_label(&preview["policy_name"], &preview["policy_version"]);
    let width = CHANGED_TERMS.iter().map(|n| n.len()).max().unwrap_or(0);
    let shown = |value: &Value| {
        let text = cell(value);
        if text.is_empty() { "none".into() } else { text }
    };
    for item in items(preview) {
        let id = cell(&item["licence_id"]);
        if item["changed"] == Value::Bool(false) {
            writeln!(out, "{id}: already on {target}")?;
            continue;
        }
        let previous = policy_label(
            &item["previous_policy_name"],
            &item["previous_policy_version"],
        );
        writeln!(out, "{id}: {previous} -> {target}")?;
        for name in CHANGED_TERMS {
            let (before, after) = (&item[format!("previous_{name}")], &item[*name]);
            let text = if before == after {
                shown(after)
            } else {
                format!("{} -> {}", shown(before), shown(after))
            };
            writeln!(out, "  {name:<width$}  {text}")?;
        }
    }
    Ok(())
}

/// Preview moving `ids` to `policy`, confirm, then apply with the previewed
/// revisions so a licence that changed in between is not moved.
pub fn change(
    ctx: &mut Ctx,
    policy: &str,
    reason: &str,
    yes: bool,
    licences: Vec<String>,
) -> Result<()> {
    let mut ids: Vec<String> = Vec::new();
    for id in licences {
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    let api = ctx.api()?;
    let mut previews = Vec::new();
    for batch in ids.chunks(BATCH) {
        let body = json!({"licence_ids": batch, "policy_id": policy});
        previews.push(
            api.post(&["licences", "policy-changes", "preview"], &body)?
                .json()?,
        );
    }
    let pending: Vec<Vec<Value>> = previews
        .iter()
        .map(|preview| {
            items(preview)
                .iter()
                .filter(|item| item["changed"] != Value::Bool(false))
                .map(|item| json!({"id": item["licence_id"], "revision": item["revision"]}))
                .collect()
        })
        .collect();
    let count: usize = pending.iter().map(Vec::len).sum();
    let json_output = ctx.cli.json;
    // Keep standard output to the final JSON document with --json.
    let preview_out: &mut dyn Write = if json_output {
        &mut *ctx.io.err
    } else {
        &mut *ctx.io.out
    };
    for preview in &previews {
        render_preview(preview_out, preview)?;
    }
    let all = merged(&previews);
    let target = policy_label(&all["policy_name"], &all["policy_version"]);
    if count == 0 {
        return if json_output {
            writeln!(ctx.io.out, "{all}").map_err(Failure::from)
        } else {
            ctx.done(&format!("Every licence is already on {target}."))
        };
    }
    if !yes {
        if !ctx.io.stdin_terminal {
            return Err(Failure::Usage(
                "no licences changed; add --yes to apply without a prompt".into(),
            ));
        }
        write!(ctx.io.err, "Move {count} licence(s) to {target}? [y/N] ")?;
        ctx.io.err.flush()?;
        let mut answer = String::new();
        (&mut *ctx.io.stdin).take(64).read_line(&mut answer)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            return Err(Failure::Other("cancelled; no licences changed".into()));
        }
    }
    let mut results = Vec::new();
    for batch in pending.iter().filter(|batch| !batch.is_empty()) {
        let body = json!({"licences": batch, "policy_id": policy, "reason": reason});
        match api.post(&["licences", "policy-changes"], &body) {
            Ok(response) => results.push(response.json()?),
            Err(error) => {
                let moved: usize = results.iter().map(|r| items(r).len()).sum();
                if moved > 0 {
                    writeln!(
                        ctx.io.err,
                        "orbit: {moved} licence(s) moved to {target} before this failure"
                    )?;
                }
                return Err(error);
            }
        }
    }
    let result = merged(&results);
    if json_output {
        writeln!(ctx.io.out, "{result}")?;
        return Ok(());
    }
    let moved = items(&result)
        .iter()
        .filter(|item| item["changed"] != Value::Bool(false))
        .count();
    ctx.done(&format!("Moved {moved} licence(s) to {target}."))
}
