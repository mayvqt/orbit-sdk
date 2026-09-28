//! `orbit releases`.

use crate::{
    app::{Ctx, Failure, Result},
    args::{Delivery, Notes, Releases},
    files,
    output::{fields, next_page, table},
};
use reqwest::Method;
use serde_json::{Value, json};
use std::io::Write;

const ARTIFACT_COLUMNS: &[&str] = &[
    "id",
    "platform",
    "architecture",
    "filename",
    "byte_length",
    "delivery_mode",
    "required_feature",
];

fn release(out: &mut dyn Write, value: &Value) -> std::io::Result<()> {
    fields(
        out,
        value,
        &[
            "id",
            "channel",
            "version",
            "state",
            "release_number",
            "created_at",
            "published_at",
            "notes",
        ],
    )?;
    let artifacts = value["artifacts"].as_array().cloned().unwrap_or_default();
    writeln!(out)?;
    if artifacts.is_empty() {
        return writeln!(out, "No files.");
    }
    table(out, ARTIFACT_COLUMNS, &artifacts)
}

fn notes(notes: Notes) -> Result<Option<String>> {
    match (notes.notes, notes.notes_file) {
        (Some(text), _) => Ok(Some(text)),
        (None, Some(path)) => std::fs::read_to_string(&path)
            .map(Some)
            .map_err(|e| Failure::Usage(format!("{}: {e}", path.display()))),
        (None, None) => Ok(None),
    }
}

fn publication(ctx: &mut Ctx, id: &str, action: &str) -> Result<()> {
    let api = ctx.api()?;
    let body = json!({"idempotency_key": ctx.idempotency_key()?});
    let response = api.post(&["releases", id, action], &body)?;
    ctx.emit(&response, release)
}

pub fn run(ctx: &mut Ctx, command: Releases) -> Result<()> {
    match command {
        Releases::List {
            channel,
            limit,
            after,
        } => {
            let limit = limit.map(|l| l.to_string());
            let mut query = Vec::new();
            if let Some(channel) = &channel {
                query.push(("channel", channel.as_str()));
            }
            if let Some(limit) = &limit {
                query.push(("limit", limit));
            }
            if let Some(after) = &after {
                query.push(("after", after));
            }
            let response = ctx.api()?.get(&["releases"], &query)?;
            ctx.emit(&response, |out, page| {
                let rows: Vec<Value> = page["items"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|mut r| {
                        r["files"] = json!(r["artifacts"].as_array().map_or(0, Vec::len));
                        r
                    })
                    .collect();
                table(
                    out,
                    &[
                        "id",
                        "channel",
                        "version",
                        "state",
                        "release_number",
                        "files",
                        "published_at",
                    ],
                    &rows,
                )?;
                next_page(out, page)
            })
        }
        Releases::Show { release: id } => {
            let response = ctx.api()?.get(&["releases", &id], &[])?;
            ctx.emit(&response, release)
        }
        Releases::Create {
            version,
            channel,
            notes: text,
        } => {
            let notes = notes(text)?.unwrap_or_default();
            let api = ctx.api()?;
            let body = json!({
                "channel": channel,
                "version": version,
                "notes": notes,
                "idempotency_key": ctx.idempotency_key()?,
            });
            let response = api.post(&["releases"], &body)?;
            ctx.emit(&response, release)
        }
        Releases::Edit {
            release: id,
            version,
            channel,
            notes: text,
        } => {
            let notes = notes(text)?;
            if version.is_none() && channel.is_none() && notes.is_none() {
                return Err(Failure::Usage(
                    "pass --version, --channel, --notes or --notes-file".into(),
                ));
            }
            let api = ctx.api()?;
            // The API replaces complete metadata, so keep unchanged fields.
            let current = api.get(&["releases", &id], &[])?.json()?;
            let keep = |name: &str| current[name].as_str().unwrap_or_default().to_owned();
            let body = json!({
                "channel": channel.unwrap_or_else(|| keep("channel")),
                "version": version.unwrap_or_else(|| keep("version")),
                "notes": notes.unwrap_or_else(|| keep("notes")),
                "idempotency_key": ctx.idempotency_key()?,
            });
            let response = api.send(Method::PATCH, &["releases", &id], &[], Some(&body))?;
            ctx.emit(&response, release)
        }
        Releases::AddArtifact {
            release: id,
            file,
            url,
            platform,
            architecture,
            filename,
            required_feature,
            delivery,
        } => {
            if !url.starts_with("https://") {
                return Err(Failure::Usage("--url must be an https:// URL".into()));
            }
            let filename = match filename {
                Some(name) => name,
                None => file
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(str::to_owned)
                    .ok_or_else(|| Failure::Usage("pass --filename for this file name".into()))?,
            };
            let digest = files::digest_file(&file)?;
            let api = ctx.api()?;
            let body = json!({
                "platform": platform,
                "architecture": architecture,
                "filename": filename,
                "byte_length": digest.byte_length,
                "sha256": digest.sha256,
                "delivery_mode": match delivery {
                    Delivery::Public => "public",
                    Delivery::Protected => "protected",
                },
                "url": url,
                "required_feature": required_feature,
                "idempotency_key": ctx.idempotency_key()?,
            });
            let response = api.post(&["releases", &id, "artifacts"], &body)?;
            ctx.emit(&response, |out, artifact| {
                fields(
                    out,
                    artifact,
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
                )
            })
        }
        Releases::RemoveArtifact {
            release: id,
            artifact,
        } => {
            let api = ctx.api()?;
            let body = json!({"idempotency_key": ctx.idempotency_key()?});
            api.send(
                Method::DELETE,
                &["releases", &id, "artifacts", &artifact],
                &[],
                Some(&body),
            )?;
            ctx.done("File removed.")
        }
        Releases::Publish { release: id } => publication(ctx, &id, "publish"),
        Releases::Unpublish { release: id } => publication(ctx, &id, "unpublish"),
    }
}
