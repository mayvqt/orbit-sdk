//! `orbit credentials`: the local token store.

use crate::{
    api,
    app::{Ctx, Failure, Result},
    args::Credentials,
    config::{self, Profile},
};
use serde_json::json;
use std::io::{BufRead, Read};

pub fn run(ctx: &mut Ctx, command: Credentials) -> Result<()> {
    match command {
        Credentials::Set => set(ctx),
        Credentials::Show => show(ctx),
        Credentials::Remove => remove(ctx),
    }
}

fn read_token(ctx: &mut Ctx) -> Result<String> {
    let mut token = String::new();
    if ctx.io.stdin_terminal {
        token = rpassword::prompt_password("Management token: ")?;
    } else {
        (&mut *ctx.io.stdin).take(4096).read_line(&mut token)?;
    }
    let token = token.trim().to_owned();
    if config::valid_token(&token) {
        Ok(token)
    } else {
        Err(Failure::Usage(
            "expected an Orbit management token (orb_mgmt_…) on standard input".into(),
        ))
    }
}

fn set(ctx: &mut Ctx) -> Result<()> {
    let name = ctx.profile_name()?;
    let required = |value: Option<String>, flag: &str| {
        value.ok_or_else(|| Failure::Usage(format!("`orbit credentials set` needs {flag}")))
    };
    let application_id = required(ctx.application_id(), "--application-id")?;
    let environment_id = required(ctx.environment_id(), "--environment-id")?;
    let api_url = ctx.cli.api_url.clone();
    if let Some(url) = &api_url {
        api::base_url(url)?;
    }
    let dir = config::directory(ctx.env)?;
    let mut store = config::load(&dir)?;
    let token = read_token(ctx)?;
    let redacted = config::redact(&token);
    store.profiles.insert(
        name.clone(),
        Profile {
            token,
            application_id,
            environment_id,
            api_url,
        },
    );
    config::save(&dir, &store)?;
    writeln!(
        ctx.io.out,
        "Saved {redacted} as profile `{name}` in {}.",
        dir.join(config::FILE_NAME).display()
    )?;
    Ok(())
}

fn show(ctx: &mut Ctx) -> Result<()> {
    let name = ctx.profile_name()?;
    let dir = config::directory(ctx.env)?;
    let saved = config::load(&dir)?.profiles.remove(&name);
    let env_token = ctx.env_token();
    let (token, source) = match (&env_token, &saved) {
        (Some(token), _) => (token.as_str(), "ORBIT_MANAGEMENT_TOKEN"),
        (None, Some(profile)) => (profile.token.as_str(), "saved profile"),
        (None, None) => {
            return Err(Failure::Other(format!(
                "no credentials for profile `{name}`; run `orbit credentials set`"
            )));
        }
    };
    let value = json!({
        "profile": name,
        "token": config::redact(token),
        "token_source": source,
        "application_id": ctx.application_id()
            .or_else(|| saved.as_ref().map(|p| p.application_id.clone())),
        "environment_id": ctx.environment_id()
            .or_else(|| saved.as_ref().map(|p| p.environment_id.clone())),
        "api_url": ctx.api_url()
            .or_else(|| saved.as_ref().and_then(|p| p.api_url.clone()))
            .unwrap_or_else(|| api::DEFAULT_URL.into()),
        "file": dir.join(config::FILE_NAME).display().to_string(),
    });
    if ctx.cli.json {
        writeln!(ctx.io.out, "{value}")?;
    } else {
        crate::output::fields(
            ctx.io.out,
            &value,
            &[
                "profile",
                "token",
                "token_source",
                "application_id",
                "environment_id",
                "api_url",
                "file",
            ],
        )?;
    }
    Ok(())
}

fn remove(ctx: &mut Ctx) -> Result<()> {
    let name = ctx.profile_name()?;
    let dir = config::directory(ctx.env)?;
    let mut store = config::load(&dir)?;
    if store.profiles.remove(&name).is_none() {
        return Err(Failure::Other(format!("no saved profile `{name}`")));
    }
    config::save(&dir, &store)?;
    ctx.done(&format!("Removed profile `{name}`."))
}
