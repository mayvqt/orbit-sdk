//! Argument dispatch, credential resolution and error reporting.

use crate::{
    api::{self, Api, Response},
    args::{Cli, Command, Global},
    config, credentials, licences, releases,
};
use clap::Parser;
use serde_json::Value;
use std::{
    ffi::OsString,
    io::{BufRead, Write},
};

pub trait Env {
    fn var(&self, name: &str) -> Option<String>;
}

pub struct SystemEnv;

impl Env for SystemEnv {
    fn var(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

#[derive(Debug)]
pub enum Failure {
    /// The invocation cannot run as given (exit status 2).
    Usage(String),
    /// The API rejected the request.
    Api {
        status: u16,
        code: String,
        message: String,
        request_id: Option<String>,
    },
    /// No complete response arrived.
    Transport(String),
    Other(String),
}

impl From<std::io::Error> for Failure {
    fn from(error: std::io::Error) -> Self {
        Self::Other(error.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Failure>;

pub struct Io<'a> {
    pub stdin: &'a mut dyn BufRead,
    pub stdin_terminal: bool,
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
}

pub struct Ctx<'a, 'b> {
    pub cli: Global,
    pub env: &'a dyn Env,
    pub io: &'a mut Io<'b>,
    used_key: Option<String>,
}

impl Ctx<'_, '_> {
    fn setting(&self, flag: Option<&String>, name: &str) -> Option<String> {
        flag.cloned()
            .or_else(|| self.env.var(name))
            .filter(|v| !v.is_empty())
    }

    pub fn profile_name(&self) -> Result<String> {
        let name = self
            .setting(self.cli.profile.as_ref(), "ORBIT_PROFILE")
            .unwrap_or_else(|| "default".into());
        if config::valid_profile_name(&name) {
            Ok(name)
        } else {
            Err(Failure::Usage(format!(
                "invalid profile name `{name}`; use letters, digits, `-` and `_`"
            )))
        }
    }

    pub fn application_id(&self) -> Option<String> {
        self.setting(self.cli.application_id.as_ref(), "ORBIT_APPLICATION_ID")
    }

    pub fn environment_id(&self) -> Option<String> {
        self.setting(self.cli.environment_id.as_ref(), "ORBIT_ENVIRONMENT_ID")
    }

    pub fn api_url(&self) -> Option<String> {
        self.setting(self.cli.api_url.as_ref(), "ORBIT_API_URL")
    }

    pub fn env_token(&self) -> Option<String> {
        self.env
            .var("ORBIT_MANAGEMENT_TOKEN")
            .filter(|v| !v.is_empty())
    }

    /// Connect with the token from `ORBIT_MANAGEMENT_TOKEN` or the saved
    /// profile; flags and environment variables override saved settings.
    pub fn api(&self) -> Result<Api> {
        let profile_name = self.profile_name()?;
        let token = self.env_token();
        let application = self.application_id();
        let environment = self.environment_id();
        let profile = if token.is_none() || application.is_none() || environment.is_none() {
            config::load(&config::directory(self.env)?)?
                .profiles
                .remove(&profile_name)
        } else {
            None
        };
        let token = match (token, &profile) {
            (Some(token), _) if config::valid_token(&token) => token,
            (Some(_), _) => {
                return Err(Failure::Usage(
                    "ORBIT_MANAGEMENT_TOKEN is not an Orbit management token".into(),
                ));
            }
            (None, Some(profile)) if config::valid_token(&profile.token) => profile.token.clone(),
            (None, Some(_)) => {
                return Err(Failure::Usage(format!(
                    "the saved token for profile `{profile_name}` is malformed; run `orbit credentials set`"
                )));
            }
            (None, None) => {
                return Err(Failure::Usage(format!(
                    "no management token for profile `{profile_name}`; run `orbit credentials set` or set ORBIT_MANAGEMENT_TOKEN"
                )));
            }
        };
        let missing = |what: &str, flag: &str| {
            Failure::Usage(format!(
                "no {what}; pass {flag} or save it with `orbit credentials set`"
            ))
        };
        let application = application
            .or_else(|| profile.as_ref().map(|p| p.application_id.clone()))
            .ok_or_else(|| missing("application ID", "--application-id"))?;
        let environment = environment
            .or_else(|| profile.as_ref().map(|p| p.environment_id.clone()))
            .ok_or_else(|| missing("environment ID", "--environment-id"))?;
        let url = self
            .api_url()
            .or_else(|| profile.as_ref().and_then(|p| p.api_url.clone()))
            .unwrap_or_else(|| api::DEFAULT_URL.into());
        Api::new(api::base_url(&url)?, &token, application, environment)
    }

    /// The key for this invocation's operation: `--idempotency-key` or a new one.
    pub fn idempotency_key(&mut self) -> Result<String> {
        let key = match &self.cli.idempotency_key {
            Some(key) if crate::files::valid_idempotency_key(key) => key.clone(),
            Some(_) => {
                return Err(Failure::Usage(
                    "--idempotency-key must be 16 to 128 printable ASCII characters".into(),
                ));
            }
            None => crate::files::idempotency_key()?,
        };
        self.used_key = Some(key.clone());
        Ok(key)
    }

    /// Print the response JSON unchanged with `--json`, otherwise render it.
    pub fn emit(
        &mut self,
        response: &Response,
        render: impl FnOnce(&mut dyn Write, &Value) -> std::io::Result<()>,
    ) -> Result<()> {
        if self.cli.json {
            self.io.out.write_all(&response.body)?;
            if !response.body.ends_with(b"\n") {
                writeln!(self.io.out)?;
            }
        } else {
            render(self.io.out, &response.json()?)?;
        }
        Ok(())
    }

    /// Report a change that has no response body.
    pub fn done(&mut self, message: &str) -> Result<()> {
        if !self.cli.json {
            writeln!(self.io.out, "{message}")?;
        }
        Ok(())
    }
}

/// Run one invocation and return its exit status: 0 success, 1 API or other
/// failure, 2 usage error.
pub fn run<I, T>(args: I, env: &dyn Env, io: &mut Io<'_>) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let Cli { global, command } = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let text = error.render().to_string();
            return if error.use_stderr() {
                let _ = write!(io.err, "{text}");
                2
            } else {
                let _ = write!(io.out, "{text}");
                0
            };
        }
    };
    let mut ctx = Ctx {
        cli: global,
        env,
        io,
        used_key: None,
    };
    let result = match command {
        Command::Credentials(command) => credentials::run(&mut ctx, command),
        Command::Policies(command) => licences::policies(&mut ctx, command),
        Command::Licences(command) => licences::run(&mut ctx, command),
        Command::Releases(command) => releases::run(&mut ctx, command),
    };
    let Err(failure) = result else { return 0 };
    let err = &mut *ctx.io.err;
    let (status, uncertain) = match &failure {
        Failure::Usage(message) => {
            let _ = writeln!(err, "orbit: {message}");
            return 2;
        }
        Failure::Api {
            status,
            code,
            message,
            request_id,
        } => {
            let request = request_id
                .as_deref()
                .map(|id| format!(", request {}", crate::output::cell(&Value::from(id))))
                .unwrap_or_default();
            let _ = writeln!(
                err,
                "orbit: {}: {} (HTTP {status}{request})",
                crate::output::cell(&Value::from(code.as_str())),
                crate::output::cell(&Value::from(message.as_str()))
            );
            (1, *status >= 500 || *status == 429)
        }
        Failure::Transport(message) => {
            let _ = writeln!(err, "orbit: cannot reach Orbit: {message}");
            (1, true)
        }
        Failure::Other(message) => {
            let _ = writeln!(err, "orbit: {message}");
            (1, false)
        }
    };
    if let (true, Some(key)) = (uncertain, &ctx.used_key) {
        let _ = writeln!(
            err,
            "orbit: the change may have been applied; repeat the command with --idempotency-key {key}"
        );
    }
    status
}
