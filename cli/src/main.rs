//! `orbit`: command-line tool for the Orbit management API.

mod api;
mod app;
mod args;
mod config;
mod credentials;
mod files;
mod licences;
mod output;
mod policies;
mod releases;
#[cfg(test)]
mod tests;

use std::{
    io::{IsTerminal, Write},
    process::ExitCode,
};

fn main() -> ExitCode {
    let stdin = std::io::stdin();
    let stdin_terminal = stdin.is_terminal();
    let mut stdin = stdin.lock();
    let mut out = std::io::stdout().lock();
    let mut err = std::io::stderr().lock();
    let status = app::run(
        std::env::args_os(),
        &app::SystemEnv,
        &mut app::Io {
            stdin: &mut stdin,
            stdin_terminal,
            out: &mut out,
            err: &mut err,
        },
    );
    let _ = out.flush();
    ExitCode::from(status)
}
