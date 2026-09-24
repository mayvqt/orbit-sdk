//! Fixed secret-tool invocation with bounded, private pipes and a hard deadline.

use super::format::MAX_STDOUT;
use crate::{Error, Result};
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use std::{
    io::{ErrorKind, Read, Write},
    os::fd::AsFd,
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

const MAX_STDERR: usize = 4096;
const DEADLINE: Duration = Duration::from_secs(5);
const EXECUTABLE: &str = "/usr/bin/secret-tool";

struct Reap(Child);
impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Output {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn nonblocking(fd: impl AsFd) -> Result<()> {
    let flags = fcntl_getfl(&fd).map_err(|_| Error::Storage)?;
    fcntl_setfl(fd, flags | OFlags::NONBLOCK).map_err(|_| Error::Storage)
}

fn drain(reader: &mut impl Read, bytes: &mut Vec<u8>, limit: usize) -> Result<bool> {
    let mut buffer = [0; 1024];
    loop {
        let length = buffer.len().min(limit - bytes.len() + 1);
        match reader.read(&mut buffer[..length]) {
            Ok(0) => return Ok(true),
            Ok(length) => {
                if bytes.len() + length > limit {
                    return Err(Error::Storage);
                }
                bytes.extend_from_slice(&buffer[..length]);
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err(Error::Storage),
        }
    }
}

fn run(command: &mut Command, input: &[u8], timeout: Duration) -> Result<Output> {
    let started = Instant::now();
    let child = Reap(
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| Error::Storage)?,
    );
    run_with_pipes(child, input, started, timeout)
}

fn run_with_pipes(
    mut child: Reap,
    input: &[u8],
    started: Instant,
    timeout: Duration,
) -> Result<Output> {
    let mut stdin = child.0.stdin.take();
    let mut stdout = child.0.stdout.take().ok_or(Error::Storage)?;
    let mut stderr = child.0.stderr.take().ok_or(Error::Storage)?;
    nonblocking(stdin.as_ref().ok_or(Error::Storage)?)?;
    nonblocking(&stdout)?;
    nonblocking(&stderr)?;
    let mut written = 0;
    let mut out = Vec::new();
    let mut err = Vec::new();
    loop {
        if started.elapsed() >= timeout {
            return Err(Error::Storage);
        }
        if written == input.len() {
            stdin = None;
        } else if let Some(stdin) = &mut stdin {
            match stdin.write(&input[written..]) {
                Ok(0) => return Err(Error::Storage),
                Ok(length) => written += length,
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
                Err(_) => return Err(Error::Storage),
            }
        }
        let stdout_done = drain(&mut stdout, &mut out, MAX_STDOUT)?;
        let stderr_done = drain(&mut stderr, &mut err, MAX_STDERR)?;
        if let Some(status) = child.0.try_wait().map_err(|_| Error::Storage)?
            && stdout_done
            && stderr_done
        {
            if written != input.len() {
                return Err(Error::Storage);
            }
            return Ok(Output {
                status,
                stdout: out,
                stderr: err,
            });
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn command(operation: &str, scope: &str) -> Command {
    let mut command = Command::new(EXECUTABLE);
    command.arg(operation);
    if operation == "store" {
        command.args(["--label=Orbit Rust SDK activation", "--collection=default"]);
    }
    command.args(["application", "orbit-sdk", "sdk", "rust", "scope", scope]);
    command
}

pub(super) fn lookup(scope: &str) -> Result<Option<Vec<u8>>> {
    classify_lookup(run(&mut command("lookup", scope), &[], DEADLINE)?)
}

fn classify_lookup(output: Output) -> Result<Option<Vec<u8>>> {
    if !output.stderr.is_empty() {
        return Err(Error::Storage);
    }
    if output.status.success() {
        return Ok(Some(output.stdout));
    }
    if output.status.code() == Some(1) && output.stdout.is_empty() {
        return Ok(None);
    }
    Err(Error::Storage)
}

pub(super) fn store(scope: &str, record: &[u8]) -> Result<()> {
    if record.len() > super::format::MAX_BASE64 {
        return Err(Error::Storage);
    }
    let output = run(&mut command("store", scope), record, DEADLINE)?;
    if !output.status.success() || !output.stdout.is_empty() || !output.stderr.is_empty() {
        return Err(Error::Storage);
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn clear(scope: &str) -> Result<()> {
    let output = run(&mut command("clear", scope), &[], DEADLINE)?;
    if !output.status.success() || !output.stdout.is_empty() || !output.stderr.is_empty() {
        return Err(Error::Storage);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn only_quiet_exit_one_means_missing() {
        for (code, stdout, stderr, missing) in [
            (1, b"".as_slice(), b"".as_slice(), true),
            (1, b"diagnostic", b"", false),
            (1, b"", b"diagnostic", false),
            (2, b"", b"", false),
            (0, b"record", b"diagnostic", false),
        ] {
            let value = classify_lookup(Output {
                status: ExitStatus::from_raw(code << 8),
                stdout: stdout.to_vec(),
                stderr: stderr.to_vec(),
            });
            assert_eq!(matches!(value, Ok(None)), missing);
            if !missing {
                assert!(value.is_err());
            }
        }
    }

    #[test]
    fn bounded_pipes_capture_both_streams_and_send_stdin_without_argv_secrets() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "cat; printf diagnostic >&2"]);
        let output = run(
            &mut command,
            b"synthetic-private-input",
            Duration::from_secs(10),
        )
        .unwrap();
        assert!(output.status.success());
        assert!(output.stdout == b"synthetic-private-input");
        assert!(output.stderr == b"diagnostic");
        for script in ["head -c 5466 /dev/zero", "head -c 4097 /dev/zero >&2"] {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", script]);
            assert!(matches!(
                run(&mut command, &[], Duration::from_secs(10)),
                Err(Error::Storage)
            ));
        }
    }

    #[test]
    fn deadline_kills_reaps_and_redacts_the_helper() {
        let started = Instant::now();
        let child = Reap(
            Command::new("/usr/bin/sleep")
                .arg("30")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let pid = child.0.id();
        let error = match run_with_pipes(child, &[], started, Duration::ZERO) {
            Ok(_) => panic!("Synthetic helper unexpectedly completed"),
            Err(error) => error,
        };
        assert!(
            !std::path::Path::new("/proc").join(pid.to_string()).exists(),
            "Synthetic helper was not reaped"
        );
        assert_eq!(format!("{error:?}"), "Credential storage failed");
        assert_eq!(format!("{error}"), "Credential storage failed");
    }
}
