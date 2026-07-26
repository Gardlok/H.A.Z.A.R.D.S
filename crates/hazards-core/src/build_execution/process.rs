use std::{
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::BuildInvocationTemplate;

use super::materialize::directory_size_bounded;
use super::{BuildExecutionLimits, SourceBuildError, io_error};

const POLL_INTERVAL: Duration = Duration::from_millis(25);
const SIZE_POLL_INTERVAL: Duration = Duration::from_secs(1);
const TERMINATION_GRACE: Duration = Duration::from_secs(2);
const SIGTERM: i32 = 15;
const SIGKILL: i32 = 9;
const ESRCH: i32 = 3;

#[cfg(unix)]
unsafe extern "C" {
    fn kill(pid: i32, signal: i32) -> i32;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProcessOutcome {
    Succeeded,
    Failed,
    TimedOut,
    OutputLimitExceeded,
    FilesystemLimitExceeded,
    Ambiguous,
}

pub(super) struct ProcessReport {
    pub outcome: ProcessOutcome,
    pub started_at_unix: u64,
    pub finished_at_unix: u64,
    pub duration_millis: u64,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout_path: PathBuf,
    pub stderr_path: PathBuf,
    pub detail: String,
}

pub(super) fn run_controlled(
    invocation: &BuildInvocationTemplate,
    build_root: &Path,
    limits: BuildExecutionLimits,
) -> Result<ProcessReport, SourceBuildError> {
    if invocation.network_enabled {
        return Err(SourceBuildError::Process(
            "refusing an invocation that permits network access".to_owned(),
        ));
    }
    if !invocation.clear_environment {
        return Err(SourceBuildError::Process(
            "refusing an invocation that inherits the caller environment".to_owned(),
        ));
    }
    let stdout_path = build_root.join("stdout.capture");
    let stderr_path = build_root.join("stderr.capture");
    let stdout = create_capture(&stdout_path)?;
    let stderr = create_capture(&stderr_path)?;

    let started_wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| SourceBuildError::Clock(error.to_string()))?;
    let started = Instant::now();
    let timeout = Duration::from_secs(limits.timeout_seconds);

    let mut command = Command::new(&invocation.program);
    command
        .args(&invocation.arguments)
        .current_dir(&invocation.current_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    command.env_clear();
    for name in &invocation.remove_environment {
        command.env_remove(name);
    }
    command.envs(&invocation.fixed_environment);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    let mut child = command.spawn().map_err(|error| {
        SourceBuildError::Process(format!(
            "could not spawn {}: {error}",
            invocation.program.display()
        ))
    })?;
    let mut last_size_check = Instant::now();
    let (outcome, status, detail) = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let outcome = if status.success() {
                    ProcessOutcome::Succeeded
                } else {
                    ProcessOutcome::Failed
                };
                break (outcome, Some(status), format!("process exited with {status}"));
            }
            Ok(None) => {}
            Err(error) => {
                let termination = terminate_process_group(&mut child);
                let detail = match termination {
                    Ok(status) => format!(
                        "process status became unobservable ({error}); termination returned {status}"
                    ),
                    Err(kill_error) => format!(
                        "process status became unobservable ({error}) and termination was uncertain ({kill_error})"
                    ),
                };
                break (ProcessOutcome::Ambiguous, None, detail);
            }
        }

        let output_size = match (file_length(&stdout_path), file_length(&stderr_path)) {
            (Ok(stdout), Ok(stderr)) => stdout.saturating_add(stderr),
            (left, right) => {
                let error = left.err().or_else(|| right.err()).expect("one size failed");
                let status = terminate_process_group(&mut child).ok();
                break (
                    ProcessOutcome::Ambiguous,
                    status,
                    format!("could not observe build output size: {error}"),
                );
            }
        };
        if output_size > limits.maximum_output_bytes {
            let status = terminate_process_group(&mut child).ok();
            break (
                if status.is_some() {
                    ProcessOutcome::OutputLimitExceeded
                } else {
                    ProcessOutcome::Ambiguous
                },
                status,
                format!(
                    "combined output exceeded {} bytes",
                    limits.maximum_output_bytes
                ),
            );
        }
        if started.elapsed() > timeout {
            let status = terminate_process_group(&mut child).ok();
            break (
                if status.is_some() {
                    ProcessOutcome::TimedOut
                } else {
                    ProcessOutcome::Ambiguous
                },
                status,
                format!("build exceeded {} seconds", limits.timeout_seconds),
            );
        }
        if last_size_check.elapsed() >= SIZE_POLL_INTERVAL {
            last_size_check = Instant::now();
            let size = match directory_size_bounded(build_root, limits.maximum_build_bytes) {
                Ok(size) => size,
                Err(error) => {
                    let status = terminate_process_group(&mut child).ok();
                    break (
                        ProcessOutcome::Ambiguous,
                        status,
                        format!("could not observe build-tree size: {error}"),
                    );
                }
            };
            if size > limits.maximum_build_bytes {
                let status = terminate_process_group(&mut child).ok();
                break (
                    if status.is_some() {
                        ProcessOutcome::FilesystemLimitExceeded
                    } else {
                        ProcessOutcome::Ambiguous
                    },
                    status,
                    format!(
                        "build tree exceeded {} bytes",
                        limits.maximum_build_bytes
                    ),
                );
            }
        }
        thread::sleep(POLL_INTERVAL);
    };

    let mut outcome = outcome;
    let mut detail = detail;
    for path in [&stdout_path, &stderr_path] {
        if let Err(error) = cap_capture(path, limits.maximum_output_bytes) {
            outcome = ProcessOutcome::Ambiguous;
            detail.push_str(&format!("; could not cap captured output: {error}"));
        }
    }
    let elapsed = started.elapsed();
    let duration_millis = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);

    Ok(ProcessReport {
        outcome,
        started_at_unix: started_wall.as_secs(),
        finished_at_unix: started_wall.as_secs().saturating_add(elapsed.as_secs()),
        duration_millis,
        exit_code: status.as_ref().and_then(ExitStatus::code),
        signal: status.as_ref().and_then(exit_signal),
        stdout_path,
        stderr_path,
        detail,
    })
}

fn create_capture(path: &Path) -> Result<File, SourceBuildError> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| io_error("create build output capture", path, error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| io_error("set build output permissions", path, error))?;
    }
    Ok(file)
}

fn file_length(path: &Path) -> Result<u64, SourceBuildError> {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.len())
        .map_err(|error| io_error("inspect build output size", path, error))
}

fn cap_capture(path: &Path, maximum: u64) -> Result<(), SourceBuildError> {
    let file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|error| io_error("open build output for truncation", path, error))?;
    if file
        .metadata()
        .map_err(|error| io_error("inspect build output", path, error))?
        .len()
        > maximum
    {
        file.set_len(maximum)
            .map_err(|error| io_error("truncate build output", path, error))?;
    }
    file.sync_all()
        .map_err(|error| io_error("synchronize build output", path, error))
}

fn terminate_process_group(child: &mut std::process::Child) -> io::Result<ExitStatus> {
    #[cfg(unix)]
    {
        let pid = i32::try_from(child.id())
            .map_err(|_| io::Error::other("child process identifier does not fit i32"))?;
        send_group_signal(pid, SIGTERM)?;
        let started = Instant::now();
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok(status);
            }
            if started.elapsed() >= TERMINATION_GRACE {
                break;
            }
            thread::sleep(POLL_INTERVAL);
        }
        send_group_signal(pid, SIGKILL)?;
        child.wait()
    }
    #[cfg(not(unix))]
    {
        child.kill()?;
        child.wait()
    }
}

#[cfg(unix)]
fn send_group_signal(pid: i32, signal: i32) -> io::Result<()> {
    let result = unsafe { kill(-pid, signal) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(ESRCH) {
        Ok(())
    } else {
        Err(error)
    }
}

fn exit_signal(status: &ExitStatus) -> Option<i32> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        None
    }
}
