use std::{
    collections::BTreeMap,
    env,
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use super::{MAX_PROBE_OUTPUT, PROBE_TIMEOUT};

pub(super) fn locate_command(command: &str) -> Option<PathBuf> {
    let candidate = PathBuf::from(command);
    let path = if candidate.components().count() > 1 {
        candidate
    } else {
        env::var_os("PATH").and_then(|value| {
            env::split_paths(&value)
                .map(|directory| directory.join(command))
                .find(|path| is_executable(path))
        })?
    };
    let file_name = path.file_name()?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let absolute = fs::canonicalize(parent).ok()?.join(file_name);
    is_executable(&absolute).then_some(absolute)
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

pub(super) fn run_bounded(executable: &Path, arguments: &[String]) -> Result<String, String> {
    let stdout = NamedTempFile::new().map_err(|error| error.to_string())?;
    let stderr = NamedTempFile::new().map_err(|error| error.to_string())?;
    let stdout_file = stdout.reopen().map_err(|error| error.to_string())?;
    let stderr_file = stderr.reopen().map_err(|error| error.to_string())?;
    let mut child = Command::new(executable)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .spawn()
        .map_err(|error| error.to_string())?;
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            let output = read_probe_output(stdout.path(), stderr.path())?;
            if status.success() {
                return Ok(output);
            }
            return Err(format!("exited with {status}: {output}"));
        }
        let output_size = stdout
            .as_file()
            .metadata()
            .map_err(|error| error.to_string())?
            .len()
            .saturating_add(
                stderr
                    .as_file()
                    .metadata()
                    .map_err(|error| error.to_string())?
                    .len(),
            );
        if output_size > MAX_PROBE_OUTPUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("output exceeded {MAX_PROBE_OUTPUT} bytes"));
        }
        if started.elapsed() > PROBE_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "probe exceeded {} seconds",
                PROBE_TIMEOUT.as_secs()
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn read_probe_output(stdout: &Path, stderr: &Path) -> Result<String, String> {
    let stdout = read_bounded(stdout, MAX_PROBE_OUTPUT).map_err(|error| error.to_string())?;
    let stderr = read_bounded(stderr, MAX_PROBE_OUTPUT).map_err(|error| error.to_string())?;
    let stdout = String::from_utf8_lossy(&stdout);
    let stderr = String::from_utf8_lossy(&stderr);
    let text = if stdout.trim().is_empty() {
        stderr.trim()
    } else {
        stdout.trim()
    };
    Ok(text.to_owned())
}

fn read_bounded(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(io::Error::other("file exceeded read limit"));
    }
    Ok(bytes)
}

pub(super) fn parse_verbose_version(output: &str) -> BTreeMap<String, String> {
    output
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect()
}

pub(super) fn first_release(output: &str) -> Option<String> {
    output
        .split(|character: char| character.is_whitespace() || character == '(')
        .find(|part| valid_release(part))
        .map(str::to_owned)
}

pub(super) fn first_line(output: &str) -> Option<String> {
    output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_owned)
}

pub(super) fn version_at_least(actual: &str, minimum: &str) -> bool {
    let actual = leading_version(actual);
    let minimum = leading_version(minimum);
    !actual.is_empty()
        && !minimum.is_empty()
        && normalized_version(&actual) >= normalized_version(&minimum)
}

pub(super) fn leading_version(value: &str) -> Vec<u64> {
    let start = value
        .char_indices()
        .find(|(_, character)| character.is_ascii_digit())
        .map(|(index, _)| index)
        .unwrap_or(value.len());
    value[start..]
        .split(|character: char| !character.is_ascii_digit())
        .take_while(|part| !part.is_empty())
        .filter_map(|part| part.parse().ok())
        .collect()
}

fn normalized_version(parts: &[u64]) -> [u64; 3] {
    [
        parts.first().copied().unwrap_or_default(),
        parts.get(1).copied().unwrap_or_default(),
        parts.get(2).copied().unwrap_or_default(),
    ]
}

pub(super) fn canonical_existing_executable(path: &Path) -> Result<PathBuf, String> {
    let canonical = fs::canonicalize(path).map_err(|error| error.to_string())?;
    if is_executable(&canonical) {
        Ok(canonical)
    } else {
        Err(format!("{} is not an executable file", canonical.display()))
    }
}

pub(super) fn canonical_existing_directory(path: &Path) -> Result<PathBuf, String> {
    let canonical = fs::canonicalize(path).map_err(|error| error.to_string())?;
    let metadata = fs::metadata(&canonical).map_err(|error| error.to_string())?;
    if metadata.is_dir() {
        Ok(canonical)
    } else {
        Err(format!("{} is not a directory", canonical.display()))
    }
}

pub(super) fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(super) fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub(super) fn safe_target(value: &str) -> bool {
    safe_component(value) && value.contains("-unknown-linux-")
}

pub(super) fn safe_command(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'))
}

pub(super) fn safe_module(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'))
}

pub(super) fn safe_environment_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

pub(super) fn valid_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn valid_release(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    (2..=3).contains(&parts.len())
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

pub(super) fn valid_date(value: &str) -> bool {
    value.len() == 10
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value
            .bytes()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit())
}
