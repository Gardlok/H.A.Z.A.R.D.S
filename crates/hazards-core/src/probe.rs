use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

/// A command found using one of a tool's trusted registry names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocatedCommand {
    pub command: String,
    pub path: PathBuf,
}

/// Read-only access to the host environment.
///
/// Implementations receive executable names and argument vectors from the
/// validated Arsenal registry. They never receive or evaluate shell text.
pub trait EnvironmentProbe {
    fn locate(&self, commands: &[&str]) -> Option<LocatedCommand>;
    fn version(&self, executable: &Path, args: &[String]) -> Result<String, String>;
}

/// The real host probe used by the CLI.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemProbe;

impl EnvironmentProbe for SystemProbe {
    fn locate(&self, commands: &[&str]) -> Option<LocatedCommand> {
        commands.iter().find_map(|command| {
            find_command(command).map(|path| LocatedCommand {
                command: (*command).to_owned(),
                path,
            })
        })
    }

    fn version(&self, executable: &Path, args: &[String]) -> Result<String, String> {
        let output = Command::new(executable)
            .args(args)
            .output()
            .map_err(|error| error.to_string())?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let text = if stdout.trim().is_empty() {
            stderr.trim()
        } else {
            stdout.trim()
        };

        if output.status.success() {
            Ok(text.to_owned())
        } else {
            Err(format!(
                "exited with {}{}",
                output.status,
                if text.is_empty() {
                    String::new()
                } else {
                    format!(": {text}")
                }
            ))
        }
    }
}

fn find_command(command: &str) -> Option<PathBuf> {
    let candidate = PathBuf::from(command);
    if candidate.components().count() > 1 {
        return is_executable(&candidate).then_some(candidate);
    }

    env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|directory| directory.join(command))
            .find(|candidate| is_executable(candidate))
    })
}

fn is_executable(candidate: &Path) -> bool {
    let Ok(metadata) = candidate.metadata() else {
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
