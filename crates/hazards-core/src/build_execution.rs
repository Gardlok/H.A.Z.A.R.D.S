use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use thiserror::Error;

use crate::{
    AcquisitionItem, BuildContractError, BuildContractItem, BuildContractPlanner,
    BuildContractStatus, BuildInvocationTemplate, HazardsPaths, Platform, ResolvedProfile,
};

mod artifact;
mod materialize;
mod process;
#[cfg(test)]
mod tests;

use artifact::verify_and_store_artifact;
use materialize::materialize_build_inputs;
use process::{ProcessOutcome, run_controlled};

const RECEIPT_SCHEMA_VERSION: u8 = 1;
const LOG_READ_LIMIT: u64 = 16 * 1024 * 1024;
static RECEIPT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BuildExecutionLimits {
    pub timeout_seconds: u64,
    pub maximum_output_bytes: u64,
    pub maximum_build_bytes: u64,
}

impl Default for BuildExecutionLimits {
    fn default() -> Self {
        Self {
            timeout_seconds: 60 * 60,
            maximum_output_bytes: 16 * 1024 * 1024,
            maximum_build_bytes: 8 * 1024 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlledBuildOutcome {
    Succeeded,
    Failed,
    TimedOut,
    OutputLimitExceeded,
    FilesystemLimitExceeded,
    ArtifactRejected,
    EvidenceChanged,
    Ambiguous,
}

impl std::fmt::Display for ControlledBuildOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::TimedOut => "timed-out",
            Self::OutputLimitExceeded => "output-limit-exceeded",
            Self::FilesystemLimitExceeded => "filesystem-limit-exceeded",
            Self::ArtifactRejected => "artifact-rejected",
            Self::EvidenceChanged => "evidence-changed",
            Self::Ambiguous => "ambiguous",
        };
        formatter.write_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuiltArtifactEvidence {
    pub name: String,
    pub source_path: PathBuf,
    pub object_path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub mode: u32,
    pub elf_machine: u16,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceBuildReceipt {
    pub schema_version: u8,
    pub receipt_id: String,
    pub tool_id: String,
    pub version: String,
    pub contract_sha256: String,
    pub invocation: BuildInvocationTemplate,
    pub limits: BuildExecutionLimits,
    pub started_at_unix: u64,
    pub finished_at_unix: u64,
    pub duration_millis: u64,
    pub outcome: ControlledBuildOutcome,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout_log_path: PathBuf,
    pub stderr_log_path: PathBuf,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub stdout_size: u64,
    pub stderr_size: u64,
    pub artifact: Option<BuiltArtifactEvidence>,
    pub build_root_preserved: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceBuildResult {
    pub receipt_path: PathBuf,
    pub receipt: SourceBuildReceipt,
}

pub struct SourceBuildExecutor<'a> {
    paths: &'a HazardsPaths,
    limits: BuildExecutionLimits,
}

impl<'a> SourceBuildExecutor<'a> {
    pub fn for_paths(paths: &'a HazardsPaths) -> Self {
        Self {
            paths,
            limits: BuildExecutionLimits::default(),
        }
    }

    pub fn with_limits(paths: &'a HazardsPaths, limits: BuildExecutionLimits) -> Self {
        Self { paths, limits }
    }

    pub fn execute(
        &self,
        profile: &ResolvedProfile,
        platform: &Platform,
        item: &AcquisitionItem,
        confirmation: &str,
    ) -> Result<SourceBuildResult, SourceBuildError> {
        let confirmed_digest = parse_confirmation(confirmation)?;
        let contract = inspect_contract(self.paths, profile, platform, item)?;
        let contract_digest = contract
            .contract_sha256
            .as_deref()
            .ok_or(SourceBuildError::MissingContractDigest)?;
        if confirmed_digest != contract_digest {
            return Err(SourceBuildError::ConfirmationMismatch {
                expected: contract_digest.to_owned(),
                provided: confirmed_digest.to_owned(),
            });
        }

        let invocation = contract
            .invocation
            .clone()
            .ok_or(SourceBuildError::MissingInvocation)?;
        let source = contract
            .source
            .as_ref()
            .ok_or(SourceBuildError::MissingSourceEvidence)?;
        let build_root = invocation
            .current_dir
            .parent()
            .ok_or_else(|| {
                SourceBuildError::Validation("build source path has no parent".to_owned())
            })?
            .to_path_buf();
        if invocation
            .current_dir
            .file_name()
            .and_then(|name| name.to_str())
            != Some("source")
        {
            return Err(SourceBuildError::Validation(
                "contract invocation does not use a private source copy".to_owned(),
            ));
        }

        let receipt_id = receipt_id()?;
        if let Err(error) = materialize_build_inputs(
            self.paths,
            item,
            &contract,
            &invocation,
            &build_root,
            self.limits.maximum_build_bytes,
        ) {
            let _ = fs::remove_dir_all(&build_root);
            return Err(error);
        }

        let process = match run_controlled(&invocation, &build_root, self.limits) {
            Ok(process) => process,
            Err(error) => {
                let _ = fs::remove_dir_all(&build_root);
                return Err(error);
            }
        };
        let mut outcome = match process.outcome {
            ProcessOutcome::Succeeded => ControlledBuildOutcome::Succeeded,
            ProcessOutcome::Failed => ControlledBuildOutcome::Failed,
            ProcessOutcome::TimedOut => ControlledBuildOutcome::TimedOut,
            ProcessOutcome::OutputLimitExceeded => ControlledBuildOutcome::OutputLimitExceeded,
            ProcessOutcome::FilesystemLimitExceeded => {
                ControlledBuildOutcome::FilesystemLimitExceeded
            }
            ProcessOutcome::Ambiguous => ControlledBuildOutcome::Ambiguous,
        };
        let mut detail = process.detail.clone();
        let mut artifact = None;

        if outcome != ControlledBuildOutcome::Ambiguous {
            match inspect_contract(self.paths, profile, platform, item) {
                Ok(after) if after.contract_sha256.as_deref() == Some(contract_digest) => {}
                Ok(_) => {
                    outcome = ControlledBuildOutcome::EvidenceChanged;
                    detail = "source, dependency, toolchain, native, environment, or invocation evidence changed during execution".to_owned();
                }
                Err(error) => {
                    outcome = ControlledBuildOutcome::EvidenceChanged;
                    detail = format!("post-build contract verification failed: {error}");
                }
            }
        }

        if outcome == ControlledBuildOutcome::Succeeded {
            match verify_and_store_artifact(self.paths, &invocation, source, &build_root, &item.id)
            {
                Ok(evidence) => artifact = Some(evidence),
                Err(error) => {
                    outcome = ControlledBuildOutcome::ArtifactRejected;
                    detail = error.to_string();
                }
            }
        }

        let log_dir = receipt_log_dir(self.paths, item, &receipt_id)?;
        let stdout_log_path = persist_log(
            &process.stdout_path,
            &log_dir.join("stdout.log"),
            self.limits.maximum_output_bytes,
        )?;
        let stderr_log_path = persist_log(
            &process.stderr_path,
            &log_dir.join("stderr.log"),
            self.limits.maximum_output_bytes,
        )?;
        let stdout_size = file_size(&stdout_log_path)?;
        let stderr_size = file_size(&stderr_log_path)?;
        let stdout_sha256 = hash_file_bounded(&stdout_log_path, LOG_READ_LIMIT)?;
        let stderr_sha256 = hash_file_bounded(&stderr_log_path, LOG_READ_LIMIT)?;

        let preserve_build_root = matches!(
            outcome,
            ControlledBuildOutcome::Ambiguous
                | ControlledBuildOutcome::ArtifactRejected
                | ControlledBuildOutcome::EvidenceChanged
        );
        let receipt = SourceBuildReceipt {
            schema_version: RECEIPT_SCHEMA_VERSION,
            receipt_id: receipt_id.clone(),
            tool_id: item.id.clone(),
            version: item.target_version.clone(),
            contract_sha256: contract_digest.to_owned(),
            invocation,
            limits: self.limits,
            started_at_unix: process.started_at_unix,
            finished_at_unix: process.finished_at_unix,
            duration_millis: process.duration_millis,
            outcome,
            exit_code: process.exit_code,
            signal: process.signal,
            stdout_log_path,
            stderr_log_path,
            stdout_sha256,
            stderr_sha256,
            stdout_size,
            stderr_size,
            artifact,
            build_root_preserved: preserve_build_root,
            detail,
        };
        let receipt_path = persist_receipt(self.paths, item, &receipt)?;

        if !preserve_build_root {
            fs::remove_dir_all(&build_root)
                .map_err(|source| io_error("remove completed build root", &build_root, source))?;
        }

        Ok(SourceBuildResult {
            receipt_path,
            receipt,
        })
    }
}

fn inspect_contract(
    paths: &HazardsPaths,
    profile: &ResolvedProfile,
    platform: &Platform,
    item: &AcquisitionItem,
) -> Result<BuildContractItem, SourceBuildError> {
    let plan =
        BuildContractPlanner::for_paths(paths)?.plan(profile, platform, std::slice::from_ref(item));
    let inspected = plan.items.into_iter().next().ok_or_else(|| {
        SourceBuildError::Validation("build contract returned no item".to_owned())
    })?;
    if inspected.status != BuildContractStatus::ContractReady {
        return Err(SourceBuildError::ContractNotReady {
            status: inspected.status,
            detail: inspected.detail,
        });
    }
    Ok(inspected)
}

fn parse_confirmation(value: &str) -> Result<&str, SourceBuildError> {
    let digest = value
        .strip_prefix("sha256:")
        .ok_or(SourceBuildError::MalformedConfirmation)?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SourceBuildError::MalformedConfirmation);
    }
    Ok(digest)
}

fn receipt_id() -> Result<String, SourceBuildError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| SourceBuildError::Clock(error.to_string()))?;
    Ok(format!(
        "{}-{:09}-{}-{}",
        now.as_secs(),
        now.subsec_nanos(),
        std::process::id(),
        RECEIPT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ))
}

fn receipt_log_dir(
    paths: &HazardsPaths,
    item: &AcquisitionItem,
    receipt_id: &str,
) -> Result<PathBuf, SourceBuildError> {
    let directory = paths
        .state
        .join("build-logs")
        .join(&item.id)
        .join(&item.target_version)
        .join(receipt_id);
    ensure_private_directory(&directory)?;
    Ok(directory)
}

fn persist_log(
    source: &Path,
    destination: &Path,
    maximum: u64,
) -> Result<PathBuf, SourceBuildError> {
    let parent = destination
        .parent()
        .ok_or_else(|| SourceBuildError::Validation("log path has no parent".to_owned()))?;
    let input = File::open(source).map_err(|error| io_error("open build log", source, error))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .map_err(|error| io_error("create temporary build log", parent, error))?;
    io::copy(&mut input.take(maximum), temporary.as_file_mut())
        .map_err(|error| io_error("copy build log", temporary.path(), error))?;
    temporary
        .as_file_mut()
        .sync_all()
        .map_err(|error| io_error("synchronize build log", temporary.path(), error))?;
    let file = temporary
        .persist_noclobber(destination)
        .map_err(|error| io_error("persist build log", destination, error.error))?;
    set_private_file(&file, destination)?;
    sync_directory(parent)?;
    Ok(destination.to_path_buf())
}

fn persist_receipt(
    paths: &HazardsPaths,
    item: &AcquisitionItem,
    receipt: &SourceBuildReceipt,
) -> Result<PathBuf, SourceBuildError> {
    let directory = paths
        .state
        .join("receipts")
        .join("source-builds")
        .join(&item.id)
        .join(&item.target_version);
    ensure_private_directory(&directory)?;
    let receipt_path = directory.join(format!("{}.json", receipt.receipt_id));
    let mut encoded = serde_json::to_vec_pretty(receipt)
        .map_err(|error| SourceBuildError::Evidence(error.to_string()))?;
    encoded.push(b'\n');
    let mut temporary = NamedTempFile::new_in(&directory)
        .map_err(|error| io_error("create temporary source-build receipt", &directory, error))?;
    temporary
        .write_all(&encoded)
        .map_err(|error| io_error("write source-build receipt", temporary.path(), error))?;
    temporary
        .as_file_mut()
        .sync_all()
        .map_err(|error| io_error("synchronize source-build receipt", temporary.path(), error))?;
    let file = temporary
        .persist_noclobber(&receipt_path)
        .map_err(|error| io_error("persist source-build receipt", &receipt_path, error.error))?;
    set_private_file(&file, &receipt_path)?;
    sync_directory(&directory)?;
    Ok(receipt_path)
}

pub(super) fn ensure_private_directory(path: &Path) -> Result<(), SourceBuildError> {
    if !path.is_absolute() {
        return Err(SourceBuildError::UnsafePath {
            path: path.to_path_buf(),
            reason: "private directory path is not absolute".to_owned(),
        });
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir => current.push(Path::new("/")),
            std::path::Component::Normal(value) => {
                current.push(value);
                let created = match fs::symlink_metadata(&current) {
                    Ok(metadata) => {
                        if metadata.file_type().is_symlink() || !metadata.is_dir() {
                            return Err(SourceBuildError::UnsafePath {
                                path: current,
                                reason: "expected a real directory".to_owned(),
                            });
                        }
                        false
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        fs::create_dir(&current).map_err(|source| {
                            io_error("create private directory", &current, source)
                        })?;
                        true
                    }
                    Err(error) => {
                        return Err(io_error("inspect private directory", &current, error));
                    }
                };
                if created || current == path {
                    set_directory_mode(&current)?;
                }
            }
            _ => {
                return Err(SourceBuildError::UnsafePath {
                    path: path.to_path_buf(),
                    reason: "private directory path contains an unsafe component".to_owned(),
                });
            }
        }
    }
    Ok(())
}

fn set_directory_mode(path: &Path) -> Result<(), SourceBuildError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| io_error("set private directory permissions", path, error))?;
    }
    Ok(())
}

pub(super) fn set_private_file(file: &File, path: &Path) -> Result<(), SourceBuildError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| io_error("set private file permissions", path, error))?;
    }
    Ok(())
}

pub(super) fn sync_directory(path: &Path) -> Result<(), SourceBuildError> {
    let directory = File::open(path)
        .map_err(|error| io_error("open directory for synchronization", path, error))?;
    directory
        .sync_all()
        .map_err(|error| io_error("synchronize directory", path, error))
}

pub(super) fn hash_file_bounded(path: &Path, maximum: u64) -> Result<String, SourceBuildError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect file for hashing", path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return Err(SourceBuildError::UnsafePath {
            path: path.to_path_buf(),
            reason: format!("expected a regular file no larger than {maximum} bytes"),
        });
    }
    let mut file =
        File::open(path).map_err(|error| io_error("open file for hashing", path, error))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| io_error("read file for hashing", path, error))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

pub(super) fn file_size(path: &Path) -> Result<u64, SourceBuildError> {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.len())
        .map_err(|error| io_error("inspect file size", path, error))
}

pub(super) fn io_error(action: &'static str, path: &Path, source: io::Error) -> SourceBuildError {
    SourceBuildError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

#[derive(Debug, Error)]
pub enum SourceBuildError {
    #[error(transparent)]
    Contract(#[from] BuildContractError),
    #[error("build contract is not ready ({status}): {detail}")]
    ContractNotReady {
        status: BuildContractStatus,
        detail: String,
    },
    #[error("confirmation must have the form sha256:<64 lowercase hexadecimal characters>")]
    MalformedConfirmation,
    #[error(
        "build confirmation does not match the current contract: expected sha256:{expected}, received sha256:{provided}"
    )]
    ConfirmationMismatch { expected: String, provided: String },
    #[error("ready build contract did not include a digest")]
    MissingContractDigest,
    #[error("ready build contract did not include an invocation")]
    MissingInvocation,
    #[error("ready build contract did not include source evidence")]
    MissingSourceEvidence,
    #[error("ready build contract did not include dependency evidence")]
    MissingDependencyEvidence,
    #[error("source-build validation failed: {0}")]
    Validation(String),
    #[error("unsafe source-build path {path}: {reason}")]
    UnsafePath { path: PathBuf, reason: String },
    #[error("{action} at {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not serialize or parse source-build evidence: {0}")]
    Evidence(String),
    #[error("system clock is before the Unix epoch: {0}")]
    Clock(String),
    #[error("controlled build process failed before a durable receipt could be written: {0}")]
    Process(String),
    #[error("built artifact was rejected: {0}")]
    Artifact(String),
    #[error(transparent)]
    Dependency(#[from] crate::CargoDependencyError),
}
