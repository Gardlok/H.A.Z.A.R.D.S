use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use arsenallspice::Registry;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::{Builder, NamedTempFile};
use thiserror::Error;

use crate::{
    HazardsPaths, ManagedActivation, ResolvedProfile,
    acquire::{
        ensure_private_dir, ensure_private_subdirectories, set_private_file_permissions,
        sync_directory,
    },
    provision::version_matches,
};

const PROFILE_SCHEMA_VERSION: u8 = 1;
const GENERATION_RECEIPT_SCHEMA_VERSION: u8 = 1;
const DRY_RUN_RECEIPT_SCHEMA_VERSION: u8 = 1;
const MAX_CONFIG_SIZE: usize = 1024 * 1024;
const MAX_COMMAND_OUTPUT: u64 = 8 * 1024 * 1024;
const MAX_WATCHED_FILE_SIZE: u64 = 64 * 1024 * 1024;
const VERSION_TIMEOUT: Duration = Duration::from_secs(10);
const DRY_RUN_TIMEOUT: Duration = Duration::from_secs(60);
static RECEIPT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// One source-to-target mapping selected for a resolved HAZARDS profile.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DotfileMapping {
    pub package: String,
    pub source: PathBuf,
    pub source_size: u64,
    pub source_sha256: String,
    pub target: PathBuf,
}

/// Deterministic identity for generated Dotter configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DotterProfileManifest {
    pub schema_version: u8,
    pub profile_id: String,
    pub host: String,
    pub persistence: String,
    pub role: String,
    pub workspace_root: PathBuf,
    pub global_config: PathBuf,
    pub global_sha256: String,
    pub local_sha256: String,
    pub packages: Vec<String>,
    pub mappings: Vec<DotfileMapping>,
}

/// Whether generation changed the HAZARDS-owned profile files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DotterGenerationOutcome {
    Generated,
    Unchanged,
}

impl std::fmt::Display for DotterGenerationOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Generated => formatter.write_str("generated"),
            Self::Unchanged => formatter.write_str("unchanged"),
        }
    }
}

/// Append-only evidence for one deterministic profile generation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DotterGenerationReceipt {
    pub schema_version: u8,
    pub receipt_id: String,
    pub profile_id: String,
    pub global_sha256: String,
    pub local_sha256: String,
    pub package_count: usize,
    pub mapping_count: usize,
    pub outcome: DotterGenerationOutcome,
    pub generated_at_unix: u64,
}

/// Files and evidence produced by `dotfiles generate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GeneratedDotterProfile {
    pub profile_directory: PathBuf,
    pub local_config_path: PathBuf,
    pub manifest_path: PathBuf,
    pub receipt_path: PathBuf,
    pub manifest: DotterProfileManifest,
    pub receipt: DotterGenerationReceipt,
}

/// Result classification for a real Dotter `--dry-run`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DotterDryRunOutcome {
    Clean,
    CommandFailed,
    MutationDetected,
}

impl std::fmt::Display for DotterDryRunOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clean => formatter.write_str("dry-run-clean"),
            Self::CommandFailed => formatter.write_str("dry-run-failed"),
            Self::MutationDetected => formatter.write_str("mutation-detected"),
        }
    }
}

/// Append-only evidence for a Dotter dry-run and target immutability check.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DotterDryRunReceipt {
    pub schema_version: u8,
    pub receipt_id: String,
    pub profile_id: String,
    pub dotter_version: String,
    pub global_sha256: String,
    pub local_sha256: String,
    pub watched_path_count: usize,
    pub changed_paths: Vec<PathBuf>,
    pub exit_code: Option<i32>,
    pub command_failure: Option<String>,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub outcome: DotterDryRunOutcome,
    pub ran_at_unix: u64,
}

/// Captured output and evidence from `dotfiles dry-run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DotterDryRunReport {
    pub executable: PathBuf,
    pub local_config_path: PathBuf,
    pub receipt_path: PathBuf,
    pub stdout: String,
    pub stderr: String,
    pub receipt: DotterDryRunReceipt,
}

/// Exact invocation passed to a Dotter runner without a shell.
pub struct DotterInvocation<'a> {
    pub executable: &'a Path,
    pub working_directory: &'a Path,
    pub arguments: &'a [OsString],
    pub capture_directory: &'a Path,
}

/// Bounded process result used by the dry-run verifier.
pub struct DotterCommandOutput {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub failure: Option<String>,
}

impl DotterCommandOutput {
    fn succeeded(&self) -> bool {
        self.failure.is_none() && self.exit_code == Some(0)
    }
}

/// Injectable execution boundary for unit tests and the real Dotter process.
pub trait DotterRunner {
    fn version(&self, executable: &Path, capture_directory: &Path) -> Result<String, String>;
    fn dry_run(&self, invocation: DotterInvocation<'_>) -> Result<DotterCommandOutput, String>;
}

/// Real bounded, shell-free Dotter process execution.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemDotterRunner;

impl DotterRunner for SystemDotterRunner {
    fn version(&self, executable: &Path, capture_directory: &Path) -> Result<String, String> {
        let output = run_bounded(
            executable,
            None,
            &[OsString::from("--version")],
            capture_directory,
            VERSION_TIMEOUT,
        )?;
        if !output.succeeded() {
            return Err(command_failure(&output));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        Ok(if stdout.trim().is_empty() {
            stderr.trim().to_owned()
        } else {
            stdout.trim().to_owned()
        })
    }

    fn dry_run(&self, invocation: DotterInvocation<'_>) -> Result<DotterCommandOutput, String> {
        run_bounded(
            invocation.executable,
            Some(invocation.working_directory),
            invocation.arguments,
            invocation.capture_directory,
            DRY_RUN_TIMEOUT,
        )
    }
}

/// Profile-aware Dotter configuration generation and verified dry-run.
pub struct DotfilesManager<'a, R = SystemDotterRunner> {
    registry: &'a Registry,
    profile: &'a ResolvedProfile,
    paths: HazardsPaths,
    workspace_root: PathBuf,
    runner: R,
}

impl<'a> DotfilesManager<'a, SystemDotterRunner> {
    pub fn new(
        registry: &'a Registry,
        profile: &'a ResolvedProfile,
        paths: &HazardsPaths,
        workspace_root: impl AsRef<Path>,
    ) -> Result<Self, DotfilesError> {
        Self::with_runner(registry, profile, paths, workspace_root, SystemDotterRunner)
    }
}

impl<'a, R: DotterRunner> DotfilesManager<'a, R> {
    pub fn with_runner(
        registry: &'a Registry,
        profile: &'a ResolvedProfile,
        paths: &HazardsPaths,
        workspace_root: impl AsRef<Path>,
        runner: R,
    ) -> Result<Self, DotfilesError> {
        let workspace_root = canonical_workspace_root(workspace_root.as_ref())?;
        Ok(Self {
            registry,
            profile,
            paths: paths.clone(),
            workspace_root,
            runner,
        })
    }

    /// Find a HAZARDS checkout from a starting directory or one of its parents.
    pub fn discover_workspace(start: impl AsRef<Path>) -> Result<PathBuf, DotfilesError> {
        let mut current = fs::canonicalize(start.as_ref()).map_err(|error| {
            io_error("canonicalize workspace search path", start.as_ref(), error)
        })?;
        if current.is_file() {
            current.pop();
        }
        loop {
            if current
                .join("ingredients/dotterbatter/global.toml")
                .is_file()
            {
                return canonical_workspace_root(&current);
            }
            if !current.pop() {
                return Err(DotfilesError::WorkspaceNotFound(
                    start.as_ref().to_path_buf(),
                ));
            }
        }
    }

    pub fn generate(&self) -> Result<GeneratedDotterProfile, DotfilesError> {
        let expected = self.expected_profile()?;
        let _lock = self.acquire_lock(&expected.manifest.profile_id)?;
        let profile_directory = ensure_private_subdirectories(
            &self.paths.state,
            &["dotter", "profiles", &expected.manifest.profile_id],
        )?;
        let local_config_path = profile_directory.join("local.toml");
        let manifest_path = profile_directory.join("manifest.json");
        let manifest_bytes = encode_json(&expected.manifest)?;

        let unchanged = read_optional_private_file(&local_config_path)?.as_deref()
            == Some(expected.local_config.as_slice())
            && read_optional_private_file(&manifest_path)?.as_deref()
                == Some(manifest_bytes.as_slice());
        let outcome = if unchanged {
            DotterGenerationOutcome::Unchanged
        } else {
            write_atomic_private(
                &profile_directory,
                &local_config_path,
                &expected.local_config,
            )?;
            write_atomic_private(&profile_directory, &manifest_path, &manifest_bytes)?;
            DotterGenerationOutcome::Generated
        };

        let (receipt_id, generated_at_unix) = receipt_identity()?;
        let receipt = DotterGenerationReceipt {
            schema_version: GENERATION_RECEIPT_SCHEMA_VERSION,
            receipt_id,
            profile_id: expected.manifest.profile_id.clone(),
            global_sha256: expected.manifest.global_sha256.clone(),
            local_sha256: expected.manifest.local_sha256.clone(),
            package_count: expected.manifest.packages.len(),
            mapping_count: expected.manifest.mappings.len(),
            outcome,
            generated_at_unix,
        };
        let receipt_path = self.write_generation_receipt(&receipt)?;
        Ok(GeneratedDotterProfile {
            profile_directory,
            local_config_path,
            manifest_path,
            receipt_path,
            manifest: expected.manifest,
            receipt,
        })
    }

    pub fn dry_run(
        &self,
        activation: &ManagedActivation,
    ) -> Result<DotterDryRunReport, DotfilesError> {
        let expected = self.expected_profile()?;
        let _lock = self.acquire_lock(&expected.manifest.profile_id)?;
        self.validate_generated_profile(&expected)?;
        if activation.tool_id != "dotter" {
            return Err(DotfilesError::WrongActivation(activation.tool_id.clone()));
        }

        let install = self
            .registry
            .install_spec("dotter")
            .ok_or(DotfilesError::MissingDotterIntent)?;
        if activation.version != install.target_version {
            return Err(DotfilesError::DotterVersion {
                expected: install.target_version.clone(),
                actual: activation.version.clone(),
            });
        }

        let dry_run_root =
            ensure_private_subdirectories(&self.paths.cache, &["dotter", "dry-runs"])?;
        let scratch = Builder::new()
            .prefix(".dry-run-")
            .tempdir_in(&dry_run_root)
            .map_err(|error| io_error("create Dotter dry-run directory", &dry_run_root, error))?;
        ensure_private_dir(scratch.path())?;
        let cache_directory = scratch.path().join("cache");
        fs::create_dir(&cache_directory)
            .map_err(|error| io_error("create temporary Dotter cache", &cache_directory, error))?;
        set_directory_mode(&cache_directory, 0o700)?;

        let version = self
            .runner
            .version(&activation.activation_path, scratch.path())
            .map_err(DotfilesError::DotterExecution)?;
        if !version_matches(&version, &install.target_version) {
            return Err(DotfilesError::DotterVersion {
                expected: install.target_version.clone(),
                actual: version,
            });
        }

        let local_config_path = self
            .profile_directory(&expected.manifest.profile_id)
            .join("local.toml");
        let arguments = dotter_dry_run_arguments(
            &expected.manifest.global_config,
            &local_config_path,
            scratch.path(),
            &cache_directory,
        );
        let watched_paths = watched_paths(&self.paths.home, &expected.manifest.mappings)?;
        let before = fingerprint_paths(&watched_paths)?;
        let output = self
            .runner
            .dry_run(DotterInvocation {
                executable: &activation.activation_path,
                working_directory: &self.workspace_root,
                arguments: &arguments,
                capture_directory: scratch.path(),
            })
            .map_err(DotfilesError::DotterExecution)?;
        let after = fingerprint_paths(&watched_paths)?;
        let changed_paths = before
            .iter()
            .filter_map(|(path, fingerprint)| {
                (after.get(path) != Some(fingerprint)).then_some(path.clone())
            })
            .collect::<Vec<_>>();
        let outcome = if !changed_paths.is_empty() {
            DotterDryRunOutcome::MutationDetected
        } else if output.succeeded() {
            DotterDryRunOutcome::Clean
        } else {
            DotterDryRunOutcome::CommandFailed
        };
        let (receipt_id, ran_at_unix) = receipt_identity()?;
        let receipt = DotterDryRunReceipt {
            schema_version: DRY_RUN_RECEIPT_SCHEMA_VERSION,
            receipt_id,
            profile_id: expected.manifest.profile_id.clone(),
            dotter_version: version,
            global_sha256: expected.manifest.global_sha256,
            local_sha256: expected.manifest.local_sha256,
            watched_path_count: watched_paths.len(),
            changed_paths,
            exit_code: output.exit_code,
            command_failure: output.failure.clone(),
            stdout_sha256: hash_bytes(&output.stdout),
            stderr_sha256: hash_bytes(&output.stderr),
            outcome,
            ran_at_unix,
        };
        let receipt_path = self.write_dry_run_receipt(&receipt)?;
        Ok(DotterDryRunReport {
            executable: activation.activation_path.clone(),
            local_config_path,
            receipt_path,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            receipt,
        })
    }

    fn expected_profile(&self) -> Result<ExpectedProfile, DotfilesError> {
        let global_config = self
            .workspace_root
            .join("ingredients/dotterbatter/global.toml");
        let global_bytes = read_bounded_regular_file(&global_config, MAX_CONFIG_SIZE)?;
        let document: toml::Value = toml::from_slice(&global_bytes)
            .map_err(|error| DotfilesError::Configuration(error.to_string()))?;
        let table = document.as_table().ok_or_else(|| {
            DotfilesError::Configuration("Dotter global configuration is not a table".to_owned())
        })?;

        let mut packages = Vec::new();
        let mut mappings = Vec::new();
        let mut targets = BTreeSet::new();
        for pillar_id in &self.profile.required_pillars {
            let pillar = self
                .registry
                .pillars
                .iter()
                .find(|pillar| pillar.id == *pillar_id)
                .ok_or_else(|| DotfilesError::UnknownPillar((*pillar_id).to_owned()))?;
            let Some(package) = table.get(&pillar.ingredient) else {
                continue;
            };
            validate_identifier("Dotter package", &pillar.ingredient)?;
            let files = package
                .get("files")
                .and_then(toml::Value::as_table)
                .ok_or_else(|| DotfilesError::MissingFilesTable(pillar.ingredient.clone()))?;
            packages.push(pillar.ingredient.clone());
            for (source, target) in files {
                let target = target
                    .as_str()
                    .ok_or_else(|| DotfilesError::UnsupportedMapping {
                        package: pillar.ingredient.clone(),
                        source_path: source.clone(),
                    })?;
                let source_path = validate_source(&self.workspace_root, source)?;
                let target_path = validate_target(&self.paths.home, target)?;
                if !targets.insert(target_path.clone()) {
                    return Err(DotfilesError::DuplicateTarget(target_path));
                }
                mappings.push(DotfileMapping {
                    package: pillar.ingredient.clone(),
                    source_size: fs::metadata(&source_path)
                        .map_err(|error| {
                            io_error("inspect selected dotfile source", &source_path, error)
                        })?
                        .len(),
                    source_sha256: hash_file(&source_path)?,
                    source: source_path,
                    target: target_path,
                });
            }
        }
        if packages.is_empty() {
            return Err(DotfilesError::NoPackages);
        }

        let mut local_table = toml::map::Map::new();
        local_table.insert(
            "packages".to_owned(),
            toml::Value::Array(
                packages
                    .iter()
                    .map(|package| toml::Value::String(package.clone()))
                    .collect(),
            ),
        );
        let mut local_config =
            b"# Generated by HAZARDS. Edit the profile model, not this file.\n".to_vec();
        local_config.extend(
            toml::to_string(&toml::Value::Table(local_table))
                .map_err(|error| DotfilesError::Configuration(error.to_string()))?
                .as_bytes(),
        );

        let profile_id = profile_id(self.profile);
        let manifest = DotterProfileManifest {
            schema_version: PROFILE_SCHEMA_VERSION,
            profile_id,
            host: self.profile.host.to_string(),
            persistence: self.profile.persistence.to_string(),
            role: self.profile.role.to_string(),
            workspace_root: self.workspace_root.clone(),
            global_config,
            global_sha256: hash_bytes(&global_bytes),
            local_sha256: hash_bytes(&local_config),
            packages,
            mappings,
        };
        Ok(ExpectedProfile {
            local_config,
            manifest,
        })
    }

    fn validate_generated_profile(&self, expected: &ExpectedProfile) -> Result<(), DotfilesError> {
        let directory = ensure_private_subdirectories(
            &self.paths.state,
            &["dotter", "profiles", &expected.manifest.profile_id],
        )?;
        let local_path = directory.join("local.toml");
        let manifest_path = directory.join("manifest.json");
        let local = read_required_private_file(&local_path)?;
        let manifest_bytes = read_required_private_file(&manifest_path)?;
        let manifest: DotterProfileManifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|error| DotfilesError::Configuration(error.to_string()))?;
        if local != expected.local_config || manifest != expected.manifest {
            return Err(DotfilesError::StaleProfile {
                profile: expected.manifest.profile_id.clone(),
            });
        }
        Ok(())
    }

    fn profile_directory(&self, profile_id: &str) -> PathBuf {
        self.paths
            .state
            .join("dotter")
            .join("profiles")
            .join(profile_id)
    }

    fn acquire_lock(&self, profile_id: &str) -> Result<DotfilesLock, DotfilesError> {
        let directory = ensure_private_subdirectories(&self.paths.state, &["locks", "dotfiles"])?;
        let path = directory.join(format!("{profile_id}.lock"));
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|error| io_error("open Dotter profile lock", &path, error))?;
        set_private_file_permissions(&file, &path)?;
        file.try_lock_exclusive().map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                DotfilesError::Concurrent(profile_id.to_owned())
            } else {
                io_error("lock Dotter profile operation", &path, error)
            }
        })?;
        Ok(DotfilesLock { file })
    }

    fn write_generation_receipt(
        &self,
        receipt: &DotterGenerationReceipt,
    ) -> Result<PathBuf, DotfilesError> {
        let directory = ensure_private_subdirectories(
            &self.paths.state,
            &["receipts", "dotfiles", "generation", &receipt.profile_id],
        )?;
        let path = directory.join(format!("{}.json", receipt.receipt_id));
        write_json_noclobber(&directory, &path, receipt)?;
        Ok(path)
    }

    fn write_dry_run_receipt(
        &self,
        receipt: &DotterDryRunReceipt,
    ) -> Result<PathBuf, DotfilesError> {
        let directory = ensure_private_subdirectories(
            &self.paths.state,
            &["receipts", "dotfiles", "dry-runs", &receipt.profile_id],
        )?;
        let path = directory.join(format!("{}.json", receipt.receipt_id));
        write_json_noclobber(&directory, &path, receipt)?;
        Ok(path)
    }
}

#[derive(Debug, Error)]
pub enum DotfilesError {
    #[error("could not find a HAZARDS workspace from {0}")]
    WorkspaceNotFound(PathBuf),
    #[error("HAZARDS workspace is invalid at {0}")]
    InvalidWorkspace(PathBuf),
    #[error("unknown resolved pillar {0}")]
    UnknownPillar(String),
    #[error("Dotter package {0} does not contain a files table")]
    MissingFilesTable(String),
    #[error("Dotter mapping {package}.{source_path} uses an unsupported target value")]
    UnsupportedMapping {
        package: String,
        source_path: String,
    },
    #[error("Dotter profile selects no configured packages")]
    NoPackages,
    #[error("unsafe {field}: {value}")]
    UnsafeIdentifier { field: &'static str, value: String },
    #[error("Dotter source path is unsafe or unavailable: {0}")]
    UnsafeSource(PathBuf),
    #[error("Dotter target must be a safe path beneath HOME: {0}")]
    UnsafeTarget(String),
    #[error("multiple Dotter mappings target {0}")]
    DuplicateTarget(PathBuf),
    #[error("generated Dotter profile {profile} is missing or stale; run dotfiles generate")]
    StaleProfile { profile: String },
    #[error("expected the managed Dotter activation, found {0}")]
    WrongActivation(String),
    #[error("Arsenal has no Dotter installation intent")]
    MissingDotterIntent,
    #[error("Dotter version mismatch: expected {expected}, found {actual}")]
    DotterVersion { expected: String, actual: String },
    #[error("Dotter execution failed: {0}")]
    DotterExecution(String),
    #[error("watched dotfile is too large to fingerprint safely: {path} ({size} bytes)")]
    WatchedFileTooLarge { path: PathBuf, size: u64 },
    #[error("Dotter configuration or evidence is invalid: {0}")]
    Configuration(String),
    #[error("Dotter profile operation is already running: {0}")]
    Concurrent(String),
    #[error("system clock is before the Unix epoch: {0}")]
    Clock(String),
    #[error("{action} at {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    PrivatePath(#[from] crate::VerifiedArtifactError),
}

struct ExpectedProfile {
    local_config: Vec<u8>,
    manifest: DotterProfileManifest,
}

struct DotfilesLock {
    file: File,
}

impl Drop for DotfilesLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PathFingerprint {
    kind: FingerprintKind,
    size: u64,
    sha256: Option<String>,
    link_target: Option<PathBuf>,
    mode: u32,
    modified_nanos: Option<u128>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FingerprintKind {
    Absent,
    File,
    Directory,
    Symlink,
    Other,
}

fn canonical_workspace_root(path: &Path) -> Result<PathBuf, DotfilesError> {
    let root = fs::canonicalize(path)
        .map_err(|error| io_error("canonicalize HAZARDS workspace", path, error))?;
    let metadata = fs::symlink_metadata(&root)
        .map_err(|error| io_error("inspect HAZARDS workspace", &root, error))?;
    if !metadata.is_dir() || !root.join("ingredients/dotterbatter/global.toml").is_file() {
        return Err(DotfilesError::InvalidWorkspace(root));
    }
    Ok(root)
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), DotfilesError> {
    let safe = !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if safe {
        Ok(())
    } else {
        Err(DotfilesError::UnsafeIdentifier {
            field,
            value: value.to_owned(),
        })
    }
}

fn strict_relative_path(value: &str) -> Option<PathBuf> {
    let path = Path::new(value);
    (!value.is_empty()
        && value.len() <= 4096
        && !value.contains('\\')
        && path.components().all(|component| {
            matches!(
                component,
                Component::Normal(name) if name.as_encoded_bytes().len() <= 255
            )
        }))
    .then(|| path.to_path_buf())
}

fn validate_source(root: &Path, value: &str) -> Result<PathBuf, DotfilesError> {
    let relative =
        strict_relative_path(value).ok_or_else(|| DotfilesError::UnsafeSource(value.into()))?;
    let source = root.join(relative);
    let metadata =
        fs::symlink_metadata(&source).map_err(|_| DotfilesError::UnsafeSource(source.clone()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DotfilesError::UnsafeSource(source));
    }
    let canonical =
        fs::canonicalize(&source).map_err(|_| DotfilesError::UnsafeSource(source.clone()))?;
    if !canonical.starts_with(root) {
        return Err(DotfilesError::UnsafeSource(canonical));
    }
    Ok(canonical)
}

fn validate_target(home: &Path, value: &str) -> Result<PathBuf, DotfilesError> {
    let relative = value
        .strip_prefix("~/")
        .and_then(strict_relative_path)
        .ok_or_else(|| DotfilesError::UnsafeTarget(value.to_owned()))?;
    Ok(home.join(relative))
}

fn profile_id(profile: &ResolvedProfile) -> String {
    format!("{}-{}-{}", profile.host, profile.persistence, profile.role)
}

fn read_bounded_regular_file(path: &Path, maximum: usize) -> Result<Vec<u8>, DotfilesError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| io_error("inspect Dotter file", path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err(DotfilesError::Configuration(format!(
            "{} is not an accepted regular file",
            path.display()
        )));
    }
    fs::read(path).map_err(|error| io_error("read Dotter file", path, error))
}

fn read_optional_private_file(path: &Path) -> Result<Option<Vec<u8>>, DotfilesError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error("inspect generated Dotter file", path, error)),
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() > MAX_CONFIG_SIZE as u64 =>
        {
            Err(DotfilesError::Configuration(format!(
                "{} is not an accepted private file",
                path.display()
            )))
        }
        Ok(metadata) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(DotfilesError::Configuration(format!(
                        "{} is not private",
                        path.display()
                    )));
                }
            }
            fs::read(path)
                .map(Some)
                .map_err(|error| io_error("read generated Dotter file", path, error))
        }
    }
}

fn read_required_private_file(path: &Path) -> Result<Vec<u8>, DotfilesError> {
    read_optional_private_file(path)?.ok_or_else(|| DotfilesError::StaleProfile {
        profile: path
            .parent()
            .and_then(Path::file_name)
            .and_then(|value| value.to_str())
            .unwrap_or("<unknown>")
            .to_owned(),
    })
}

fn encode_json(value: &impl Serialize) -> Result<Vec<u8>, DotfilesError> {
    let mut encoded = serde_json::to_vec_pretty(value)
        .map_err(|error| DotfilesError::Configuration(error.to_string()))?;
    encoded.push(b'\n');
    if encoded.len() > MAX_CONFIG_SIZE {
        return Err(DotfilesError::Configuration(
            "serialized Dotter evidence exceeds the size limit".to_owned(),
        ));
    }
    Ok(encoded)
}

fn write_atomic_private(directory: &Path, path: &Path, bytes: &[u8]) -> Result<(), DotfilesError> {
    let mut temporary = NamedTempFile::new_in(directory)
        .map_err(|error| io_error("create temporary Dotter profile file", directory, error))?;
    set_private_file_permissions(temporary.as_file(), temporary.path())?;
    temporary
        .write_all(bytes)
        .map_err(|error| io_error("write Dotter profile file", temporary.path(), error))?;
    temporary
        .as_file_mut()
        .sync_all()
        .map_err(|error| io_error("synchronize Dotter profile file", temporary.path(), error))?;
    temporary
        .persist(path)
        .map_err(|error| io_error("persist Dotter profile file", path, error.error))?;
    sync_directory(directory)?;
    Ok(())
}

fn write_json_noclobber(
    directory: &Path,
    path: &Path,
    value: &impl Serialize,
) -> Result<(), DotfilesError> {
    let encoded = encode_json(value)?;
    let mut temporary = NamedTempFile::new_in(directory)
        .map_err(|error| io_error("create temporary Dotter receipt", directory, error))?;
    set_private_file_permissions(temporary.as_file(), temporary.path())?;
    temporary
        .write_all(&encoded)
        .map_err(|error| io_error("write Dotter receipt", temporary.path(), error))?;
    temporary
        .as_file_mut()
        .sync_all()
        .map_err(|error| io_error("synchronize Dotter receipt", temporary.path(), error))?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| io_error("persist Dotter receipt", path, error.error))?;
    sync_directory(directory)?;
    Ok(())
}

fn dotter_dry_run_arguments(
    global_config: &Path,
    local_config: &Path,
    scratch: &Path,
    cache_directory: &Path,
) -> Vec<OsString> {
    let options = [
        ("--global-config", global_config),
        ("--local-config", local_config),
        ("--cache-file", &scratch.join("cache.toml")),
        ("--cache-directory", cache_directory),
        ("--pre-deploy", &scratch.join("hooks/pre-deploy.disabled")),
        ("--post-deploy", &scratch.join("hooks/post-deploy.disabled")),
        (
            "--pre-undeploy",
            &scratch.join("hooks/pre-undeploy.disabled"),
        ),
        (
            "--post-undeploy",
            &scratch.join("hooks/post-undeploy.disabled"),
        ),
    ];
    let mut arguments = Vec::with_capacity(options.len() * 2 + 3);
    for (flag, path) in options {
        arguments.push(OsString::from(flag));
        arguments.push(path.as_os_str().to_owned());
    }
    arguments.extend([
        OsString::from("--dry-run"),
        OsString::from("--noconfirm"),
        OsString::from("deploy"),
    ]);
    arguments
}

fn watched_paths(
    home: &Path,
    mappings: &[DotfileMapping],
) -> Result<BTreeSet<PathBuf>, DotfilesError> {
    let mut paths = BTreeSet::new();
    for mapping in mappings {
        if !mapping.target.starts_with(home) {
            return Err(DotfilesError::UnsafeTarget(
                mapping.target.display().to_string(),
            ));
        }
        let mut current = Some(mapping.target.as_path());
        while let Some(path) = current {
            if path == home {
                break;
            }
            paths.insert(path.to_path_buf());
            current = path.parent();
        }
    }
    Ok(paths)
}

fn fingerprint_paths(
    paths: &BTreeSet<PathBuf>,
) -> Result<BTreeMap<PathBuf, PathFingerprint>, DotfilesError> {
    paths
        .iter()
        .map(|path| Ok((path.clone(), fingerprint(path)?)))
        .collect()
}

fn fingerprint(path: &Path) -> Result<PathFingerprint, DotfilesError> {
    let metadata = match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(PathFingerprint {
                kind: FingerprintKind::Absent,
                size: 0,
                sha256: None,
                link_target: None,
                mode: 0,
                modified_nanos: None,
            });
        }
        Err(error) => return Err(io_error("fingerprint dotfile path", path, error)),
        Ok(metadata) => metadata,
    };
    let kind = if metadata.file_type().is_symlink() {
        FingerprintKind::Symlink
    } else if metadata.is_file() {
        FingerprintKind::File
    } else if metadata.is_dir() {
        FingerprintKind::Directory
    } else {
        FingerprintKind::Other
    };
    if kind == FingerprintKind::File && metadata.len() > MAX_WATCHED_FILE_SIZE {
        return Err(DotfilesError::WatchedFileTooLarge {
            path: path.to_path_buf(),
            size: metadata.len(),
        });
    }
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o7777
    };
    #[cfg(not(unix))]
    let mode = 0;
    let modified_nanos = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos());
    Ok(PathFingerprint {
        kind,
        size: metadata.len(),
        sha256: (kind == FingerprintKind::File)
            .then(|| hash_file(path))
            .transpose()?,
        link_target: (kind == FingerprintKind::Symlink)
            .then(|| {
                fs::read_link(path).map_err(|error| io_error("read dotfile symlink", path, error))
            })
            .transpose()?,
        mode,
        modified_nanos,
    })
}

fn run_bounded(
    executable: &Path,
    working_directory: Option<&Path>,
    arguments: &[OsString],
    capture_directory: &Path,
    timeout: Duration,
) -> Result<DotterCommandOutput, String> {
    let stdout = NamedTempFile::new_in(capture_directory).map_err(|error| error.to_string())?;
    let stderr = NamedTempFile::new_in(capture_directory).map_err(|error| error.to_string())?;
    let stdout_path = stdout.path().to_path_buf();
    let stderr_path = stderr.path().to_path_buf();
    let mut command = Command::new(executable);
    command
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            stdout.reopen().map_err(|error| error.to_string())?,
        ))
        .stderr(Stdio::from(
            stderr.reopen().map_err(|error| error.to_string())?,
        ));
    if let Some(directory) = working_directory {
        command.current_dir(directory);
    }
    let mut child = command.spawn().map_err(|error| error.to_string())?;
    let started = Instant::now();
    let (status, failure) = loop {
        match child.try_wait().map_err(|error| error.to_string())? {
            Some(status) => break (Some(status), None),
            None => {
                let output_size = file_size(&stdout_path)? + file_size(&stderr_path)?;
                if output_size > MAX_COMMAND_OUTPUT {
                    let _ = child.kill();
                    let status = child.wait().ok();
                    break (
                        status,
                        Some(format!(
                            "captured output exceeded {} bytes",
                            MAX_COMMAND_OUTPUT
                        )),
                    );
                }
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let status = child.wait().ok();
                    break (
                        status,
                        Some(format!("command exceeded {} seconds", timeout.as_secs())),
                    );
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
    };
    let stdout = read_command_output(&stdout_path)?;
    let stderr = read_command_output(&stderr_path)?;
    Ok(DotterCommandOutput {
        exit_code: status.and_then(|status| status.code()),
        stdout,
        stderr,
        failure,
    })
}

fn file_size(path: &Path) -> Result<u64, String> {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .map_err(|error| error.to_string())
}

fn read_command_output(path: &Path) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|error| error.to_string())?;
    let mut output = Vec::new();
    file.take(MAX_COMMAND_OUTPUT + 1)
        .read_to_end(&mut output)
        .map_err(|error| error.to_string())?;
    if output.len() as u64 > MAX_COMMAND_OUTPUT {
        return Err("captured command output exceeds the size limit".to_owned());
    }
    Ok(output)
}

fn command_failure(output: &DotterCommandOutput) -> String {
    if let Some(failure) = &output.failure {
        return failure.clone();
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    format!(
        "exited with code {:?}{}",
        output.exit_code,
        if detail.is_empty() {
            String::new()
        } else {
            format!(": {detail}")
        }
    )
}

fn hash_file(path: &Path) -> Result<String, DotfilesError> {
    let mut file =
        File::open(path).map_err(|error| io_error("open dotfile for hashing", path, error))?;
    let mut digest = Sha256::new();
    io::copy(&mut file, &mut digest).map_err(|error| io_error("hash dotfile", path, error))?;
    Ok(format!("{:x}", digest.finalize()))
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn receipt_identity() -> Result<(String, u64), DotfilesError> {
    let occurred = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| DotfilesError::Clock(error.to_string()))?;
    Ok((
        format!(
            "{}-{:09}-{}-{}",
            occurred.as_secs(),
            occurred.subsec_nanos(),
            std::process::id(),
            RECEIPT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ),
        occurred.as_secs(),
    ))
}

fn set_directory_mode(path: &Path, mode: u32) -> Result<(), DotfilesError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| io_error("set Dotter directory permissions", path, error))?;
    }
    Ok(())
}

fn io_error(action: &'static str, path: &Path, source: io::Error) -> DotfilesError {
    DotfilesError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use crate::{HostKind, Persistence, Role};

    use super::*;

    struct FakeRunner {
        output: DotterCommandOutput,
        mutation: Option<PathBuf>,
    }

    impl FakeRunner {
        fn clean() -> Self {
            Self {
                output: DotterCommandOutput {
                    exit_code: Some(0),
                    stdout: b"dry run only\n".to_vec(),
                    stderr: Vec::new(),
                    failure: None,
                },
                mutation: None,
            }
        }
    }

    impl DotterRunner for FakeRunner {
        fn version(&self, _executable: &Path, _capture_directory: &Path) -> Result<String, String> {
            Ok("dotter 0.13.5".to_owned())
        }

        fn dry_run(&self, invocation: DotterInvocation<'_>) -> Result<DotterCommandOutput, String> {
            assert!(
                invocation
                    .arguments
                    .iter()
                    .any(|value| value == OsStr::new("--dry-run"))
            );
            assert!(
                !invocation
                    .arguments
                    .iter()
                    .any(|value| value == OsStr::new("--force"))
            );
            if let Some(path) = &self.mutation {
                fs::create_dir_all(path.parent().expect("target should have a parent"))
                    .expect("mutation parent should exist");
                fs::write(path, b"Dotter lied").expect("mutation should write");
            }
            Ok(DotterCommandOutput {
                exit_code: self.output.exit_code,
                stdout: self.output.stdout.clone(),
                stderr: self.output.stderr.clone(),
                failure: self.output.failure.clone(),
            })
        }
    }

    fn fixture() -> (tempfile::TempDir, Registry, HazardsPaths) {
        let root = tempfile::tempdir().expect("fixture root should exist");
        let workspace = root.path().join("workspace");
        for path in [
            "ingredients/dotterbatter",
            "ingredients/helixer",
            "ingredients/alacarte",
            "ingredients/zellijuice/layouts",
        ] {
            fs::create_dir_all(workspace.join(path)).expect("fixture directory should exist");
        }
        fs::write(
            workspace.join("ingredients/dotterbatter/global.toml"),
            r#"[helixer.files]
"ingredients/helixer/config.toml" = "~/.config/helix/config.toml"

[alacarte.files]
"ingredients/alacarte/alacritty.toml" = "~/.config/alacritty/alacritty.toml"

[zellijuice.files]
"ingredients/zellijuice/config.kdl" = "~/.config/zellij/config.kdl"
"ingredients/zellijuice/layouts/hazards.kdl" = "~/.config/zellij/layouts/hazards.kdl"
"#,
        )
        .expect("global fixture should write");
        for path in [
            "ingredients/helixer/config.toml",
            "ingredients/alacarte/alacritty.toml",
            "ingredients/zellijuice/config.kdl",
            "ingredients/zellijuice/layouts/hazards.kdl",
        ] {
            fs::write(workspace.join(path), path.as_bytes()).expect("source fixture should write");
        }
        let home = root.path().join("home");
        fs::create_dir(&home).expect("home should exist");
        let paths = HazardsPaths {
            home: home.clone(),
            config: home.join(".config/hazards"),
            data: home.join(".local/share/hazards"),
            state: home.join(".local/state/hazards"),
            cache: home.join(".cache/hazards"),
            bin: home.join(".local/bin"),
        };
        (
            root,
            Registry::embedded().expect("registry should load"),
            paths,
        )
    }

    fn workspace(root: &tempfile::TempDir) -> PathBuf {
        root.path().join("workspace")
    }

    fn activation(paths: &HazardsPaths) -> ManagedActivation {
        ManagedActivation {
            tool_id: "dotter".to_owned(),
            version: "0.13.5".to_owned(),
            activation_path: paths.bin.join("dotter"),
            payload_path: paths.data.join("apps/dotter/0.13.5/digest/dotter"),
            version_output: "dotter 0.13.5".to_owned(),
        }
    }

    #[test]
    fn desktop_generation_is_deterministic_private_and_idempotent() {
        let (root, registry, paths) = fixture();
        let profile =
            ResolvedProfile::new(HostKind::Desktop, Persistence::Local, Role::Development);
        let manager =
            DotfilesManager::new(&registry, &profile, &paths, workspace(&root)).expect("manager");

        let first = manager.generate().expect("profile should generate");
        let second = manager.generate().expect("profile should be idempotent");

        assert_eq!(
            first.manifest.packages,
            ["helixer", "alacarte", "zellijuice"]
        );
        assert_eq!(first.manifest.mappings.len(), 4);
        assert_eq!(first.receipt.outcome, DotterGenerationOutcome::Generated);
        assert_eq!(second.receipt.outcome, DotterGenerationOutcome::Unchanged);
        assert_eq!(
            fs::read_to_string(&first.local_config_path).expect("local config should read"),
            "# Generated by HAZARDS. Edit the profile model, not this file.\npackages = [\"helixer\", \"alacarte\", \"zellijuice\"]\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&first.local_config_path)
                    .expect("local config metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn remote_generation_omits_client_side_alacritty() {
        let (root, registry, paths) = fixture();
        let profile = ResolvedProfile::new(HostKind::Remote, Persistence::Ghost, Role::Operations);
        let manager =
            DotfilesManager::new(&registry, &profile, &paths, workspace(&root)).expect("manager");

        let generated = manager.generate().expect("profile should generate");

        assert_eq!(generated.manifest.packages, ["helixer", "zellijuice"]);
        assert!(
            generated
                .manifest
                .mappings
                .iter()
                .all(|mapping| mapping.package != "alacarte")
        );
    }

    #[test]
    fn unsafe_targets_and_sources_are_rejected() {
        let (root, registry, paths) = fixture();
        let profile =
            ResolvedProfile::new(HostKind::Desktop, Persistence::Local, Role::Development);
        let global = workspace(&root).join("ingredients/dotterbatter/global.toml");
        let original = fs::read_to_string(&global).expect("global config should read");
        fs::write(
            &global,
            original.replace(
                "\"~/.config/helix/config.toml\"",
                "\"/etc/helix/config.toml\"",
            ),
        )
        .expect("unsafe target should write");
        let manager =
            DotfilesManager::new(&registry, &profile, &paths, workspace(&root)).expect("manager");
        assert!(matches!(
            manager.generate(),
            Err(DotfilesError::UnsafeTarget(_))
        ));

        fs::write(
            &global,
            original.replace("\"ingredients/helixer/config.toml\"", "\"../outside.toml\""),
        )
        .expect("unsafe source should write");
        let manager =
            DotfilesManager::new(&registry, &profile, &paths, workspace(&root)).expect("manager");
        assert!(matches!(
            manager.generate(),
            Err(DotfilesError::UnsafeSource(_))
        ));
    }

    #[test]
    fn clean_dry_run_captures_output_and_preserves_targets() {
        let (root, registry, paths) = fixture();
        let profile =
            ResolvedProfile::new(HostKind::Desktop, Persistence::Local, Role::Development);
        let manager = DotfilesManager::with_runner(
            &registry,
            &profile,
            &paths,
            workspace(&root),
            FakeRunner::clean(),
        )
        .expect("manager");
        manager.generate().expect("profile should generate");

        let report = manager
            .dry_run(&activation(&paths))
            .expect("dry run should complete");

        assert_eq!(report.receipt.outcome, DotterDryRunOutcome::Clean);
        assert!(report.receipt.changed_paths.is_empty());
        assert_eq!(report.stdout, "dry run only\n");
        assert!(report.receipt.watched_path_count >= 4);
    }

    #[test]
    fn dry_run_detects_a_target_or_parent_mutation() {
        let (root, registry, paths) = fixture();
        let profile =
            ResolvedProfile::new(HostKind::Desktop, Persistence::Local, Role::Development);
        let target = paths.home.join(".config/helix/config.toml");
        let manager = DotfilesManager::with_runner(
            &registry,
            &profile,
            &paths,
            workspace(&root),
            FakeRunner {
                mutation: Some(target.clone()),
                ..FakeRunner::clean()
            },
        )
        .expect("manager");
        manager.generate().expect("profile should generate");

        let report = manager
            .dry_run(&activation(&paths))
            .expect("mutation should be reported");

        assert_eq!(
            report.receipt.outcome,
            DotterDryRunOutcome::MutationDetected
        );
        assert!(report.receipt.changed_paths.contains(&target));
        assert!(report.receipt_path.is_file());
    }

    #[test]
    fn dry_run_reports_nonzero_exit_without_calling_it_clean() {
        let (root, registry, paths) = fixture();
        let profile =
            ResolvedProfile::new(HostKind::Desktop, Persistence::Local, Role::Development);
        let manager = DotfilesManager::with_runner(
            &registry,
            &profile,
            &paths,
            workspace(&root),
            FakeRunner {
                output: DotterCommandOutput {
                    exit_code: Some(2),
                    stdout: Vec::new(),
                    stderr: b"configuration rejected".to_vec(),
                    failure: None,
                },
                mutation: None,
            },
        )
        .expect("manager");
        manager.generate().expect("profile should generate");

        let report = manager
            .dry_run(&activation(&paths))
            .expect("failed command should be receipted");

        assert_eq!(report.receipt.outcome, DotterDryRunOutcome::CommandFailed);
        assert_eq!(report.receipt.exit_code, Some(2));
        assert_eq!(report.stderr, "configuration rejected");
    }

    #[test]
    fn dry_run_refuses_a_missing_or_edited_generated_profile() {
        let (root, registry, paths) = fixture();
        let profile =
            ResolvedProfile::new(HostKind::Desktop, Persistence::Local, Role::Development);
        let manager = DotfilesManager::with_runner(
            &registry,
            &profile,
            &paths,
            workspace(&root),
            FakeRunner::clean(),
        )
        .expect("manager");
        assert!(matches!(
            manager.dry_run(&activation(&paths)),
            Err(DotfilesError::StaleProfile { .. })
        ));

        let generated = manager.generate().expect("profile should generate");
        fs::write(&generated.local_config_path, b"packages = []\n")
            .expect("generated profile should be edited");
        assert!(matches!(
            manager.dry_run(&activation(&paths)),
            Err(DotfilesError::StaleProfile { .. })
        ));
    }

    #[test]
    fn workspace_discovery_walks_up_from_a_nested_directory() {
        let (root, _registry, _paths) = fixture();
        let nested = workspace(&root).join("ingredients/zellijuice/layouts");

        assert_eq!(
            DotfilesManager::<SystemDotterRunner>::discover_workspace(&nested)
                .expect("workspace should be found"),
            fs::canonicalize(workspace(&root)).expect("workspace should canonicalize")
        );
    }
}
