use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::{Builder, TempDir};
use thiserror::Error;

use crate::{
    AcquisitionItem, AcquisitionStatus, EnvironmentProbe, HazardsPaths, MaterializationError,
    Materializer, SystemProbe,
    acquire::{
        ensure_private_dir, ensure_private_subdirectories, set_private_file_permissions,
        sync_directory, validate_component,
    },
    materialize::{MaterializedEntry, MaterializedEntryKind, VerifiedStage},
    provision::version_matches,
};

const INSTALLATION_MANIFEST_NAME: &str = ".hazards-installation.json";
const INSTALLATION_MANIFEST_SCHEMA_VERSION: u8 = 1;
const INSTALLATION_RECEIPT_SCHEMA_VERSION: u8 = 1;
const MAX_EVIDENCE_SIZE: usize = 16 * 1024 * 1024;
const MAX_INSTALLED_PAYLOAD_SIZE: u64 = 512 * 1024 * 1024;
const MAX_INSTALLED_ENTRIES: usize = 100_000;
const COPY_BUFFER_SIZE: usize = 64 * 1024;
static RECEIPT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Whether durable application bytes were created or independently verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreOutcome {
    Stored,
    StoreHit,
}

/// The completed state transition represented by an installation receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallationOutcome {
    Installed,
    Upgraded,
    AlreadyActive,
    ActivationRolledBack,
    RollbackFailed,
    RolledBack,
}

impl std::fmt::Display for InstallationOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Installed => formatter.write_str("installed"),
            Self::Upgraded => formatter.write_str("upgraded"),
            Self::AlreadyActive => formatter.write_str("already-active"),
            Self::ActivationRolledBack => formatter.write_str("activation-rolled-back"),
            Self::RollbackFailed => formatter.write_str("rollback-failed"),
            Self::RolledBack => formatter.write_str("rolled-back"),
        }
    }
}

/// Append-only evidence for activation, automatic recovery, or explicit rollback.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct InstallationReceipt {
    pub schema_version: u8,
    pub receipt_id: String,
    pub related_receipt_id: Option<String>,
    pub tool_id: String,
    pub version: String,
    pub command: String,
    pub artifact_sha256: String,
    pub payload_sha256: String,
    pub store_path: PathBuf,
    pub activation_path: PathBuf,
    pub previous_target: Option<PathBuf>,
    pub active_target: Option<PathBuf>,
    pub previous_resolved_path: Option<PathBuf>,
    pub store_outcome: StoreOutcome,
    pub outcome: InstallationOutcome,
    pub version_output: Option<String>,
    pub failure: Option<String>,
    pub occurred_at_unix: u64,
}

/// Result of a successful installation or idempotent activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstalledArtifact {
    pub store_path: PathBuf,
    pub payload_path: PathBuf,
    pub activation_path: PathBuf,
    pub receipt_path: PathBuf,
    pub receipt: InstallationReceipt,
}

/// Result of restoring the activation that preceded an installation receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RolledBackArtifact {
    pub activation_path: PathBuf,
    pub active_target: Option<PathBuf>,
    pub receipt_path: PathBuf,
    pub receipt: InstallationReceipt,
}

/// A HAZARDS-managed command whose store, payload, version, and PATH activation
/// were independently verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagedActivation {
    pub tool_id: String,
    pub version: String,
    pub activation_path: PathBuf,
    pub payload_path: PathBuf,
    pub version_output: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct InstallationManifest {
    schema_version: u8,
    tool_id: String,
    version: String,
    command: String,
    artifact_sha256: String,
    payload_path: String,
    payload_size: u64,
    payload_sha256: String,
    architecture: String,
    entries: Vec<MaterializedEntry>,
}

/// Transactional rootless activation from verified HAZARDS staging.
pub struct Installer<P = SystemProbe> {
    materializer: Materializer,
    data_root: PathBuf,
    state_root: PathBuf,
    bin_root: PathBuf,
    probe: P,
}

impl Installer<SystemProbe> {
    pub fn for_paths(paths: &HazardsPaths) -> Self {
        Self::with_probe(
            paths.cache.clone(),
            paths.data.clone(),
            paths.state.clone(),
            paths.bin.clone(),
            SystemProbe,
        )
    }
}

impl<P: EnvironmentProbe> Installer<P> {
    pub fn with_probe(
        cache_root: impl Into<PathBuf>,
        data_root: impl Into<PathBuf>,
        state_root: impl Into<PathBuf>,
        bin_root: impl Into<PathBuf>,
        probe: P,
    ) -> Self {
        let cache_root = cache_root.into();
        let state_root = state_root.into();
        Self {
            materializer: Materializer::new(cache_root, state_root.clone()),
            data_root: data_root.into(),
            state_root,
            bin_root: bin_root.into(),
            probe,
        }
    }

    pub fn install(
        &self,
        item: &AcquisitionItem,
        command: &str,
        version_args: &[String],
    ) -> Result<InstalledArtifact, InstallationError> {
        validate_request(item, command)?;
        let _lock = self.acquire_lock(&item.id)?;
        let stage = self.materializer.verify_existing(item)?;
        let (store_path, store_outcome, install_manifest) =
            self.prepare_store(item, command, &stage)?;
        let payload_path = store_path.join(&install_manifest.payload_path);
        self.verify_version(
            &payload_path,
            version_args,
            &install_manifest.version,
            "stored payload",
        )?;

        ensure_user_bin(&self.bin_root)?;
        let activation_path = self.bin_root.join(command);
        let previous = self.inspect_activation(&activation_path, &item.id, command)?;
        let previous_target = previous.target().cloned();
        let previous_resolved_path = self.probe.locate(&[command]).map(|located| located.path);

        if previous_target.as_deref() == Some(payload_path.as_path()) {
            let version_output = self.verify_activation(
                &activation_path,
                command,
                version_args,
                &install_manifest.version,
            )?;
            let receipt = self.receipt(
                item,
                command,
                &store_path,
                &activation_path,
                previous_target.clone(),
                Some(payload_path.clone()),
                previous_resolved_path,
                store_outcome,
                InstallationOutcome::AlreadyActive,
                Some(version_output),
                None,
                None,
            )?;
            let receipt_path = self.write_receipt(&receipt)?;
            return Ok(InstalledArtifact {
                store_path,
                payload_path,
                activation_path,
                receipt_path,
                receipt,
            });
        }

        replace_activation(
            &activation_path,
            previous_target.as_deref(),
            Some(&payload_path),
        )?;

        let postflight = self.verify_activation(
            &activation_path,
            command,
            version_args,
            &install_manifest.version,
        );
        let version_output = match postflight {
            Ok(output) => output,
            Err(error) => {
                return Err(self.recover_failed_activation(
                    item,
                    command,
                    &store_path,
                    &activation_path,
                    previous_target,
                    &payload_path,
                    previous_resolved_path,
                    store_outcome,
                    error.to_string(),
                ));
            }
        };

        let outcome = if previous_target.is_some() {
            InstallationOutcome::Upgraded
        } else {
            InstallationOutcome::Installed
        };
        let receipt = self.receipt(
            item,
            command,
            &store_path,
            &activation_path,
            previous_target.clone(),
            Some(payload_path.clone()),
            previous_resolved_path.clone(),
            store_outcome,
            outcome,
            Some(version_output),
            None,
            None,
        )?;
        let receipt_path = match self.write_receipt(&receipt) {
            Ok(path) => path,
            Err(error) => {
                let evidence_failure = format!("could not persist installation receipt: {error}");
                return Err(self.recover_failed_activation(
                    item,
                    command,
                    &store_path,
                    &activation_path,
                    previous_target,
                    &payload_path,
                    previous_resolved_path,
                    store_outcome,
                    evidence_failure,
                ));
            }
        };

        Ok(InstalledArtifact {
            store_path,
            payload_path,
            activation_path,
            receipt_path,
            receipt,
        })
    }

    pub fn verify_active(
        &self,
        tool_id: &str,
        command: &str,
        version_args: &[String],
    ) -> Result<ManagedActivation, InstallationError> {
        validate_component("tool identifier", tool_id)?;
        validate_command(command)?;
        let _lock = self.acquire_lock(tool_id)?;
        let activation_path = self.bin_root.join(command);
        let current = self.inspect_activation(&activation_path, tool_id, command)?;
        let payload_path = current
            .target()
            .cloned()
            .ok_or_else(|| InstallationError::NoActiveInstallation(tool_id.to_owned()))?;
        let manifest = self.validate_managed_target(&payload_path, tool_id, command)?;
        let version_output =
            self.verify_activation(&activation_path, command, version_args, &manifest.version)?;
        Ok(ManagedActivation {
            tool_id: tool_id.to_owned(),
            version: manifest.version,
            activation_path,
            payload_path,
            version_output,
        })
    }

    pub fn rollback(
        &self,
        tool_id: &str,
        command: &str,
        version_args: &[String],
    ) -> Result<RolledBackArtifact, InstallationError> {
        validate_component("tool identifier", tool_id)?;
        validate_command(command)?;
        let _lock = self.acquire_lock(tool_id)?;
        let activation_path = self.bin_root.join(command);
        let current = self.inspect_activation(&activation_path, tool_id, command)?;
        let current_target = current
            .target()
            .cloned()
            .ok_or_else(|| InstallationError::NoActiveInstallation(tool_id.to_owned()))?;
        let current_manifest = self.validate_managed_target(&current_target, tool_id, command)?;
        let candidate = self
            .rollback_candidate(tool_id, &current_target)?
            .ok_or_else(|| InstallationError::NoRollback(tool_id.to_owned()))?;

        let restored_manifest = candidate
            .previous_target
            .as_deref()
            .map(|target| self.validate_managed_target(target, tool_id, command))
            .transpose()?;
        if let (Some(target), Some(manifest)) = (
            candidate.previous_target.as_deref(),
            restored_manifest.as_ref(),
        ) {
            self.verify_version(target, version_args, &manifest.version, "rollback payload")?;
        }

        replace_activation(
            &activation_path,
            Some(&current_target),
            candidate.previous_target.as_deref(),
        )?;
        let postflight = match restored_manifest.as_ref() {
            Some(manifest) => self
                .verify_activation(&activation_path, command, version_args, &manifest.version)
                .map(Some),
            None => self
                .verify_restored_resolution(command, candidate.previous_resolved_path.as_deref())
                .map(|()| None),
        };

        let version_output = match postflight {
            Ok(output) => output,
            Err(error) => {
                let recovery = replace_activation(
                    &activation_path,
                    candidate.previous_target.as_deref(),
                    Some(&current_target),
                );
                let recovery_succeeded = recovery.is_ok();
                let reason = match recovery {
                    Ok(()) => {
                        format!("rollback validation failed and activation was restored: {error}")
                    }
                    Err(ref recovery) => format!(
                        "rollback validation failed ({error}); restoring the active target also failed: {recovery}"
                    ),
                };
                let outcome = if recovery_succeeded {
                    InstallationOutcome::ActivationRolledBack
                } else {
                    InstallationOutcome::RollbackFailed
                };
                let failure_receipt = self.receipt_from_manifest(
                    tool_id,
                    command,
                    &current_manifest,
                    &activation_path,
                    candidate.previous_target.clone(),
                    Some(current_target.clone()),
                    candidate.previous_resolved_path.clone(),
                    StoreOutcome::StoreHit,
                    outcome,
                    None,
                    Some(reason.clone()),
                    Some(candidate.receipt_id.clone()),
                )?;
                let _ = self.write_receipt(&failure_receipt);
                return Err(InstallationError::RollbackFailed {
                    tool: tool_id.to_owned(),
                    reason,
                });
            }
        };

        let receipt = self.receipt_from_manifest(
            tool_id,
            command,
            &current_manifest,
            &activation_path,
            Some(current_target.clone()),
            candidate.previous_target.clone(),
            candidate.previous_resolved_path.clone(),
            StoreOutcome::StoreHit,
            InstallationOutcome::RolledBack,
            version_output,
            None,
            Some(candidate.receipt_id.clone()),
        )?;
        let receipt_path = match self.write_receipt(&receipt) {
            Ok(path) => path,
            Err(error) => {
                let recovery = replace_activation(
                    &activation_path,
                    candidate.previous_target.as_deref(),
                    Some(&current_target),
                );
                return Err(InstallationError::RollbackFailed {
                    tool: tool_id.to_owned(),
                    reason: format!(
                        "could not persist rollback receipt ({error}); restoring the active target returned {recovery:?}"
                    ),
                });
            }
        };

        Ok(RolledBackArtifact {
            activation_path,
            active_target: candidate.previous_target,
            receipt_path,
            receipt,
        })
    }

    fn prepare_store(
        &self,
        item: &AcquisitionItem,
        command: &str,
        stage: &VerifiedStage,
    ) -> Result<(PathBuf, StoreOutcome, InstallationManifest), InstallationError> {
        let artifact = item
            .artifact
            .as_ref()
            .ok_or_else(|| InstallationError::Unavailable(item.id.clone()))?;
        let version_root = ensure_private_subdirectories(
            &self.data_root,
            &["apps", &item.id, &item.target_version],
        )?;
        let store_path = version_root.join(&artifact.sha256);
        let manifest = InstallationManifest {
            schema_version: INSTALLATION_MANIFEST_SCHEMA_VERSION,
            tool_id: item.id.clone(),
            version: item.target_version.clone(),
            command: command.to_owned(),
            artifact_sha256: artifact.sha256.clone(),
            payload_path: stage.manifest.payload_path.clone(),
            payload_size: stage.manifest.payload_size,
            payload_sha256: stage.manifest.payload_sha256.clone(),
            architecture: stage.manifest.architecture.clone(),
            entries: stage.manifest.entries.clone(),
        };

        if store_path.exists() {
            let existing = validate_store(&store_path)?;
            ensure_store_identity(&store_path, &existing, &manifest)?;
            return Ok((store_path, StoreOutcome::StoreHit, existing));
        }

        if manifest
            .entries
            .iter()
            .any(|entry| entry.path == INSTALLATION_MANIFEST_NAME)
        {
            return Err(InstallationError::ReservedPath(
                INSTALLATION_MANIFEST_NAME.to_owned(),
            ));
        }

        let candidate = Builder::new()
            .prefix(".install-")
            .tempdir_in(&version_root)
            .map_err(|error| {
                io_error("create temporary installation store", &version_root, error)
            })?;
        ensure_private_dir(candidate.path())?;
        copy_verified_tree(stage, candidate.path())?;
        set_payload_executable(candidate.path(), &manifest)?;
        write_json_noclobber(
            candidate.path(),
            &candidate.path().join(INSTALLATION_MANIFEST_NAME),
            &manifest,
        )?;
        validate_store(candidate.path())?;

        match fs::rename(candidate.path(), &store_path) {
            Ok(()) => {
                persist_tempdir(candidate);
                sync_directory(&version_root)?;
                Ok((store_path, StoreOutcome::Stored, manifest))
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::AlreadyExists | io::ErrorKind::DirectoryNotEmpty
                ) =>
            {
                let existing = validate_store(&store_path)?;
                ensure_store_identity(&store_path, &existing, &manifest)?;
                Ok((store_path, StoreOutcome::StoreHit, existing))
            }
            Err(error) => Err(io_error("persist installation store", &store_path, error)),
        }
    }

    fn inspect_activation(
        &self,
        path: &Path,
        tool_id: &str,
        command: &str,
    ) -> Result<ActivationState, InstallationError> {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(ActivationState::Absent),
            Err(error) => Err(io_error("inspect activation", path, error)),
            Ok(metadata) if metadata.file_type().is_symlink() => {
                let target = fs::read_link(path)
                    .map_err(|error| io_error("read activation target", path, error))?;
                self.validate_managed_target(&target, tool_id, command)?;
                Ok(ActivationState::Managed(target))
            }
            Ok(_) => Err(InstallationError::UnmanagedActivation(path.to_path_buf())),
        }
    }

    fn validate_managed_target(
        &self,
        target: &Path,
        tool_id: &str,
        command: &str,
    ) -> Result<InstallationManifest, InstallationError> {
        if !target.is_absolute()
            || target
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        {
            return Err(InstallationError::UnmanagedTarget(target.to_path_buf()));
        }
        let tool_root = self.data_root.join("apps").join(tool_id);
        let relative = target
            .strip_prefix(&tool_root)
            .map_err(|_| InstallationError::UnmanagedTarget(target.to_path_buf()))?;
        let mut components = relative.components();
        let Some(Component::Normal(version)) = components.next() else {
            return Err(InstallationError::UnmanagedTarget(target.to_path_buf()));
        };
        let Some(Component::Normal(artifact)) = components.next() else {
            return Err(InstallationError::UnmanagedTarget(target.to_path_buf()));
        };
        let payload_relative: PathBuf = components.collect();
        if payload_relative.as_os_str().is_empty() {
            return Err(InstallationError::UnmanagedTarget(target.to_path_buf()));
        }
        let store_path = tool_root.join(version).join(artifact);
        let manifest = validate_store(&store_path)?;
        if manifest.tool_id != tool_id
            || manifest.command != command
            || store_path.join(&manifest.payload_path) != target
        {
            return Err(InstallationError::CorruptStore {
                path: store_path,
                reason: "activation target does not match its installation manifest".to_owned(),
            });
        }
        Ok(manifest)
    }

    fn verify_version(
        &self,
        executable: &Path,
        args: &[String],
        expected: &str,
        subject: &'static str,
    ) -> Result<String, InstallationError> {
        let output = self.probe.version(executable, args).map_err(|reason| {
            InstallationError::HealthCheck {
                subject,
                path: executable.to_path_buf(),
                reason,
            }
        })?;
        if !version_matches(&output, expected) {
            return Err(InstallationError::VersionMismatch {
                path: executable.to_path_buf(),
                expected: expected.to_owned(),
                actual: output,
            });
        }
        Ok(output)
    }

    fn verify_activation(
        &self,
        activation: &Path,
        command: &str,
        args: &[String],
        expected: &str,
    ) -> Result<String, InstallationError> {
        let output = self.verify_version(activation, args, expected, "activated command")?;
        let located =
            self.probe
                .locate(&[command])
                .ok_or_else(|| InstallationError::PathVerification {
                    command: command.to_owned(),
                    expected: activation.to_path_buf(),
                    actual: None,
                })?;
        if normalize_command_path(&located.path)? != normalize_command_path(activation)? {
            return Err(InstallationError::PathVerification {
                command: command.to_owned(),
                expected: activation.to_path_buf(),
                actual: Some(located.path),
            });
        }
        Ok(output)
    }

    fn verify_restored_resolution(
        &self,
        command: &str,
        expected: Option<&Path>,
    ) -> Result<(), InstallationError> {
        let actual = self.probe.locate(&[command]).map(|located| located.path);
        let matches = match (actual.as_deref(), expected) {
            (None, None) => true,
            (Some(actual), Some(expected)) => {
                normalize_command_path(actual)? == normalize_command_path(expected)?
            }
            _ => false,
        };
        if matches {
            Ok(())
        } else {
            Err(InstallationError::PathVerification {
                command: command.to_owned(),
                expected: expected
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("<absent>")),
                actual,
            })
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn recover_failed_activation(
        &self,
        item: &AcquisitionItem,
        command: &str,
        store_path: &Path,
        activation_path: &Path,
        previous_target: Option<PathBuf>,
        failed_target: &Path,
        previous_resolved_path: Option<PathBuf>,
        store_outcome: StoreOutcome,
        failure: String,
    ) -> InstallationError {
        let recovery = replace_activation(
            activation_path,
            Some(failed_target),
            previous_target.as_deref(),
        );
        let (outcome, reason) = match recovery {
            Ok(()) => (
                InstallationOutcome::ActivationRolledBack,
                format!("{failure}; prior activation restored"),
            ),
            Err(error) => (
                InstallationOutcome::RollbackFailed,
                format!("{failure}; restoring the prior activation failed: {error}"),
            ),
        };
        if let Ok(receipt) = self.receipt(
            item,
            command,
            store_path,
            activation_path,
            Some(failed_target.to_path_buf()),
            previous_target,
            previous_resolved_path,
            store_outcome,
            outcome,
            None,
            Some(reason.clone()),
            None,
        ) {
            let _ = self.write_receipt(&receipt);
        }
        InstallationError::ActivationFailed {
            tool: item.id.clone(),
            reason,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn receipt(
        &self,
        item: &AcquisitionItem,
        command: &str,
        store_path: &Path,
        activation_path: &Path,
        previous_target: Option<PathBuf>,
        active_target: Option<PathBuf>,
        previous_resolved_path: Option<PathBuf>,
        store_outcome: StoreOutcome,
        outcome: InstallationOutcome,
        version_output: Option<String>,
        failure: Option<String>,
        related_receipt_id: Option<String>,
    ) -> Result<InstallationReceipt, InstallationError> {
        let artifact = item
            .artifact
            .as_ref()
            .ok_or_else(|| InstallationError::Unavailable(item.id.clone()))?;
        let payload_sha256 = artifact
            .payload_sha256
            .clone()
            .ok_or_else(|| InstallationError::Unavailable(item.id.clone()))?;
        let (receipt_id, occurred_at_unix) = receipt_identity()?;
        Ok(InstallationReceipt {
            schema_version: INSTALLATION_RECEIPT_SCHEMA_VERSION,
            receipt_id,
            related_receipt_id,
            tool_id: item.id.clone(),
            version: item.target_version.clone(),
            command: command.to_owned(),
            artifact_sha256: artifact.sha256.clone(),
            payload_sha256,
            store_path: store_path.to_path_buf(),
            activation_path: activation_path.to_path_buf(),
            previous_target,
            active_target,
            previous_resolved_path,
            store_outcome,
            outcome,
            version_output,
            failure,
            occurred_at_unix,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn receipt_from_manifest(
        &self,
        tool_id: &str,
        command: &str,
        manifest: &InstallationManifest,
        activation_path: &Path,
        previous_target: Option<PathBuf>,
        active_target: Option<PathBuf>,
        previous_resolved_path: Option<PathBuf>,
        store_outcome: StoreOutcome,
        outcome: InstallationOutcome,
        version_output: Option<String>,
        failure: Option<String>,
        related_receipt_id: Option<String>,
    ) -> Result<InstallationReceipt, InstallationError> {
        let (receipt_id, occurred_at_unix) = receipt_identity()?;
        Ok(InstallationReceipt {
            schema_version: INSTALLATION_RECEIPT_SCHEMA_VERSION,
            receipt_id,
            related_receipt_id,
            tool_id: tool_id.to_owned(),
            version: manifest.version.clone(),
            command: command.to_owned(),
            artifact_sha256: manifest.artifact_sha256.clone(),
            payload_sha256: manifest.payload_sha256.clone(),
            store_path: self
                .data_root
                .join("apps")
                .join(tool_id)
                .join(&manifest.version)
                .join(&manifest.artifact_sha256),
            activation_path: activation_path.to_path_buf(),
            previous_target,
            active_target,
            previous_resolved_path,
            store_outcome,
            outcome,
            version_output,
            failure,
            occurred_at_unix,
        })
    }

    fn write_receipt(&self, receipt: &InstallationReceipt) -> Result<PathBuf, InstallationError> {
        let directory = ensure_private_subdirectories(
            &self.state_root,
            &[
                "receipts",
                "installations",
                &receipt.tool_id,
                &receipt.version,
            ],
        )?;
        let path = directory.join(format!("{}.json", receipt.receipt_id));
        write_json_noclobber(&directory, &path, receipt)?;
        Ok(path)
    }

    fn rollback_candidate(
        &self,
        tool_id: &str,
        current_target: &Path,
    ) -> Result<Option<InstallationReceipt>, InstallationError> {
        let mut receipts = read_installation_receipts(&self.state_root, tool_id)?;
        receipts.sort_by(|left, right| {
            right
                .occurred_at_unix
                .cmp(&left.occurred_at_unix)
                .then_with(|| right.receipt_id.cmp(&left.receipt_id))
        });
        Ok(receipts.into_iter().find(|receipt| {
            matches!(
                receipt.outcome,
                InstallationOutcome::Installed | InstallationOutcome::Upgraded
            ) && receipt.active_target.as_deref() == Some(current_target)
        }))
    }

    fn acquire_lock(&self, tool_id: &str) -> Result<InstallationLock, InstallationError> {
        let directory =
            ensure_private_subdirectories(&self.state_root, &["locks", "installations"])?;
        let path = directory.join(format!("{tool_id}.lock"));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|error| io_error("open installation lock", &path, error))?;
        set_private_file_permissions(&file, &path)?;
        file.try_lock_exclusive().map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                InstallationError::Concurrent(tool_id.to_owned())
            } else {
                io_error("lock installation transaction", &path, error)
            }
        })?;
        Ok(InstallationLock { file })
    }
}

#[derive(Debug, Error)]
pub enum InstallationError {
    #[error("artifact for {0} is unavailable")]
    Unavailable(String),
    #[error("artifact for {0} is not a locked prebuilt binary")]
    NotBinary(String),
    #[error("installation destination {0} is not the managed user-local bin directory")]
    UnsupportedDestination(String),
    #[error("unsafe canonical command name: {0}")]
    UnsafeCommand(String),
    #[error("installation staging contains the reserved path {0}")]
    ReservedPath(String),
    #[error("activation path is occupied by an unmanaged entry: {0}")]
    UnmanagedActivation(PathBuf),
    #[error("activation points outside the HAZARDS application store: {0}")]
    UnmanagedTarget(PathBuf),
    #[error("installation store failed verification at {path}: {reason}")]
    CorruptStore { path: PathBuf, reason: String },
    #[error("{subject} health check failed at {path}: {reason}")]
    HealthCheck {
        subject: &'static str,
        path: PathBuf,
        reason: String,
    },
    #[error("version mismatch at {path}: expected {expected}, found {actual}")]
    VersionMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    #[error(
        "{command} does not resolve through the activation path {expected}; resolved path: {actual:?}"
    )]
    PathVerification {
        command: String,
        expected: PathBuf,
        actual: Option<PathBuf>,
    },
    #[error("installation transaction for {0} is already locked")]
    Concurrent(String),
    #[error("activation changed during the transaction: {0}")]
    ConcurrentActivation(PathBuf),
    #[error("installation of {tool} failed: {reason}")]
    ActivationFailed { tool: String, reason: String },
    #[error("no HAZARDS-managed activation exists for {0}")]
    NoActiveInstallation(String),
    #[error("no earlier successful activation receipt exists for {0}")]
    NoRollback(String),
    #[error("rollback of {tool} failed: {reason}")]
    RollbackFailed { tool: String, reason: String },
    #[error("could not serialize or parse installation evidence: {0}")]
    Evidence(String),
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
    Materialization(#[from] MaterializationError),
    #[error(transparent)]
    Cache(#[from] crate::VerifiedArtifactError),
}

enum ActivationState {
    Absent,
    Managed(PathBuf),
}

impl ActivationState {
    fn target(&self) -> Option<&PathBuf> {
        match self {
            Self::Absent => None,
            Self::Managed(target) => Some(target),
        }
    }
}

struct InstallationLock {
    file: File,
}

impl Drop for InstallationLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

fn validate_request(item: &AcquisitionItem, command: &str) -> Result<(), InstallationError> {
    validate_component("tool identifier", &item.id)?;
    validate_component("version", &item.target_version)?;
    validate_command(command)?;
    if item.status != AcquisitionStatus::LockedBinary {
        return Err(InstallationError::NotBinary(item.id.clone()));
    }
    if item.destination != "~/.local/bin" {
        return Err(InstallationError::UnsupportedDestination(
            item.destination.clone(),
        ));
    }
    Ok(())
}

fn validate_command(command: &str) -> Result<(), InstallationError> {
    let safe = !command.is_empty()
        && command != "."
        && command != ".."
        && command
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if safe {
        Ok(())
    } else {
        Err(InstallationError::UnsafeCommand(command.to_owned()))
    }
}

fn copy_verified_tree(stage: &VerifiedStage, destination: &Path) -> Result<(), InstallationError> {
    for entry in &stage.manifest.entries {
        let relative = strict_relative_path(&entry.path)?;
        let source = stage.staging_path.join(&relative);
        let target = destination.join(&relative);
        match entry.kind {
            MaterializedEntryKind::Directory => ensure_store_directory(destination, &relative)?,
            MaterializedEntryKind::File => {
                ensure_store_parent(destination, &relative)?;
                copy_expected_file(&source, &target, entry)?;
            }
        }
    }
    Ok(())
}

fn copy_expected_file(
    source: &Path,
    target: &Path,
    expected: &MaterializedEntry,
) -> Result<(), InstallationError> {
    let source_metadata = fs::symlink_metadata(source)
        .map_err(|error| io_error("inspect staged source file", source, error))?;
    if source_metadata.file_type().is_symlink() || !source_metadata.is_file() {
        return Err(InstallationError::CorruptStore {
            path: source.to_path_buf(),
            reason: "staged source is not a regular file".to_owned(),
        });
    }
    let mut input =
        File::open(source).map_err(|error| io_error("open staged source file", source, error))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)
        .map_err(|error| io_error("create installed file", target, error))?;
    set_private_file_permissions(&output, target)?;

    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_SIZE];
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|error| io_error("read staged source file", source, error))?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or_else(|| InstallationError::CorruptStore {
                path: source.to_path_buf(),
                reason: "file size overflow".to_owned(),
            })?;
        digest.update(&buffer[..read]);
        output
            .write_all(&buffer[..read])
            .map_err(|error| io_error("write installed file", target, error))?;
    }
    output
        .sync_all()
        .map_err(|error| io_error("synchronize installed file", target, error))?;
    let actual_digest = format!("{:x}", digest.finalize());
    if size != expected.size || expected.sha256.as_deref() != Some(actual_digest.as_str()) {
        return Err(InstallationError::CorruptStore {
            path: source.to_path_buf(),
            reason: "staged source changed while it was copied".to_owned(),
        });
    }
    Ok(())
}

fn set_payload_executable(
    root: &Path,
    manifest: &InstallationManifest,
) -> Result<(), InstallationError> {
    let payload = root.join(&manifest.payload_path);
    let metadata = fs::symlink_metadata(&payload)
        .map_err(|error| io_error("inspect installed payload", &payload, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(InstallationError::CorruptStore {
            path: payload,
            reason: "locked payload is not a regular file".to_owned(),
        });
    }
    if metadata.len() != manifest.payload_size || hash_file(&payload)? != manifest.payload_sha256 {
        return Err(InstallationError::CorruptStore {
            path: payload,
            reason: "locked payload identity changed during installation".to_owned(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&payload, fs::Permissions::from_mode(0o700))
            .map_err(|error| io_error("make installed payload executable", &payload, error))?;
    }
    Ok(())
}

fn ensure_store_parent(root: &Path, relative: &Path) -> Result<(), InstallationError> {
    if let Some(parent) = relative.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_store_directory(root, parent)?;
        }
    }
    Ok(())
}

fn ensure_store_directory(root: &Path, relative: &Path) -> Result<(), InstallationError> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(value) = component else {
            return Err(InstallationError::CorruptStore {
                path: relative.to_path_buf(),
                reason: "non-normal directory component".to_owned(),
            });
        };
        current.push(value);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(InstallationError::CorruptStore {
                    path: current,
                    reason: "directory collides with a non-directory".to_owned(),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current)
                    .map_err(|error| io_error("create installation directory", &current, error))?;
            }
            Err(error) => return Err(io_error("inspect installation directory", &current, error)),
        }
        set_directory_mode(&current, 0o700)?;
    }
    Ok(())
}

fn validate_store(path: &Path) -> Result<InstallationManifest, InstallationError> {
    let root_metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect installation store", path, error))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(InstallationError::CorruptStore {
            path: path.to_path_buf(),
            reason: "store root is not a real directory".to_owned(),
        });
    }
    verify_mode(path, &root_metadata, 0o700)?;
    let manifest_path = path.join(INSTALLATION_MANIFEST_NAME);
    let manifest_metadata = fs::symlink_metadata(&manifest_path)
        .map_err(|error| io_error("inspect installation manifest", &manifest_path, error))?;
    if manifest_metadata.file_type().is_symlink()
        || !manifest_metadata.is_file()
        || manifest_metadata.len() > MAX_EVIDENCE_SIZE as u64
    {
        return Err(InstallationError::CorruptStore {
            path: manifest_path,
            reason: "installation manifest is not an accepted private file".to_owned(),
        });
    }
    verify_mode(&manifest_path, &manifest_metadata, 0o600)?;
    let encoded = fs::read(&manifest_path)
        .map_err(|error| io_error("read installation manifest", &manifest_path, error))?;
    let manifest: InstallationManifest = serde_json::from_slice(&encoded)
        .map_err(|error| InstallationError::Evidence(error.to_string()))?;
    if manifest.schema_version != INSTALLATION_MANIFEST_SCHEMA_VERSION {
        return Err(InstallationError::CorruptStore {
            path: path.to_path_buf(),
            reason: "unsupported installation manifest schema".to_owned(),
        });
    }
    validate_installation_manifest(path, &manifest)?;
    let mut entries = Vec::new();
    inspect_store_directory(path, path, &manifest.payload_path, &mut entries)?;
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    if entries != manifest.entries {
        return Err(InstallationError::CorruptStore {
            path: path.to_path_buf(),
            reason: "installed tree does not match its manifest".to_owned(),
        });
    }
    let payload = path.join(&manifest.payload_path);
    let metadata = fs::symlink_metadata(&payload)
        .map_err(|error| io_error("inspect installed payload", &payload, error))?;
    if !metadata.is_file()
        || metadata.len() != manifest.payload_size
        || hash_file(&payload)? != manifest.payload_sha256
    {
        return Err(InstallationError::CorruptStore {
            path: payload,
            reason: "installed payload identity does not match the manifest".to_owned(),
        });
    }
    Ok(manifest)
}

fn validate_installation_manifest(
    store_path: &Path,
    manifest: &InstallationManifest,
) -> Result<(), InstallationError> {
    let component_is_safe = |value: &str| {
        !value.is_empty()
            && value != "."
            && value != ".."
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    };
    let digest_is_safe = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    };
    if !component_is_safe(&manifest.tool_id)
        || !component_is_safe(&manifest.version)
        || !component_is_safe(&manifest.architecture)
        || validate_command(&manifest.command).is_err()
        || !digest_is_safe(&manifest.artifact_sha256)
        || !digest_is_safe(&manifest.payload_sha256)
        || strict_relative_path(&manifest.payload_path).is_err()
        || manifest.payload_path == INSTALLATION_MANIFEST_NAME
        || manifest.payload_size > MAX_INSTALLED_PAYLOAD_SIZE
        || manifest.entries.len() > MAX_INSTALLED_ENTRIES
    {
        return Err(InstallationError::CorruptStore {
            path: store_path.to_path_buf(),
            reason: "installation manifest contains an unsafe or excessive field".to_owned(),
        });
    }
    Ok(())
}

fn inspect_store_directory(
    root: &Path,
    directory: &Path,
    payload_path: &str,
    entries: &mut Vec<MaterializedEntry>,
) -> Result<(), InstallationError> {
    for result in fs::read_dir(directory)
        .map_err(|error| io_error("read installation directory", directory, error))?
    {
        let entry =
            result.map_err(|error| io_error("read installation entry", directory, error))?;
        let path = entry.path();
        if path == root.join(INSTALLATION_MANIFEST_NAME) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| io_error("inspect installation entry", &path, error))?;
        let relative = path
            .strip_prefix(root)
            .map_err(|error| InstallationError::Evidence(error.to_string()))?;
        let relative = strict_relative_path(relative.to_str().ok_or_else(|| {
            InstallationError::CorruptStore {
                path: path.clone(),
                reason: "path is not valid UTF-8".to_owned(),
            }
        })?)?;
        let display = relative
            .to_str()
            .expect("strict relative path should remain UTF-8")
            .to_owned();
        if metadata.file_type().is_symlink() {
            return Err(InstallationError::CorruptStore {
                path,
                reason: "symbolic links are not accepted in the store".to_owned(),
            });
        }
        if metadata.is_dir() {
            verify_mode(&path, &metadata, 0o700)?;
            entries.push(MaterializedEntry {
                path: display,
                kind: MaterializedEntryKind::Directory,
                size: 0,
                sha256: None,
            });
            inspect_store_directory(root, &path, payload_path, entries)?;
        } else if metadata.is_file() {
            let expected_mode = if display == payload_path {
                0o700
            } else {
                0o600
            };
            verify_mode(&path, &metadata, expected_mode)?;
            entries.push(MaterializedEntry {
                path: display,
                kind: MaterializedEntryKind::File,
                size: metadata.len(),
                sha256: Some(hash_file(&path)?),
            });
        } else {
            return Err(InstallationError::CorruptStore {
                path,
                reason: "entry is not a regular file or directory".to_owned(),
            });
        }
    }
    Ok(())
}

fn ensure_store_identity(
    path: &Path,
    actual: &InstallationManifest,
    expected: &InstallationManifest,
) -> Result<(), InstallationError> {
    if actual == expected {
        Ok(())
    } else {
        Err(InstallationError::CorruptStore {
            path: path.to_path_buf(),
            reason: "content-addressed store identity does not match verified staging".to_owned(),
        })
    }
}

fn ensure_user_bin(path: &Path) -> Result<(), InstallationError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(InstallationError::UnmanagedActivation(path.to_path_buf()));
        }
        Ok(metadata) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o022 != 0 {
                    return Err(InstallationError::CorruptStore {
                        path: path.to_path_buf(),
                        reason: "user bin directory is writable by group or other".to_owned(),
                    });
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)
                .map_err(|error| io_error("create user bin directory", path, error))?;
            set_directory_mode(path, 0o755)?;
        }
        Err(error) => return Err(io_error("inspect user bin directory", path, error)),
    }
    Ok(())
}

fn replace_activation(
    activation: &Path,
    expected_current: Option<&Path>,
    replacement: Option<&Path>,
) -> Result<(), InstallationError> {
    let actual = match fs::symlink_metadata(activation) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(io_error("inspect activation", activation, error)),
        Ok(metadata) if metadata.file_type().is_symlink() => Some(
            fs::read_link(activation)
                .map_err(|error| io_error("read activation target", activation, error))?,
        ),
        Ok(_) => {
            return Err(InstallationError::UnmanagedActivation(
                activation.to_path_buf(),
            ));
        }
    };
    if actual.as_deref() != expected_current {
        return Err(InstallationError::ConcurrentActivation(
            activation.to_path_buf(),
        ));
    }

    match replacement {
        Some(target) => {
            let parent = activation
                .parent()
                .ok_or_else(|| InstallationError::ConcurrentActivation(activation.to_path_buf()))?;
            let file_name = activation
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| InstallationError::UnsafeCommand("activation".to_owned()))?;
            let (unique, _) = receipt_identity()?;
            let temporary = parent.join(format!(".hazards-{file_name}-{unique}"));
            create_symlink(target, &temporary)?;
            if let Err(error) = fs::rename(&temporary, activation) {
                let _ = fs::remove_file(&temporary);
                return Err(io_error("activate installed command", activation, error));
            }
        }
        None => fs::remove_file(activation)
            .map_err(|error| io_error("remove installed activation", activation, error))?,
    }
    if let Some(parent) = activation.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

#[cfg(unix)]
fn create_symlink(target: &Path, link: &Path) -> Result<(), InstallationError> {
    std::os::unix::fs::symlink(target, link)
        .map_err(|error| io_error("create activation symlink", link, error))
}

#[cfg(not(unix))]
fn create_symlink(_target: &Path, link: &Path) -> Result<(), InstallationError> {
    Err(InstallationError::Io {
        action: "create activation symlink",
        path: link.to_path_buf(),
        source: io::Error::new(io::ErrorKind::Unsupported, "Unix symlinks are required"),
    })
}

fn read_installation_receipts(
    state_root: &Path,
    tool_id: &str,
) -> Result<Vec<InstallationReceipt>, InstallationError> {
    let tool_root = state_root
        .join("receipts")
        .join("installations")
        .join(tool_id);
    match fs::symlink_metadata(&tool_root) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(io_error("inspect installation receipts", &tool_root, error)),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(InstallationError::Evidence(
                "installation receipt root is not a real directory".to_owned(),
            ));
        }
        Ok(_) => {}
    }
    let mut receipts = Vec::new();
    for version in fs::read_dir(&tool_root)
        .map_err(|error| io_error("read installation receipt root", &tool_root, error))?
    {
        let version =
            version.map_err(|error| io_error("read installation receipt", &tool_root, error))?;
        let version_path = version.path();
        let metadata = fs::symlink_metadata(&version_path)
            .map_err(|error| io_error("inspect receipt version directory", &version_path, error))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(InstallationError::Evidence(format!(
                "unexpected entry in installation receipt root: {}",
                version_path.display()
            )));
        }
        for receipt in fs::read_dir(&version_path)
            .map_err(|error| io_error("read receipt version directory", &version_path, error))?
        {
            let receipt = receipt
                .map_err(|error| io_error("read installation receipt", &version_path, error))?;
            let path = receipt.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| io_error("inspect installation receipt", &path, error))?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() > MAX_EVIDENCE_SIZE as u64
            {
                return Err(InstallationError::Evidence(format!(
                    "invalid installation receipt: {}",
                    path.display()
                )));
            }
            verify_mode(&path, &metadata, 0o600)?;
            let encoded = fs::read(&path)
                .map_err(|error| io_error("read installation receipt", &path, error))?;
            let receipt: InstallationReceipt = serde_json::from_slice(&encoded)
                .map_err(|error| InstallationError::Evidence(error.to_string()))?;
            if receipt.schema_version != INSTALLATION_RECEIPT_SCHEMA_VERSION
                || receipt.tool_id != tool_id
            {
                return Err(InstallationError::Evidence(format!(
                    "installation receipt identity mismatch: {}",
                    path.display()
                )));
            }
            receipts.push(receipt);
        }
    }
    Ok(receipts)
}

fn write_json_noclobber(
    directory: &Path,
    path: &Path,
    value: &impl Serialize,
) -> Result<(), InstallationError> {
    let mut encoded = serde_json::to_vec_pretty(value)
        .map_err(|error| InstallationError::Evidence(error.to_string()))?;
    encoded.push(b'\n');
    if encoded.len() > MAX_EVIDENCE_SIZE {
        return Err(InstallationError::Evidence(format!(
            "serialized evidence is {} bytes; limit is {}",
            encoded.len(),
            MAX_EVIDENCE_SIZE
        )));
    }
    let mut temporary = tempfile::NamedTempFile::new_in(directory)
        .map_err(|error| io_error("create temporary evidence file", directory, error))?;
    temporary
        .write_all(&encoded)
        .map_err(|error| io_error("write evidence file", temporary.path(), error))?;
    temporary
        .as_file_mut()
        .sync_all()
        .map_err(|error| io_error("synchronize evidence file", temporary.path(), error))?;
    let file = temporary
        .persist_noclobber(path)
        .map_err(|error| io_error("persist evidence file", path, error.error))?;
    set_private_file_permissions(&file, path)?;
    sync_directory(directory)?;
    Ok(())
}

fn strict_relative_path(value: &str) -> Result<PathBuf, InstallationError> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > 4096
        || value.contains('\\')
        || path.components().any(|component| {
            !matches!(
                component,
                Component::Normal(name) if name.as_encoded_bytes().len() <= 255
            )
        })
    {
        return Err(InstallationError::CorruptStore {
            path: path.to_path_buf(),
            reason: "path is not a safe relative UTF-8 path".to_owned(),
        });
    }
    Ok(path.to_path_buf())
}

fn hash_file(path: &Path) -> Result<String, InstallationError> {
    let mut file =
        File::open(path).map_err(|error| io_error("open installed file", path, error))?;
    let mut digest = Sha256::new();
    io::copy(&mut file, &mut digest)
        .map_err(|error| io_error("hash installed file", path, error))?;
    Ok(format!("{:x}", digest.finalize()))
}

fn verify_mode(
    path: &Path,
    metadata: &fs::Metadata,
    expected: u32,
) -> Result<(), InstallationError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let actual = metadata.permissions().mode() & 0o777;
        if actual != expected {
            return Err(InstallationError::CorruptStore {
                path: path.to_path_buf(),
                reason: format!("expected mode {expected:o}, found {actual:o}"),
            });
        }
    }
    Ok(())
}

fn set_directory_mode(path: &Path, mode: u32) -> Result<(), InstallationError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| io_error("set directory permissions", path, error))?;
    }
    Ok(())
}

fn normalize_command_path(path: &Path) -> Result<PathBuf, InstallationError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| io_error("resolve current directory", Path::new("."), error))?
            .join(path)
    };
    let parent = absolute
        .parent()
        .ok_or_else(|| InstallationError::ConcurrentActivation(absolute.clone()))?;
    let parent = fs::canonicalize(parent)
        .map_err(|error| io_error("canonicalize command directory", parent, error))?;
    Ok(parent.join(
        absolute
            .file_name()
            .ok_or_else(|| InstallationError::ConcurrentActivation(absolute.clone()))?,
    ))
}

fn receipt_identity() -> Result<(String, u64), InstallationError> {
    let occurred = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| InstallationError::Clock(error.to_string()))?;
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

fn persist_tempdir(mut directory: TempDir) {
    directory.disable_cleanup(true);
}

fn io_error(action: &'static str, path: &Path, source: io::Error) -> InstallationError {
    InstallationError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, path::Path};

    use arsenallspice::{AcquisitionMethod, ArtifactFormat, DigestEvidence, LockedArtifact};
    use flate2::{Compression, write::GzEncoder};
    use tar::{Builder as TarBuilder, Header};

    use super::*;
    use crate::{AcquisitionStatus, LocatedCommand, MaterializationOutcome, ProvisionStatus};

    #[derive(Clone)]
    struct FakeProbe {
        bin: PathBuf,
        fail_activation: bool,
        shadow: Option<PathBuf>,
    }

    impl FakeProbe {
        fn healthy(bin: PathBuf) -> Self {
            Self {
                bin,
                fail_activation: false,
                shadow: None,
            }
        }

        fn failing_activation(bin: PathBuf) -> Self {
            Self {
                bin,
                fail_activation: true,
                shadow: None,
            }
        }

        fn shadowed(bin: PathBuf, shadow: PathBuf) -> Self {
            Self {
                bin,
                fail_activation: false,
                shadow: Some(shadow),
            }
        }
    }

    impl EnvironmentProbe for FakeProbe {
        fn locate(&self, commands: &[&str]) -> Option<LocatedCommand> {
            let command = commands.first()?;
            if let Some(shadow) = &self.shadow {
                return Some(LocatedCommand {
                    command: (*command).to_owned(),
                    path: shadow.clone(),
                });
            }
            let candidate = self.bin.join(command);
            candidate.metadata().ok().filter(|metadata| {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
                }
                #[cfg(not(unix))]
                {
                    metadata.is_file()
                }
            })?;
            Some(LocatedCommand {
                command: (*command).to_owned(),
                path: candidate,
            })
        }

        fn version(&self, executable: &Path, _args: &[String]) -> Result<String, String> {
            if self.fail_activation && executable.starts_with(&self.bin) {
                return Err("simulated post-activation failure".to_owned());
            }
            let canonical = fs::canonicalize(executable).map_err(|error| error.to_string())?;
            let components = canonical
                .components()
                .filter_map(|component| match component {
                    Component::Normal(value) => value.to_str(),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let version = components
                .windows(3)
                .find_map(|window| {
                    (window[0] == "apps" && window[1] == "dotter").then_some(window[2])
                })
                .ok_or_else(|| "payload is not in the application store".to_owned())?;
            Ok(format!("dotter {version}"))
        }
    }

    fn elf(marker: &[u8]) -> Vec<u8> {
        let mut body = vec![0_u8; 64];
        body[..4].copy_from_slice(b"\x7fELF");
        body[4] = 2;
        body[5] = 1;
        body[6] = 1;
        body[16..18].copy_from_slice(&3_u16.to_le_bytes());
        body[18..20].copy_from_slice(&62_u16.to_le_bytes());
        body.extend_from_slice(marker);
        body
    }

    fn sha256(body: &[u8]) -> String {
        format!("{:x}", Sha256::digest(body))
    }

    fn archive(payload: &[u8]) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = TarBuilder::new(encoder);
        for (path, body) in [
            ("README.md", b"runtime support".as_slice()),
            ("bin/dotter", payload),
        ] {
            let mut header = Header::new_gnu();
            header.set_path(path).expect("test path should encode");
            header.set_size(body.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append(&header, Cursor::new(body))
                .expect("test entry should append");
        }
        let encoder = builder.into_inner().expect("test tar should finish");
        encoder.finish().expect("test gzip should finish")
    }

    fn test_item(version: &str, marker: &[u8]) -> (AcquisitionItem, Vec<u8>) {
        let payload = elf(marker);
        let object = archive(&payload);
        (
            AcquisitionItem {
                id: "dotter".to_owned(),
                name: "Dotter".to_owned(),
                provision_status: ProvisionStatus::Missing,
                target_version: version.to_owned(),
                destination: "~/.local/bin".to_owned(),
                status: AcquisitionStatus::LockedBinary,
                artifact: Some(LockedArtifact {
                    tool_id: "dotter".to_owned(),
                    version: version.to_owned(),
                    os: "linux".to_owned(),
                    architecture: "x86_64".to_owned(),
                    method: AcquisitionMethod::GithubRelease,
                    format: ArtifactFormat::TarGz,
                    name: "dotter.tar.gz".to_owned(),
                    size: object.len() as u64,
                    sha256: sha256(&object),
                    url: "https://example.invalid/dotter".to_owned(),
                    evidence: DigestEvidence::GithubAssetDigest,
                    payload_path: Some("bin/dotter".to_owned()),
                    payload_size: Some(payload.len() as u64),
                    payload_sha256: Some(sha256(&payload)),
                }),
                detail: String::new(),
            },
            object,
        )
    }

    fn paths(root: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        (
            root.join("cache"),
            root.join("data"),
            root.join("state"),
            root.join("bin"),
        )
    }

    fn materialize(root: &Path, item: &AcquisitionItem, object: &[u8]) {
        let artifact = item.artifact.as_ref().expect("artifact should exist");
        let object_dir = root
            .join("cache/objects/sha256")
            .join(&artifact.sha256[..2]);
        fs::create_dir_all(&object_dir).expect("object directory should exist");
        fs::write(object_dir.join(&artifact.sha256), object).expect("object should write");
        let result = Materializer::new(root.join("cache"), root.join("state"))
            .materialize(item)
            .expect("fixture should materialize");
        assert_eq!(result.receipt.outcome, MaterializationOutcome::Materialized);
    }

    fn test_installer(root: &Path, probe: FakeProbe) -> Installer<FakeProbe> {
        let (cache, data, state, bin) = paths(root);
        Installer::with_probe(cache, data, state, bin, probe)
    }

    #[test]
    fn installs_idempotently_and_rolls_back_the_first_activation() {
        let root = tempfile::tempdir().expect("temporary root should exist");
        let (item, object) = test_item("0.13.5", b"first");
        materialize(root.path(), &item, &object);
        let bin = root.path().join("bin");
        let installer = test_installer(root.path(), FakeProbe::healthy(bin.clone()));

        let installed = installer
            .install(&item, "dotter", &["--version".to_owned()])
            .expect("installation should succeed");
        assert_eq!(installed.receipt.outcome, InstallationOutcome::Installed);
        assert_eq!(
            fs::read_link(&installed.activation_path).expect("activation should be a symlink"),
            installed.payload_path
        );
        assert_eq!(
            fs::read(installed.store_path.join("README.md"))
                .expect("support file should be installed"),
            b"runtime support"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&installed.payload_path)
                    .expect("payload should exist")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(installed.store_path.join("README.md"))
                    .expect("support file should exist")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        let repeated = installer
            .install(&item, "dotter", &["--version".to_owned()])
            .expect("repeated installation should verify");
        assert_eq!(repeated.receipt.outcome, InstallationOutcome::AlreadyActive);
        assert_eq!(repeated.receipt.store_outcome, StoreOutcome::StoreHit);
        let active = installer
            .verify_active("dotter", "dotter", &["--version".to_owned()])
            .expect("managed activation should verify");
        assert_eq!(active.version, "0.13.5");
        assert_eq!(active.activation_path, installed.activation_path);
        assert_eq!(active.payload_path, installed.payload_path);

        let rolled_back = installer
            .rollback("dotter", "dotter", &["--version".to_owned()])
            .expect("first installation should roll back to absence");
        assert_eq!(rolled_back.receipt.outcome, InstallationOutcome::RolledBack);
        assert!(rolled_back.active_target.is_none());
        assert!(!bin.join("dotter").exists());
    }

    #[test]
    fn upgrade_rollback_restores_the_previous_managed_payload() {
        let root = tempfile::tempdir().expect("temporary root should exist");
        let (first, first_object) = test_item("0.13.4", b"first");
        let (second, second_object) = test_item("0.13.5", b"second");
        materialize(root.path(), &first, &first_object);
        materialize(root.path(), &second, &second_object);
        let bin = root.path().join("bin");
        let installer = test_installer(root.path(), FakeProbe::healthy(bin.clone()));

        let old = installer
            .install(&first, "dotter", &["--version".to_owned()])
            .expect("first version should install");
        let new = installer
            .install(&second, "dotter", &["--version".to_owned()])
            .expect("second version should upgrade");
        assert_eq!(new.receipt.outcome, InstallationOutcome::Upgraded);

        let rollback = installer
            .rollback("dotter", "dotter", &["--version".to_owned()])
            .expect("upgrade should roll back");
        assert_eq!(
            rollback.active_target.as_deref(),
            Some(old.payload_path.as_path())
        );
        assert_eq!(
            fs::read_link(bin.join("dotter")).expect("activation should remain"),
            old.payload_path
        );
    }

    #[test]
    fn unmanaged_activation_is_preserved() {
        let root = tempfile::tempdir().expect("temporary root should exist");
        let (item, object) = test_item("0.13.5", b"unmanaged");
        materialize(root.path(), &item, &object);
        let bin = root.path().join("bin");
        fs::create_dir_all(&bin).expect("bin should exist");
        fs::write(bin.join("dotter"), b"user-owned").expect("unmanaged command should exist");
        let installer = test_installer(root.path(), FakeProbe::healthy(bin.clone()));

        assert!(matches!(
            installer.install(&item, "dotter", &["--version".to_owned()]),
            Err(InstallationError::UnmanagedActivation(_))
        ));
        assert_eq!(
            fs::read(bin.join("dotter")).expect("unmanaged command should remain"),
            b"user-owned"
        );
    }

    #[test]
    fn failed_health_or_path_checks_restore_absence() {
        let health_root = tempfile::tempdir().expect("temporary root should exist");
        let (item, object) = test_item("0.13.5", b"health");
        materialize(health_root.path(), &item, &object);
        let health_bin = health_root.path().join("bin");
        let installer = test_installer(
            health_root.path(),
            FakeProbe::failing_activation(health_bin.clone()),
        );
        assert!(matches!(
            installer.install(&item, "dotter", &["--version".to_owned()]),
            Err(InstallationError::ActivationFailed { .. })
        ));
        assert!(!health_bin.join("dotter").exists());
        let receipts = read_installation_receipts(&health_root.path().join("state"), "dotter")
            .expect("failure receipt should parse");
        assert!(
            receipts
                .iter()
                .any(|receipt| { receipt.outcome == InstallationOutcome::ActivationRolledBack })
        );

        let path_root = tempfile::tempdir().expect("temporary root should exist");
        let (item, object) = test_item("0.13.5", b"path");
        materialize(path_root.path(), &item, &object);
        let path_bin = path_root.path().join("bin");
        let shadow = path_root.path().join("shadow/dotter");
        let installer = test_installer(
            path_root.path(),
            FakeProbe::shadowed(path_bin.clone(), shadow),
        );
        assert!(matches!(
            installer.install(&item, "dotter", &["--version".to_owned()]),
            Err(InstallationError::ActivationFailed { .. })
        ));
        assert!(!path_bin.join("dotter").exists());
    }

    #[test]
    fn missing_or_tampered_staging_never_activates() {
        let missing_root = tempfile::tempdir().expect("temporary root should exist");
        let (item, object) = test_item("0.13.5", b"missing");
        let artifact = item.artifact.as_ref().expect("artifact should exist");
        let object_dir = missing_root
            .path()
            .join("cache/objects/sha256")
            .join(&artifact.sha256[..2]);
        fs::create_dir_all(&object_dir).expect("object directory should exist");
        fs::write(object_dir.join(&artifact.sha256), object).expect("object should write");
        let bin = missing_root.path().join("bin");
        let installer = test_installer(missing_root.path(), FakeProbe::healthy(bin.clone()));
        assert!(matches!(
            installer.install(&item, "dotter", &["--version".to_owned()]),
            Err(InstallationError::Materialization(
                MaterializationError::MissingStage { .. }
            ))
        ));
        assert!(!bin.exists());

        let tampered_root = tempfile::tempdir().expect("temporary root should exist");
        let (item, object) = test_item("0.13.5", b"tampered");
        materialize(tampered_root.path(), &item, &object);
        let artifact = item.artifact.as_ref().expect("artifact should exist");
        let payload = tampered_root
            .path()
            .join("cache/staging/sha256")
            .join(&artifact.sha256[..2])
            .join(&artifact.sha256)
            .join("bin/dotter");
        fs::write(&payload, b"corrupt").expect("stage should be corrupted");
        let bin = tampered_root.path().join("bin");
        let installer = test_installer(tampered_root.path(), FakeProbe::healthy(bin.clone()));
        assert!(matches!(
            installer.install(&item, "dotter", &["--version".to_owned()]),
            Err(InstallationError::Materialization(
                MaterializationError::CorruptStage { .. }
            ))
        ));
        assert!(!bin.exists());
    }

    #[test]
    fn corrupt_content_addressed_store_fails_closed() {
        let root = tempfile::tempdir().expect("temporary root should exist");
        let (item, object) = test_item("0.13.5", b"store");
        materialize(root.path(), &item, &object);
        let bin = root.path().join("bin");
        let installer = test_installer(root.path(), FakeProbe::healthy(bin));
        let installed = installer
            .install(&item, "dotter", &["--version".to_owned()])
            .expect("installation should succeed");
        fs::write(&installed.payload_path, b"corrupt").expect("store should be corrupted");

        assert!(matches!(
            installer.install(&item, "dotter", &["--version".to_owned()]),
            Err(InstallationError::CorruptStore { .. })
        ));
    }

    #[test]
    fn unsafe_installation_manifest_path_fails_closed() {
        let root = tempfile::tempdir().expect("temporary root should exist");
        let (item, object) = test_item("0.13.5", b"manifest");
        materialize(root.path(), &item, &object);
        let bin = root.path().join("bin");
        let installer = test_installer(root.path(), FakeProbe::healthy(bin));
        let installed = installer
            .install(&item, "dotter", &["--version".to_owned()])
            .expect("installation should succeed");
        let manifest_path = installed.store_path.join(INSTALLATION_MANIFEST_NAME);
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).expect("manifest should be readable"))
                .expect("manifest should parse");
        manifest["payload_path"] = serde_json::Value::String("../../outside".to_owned());
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).expect("manifest should serialize"),
        )
        .expect("unsafe manifest should be written");

        assert!(matches!(
            installer.install(&item, "dotter", &["--version".to_owned()]),
            Err(InstallationError::CorruptStore { .. })
        ));
    }
}
