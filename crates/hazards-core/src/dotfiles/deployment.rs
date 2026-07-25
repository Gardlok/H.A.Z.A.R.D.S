use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use tempfile::{Builder, NamedTempFile};

use crate::{
    ManagedActivation,
    acquire::{
        ensure_private_dir, ensure_private_subdirectories, set_private_file_permissions,
        sync_directory,
    },
    provision::version_matches,
};

use super::*;

const DEPLOYMENT_PLAN_SCHEMA_VERSION: u8 = 1;
const DEPLOYMENT_TRANSACTION_SCHEMA_VERSION: u8 = 1;
const DEPLOYMENT_RECEIPT_SCHEMA_VERSION: u8 = 1;
const ROLLBACK_RECEIPT_SCHEMA_VERSION: u8 = 1;

/// What a confirmed deployment would do with one selected target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DotfileAdoptionAction {
    Create,
    Preserve,
    BackupAndReplace,
    Blocked,
}

impl std::fmt::Display for DotfileAdoptionAction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Create => formatter.write_str("create"),
            Self::Preserve => formatter.write_str("preserve"),
            Self::BackupAndReplace => formatter.write_str("backup-replace"),
            Self::Blocked => formatter.write_str("blocked"),
        }
    }
}

/// Stable target kind exposed in adoption plans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DotfileTargetKind {
    Absent,
    File,
    Directory,
    Symlink,
    Other,
}

impl From<FingerprintKind> for DotfileTargetKind {
    fn from(value: FingerprintKind) -> Self {
        match value {
            FingerprintKind::Absent => Self::Absent,
            FingerprintKind::File => Self::File,
            FingerprintKind::Directory => Self::Directory,
            FingerprintKind::Symlink => Self::Symlink,
            FingerprintKind::Other => Self::Other,
        }
    }
}

/// Read-only classification of one source-to-target adoption.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DotfileAdoptionItem {
    pub package: String,
    pub source: PathBuf,
    pub source_sha256: String,
    pub target: PathBuf,
    pub target_kind: Option<DotfileTargetKind>,
    pub target_sha256: Option<String>,
    pub target_link: Option<PathBuf>,
    pub target_mode: Option<u32>,
    pub action: DotfileAdoptionAction,
    pub detail: String,
}

/// Read-only deployment plan bound to current target and ancestor fingerprints.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DotfileDeploymentPlan {
    pub schema_version: u8,
    pub profile_id: String,
    pub global_sha256: String,
    pub local_sha256: String,
    pub watched_sha256: String,
    pub ready: bool,
    pub items: Vec<DotfileAdoptionItem>,
    pub confirmation: String,
}

/// Result of a confirmed Dotter deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DotfileDeploymentOutcome {
    Deployed,
    FailedRestored,
}

impl std::fmt::Display for DotfileDeploymentOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deployed => formatter.write_str("deployed"),
            Self::FailedRestored => formatter.write_str("failed-restored"),
        }
    }
}

/// Append-only terminal evidence for one deployment transaction.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DotfileDeploymentReceipt {
    pub schema_version: u8,
    pub transaction_id: String,
    pub profile_id: String,
    pub global_sha256: String,
    pub local_sha256: String,
    pub dotter_version: String,
    pub backup_count: usize,
    pub preview_exit_code: Option<i32>,
    pub preview_failure: Option<String>,
    pub preview_stdout_sha256: String,
    pub preview_stderr_sha256: String,
    pub exit_code: Option<i32>,
    pub command_failure: Option<String>,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub outcome: DotfileDeploymentOutcome,
    pub completed_at_unix: u64,
}

/// Captured deployment output plus durable transaction evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DotfileDeploymentReport {
    pub executable: PathBuf,
    pub transaction_directory: PathBuf,
    pub receipt_path: PathBuf,
    pub stdout: String,
    pub stderr: String,
    pub receipt: DotfileDeploymentReceipt,
}

/// Result of restoring the newest applicable deployment transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DotfileRollbackResult {
    RolledBack,
}

impl std::fmt::Display for DotfileRollbackResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("rolled-back")
    }
}

/// Append-only evidence for an explicit dotfile rollback.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct DotfileRollbackReceipt {
    pub schema_version: u8,
    pub transaction_id: String,
    pub profile_id: String,
    pub restored_files: usize,
    pub removed_links: usize,
    pub result: DotfileRollbackResult,
    pub rolled_back_at_unix: u64,
}

/// Restored targets and rollback evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DotfileRollbackReport {
    pub transaction_directory: PathBuf,
    pub receipt_path: PathBuf,
    pub receipt: DotfileRollbackReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct DeploymentTransaction {
    schema_version: u8,
    transaction_id: String,
    profile_id: String,
    workspace_root: PathBuf,
    plan: DotfileDeploymentPlan,
    before: BTreeMap<PathBuf, PathFingerprint>,
    backups: Vec<BackupRecord>,
    prepared_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct BackupRecord {
    target: PathBuf,
    source: PathBuf,
    file_name: String,
    sha256: String,
    original: PathFingerprint,
}

struct BuiltPlan {
    plan: DotfileDeploymentPlan,
    before: BTreeMap<PathBuf, PathFingerprint>,
}

struct RestoreCounts {
    files: usize,
    links: usize,
}

impl<'a, R: DotterRunner> DotfilesManager<'a, R> {
    /// Inspect current targets without writing HAZARDS state or configuration.
    pub fn adoption_plan(&self) -> Result<DotfileDeploymentPlan, DotfilesError> {
        let expected = self.expected_profile()?;
        self.validate_generated_profile(&expected)?;
        Ok(self.build_adoption_plan(&expected)?.plan)
    }

    /// Back up conflicts, run the verified Dotter deployment, verify every
    /// resulting link, and restore the original state on ordinary failure.
    pub fn deploy(
        &self,
        activation: &ManagedActivation,
        confirmation: &str,
    ) -> Result<DotfileDeploymentReport, DotfilesError> {
        let expected = self.expected_profile()?;
        let _lock = self.acquire_lock(&expected.manifest.profile_id)?;
        self.validate_generated_profile(&expected)?;
        let built = self.build_adoption_plan(&expected)?;
        if !built.plan.ready {
            let blocked = built
                .plan
                .items
                .iter()
                .filter(|item| item.action == DotfileAdoptionAction::Blocked)
                .map(|item| format!("{}: {}", item.target.display(), item.detail))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(DotfilesError::AdoptionBlocked(blocked));
        }
        if confirmation != built.plan.confirmation {
            return Err(DotfilesError::ConfirmationMismatch);
        }
        if let Some(transaction) =
            self.find_incomplete_transaction(&expected.manifest.profile_id)?
        {
            return Err(DotfilesError::PendingTransaction(transaction));
        }

        let scratch = self.deployment_scratch()?;
        let dotter_version = self.verify_deployment_activation(activation, scratch.path())?;
        let local_config_path = self
            .profile_directory(&expected.manifest.profile_id)
            .join("local.toml");
        let cache_directory = scratch.path().join("cache");
        fs::create_dir(&cache_directory)
            .map_err(|error| io_error("create temporary Dotter cache", &cache_directory, error))?;
        set_directory_mode(&cache_directory, 0o700)?;
        let preview_arguments = dotter_dry_run_arguments(
            &expected.manifest.global_config,
            &local_config_path,
            scratch.path(),
            &cache_directory,
        );
        let deploy_arguments = dotter_deploy_arguments(
            &expected.manifest.global_config,
            &local_config_path,
            scratch.path(),
            &cache_directory,
        );
        let (transaction_id, prepared_at_unix) = receipt_identity()?;
        let transaction_directory = ensure_private_subdirectories(
            &self.paths.state,
            &[
                "dotter",
                "transactions",
                &expected.manifest.profile_id,
                &transaction_id,
            ],
        )?;
        let backup_directory = transaction_directory.join("backups");
        fs::create_dir(&backup_directory).map_err(|error| {
            io_error(
                "create dotfile transaction backup directory",
                &backup_directory,
                error,
            )
        })?;
        set_directory_mode(&backup_directory, 0o700)?;
        let backups = self.create_backups(
            &built.plan,
            &built.before,
            &backup_directory,
            &expected.manifest.mappings,
        )?;
        let transaction = DeploymentTransaction {
            schema_version: DEPLOYMENT_TRANSACTION_SCHEMA_VERSION,
            transaction_id: transaction_id.clone(),
            profile_id: expected.manifest.profile_id.clone(),
            workspace_root: self.workspace_root.clone(),
            plan: built.plan,
            before: built.before,
            backups,
            prepared_at_unix,
        };
        let current =
            fingerprint_paths(&transaction.before.keys().cloned().collect::<BTreeSet<_>>())?;
        if current != transaction.before {
            return Err(DotfilesError::ConfirmationMismatch);
        }
        let prepared_path = transaction_directory.join("prepared.json");
        write_json_noclobber(&transaction_directory, &prepared_path, &transaction)?;

        if let Err(error) = remove_adopted_files(&transaction) {
            self.restore_transaction(&transaction_directory, &transaction)
                .map_err(|restore| DotfilesError::RecoveryFailed {
                    transaction: transaction_id,
                    detail: format!("{error}; automatic restore also failed: {restore}"),
                })?;
            return Err(error);
        }

        let watched = transaction.before.keys().cloned().collect::<BTreeSet<_>>();
        let preview_before = fingerprint_paths(&watched)
            .map_err(|error| self.recovery_error(&transaction_directory, &transaction, error))?;
        let mut preview = match self.runner.dry_run(DotterInvocation {
            executable: &activation.activation_path,
            working_directory: &self.workspace_root,
            arguments: &preview_arguments,
            capture_directory: scratch.path(),
        }) {
            Ok(output) => output,
            Err(error) => DotterCommandOutput {
                exit_code: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
                failure: Some(error),
            },
        };
        let preview_after = fingerprint_paths(&watched)
            .map_err(|error| self.recovery_error(&transaction_directory, &transaction, error))?;
        let preview_mutations = preview_before
            .iter()
            .filter_map(|(path, fingerprint)| {
                (preview_after.get(path) != Some(fingerprint)).then_some(path.display().to_string())
            })
            .collect::<Vec<_>>();
        if !preview_mutations.is_empty() {
            preview.failure = Some(format!(
                "deployment preview mutated: {}",
                preview_mutations.join(", ")
            ));
        }
        if !preview.succeeded() {
            self.restore_transaction(&transaction_directory, &transaction)
                .map_err(|error| DotfilesError::RecoveryFailed {
                    transaction: transaction.transaction_id.clone(),
                    detail: error,
                })?;
            return self.finish_deployment(
                activation,
                &expected,
                transaction_directory,
                &transaction,
                dotter_version,
                &preview,
                preview.clone(),
                DotfileDeploymentOutcome::FailedRestored,
            );
        }

        let mut output = match self.runner.deploy(DotterInvocation {
            executable: &activation.activation_path,
            working_directory: &self.workspace_root,
            arguments: &deploy_arguments,
            capture_directory: scratch.path(),
        }) {
            Ok(output) => output,
            Err(error) => DotterCommandOutput {
                exit_code: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
                failure: Some(error),
            },
        };

        let invalid_targets = expected
            .manifest
            .mappings
            .iter()
            .filter(|mapping| {
                unsafe_parent(&self.paths.home, &mapping.target)
                    .map(|blocked| blocked.is_some())
                    .unwrap_or(true)
                    || !symlink_points_to(&mapping.target, &mapping.source).unwrap_or(false)
            })
            .map(|mapping| mapping.target.display().to_string())
            .collect::<Vec<_>>();
        if output.succeeded() && !invalid_targets.is_empty() {
            output.failure = Some(format!(
                "post-deploy verification rejected: {}",
                invalid_targets.join(", ")
            ));
        }

        let outcome = if output.succeeded() && invalid_targets.is_empty() {
            DotfileDeploymentOutcome::Deployed
        } else {
            self.restore_transaction(&transaction_directory, &transaction)
                .map_err(|error| DotfilesError::RecoveryFailed {
                    transaction: transaction.transaction_id.clone(),
                    detail: error,
                })?;
            DotfileDeploymentOutcome::FailedRestored
        };
        self.finish_deployment(
            activation,
            &expected,
            transaction_directory,
            &transaction,
            dotter_version,
            &preview,
            output,
            outcome,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_deployment(
        &self,
        activation: &ManagedActivation,
        expected: &ExpectedProfile,
        transaction_directory: PathBuf,
        transaction: &DeploymentTransaction,
        dotter_version: String,
        preview: &DotterCommandOutput,
        output: DotterCommandOutput,
        outcome: DotfileDeploymentOutcome,
    ) -> Result<DotfileDeploymentReport, DotfilesError> {
        let (_, completed_at_unix) = receipt_identity()?;
        let receipt = DotfileDeploymentReceipt {
            schema_version: DEPLOYMENT_RECEIPT_SCHEMA_VERSION,
            transaction_id: transaction.transaction_id.clone(),
            profile_id: transaction.profile_id.clone(),
            global_sha256: expected.manifest.global_sha256.clone(),
            local_sha256: expected.manifest.local_sha256.clone(),
            dotter_version,
            backup_count: transaction.backups.len(),
            preview_exit_code: preview.exit_code,
            preview_failure: preview.failure.clone(),
            preview_stdout_sha256: hash_bytes(&preview.stdout),
            preview_stderr_sha256: hash_bytes(&preview.stderr),
            exit_code: output.exit_code,
            command_failure: output.failure.clone(),
            stdout_sha256: hash_bytes(&output.stdout),
            stderr_sha256: hash_bytes(&output.stderr),
            outcome,
            completed_at_unix,
        };
        let event_name = match outcome {
            DotfileDeploymentOutcome::Deployed => "committed.json",
            DotfileDeploymentOutcome::FailedRestored => "restored.json",
        };
        let receipt_path = transaction_directory.join(event_name);
        write_json_noclobber(&transaction_directory, &receipt_path, &receipt)?;
        Ok(DotfileDeploymentReport {
            executable: activation.activation_path.clone(),
            transaction_directory,
            receipt_path,
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            receipt,
        })
    }

    fn recovery_error(
        &self,
        directory: &Path,
        transaction: &DeploymentTransaction,
        cause: DotfilesError,
    ) -> DotfilesError {
        match self.restore_transaction(directory, transaction) {
            Ok(_) => cause,
            Err(restore) => DotfilesError::RecoveryFailed {
                transaction: transaction.transaction_id.clone(),
                detail: format!("{cause}; automatic restore also failed: {restore}"),
            },
        }
    }

    /// Restore the newest committed or interrupted transaction after proving
    /// that no target has since been replaced by unrelated data.
    pub fn rollback_deployment(&self) -> Result<DotfileRollbackReport, DotfilesError> {
        let profile = profile_id(self.profile);
        let _lock = self.acquire_lock(&profile)?;
        let (transaction_directory, transaction) = self
            .find_recoverable_transaction(&profile)?
            .ok_or_else(|| DotfilesError::NoDeployment(profile.clone()))?;
        let counts = self
            .restore_transaction(&transaction_directory, &transaction)
            .map_err(|error| DotfilesError::RecoveryFailed {
                transaction: transaction.transaction_id.clone(),
                detail: error,
            })?;
        let (_, rolled_back_at_unix) = receipt_identity()?;
        let receipt = DotfileRollbackReceipt {
            schema_version: ROLLBACK_RECEIPT_SCHEMA_VERSION,
            transaction_id: transaction.transaction_id,
            profile_id: transaction.profile_id,
            restored_files: counts.files,
            removed_links: counts.links,
            result: DotfileRollbackResult::RolledBack,
            rolled_back_at_unix,
        };
        let receipt_path = transaction_directory.join("rolled-back.json");
        write_json_noclobber(&transaction_directory, &receipt_path, &receipt)?;
        Ok(DotfileRollbackReport {
            transaction_directory,
            receipt_path,
            receipt,
        })
    }

    fn build_adoption_plan(&self, expected: &ExpectedProfile) -> Result<BuiltPlan, DotfilesError> {
        let mut items = Vec::new();
        let mut blocked = false;
        for mapping in &expected.manifest.mappings {
            if let Some((path, kind)) = unsafe_parent(&self.paths.home, &mapping.target)? {
                blocked = true;
                items.push(DotfileAdoptionItem {
                    package: mapping.package.clone(),
                    source: mapping.source.clone(),
                    source_sha256: mapping.source_sha256.clone(),
                    target: mapping.target.clone(),
                    target_kind: None,
                    target_sha256: None,
                    target_link: None,
                    target_mode: None,
                    action: DotfileAdoptionAction::Blocked,
                    detail: format!(
                        "ancestor {} is {kind}, not a real directory",
                        path.display()
                    ),
                });
                continue;
            }
            let current = fingerprint(&mapping.target)?;
            let (action, detail) = match current.kind {
                FingerprintKind::Absent => {
                    (DotfileAdoptionAction::Create, "target is absent".to_owned())
                }
                FingerprintKind::File => (
                    DotfileAdoptionAction::BackupAndReplace,
                    "regular file will be privately backed up before replacement".to_owned(),
                ),
                FingerprintKind::Symlink
                    if symlink_points_to(&mapping.target, &mapping.source)? =>
                {
                    (
                        DotfileAdoptionAction::Preserve,
                        "target already links to the selected ingredient".to_owned(),
                    )
                }
                FingerprintKind::Symlink => {
                    blocked = true;
                    (
                        DotfileAdoptionAction::Blocked,
                        "target is an unmanaged symlink".to_owned(),
                    )
                }
                FingerprintKind::Directory => {
                    blocked = true;
                    (
                        DotfileAdoptionAction::Blocked,
                        "target is a directory".to_owned(),
                    )
                }
                FingerprintKind::Other => {
                    blocked = true;
                    (
                        DotfileAdoptionAction::Blocked,
                        "target has an unsupported filesystem type".to_owned(),
                    )
                }
            };
            items.push(DotfileAdoptionItem {
                package: mapping.package.clone(),
                source: mapping.source.clone(),
                source_sha256: mapping.source_sha256.clone(),
                target: mapping.target.clone(),
                target_kind: Some(current.kind.into()),
                target_sha256: current.sha256.clone(),
                target_link: current.link_target.clone(),
                target_mode: Some(current.mode),
                action,
                detail,
            });
        }

        let before = if blocked {
            BTreeMap::new()
        } else {
            let watched = watched_paths(&self.paths.home, &expected.manifest.mappings)?;
            fingerprint_paths(&watched)?
        };
        let watched_sha256 = hash_bytes(&encode_json(&before)?);
        #[derive(Serialize)]
        struct ConfirmationIdentity<'a> {
            schema_version: u8,
            profile_id: &'a str,
            global_sha256: &'a str,
            local_sha256: &'a str,
            watched_sha256: &'a str,
            items: &'a [DotfileAdoptionItem],
        }
        let identity = ConfirmationIdentity {
            schema_version: DEPLOYMENT_PLAN_SCHEMA_VERSION,
            profile_id: &expected.manifest.profile_id,
            global_sha256: &expected.manifest.global_sha256,
            local_sha256: &expected.manifest.local_sha256,
            watched_sha256: &watched_sha256,
            items: &items,
        };
        let confirmation = format!("sha256:{}", hash_bytes(&encode_json(&identity)?));
        Ok(BuiltPlan {
            plan: DotfileDeploymentPlan {
                schema_version: DEPLOYMENT_PLAN_SCHEMA_VERSION,
                profile_id: expected.manifest.profile_id.clone(),
                global_sha256: expected.manifest.global_sha256.clone(),
                local_sha256: expected.manifest.local_sha256.clone(),
                watched_sha256,
                ready: !blocked,
                items,
                confirmation,
            },
            before,
        })
    }

    fn verify_deployment_activation(
        &self,
        activation: &ManagedActivation,
        capture_directory: &Path,
    ) -> Result<String, DotfilesError> {
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
        let version = self
            .runner
            .version(&activation.activation_path, capture_directory)
            .map_err(DotfilesError::DotterExecution)?;
        if !version_matches(&version, &install.target_version) {
            return Err(DotfilesError::DotterVersion {
                expected: install.target_version.clone(),
                actual: version,
            });
        }
        Ok(version)
    }

    fn deployment_scratch(&self) -> Result<tempfile::TempDir, DotfilesError> {
        let root = ensure_private_subdirectories(&self.paths.cache, &["dotter", "deployments"])?;
        let scratch = Builder::new()
            .prefix(".deployment-")
            .tempdir_in(&root)
            .map_err(|error| io_error("create Dotter deployment directory", &root, error))?;
        ensure_private_dir(scratch.path())?;
        Ok(scratch)
    }

    fn create_backups(
        &self,
        plan: &DotfileDeploymentPlan,
        before: &BTreeMap<PathBuf, PathFingerprint>,
        directory: &Path,
        mappings: &[DotfileMapping],
    ) -> Result<Vec<BackupRecord>, DotfilesError> {
        let mapping_sources = mappings
            .iter()
            .map(|mapping| (mapping.target.clone(), mapping.source.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut backups = Vec::new();
        for (index, item) in plan
            .items
            .iter()
            .filter(|item| item.action == DotfileAdoptionAction::BackupAndReplace)
            .enumerate()
        {
            let original = before.get(&item.target).cloned().ok_or_else(|| {
                DotfilesError::Configuration(format!(
                    "deployment plan omitted {}",
                    item.target.display()
                ))
            })?;
            if original.kind != FingerprintKind::File {
                return Err(DotfilesError::ConfirmationMismatch);
            }
            let bytes = read_bounded_regular_file(&item.target, MAX_WATCHED_FILE_SIZE as usize)?;
            if original.sha256.as_deref() != Some(hash_bytes(&bytes).as_str()) {
                return Err(DotfilesError::ConfirmationMismatch);
            }
            let file_name = format!("{index:04}.backup");
            let path = directory.join(&file_name);
            write_new_private_file(directory, &path, &bytes)?;
            let backup_sha256 = hash_file(&path)?;
            if original.sha256.as_deref() != Some(backup_sha256.as_str()) {
                return Err(DotfilesError::Configuration(format!(
                    "backup verification failed for {}",
                    item.target.display()
                )));
            }
            backups.push(BackupRecord {
                target: item.target.clone(),
                source: mapping_sources.get(&item.target).cloned().ok_or_else(|| {
                    DotfilesError::Configuration(format!(
                        "deployment mapping omitted {}",
                        item.target.display()
                    ))
                })?,
                file_name,
                sha256: backup_sha256,
                original,
            });
        }
        Ok(backups)
    }

    fn find_incomplete_transaction(&self, profile: &str) -> Result<Option<String>, DotfilesError> {
        Ok(self
            .transaction_directories(profile)?
            .into_iter()
            .find(|directory| {
                directory.join("prepared.json").is_file()
                    && !directory.join("committed.json").is_file()
                    && !directory.join("restored.json").is_file()
                    && !directory.join("rolled-back.json").is_file()
            })
            .and_then(|directory| {
                directory
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(str::to_owned)
            }))
    }

    fn find_recoverable_transaction(
        &self,
        profile: &str,
    ) -> Result<Option<(PathBuf, DeploymentTransaction)>, DotfilesError> {
        for directory in self.transaction_directories(profile)? {
            if !directory.join("prepared.json").is_file()
                || directory.join("restored.json").is_file()
                || directory.join("rolled-back.json").is_file()
            {
                continue;
            }
            let bytes = read_required_private_file(&directory.join("prepared.json"))?;
            let transaction: DeploymentTransaction = serde_json::from_slice(&bytes)
                .map_err(|error| DotfilesError::Configuration(error.to_string()))?;
            validate_transaction(&self.paths.home, &directory, profile, &transaction)?;
            return Ok(Some((directory, transaction)));
        }
        Ok(None)
    }

    fn transaction_directories(&self, profile: &str) -> Result<Vec<PathBuf>, DotfilesError> {
        validate_identifier("dotfile profile", profile)?;
        let root = self
            .paths
            .state
            .join("dotter")
            .join("transactions")
            .join(profile);
        let entries = match fs::read_dir(&root) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(io_error("read dotfile transaction directory", &root, error));
            }
            Ok(entries) => entries,
        };
        let mut directories = Vec::new();
        for entry in entries {
            let entry =
                entry.map_err(|error| io_error("read dotfile transaction entry", &root, error))?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
                io_error("inspect dotfile transaction entry", &entry.path(), error)
            })?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                directories.push(entry.path());
            }
        }
        directories.sort_by(|left, right| right.file_name().cmp(&left.file_name()));
        Ok(directories)
    }

    fn restore_transaction(
        &self,
        directory: &Path,
        transaction: &DeploymentTransaction,
    ) -> Result<RestoreCounts, String> {
        validate_transaction(
            &self.paths.home,
            directory,
            &transaction.profile_id,
            transaction,
        )
        .map_err(|error| error.to_string())?;
        let backups = transaction
            .backups
            .iter()
            .map(|backup| {
                let path = directory.join("backups").join(&backup.file_name);
                let sha256 = hash_file(&path).map_err(|error| error.to_string())?;
                if sha256 != backup.sha256 {
                    return Err(format!("backup {} failed verification", path.display()));
                }
                Ok((backup, path))
            })
            .collect::<Result<Vec<_>, String>>()?;

        for item in &transaction.plan.items {
            let original = transaction.before.get(&item.target).ok_or_else(|| {
                format!("missing original fingerprint for {}", item.target.display())
            })?;
            let current = fingerprint(&item.target).map_err(|error| error.to_string())?;
            let acceptable = match original.kind {
                FingerprintKind::File => {
                    current == *original
                        || current.kind == FingerprintKind::Absent
                        || symlink_points_to(&item.target, &item.source).unwrap_or(false)
                }
                FingerprintKind::Absent => {
                    current.kind == FingerprintKind::Absent
                        || symlink_points_to(&item.target, &item.source).unwrap_or(false)
                }
                FingerprintKind::Symlink => {
                    symlink_points_to(&item.target, &item.source).unwrap_or(false)
                }
                FingerprintKind::Directory | FingerprintKind::Other => false,
            };
            if !acceptable {
                return Err(format!(
                    "{} changed after deployment; refusing to overwrite it",
                    item.target.display()
                ));
            }
        }

        let mut counts = RestoreCounts { files: 0, links: 0 };
        for item in &transaction.plan.items {
            let original = transaction.before.get(&item.target).ok_or_else(|| {
                format!("missing original fingerprint for {}", item.target.display())
            })?;
            match original.kind {
                FingerprintKind::File => {
                    let current = fingerprint(&item.target).map_err(|error| error.to_string())?;
                    if current == *original {
                        continue;
                    }
                    if current.kind == FingerprintKind::Symlink {
                        fs::remove_file(&item.target).map_err(|error| error.to_string())?;
                        counts.links += 1;
                    }
                    let (backup, path) = backups
                        .iter()
                        .find(|(backup, _)| backup.target == item.target)
                        .ok_or_else(|| format!("backup missing for {}", item.target.display()))?;
                    restore_regular_file(path, &item.target, backup.original.mode)?;
                    counts.files += 1;
                }
                FingerprintKind::Absent => {
                    if fingerprint(&item.target)
                        .map_err(|error| error.to_string())?
                        .kind
                        == FingerprintKind::Symlink
                    {
                        fs::remove_file(&item.target).map_err(|error| error.to_string())?;
                        sync_parent(&item.target)?;
                        counts.links += 1;
                    }
                }
                FingerprintKind::Symlink => {}
                FingerprintKind::Directory | FingerprintKind::Other => {
                    return Err(format!(
                        "{} has an unsupported original type",
                        item.target.display()
                    ));
                }
            }
        }
        cleanup_originally_absent_directories(&self.paths.home, &transaction.before);
        Ok(counts)
    }
}

fn unsafe_parent(
    home: &Path,
    target: &Path,
) -> Result<Option<(PathBuf, &'static str)>, DotfilesError> {
    let home_metadata =
        fs::symlink_metadata(home).map_err(|error| io_error("inspect HOME", home, error))?;
    if home_metadata.file_type().is_symlink() || !home_metadata.is_dir() {
        return Ok(Some((home.to_path_buf(), "not a real directory")));
    }
    let mut parents = Vec::new();
    let mut current = target.parent();
    while let Some(path) = current {
        if path == home {
            break;
        }
        if !path.starts_with(home) {
            return Err(DotfilesError::UnsafeTarget(target.display().to_string()));
        }
        parents.push(path.to_path_buf());
        current = path.parent();
    }
    parents.reverse();
    for path in parents {
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(io_error("inspect dotfile target ancestor", &path, error)),
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Ok(Some((path, "a symlink")));
            }
            Ok(_) => return Ok(Some((path, "not a directory"))),
        }
    }
    Ok(None)
}

fn symlink_points_to(target: &Path, source: &Path) -> Result<bool, DotfilesError> {
    let metadata = match fs::symlink_metadata(target) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(io_error("inspect managed dotfile link", target, error)),
        Ok(metadata) => metadata,
    };
    if !metadata.file_type().is_symlink() {
        return Ok(false);
    }
    let link = fs::read_link(target)
        .map_err(|error| io_error("read managed dotfile link", target, error))?;
    let candidate = if link.is_absolute() {
        link
    } else {
        target
            .parent()
            .ok_or_else(|| DotfilesError::UnsafeTarget(target.display().to_string()))?
            .join(link)
    };
    Ok(fs::canonicalize(candidate)
        .map(|resolved| resolved == source)
        .unwrap_or(false))
}

fn remove_adopted_files(transaction: &DeploymentTransaction) -> Result<(), DotfilesError> {
    for backup in &transaction.backups {
        let current = fingerprint(&backup.target)?;
        if current != backup.original {
            return Err(DotfilesError::ConfirmationMismatch);
        }
        fs::remove_file(&backup.target)
            .map_err(|error| io_error("remove adopted dotfile", &backup.target, error))?;
        sync_parent(&backup.target).map_err(DotfilesError::Configuration)?;
    }
    Ok(())
}

fn dotter_deploy_arguments(
    global_config: &Path,
    local_config: &Path,
    scratch: &Path,
    cache_directory: &Path,
) -> Vec<OsString> {
    let mut arguments =
        dotter_dry_run_arguments(global_config, local_config, scratch, cache_directory);
    arguments.retain(|argument| argument != "--dry-run");
    arguments
}

fn write_new_private_file(
    directory: &Path,
    path: &Path,
    bytes: &[u8],
) -> Result<(), DotfilesError> {
    let mut temporary = NamedTempFile::new_in(directory)
        .map_err(|error| io_error("create temporary dotfile backup", directory, error))?;
    set_private_file_permissions(temporary.as_file(), temporary.path())?;
    temporary
        .write_all(bytes)
        .map_err(|error| io_error("write dotfile backup", temporary.path(), error))?;
    temporary
        .as_file_mut()
        .sync_all()
        .map_err(|error| io_error("synchronize dotfile backup", temporary.path(), error))?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| io_error("persist dotfile backup", path, error.error))?;
    sync_directory(directory)?;
    Ok(())
}

fn restore_regular_file(backup: &Path, target: &Path, mode: u32) -> Result<(), String> {
    let parent = target
        .parent()
        .ok_or_else(|| format!("{} has no parent", target.display()))?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let mut source = File::open(backup).map_err(|error| error.to_string())?;
    let mut temporary = NamedTempFile::new_in(parent).map_err(|error| error.to_string())?;
    io::copy(&mut source, &mut temporary).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|error| error.to_string())?;
    }
    temporary
        .as_file_mut()
        .sync_all()
        .map_err(|error| error.to_string())?;
    temporary
        .persist_noclobber(target)
        .map_err(|error| error.error.to_string())?;
    sync_parent(target)?;
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent", path.display()))?;
    sync_directory(parent).map_err(|error| error.to_string())
}

fn cleanup_originally_absent_directories(home: &Path, before: &BTreeMap<PathBuf, PathFingerprint>) {
    let mut paths = before
        .iter()
        .filter(|(path, fingerprint)| {
            path.as_path() != home && fingerprint.kind == FingerprintKind::Absent
        })
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    paths.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for path in paths {
        if fs::symlink_metadata(&path)
            .map(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            let _ = fs::remove_dir(&path);
        }
    }
}

fn validate_transaction(
    home: &Path,
    directory: &Path,
    profile: &str,
    transaction: &DeploymentTransaction,
) -> Result<(), DotfilesError> {
    if transaction.schema_version != DEPLOYMENT_TRANSACTION_SCHEMA_VERSION
        || transaction.profile_id != profile
        || directory.file_name().and_then(|name| name.to_str())
            != Some(transaction.transaction_id.as_str())
        || !transaction.plan.ready
    {
        return Err(DotfilesError::Configuration(format!(
            "invalid dotfile transaction at {}",
            directory.display()
        )));
    }
    validate_identifier("dotfile transaction", &transaction.transaction_id)?;
    for item in &transaction.plan.items {
        if !item.target.starts_with(home) {
            return Err(DotfilesError::UnsafeTarget(
                item.target.display().to_string(),
            ));
        }
    }
    for backup in &transaction.backups {
        validate_identifier("dotfile backup", &backup.file_name)?;
        if !backup.target.starts_with(home) {
            return Err(DotfilesError::UnsafeTarget(
                backup.target.display().to_string(),
            ));
        }
        let path = directory.join("backups").join(&backup.file_name);
        if !path.starts_with(directory) {
            return Err(DotfilesError::Configuration(
                "dotfile backup escaped its transaction".to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use crate::{HazardsPaths, HostKind, Persistence, ResolvedProfile, Role};

    use super::*;

    #[derive(Clone)]
    struct DeployRunner {
        links: Vec<(PathBuf, PathBuf)>,
        fail_after: Option<usize>,
    }

    impl DotterRunner for DeployRunner {
        fn version(&self, _executable: &Path, _capture_directory: &Path) -> Result<String, String> {
            Ok("dotter 0.13.5".to_owned())
        }

        fn dry_run(
            &self,
            _invocation: DotterInvocation<'_>,
        ) -> Result<DotterCommandOutput, String> {
            Ok(DotterCommandOutput {
                exit_code: Some(0),
                stdout: b"preview\n".to_vec(),
                stderr: Vec::new(),
                failure: None,
            })
        }

        fn deploy(&self, invocation: DotterInvocation<'_>) -> Result<DotterCommandOutput, String> {
            assert!(
                !invocation
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
            for (index, (source, target)) in self.links.iter().enumerate() {
                if self.fail_after == Some(index) {
                    return Ok(DotterCommandOutput {
                        exit_code: Some(2),
                        stdout: Vec::new(),
                        stderr: b"synthetic deployment failure\n".to_vec(),
                        failure: None,
                    });
                }
                fs::create_dir_all(target.parent().expect("target parent"))
                    .expect("target parent should exist");
                #[cfg(unix)]
                std::os::unix::fs::symlink(source, target)
                    .expect("managed target should be linked");
            }
            Ok(DotterCommandOutput {
                exit_code: Some(0),
                stdout: b"deployed\n".to_vec(),
                stderr: Vec::new(),
                failure: None,
            })
        }
    }

    fn fixture() -> (
        tempfile::TempDir,
        Registry,
        HazardsPaths,
        ResolvedProfile,
        Vec<(PathBuf, PathBuf)>,
    ) {
        let root = tempfile::tempdir().expect("fixture root");
        let workspace = root.path().join("workspace");
        for path in [
            "ingredients/dotterbatter",
            "ingredients/helixer",
            "ingredients/alacarte",
            "ingredients/zellijuice/layouts",
        ] {
            fs::create_dir_all(workspace.join(path)).expect("fixture directory");
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
        .expect("global fixture");
        for path in [
            "ingredients/helixer/config.toml",
            "ingredients/alacarte/alacritty.toml",
            "ingredients/zellijuice/config.kdl",
            "ingredients/zellijuice/layouts/hazards.kdl",
        ] {
            fs::write(workspace.join(path), format!("managed {path}\n"))
                .expect("ingredient fixture");
        }
        let home = root.path().join("home");
        fs::create_dir(&home).expect("home");
        let paths = HazardsPaths {
            home: home.clone(),
            config: home.join(".config/hazards"),
            data: home.join(".local/share/hazards"),
            state: home.join(".local/state/hazards"),
            cache: home.join(".cache/hazards"),
            bin: home.join(".local/bin"),
        };
        let links = [
            (
                "ingredients/helixer/config.toml",
                ".config/helix/config.toml",
            ),
            (
                "ingredients/alacarte/alacritty.toml",
                ".config/alacritty/alacritty.toml",
            ),
            (
                "ingredients/zellijuice/config.kdl",
                ".config/zellij/config.kdl",
            ),
            (
                "ingredients/zellijuice/layouts/hazards.kdl",
                ".config/zellij/layouts/hazards.kdl",
            ),
        ]
        .into_iter()
        .map(|(source, target)| {
            (
                fs::canonicalize(workspace.join(source)).expect("canonical source"),
                home.join(target),
            )
        })
        .collect();
        (
            root,
            Registry::embedded().expect("registry"),
            paths,
            ResolvedProfile::new(HostKind::Desktop, Persistence::Local, Role::Development),
            links,
        )
    }

    fn manager<'a>(
        root: &'a tempfile::TempDir,
        registry: &'a Registry,
        paths: &HazardsPaths,
        profile: &'a ResolvedProfile,
        runner: DeployRunner,
    ) -> DotfilesManager<'a, DeployRunner> {
        DotfilesManager::with_runner(
            registry,
            profile,
            paths,
            root.path().join("workspace"),
            runner,
        )
        .expect("manager")
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
    fn plan_binds_regular_conflicts_and_changes_with_the_target() {
        let (root, registry, paths, profile, links) = fixture();
        let helix = links[0].1.clone();
        fs::create_dir_all(helix.parent().expect("helix parent")).expect("helix parent");
        fs::write(&helix, b"theme = \"autumn_night\"\n").expect("existing helix");
        let manager = manager(
            &root,
            &registry,
            &paths,
            &profile,
            DeployRunner {
                links,
                fail_after: None,
            },
        );
        manager.generate().expect("profile");

        let first = manager.adoption_plan().expect("plan");
        assert!(first.ready);
        assert_eq!(
            first.items[0].action,
            DotfileAdoptionAction::BackupAndReplace
        );
        assert!(
            first
                .items
                .iter()
                .skip(1)
                .all(|item| item.action == DotfileAdoptionAction::Create)
        );

        fs::write(&helix, b"theme = \"changed\"\n").expect("changed helix");
        let second = manager.adoption_plan().expect("updated plan");
        assert_ne!(first.confirmation, second.confirmation);
        assert_ne!(first.watched_sha256, second.watched_sha256);
    }

    #[test]
    fn unmanaged_parent_symlinks_block_adoption() {
        let (root, registry, paths, profile, links) = fixture();
        let outside = root.path().join("outside");
        fs::create_dir(&outside).expect("outside");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, paths.home.join(".config")).expect("config symlink");
        let manager = manager(
            &root,
            &registry,
            &paths,
            &profile,
            DeployRunner {
                links,
                fail_after: None,
            },
        );
        manager.generate().expect("profile");

        let plan = manager.adoption_plan().expect("blocked plan");

        assert!(!plan.ready);
        assert!(
            plan.items
                .iter()
                .all(|item| item.action == DotfileAdoptionAction::Blocked)
        );
    }

    #[test]
    fn confirmed_deployment_backups_links_and_rolls_back() {
        let (root, registry, paths, profile, links) = fixture();
        let helix = &links[0].1;
        let zellij = &links[2].1;
        fs::create_dir_all(helix.parent().expect("helix parent")).expect("helix parent");
        fs::create_dir_all(zellij.parent().expect("zellij parent")).expect("zellij parent");
        fs::write(helix, b"theme = \"autumn_night\"\n").expect("helix");
        fs::write(zellij, b"theme \"gruvbox-dark\"\n").expect("zellij");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(helix, fs::Permissions::from_mode(0o640)).expect("helix mode");
        }
        let manager = manager(
            &root,
            &registry,
            &paths,
            &profile,
            DeployRunner {
                links: links.clone(),
                fail_after: None,
            },
        );
        manager.generate().expect("profile");
        let plan = manager.adoption_plan().expect("plan");

        let report = manager
            .deploy(&activation(&paths), &plan.confirmation)
            .expect("deployment");

        assert_eq!(report.receipt.outcome, DotfileDeploymentOutcome::Deployed);
        assert_eq!(report.receipt.backup_count, 2);
        for (source, target) in &links {
            assert!(symlink_points_to(target, source).expect("managed link"));
        }

        let rollback = manager.rollback_deployment().expect("rollback");
        assert_eq!(rollback.receipt.restored_files, 2);
        assert_eq!(
            fs::read(helix).expect("restored helix"),
            b"theme = \"autumn_night\"\n"
        );
        assert_eq!(
            fs::read(zellij).expect("restored zellij"),
            b"theme \"gruvbox-dark\"\n"
        );
        assert!(!links[1].1.exists());
        assert!(!links[3].1.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(helix)
                    .expect("helix metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o640
            );
        }
    }

    #[test]
    fn failed_deployment_restores_every_original_target() {
        let (root, registry, paths, profile, links) = fixture();
        let helix = &links[0].1;
        fs::create_dir_all(helix.parent().expect("helix parent")).expect("helix parent");
        fs::write(helix, b"original\n").expect("helix");
        let manager = manager(
            &root,
            &registry,
            &paths,
            &profile,
            DeployRunner {
                links: links.clone(),
                fail_after: Some(2),
            },
        );
        manager.generate().expect("profile");
        let plan = manager.adoption_plan().expect("plan");

        let report = manager
            .deploy(&activation(&paths), &plan.confirmation)
            .expect("failed deployment should report");

        assert_eq!(
            report.receipt.outcome,
            DotfileDeploymentOutcome::FailedRestored
        );
        assert_eq!(fs::read(helix).expect("restored helix"), b"original\n");
        assert!(!links[1].1.exists());
        assert!(!links[2].1.exists());
        assert!(!links[3].1.exists());
    }

    #[test]
    fn stale_confirmation_never_moves_a_target() {
        let (root, registry, paths, profile, links) = fixture();
        let helix = links[0].1.clone();
        fs::create_dir_all(helix.parent().expect("helix parent")).expect("helix parent");
        fs::write(&helix, b"first\n").expect("helix");
        let manager = manager(
            &root,
            &registry,
            &paths,
            &profile,
            DeployRunner {
                links,
                fail_after: None,
            },
        );
        manager.generate().expect("profile");
        let plan = manager.adoption_plan().expect("plan");
        fs::write(&helix, b"second\n").expect("changed helix");

        assert!(matches!(
            manager.deploy(&activation(&paths), &plan.confirmation),
            Err(DotfilesError::ConfirmationMismatch)
        ));
        assert_eq!(fs::read(&helix).expect("untouched helix"), b"second\n");
    }

    #[test]
    fn tampered_backup_prevents_destructive_rollback() {
        let (root, registry, paths, profile, links) = fixture();
        let helix = &links[0].1;
        fs::create_dir_all(helix.parent().expect("helix parent")).expect("helix parent");
        fs::write(helix, b"original\n").expect("helix");
        let manager = manager(
            &root,
            &registry,
            &paths,
            &profile,
            DeployRunner {
                links: links.clone(),
                fail_after: None,
            },
        );
        manager.generate().expect("profile");
        let plan = manager.adoption_plan().expect("plan");
        let report = manager
            .deploy(&activation(&paths), &plan.confirmation)
            .expect("deployment");
        fs::write(
            report.transaction_directory.join("backups/0000.backup"),
            b"tampered\n",
        )
        .expect("tampered backup");

        assert!(matches!(
            manager.rollback_deployment(),
            Err(DotfilesError::RecoveryFailed { .. })
        ));
        assert!(symlink_points_to(helix, &links[0].0).expect("managed link remains"));
    }
}
