use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use arsenallspice::{
    AcquisitionMethod, ArtifactFormat, CargoSourceLock, DigestEvidence, LockedArtifact,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::{Builder, TempDir};
use thiserror::Error;

mod archive;
mod evidence;
#[cfg(test)]
mod tests;

use archive::extract_and_validate;
use evidence::{
    inspect_tree, persist_candidate, validate_existing_stage, write_json_noclobber, write_manifest,
};

use crate::{
    AcquisitionItem, AcquisitionStatus, HazardsPaths,
    acquire::{
        ensure_private_dir, ensure_private_subdirectories, validate_component, verify_cached_object,
    },
};

const BUFFER_SIZE: usize = 64 * 1024;
const MANIFEST_NAME: &str = ".hazards-source-preparation.json";
const MANIFEST_SCHEMA_VERSION: u8 = 1;
const RECEIPT_SCHEMA_VERSION: u8 = 1;
const MAX_ARCHIVE_ENTRIES: usize = 100_000;
const MAX_EXPANDED_SIZE: u64 = 1024 * 1024 * 1024;
const MAX_ENTRY_SIZE: u64 = 512 * 1024 * 1024;
const MAX_METADATA_SIZE: u64 = 16 * 1024 * 1024;
const MAX_PATH_LENGTH: usize = 4096;
const MAX_COMPONENT_LENGTH: usize = 255;
const MAX_EVIDENCE_SIZE: usize = 16 * 1024 * 1024;
const CRATES_IO_REGISTRY: &str = "registry+https://github.com/rust-lang/crates.io-index";
static RECEIPT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Whether a locked source tree was created or freshly reproduced and matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourcePreparationOutcome {
    Prepared,
    StageHit,
}

impl std::fmt::Display for SourcePreparationOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Prepared => formatter.write_str("prepared"),
            Self::StageHit => formatter.write_str("stage-hit"),
        }
    }
}

/// Durable evidence that one exact crates.io source tree was privately prepared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourcePreparationReceipt {
    pub schema_version: u8,
    pub receipt_id: String,
    pub tool_id: String,
    pub version: String,
    pub artifact_sha256: String,
    pub source_root: String,
    pub manifest_sha256: String,
    pub cargo_lock_sha256: String,
    pub cargo_lock_version: u32,
    pub package_count: usize,
    pub registry_package_count: usize,
    pub local_package_count: usize,
    pub entry_count: usize,
    pub expanded_size: u64,
    pub outcome: SourcePreparationOutcome,
    pub verified_at_unix: u64,
}

/// Paths and evidence produced by successful controlled source preparation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreparedSource {
    pub staging_path: PathBuf,
    pub source_path: PathBuf,
    pub manifest_path: PathBuf,
    pub receipt_path: PathBuf,
    pub receipt: SourcePreparationReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct SourcePreparationManifest {
    schema_version: u8,
    tool_id: String,
    version: String,
    artifact_sha256: String,
    source_root: String,
    manifest_sha256: String,
    cargo_lock_sha256: String,
    cargo_lock_version: u32,
    package_count: usize,
    registry_package_count: usize,
    local_package_count: usize,
    entries: Vec<PreparedSourceEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct PreparedSourceEntry {
    path: String,
    kind: PreparedSourceEntryKind,
    size: u64,
    sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum PreparedSourceEntryKind {
    Directory,
    File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GraphInspection {
    registry_packages: usize,
    local_packages: usize,
}

/// Reproduces checksum-locked crate source in private, non-executable staging.
pub struct SourcePreparer {
    cache_root: PathBuf,
    state_root: PathBuf,
}

impl SourcePreparer {
    pub fn for_paths(paths: &HazardsPaths) -> Self {
        Self::new(paths.cache.clone(), paths.state.clone())
    }

    pub fn new(cache_root: impl Into<PathBuf>, state_root: impl Into<PathBuf>) -> Self {
        Self {
            cache_root: cache_root.into(),
            state_root: state_root.into(),
        }
    }

    pub fn prepare(
        &self,
        item: &AcquisitionItem,
    ) -> Result<PreparedSource, SourcePreparationError> {
        let (artifact, source_lock, object_path) = self.resolve(item)?;
        let staging_parent = ensure_private_subdirectories(
            &self.cache_root,
            &["sources", "sha256", &artifact.sha256[..2]],
        )?;
        let staging_path = staging_parent.join(&artifact.sha256);
        let (candidate, manifest) =
            reproduce(item, artifact, source_lock, &object_path, &staging_parent)?;

        let outcome = match fs::symlink_metadata(&staging_path) {
            Ok(_) => {
                let existing = validate_existing_stage(&staging_path, artifact, source_lock)?;
                if existing != manifest {
                    return Err(SourcePreparationError::CorruptStage {
                        path: staging_path,
                        reason:
                            "prepared source does not match a fresh reproduction from the locked object"
                                .to_owned(),
                    });
                }
                SourcePreparationOutcome::StageHit
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                persist_candidate(candidate, &staging_path, &manifest, artifact, source_lock)?
            }
            Err(error) => {
                return Err(io_error(
                    "inspect prepared source path",
                    &staging_path,
                    error,
                ));
            }
        };

        self.finish(item, artifact, source_lock, staging_path, manifest, outcome)
    }

    fn resolve<'a>(
        &self,
        item: &'a AcquisitionItem,
    ) -> Result<(&'a LockedArtifact, &'a CargoSourceLock, PathBuf), SourcePreparationError> {
        let artifact = item
            .artifact
            .as_ref()
            .ok_or_else(|| SourcePreparationError::Unavailable(item.id.clone()))?;
        validate_component("tool identifier", &item.id)?;
        validate_component("version", &item.target_version)?;
        if item.status != AcquisitionStatus::LockedSource
            || artifact.method != AcquisitionMethod::CargoRegistry
            || artifact.format != ArtifactFormat::Crate
            || artifact.evidence != DigestEvidence::CratesIoChecksum
        {
            return Err(SourcePreparationError::NotLockedSource(item.id.clone()));
        }
        if artifact.tool_id != item.id || artifact.version != item.target_version {
            return Err(SourcePreparationError::Validation(
                "source artifact identity does not match the selected acquisition item".to_owned(),
            ));
        }
        if !valid_sha256(&artifact.sha256) {
            return Err(SourcePreparationError::Validation(
                "source artifact SHA-256 is not 64 lowercase hexadecimal characters".to_owned(),
            ));
        }
        let source_lock = artifact
            .source_lock
            .as_ref()
            .ok_or_else(|| SourcePreparationError::MissingSourceLock(item.id.clone()))?;
        validate_component("source root", &source_lock.root)?;
        validate_component("source package", &source_lock.package)?;
        if source_lock.root.len() > MAX_COMPONENT_LENGTH
            || source_lock.root != format!("{}-{}", source_lock.package, artifact.version)
            || !valid_sha256(&source_lock.manifest_sha256)
            || !valid_sha256(&source_lock.cargo_lock_sha256)
            || source_lock.cargo_lock_version == 0
            || source_lock.package_count == 0
        {
            return Err(SourcePreparationError::Validation(
                "source lock identity is malformed or does not match the artifact".to_owned(),
            ));
        }
        let object_path = self
            .cache_root
            .join("objects")
            .join("sha256")
            .join(&artifact.sha256[..2])
            .join(&artifact.sha256);
        match fs::symlink_metadata(&object_path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(SourcePreparationError::MissingCache {
                    tool: item.id.clone(),
                    path: object_path,
                });
            }
            Err(error) => {
                return Err(io_error(
                    "inspect verified source object",
                    &object_path,
                    error,
                ));
            }
            Ok(_) => {}
        }
        verify_cached_object(&object_path, artifact)?;
        Ok((artifact, source_lock, object_path))
    }

    fn finish(
        &self,
        item: &AcquisitionItem,
        artifact: &LockedArtifact,
        source_lock: &CargoSourceLock,
        staging_path: PathBuf,
        manifest: SourcePreparationManifest,
        outcome: SourcePreparationOutcome,
    ) -> Result<PreparedSource, SourcePreparationError> {
        let verified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| SourcePreparationError::Clock(error.to_string()))?;
        let receipt = SourcePreparationReceipt {
            schema_version: RECEIPT_SCHEMA_VERSION,
            receipt_id: format!(
                "{}-{:09}-{}-{}",
                verified_at.as_secs(),
                verified_at.subsec_nanos(),
                std::process::id(),
                RECEIPT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ),
            tool_id: item.id.clone(),
            version: item.target_version.clone(),
            artifact_sha256: artifact.sha256.clone(),
            source_root: source_lock.root.clone(),
            manifest_sha256: source_lock.manifest_sha256.clone(),
            cargo_lock_sha256: source_lock.cargo_lock_sha256.clone(),
            cargo_lock_version: source_lock.cargo_lock_version,
            package_count: source_lock.package_count,
            registry_package_count: manifest.registry_package_count,
            local_package_count: manifest.local_package_count,
            entry_count: manifest.entries.len(),
            expanded_size: manifest
                .entries
                .iter()
                .filter(|entry| entry.kind == PreparedSourceEntryKind::File)
                .map(|entry| entry.size)
                .sum(),
            outcome,
            verified_at_unix: verified_at.as_secs(),
        };
        let receipt_path = self.write_receipt(&receipt)?;
        let source_path = staging_path.join(&source_lock.root);
        let manifest_path = staging_path.join(MANIFEST_NAME);

        Ok(PreparedSource {
            staging_path,
            source_path,
            manifest_path,
            receipt_path,
            receipt,
        })
    }

    fn write_receipt(
        &self,
        receipt: &SourcePreparationReceipt,
    ) -> Result<PathBuf, SourcePreparationError> {
        let receipt_dir = ensure_private_subdirectories(
            &self.state_root,
            &[
                "receipts",
                "source-preparations",
                &receipt.tool_id,
                &receipt.version,
            ],
        )?;
        let receipt_path = receipt_dir.join(format!("{}.json", receipt.receipt_id));
        write_json_noclobber(&receipt_dir, &receipt_path, receipt)?;
        Ok(receipt_path)
    }
}

#[derive(Debug, Error)]
pub enum SourcePreparationError {
    #[error("artifact for {0} is unavailable")]
    Unavailable(String),
    #[error("artifact for {0} is not a locked crates.io source archive")]
    NotLockedSource(String),
    #[error("source artifact for {0} has no embedded Cargo lock identity")]
    MissingSourceLock(String),
    #[error("verified cache object for {tool} is missing at {path}; acquire it first")]
    MissingCache { tool: String, path: PathBuf },
    #[error("unsafe source archive entry {entry}: {reason}")]
    UnsafeEntry { entry: String, reason: String },
    #[error("source archive contains more than {maximum} entries")]
    TooManyEntries { maximum: usize },
    #[error("source entry {entry} expands to {actual} bytes; limit is {maximum}")]
    EntryTooLarge {
        entry: String,
        actual: u64,
        maximum: u64,
    },
    #[error("source archive expands beyond the {maximum} byte safety limit")]
    ExpandedTooLarge { maximum: u64 },
    #[error("source archive omitted {0}")]
    MissingMetadata(&'static str),
    #[error("source archive validation failed: {0}")]
    Validation(String),
    #[error("prepared source failed verification at {path}: {reason}")]
    CorruptStage { path: PathBuf, reason: String },
    #[error("could not process source archive: {0}")]
    Archive(String),
    #[error("{action} at {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not serialize or parse source-preparation evidence: {0}")]
    Evidence(String),
    #[error("system clock is before the Unix epoch: {0}")]
    Clock(String),
    #[error(transparent)]
    Cache(#[from] crate::VerifiedArtifactError),
}

fn reproduce(
    item: &AcquisitionItem,
    artifact: &LockedArtifact,
    source_lock: &CargoSourceLock,
    object_path: &Path,
    staging_parent: &Path,
) -> Result<(TempDir, SourcePreparationManifest), SourcePreparationError> {
    let candidate = Builder::new()
        .prefix(".source-prepare-")
        .tempdir_in(staging_parent)
        .map_err(|error| io_error("create temporary source directory", staging_parent, error))?;
    ensure_private_dir(candidate.path())?;

    let graph = extract_and_validate(artifact, source_lock, object_path, candidate.path())?;
    let entries = inspect_tree(candidate.path())?;
    let manifest = SourcePreparationManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        tool_id: item.id.clone(),
        version: item.target_version.clone(),
        artifact_sha256: artifact.sha256.clone(),
        source_root: source_lock.root.clone(),
        manifest_sha256: source_lock.manifest_sha256.clone(),
        cargo_lock_sha256: source_lock.cargo_lock_sha256.clone(),
        cargo_lock_version: source_lock.cargo_lock_version,
        package_count: source_lock.package_count,
        registry_package_count: graph.registry_packages,
        local_package_count: graph.local_packages,
        entries,
    };
    write_manifest(candidate.path(), &manifest)?;
    Ok((candidate, manifest))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn io_error(action: &'static str, path: &Path, source: io::Error) -> SourcePreparationError {
    SourcePreparationError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}
