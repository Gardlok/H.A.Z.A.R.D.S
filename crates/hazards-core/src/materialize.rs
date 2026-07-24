use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use arsenallspice::{ArtifactFormat, LockedArtifact};
use flate2::read::GzDecoder;
use lzma_rust2::XzReader;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::{Builder, TempDir};
use thiserror::Error;
use zip::ZipArchive;

use crate::{
    AcquisitionItem, HazardsPaths,
    acquire::{
        ensure_private_dir, ensure_private_subdirectories, set_private_file_permissions,
        sync_directory, validate_component, verify_cached_object,
    },
};

const BUFFER_SIZE: usize = 64 * 1024;
const MANIFEST_NAME: &str = ".hazards-materialization.json";
const MANIFEST_SCHEMA_VERSION: u8 = 1;
const RECEIPT_SCHEMA_VERSION: u8 = 1;
const MAX_ARCHIVE_ENTRIES: usize = 100_000;
const MAX_EXPANDED_SIZE: u64 = 1024 * 1024 * 1024;
const MAX_ENTRY_SIZE: u64 = 512 * 1024 * 1024;
const MAX_PATH_LENGTH: usize = 4096;
const MAX_COMPONENT_LENGTH: usize = 255;
const MAX_EVIDENCE_SIZE: usize = 16 * 1024 * 1024;
static RECEIPT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Whether a staging tree was created or independently reproduced and matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterializationOutcome {
    Materialized,
    StageHit,
}

impl std::fmt::Display for MaterializationOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Materialized => formatter.write_str("materialized"),
            Self::StageHit => formatter.write_str("stage-hit"),
        }
    }
}

/// Durable evidence that a locked payload was safely reproduced in staging.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MaterializationReceipt {
    pub schema_version: u8,
    pub receipt_id: String,
    pub tool_id: String,
    pub version: String,
    pub artifact_sha256: String,
    pub payload_path: String,
    pub payload_size: u64,
    pub payload_sha256: String,
    pub architecture: String,
    pub entry_count: usize,
    pub expanded_size: u64,
    pub outcome: MaterializationOutcome,
    pub verified_at_unix: u64,
}

/// Paths and receipt produced by a successful materialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StagedArtifact {
    pub staging_path: PathBuf,
    pub payload_path: PathBuf,
    pub manifest_path: PathBuf,
    pub receipt_path: PathBuf,
    pub receipt: MaterializationReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct MaterializationManifest {
    schema_version: u8,
    tool_id: String,
    version: String,
    artifact_sha256: String,
    payload_path: String,
    payload_size: u64,
    payload_sha256: String,
    architecture: String,
    entries: Vec<MaterializedEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct MaterializedEntry {
    path: String,
    kind: MaterializedEntryKind,
    size: u64,
    sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum MaterializedEntryKind {
    Directory,
    File,
}

/// Reproduces verified artifacts in a private, non-executable staging cache.
pub struct Materializer {
    cache_root: PathBuf,
    state_root: PathBuf,
}

impl Materializer {
    pub fn for_paths(paths: &HazardsPaths) -> Self {
        Self::new(paths.cache.clone(), paths.state.clone())
    }

    pub fn new(cache_root: impl Into<PathBuf>, state_root: impl Into<PathBuf>) -> Self {
        Self {
            cache_root: cache_root.into(),
            state_root: state_root.into(),
        }
    }

    pub fn materialize(
        &self,
        item: &AcquisitionItem,
    ) -> Result<StagedArtifact, MaterializationError> {
        let artifact = item
            .artifact
            .as_ref()
            .ok_or_else(|| MaterializationError::Unavailable(item.id.clone()))?;
        validate_component("tool identifier", &item.id)?;
        validate_component("version", &item.target_version)?;
        let payload = locked_payload(artifact)?;

        let object_path = self
            .cache_root
            .join("objects")
            .join("sha256")
            .join(&artifact.sha256[..2])
            .join(&artifact.sha256);
        if !object_path.exists() {
            return Err(MaterializationError::MissingCache {
                tool: item.id.clone(),
                path: object_path,
            });
        }
        verify_cached_object(&object_path, artifact)?;

        let staging_parent = ensure_private_subdirectories(
            &self.cache_root,
            &["staging", "sha256", &artifact.sha256[..2]],
        )?;
        let staging_path = staging_parent.join(&artifact.sha256);
        let candidate = Builder::new()
            .prefix(".materialize-")
            .tempdir_in(&staging_parent)
            .map_err(|error| {
                io_error("create temporary staging directory", &staging_parent, error)
            })?;
        ensure_private_dir(candidate.path())?;

        extract_artifact(artifact, &object_path, candidate.path())?;
        let entries = inspect_tree(candidate.path())?;
        verify_payload(candidate.path(), payload, &artifact.architecture)?;
        let manifest = MaterializationManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            tool_id: item.id.clone(),
            version: item.target_version.clone(),
            artifact_sha256: artifact.sha256.clone(),
            payload_path: payload.path.to_owned(),
            payload_size: payload.size,
            payload_sha256: payload.sha256.to_owned(),
            architecture: artifact.architecture.clone(),
            entries,
        };
        write_manifest(candidate.path(), &manifest)?;

        let outcome = if staging_path.exists() {
            let existing = validate_existing_stage(&staging_path, payload, artifact)?;
            if existing != manifest {
                return Err(MaterializationError::CorruptStage {
                    path: staging_path,
                    reason:
                        "staged tree does not match a fresh reproduction from the locked object"
                            .to_owned(),
                });
            }
            MaterializationOutcome::StageHit
        } else {
            persist_candidate(candidate, &staging_path, &manifest, payload, artifact)?
        };

        self.finish(item, artifact, payload, staging_path, manifest, outcome)
    }

    fn finish(
        &self,
        item: &AcquisitionItem,
        artifact: &LockedArtifact,
        payload: LockedPayload<'_>,
        staging_path: PathBuf,
        manifest: MaterializationManifest,
        outcome: MaterializationOutcome,
    ) -> Result<StagedArtifact, MaterializationError> {
        let verified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| MaterializationError::Clock(error.to_string()))?;
        let receipt = MaterializationReceipt {
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
            payload_path: payload.path.to_owned(),
            payload_size: payload.size,
            payload_sha256: payload.sha256.to_owned(),
            architecture: artifact.architecture.clone(),
            entry_count: manifest.entries.len(),
            expanded_size: manifest
                .entries
                .iter()
                .filter(|entry| entry.kind == MaterializedEntryKind::File)
                .map(|entry| entry.size)
                .sum(),
            outcome,
            verified_at_unix: verified_at.as_secs(),
        };
        let receipt_path = self.write_receipt(&receipt)?;
        let payload_path = staging_path.join(payload.path);
        let manifest_path = staging_path.join(MANIFEST_NAME);

        Ok(StagedArtifact {
            staging_path,
            payload_path,
            manifest_path,
            receipt_path,
            receipt,
        })
    }

    fn write_receipt(
        &self,
        receipt: &MaterializationReceipt,
    ) -> Result<PathBuf, MaterializationError> {
        let receipt_dir = ensure_private_subdirectories(
            &self.state_root,
            &[
                "receipts",
                "materializations",
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
pub enum MaterializationError {
    #[error("artifact for {0} is unavailable")]
    Unavailable(String),
    #[error("verified cache object for {tool} is missing at {path}; acquire it first")]
    MissingCache { tool: String, path: PathBuf },
    #[error("source artifact for {0} has no executable payload to materialize")]
    SourceArtifact(String),
    #[error("artifact for {0} has incomplete locked payload identity")]
    MissingPayload(String),
    #[error("unsafe archive entry {entry}: {reason}")]
    UnsafeEntry { entry: String, reason: String },
    #[error("archive contains more than {maximum} entries")]
    TooManyEntries { maximum: usize },
    #[error("archive entry {entry} expands to {actual} bytes; limit is {maximum}")]
    EntryTooLarge {
        entry: String,
        actual: u64,
        maximum: u64,
    },
    #[error("archive expands beyond the {maximum} byte safety limit")]
    ExpandedTooLarge { maximum: u64 },
    #[error("payload is missing from the exact locked path {0}")]
    MissingPayloadPath(String),
    #[error("payload identity mismatch for {field}: expected {expected}, found {actual}")]
    PayloadMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    #[error("payload at {path} is not an accepted Linux ELF executable: {reason}")]
    InvalidElf { path: PathBuf, reason: String },
    #[error("staged tree failed verification at {path}: {reason}")]
    CorruptStage { path: PathBuf, reason: String },
    #[error("could not process artifact container: {0}")]
    Archive(String),
    #[error("{action} at {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not serialize or parse materialization evidence: {0}")]
    Evidence(String),
    #[error("system clock is before the Unix epoch: {0}")]
    Clock(String),
    #[error(transparent)]
    Cache(#[from] crate::VerifiedArtifactError),
}

#[derive(Clone, Copy)]
struct LockedPayload<'a> {
    path: &'a str,
    size: u64,
    sha256: &'a str,
}

fn locked_payload(artifact: &LockedArtifact) -> Result<LockedPayload<'_>, MaterializationError> {
    if artifact.format == ArtifactFormat::Crate {
        return Err(MaterializationError::SourceArtifact(
            artifact.tool_id.clone(),
        ));
    }
    match (
        artifact.payload_path.as_deref(),
        artifact.payload_size,
        artifact.payload_sha256.as_deref(),
    ) {
        (Some(path), Some(size), Some(sha256)) => Ok(LockedPayload { path, size, sha256 }),
        _ => Err(MaterializationError::MissingPayload(
            artifact.tool_id.clone(),
        )),
    }
}

fn extract_artifact(
    artifact: &LockedArtifact,
    object_path: &Path,
    destination: &Path,
) -> Result<(), MaterializationError> {
    let object = File::open(object_path)
        .map_err(|error| io_error("open verified cache object", object_path, error))?;
    match artifact.format {
        ArtifactFormat::Binary => {
            let payload = locked_payload(artifact)?;
            let relative = strict_relative_path(Path::new(payload.path))?;
            let target = destination.join(&relative);
            ensure_parent_directories(destination, &relative)?;
            let mut source = object;
            let mut output = create_private_file(&target)?;
            let mut expanded = 0;
            copy_entry(
                &mut source,
                &mut output,
                payload.path,
                artifact.size,
                &mut expanded,
            )?;
            output
                .sync_all()
                .map_err(|error| io_error("synchronize staged payload", &target, error))?;
        }
        ArtifactFormat::TarGz => {
            extract_tar(GzDecoder::new(object), destination)?;
        }
        ArtifactFormat::TarXz => {
            extract_tar(XzReader::new(object, false), destination)?;
        }
        ArtifactFormat::Zip => {
            extract_zip(object, destination)?;
        }
        ArtifactFormat::Crate => {
            return Err(MaterializationError::SourceArtifact(
                artifact.tool_id.clone(),
            ));
        }
    }
    Ok(())
}

fn extract_tar(reader: impl Read, destination: &Path) -> Result<(), MaterializationError> {
    let mut archive = tar::Archive::new(reader);
    let entries = archive
        .entries()
        .map_err(|error| MaterializationError::Archive(error.to_string()))?;
    let mut seen = HashSet::new();
    let mut entry_count = 0_usize;
    let mut expanded = 0_u64;

    for result in entries {
        let mut entry = result.map_err(|error| MaterializationError::Archive(error.to_string()))?;
        entry_count += 1;
        if entry_count > MAX_ARCHIVE_ENTRIES {
            return Err(MaterializationError::TooManyEntries {
                maximum: MAX_ARCHIVE_ENTRIES,
            });
        }

        let original = entry
            .path()
            .map_err(|error| MaterializationError::Archive(error.to_string()))?;
        let relative = strict_relative_path(&original)?;
        let display = relative_path_text(&relative)?;
        reject_duplicate(&mut seen, &display)?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            ensure_directory(destination, &relative)?;
        } else if entry_type.is_file() {
            let declared = entry.size();
            validate_declared_size(&display, declared, expanded)?;
            ensure_parent_directories(destination, &relative)?;
            let target = destination.join(&relative);
            let mut output = create_private_file(&target)?;
            copy_entry(&mut entry, &mut output, &display, declared, &mut expanded)?;
            output
                .sync_all()
                .map_err(|error| io_error("synchronize staged file", &target, error))?;
        } else {
            return Err(MaterializationError::UnsafeEntry {
                entry: display,
                reason: format!(
                    "tar entry type {:?} is not a regular file or directory",
                    entry_type.as_byte()
                ),
            });
        }
    }
    Ok(())
}

fn extract_zip(reader: File, destination: &Path) -> Result<(), MaterializationError> {
    let mut archive = ZipArchive::new(reader)
        .map_err(|error| MaterializationError::Archive(error.to_string()))?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(MaterializationError::TooManyEntries {
            maximum: MAX_ARCHIVE_ENTRIES,
        });
    }
    let mut seen = HashSet::new();
    let mut expanded = 0_u64;

    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| MaterializationError::Archive(error.to_string()))?;
        let name = entry.name().to_owned();
        if entry.encrypted() {
            return Err(MaterializationError::UnsafeEntry {
                entry: name,
                reason: "encrypted ZIP entries are not accepted".to_owned(),
            });
        }
        if entry.is_symlink() {
            return Err(MaterializationError::UnsafeEntry {
                entry: name,
                reason: "symbolic links are not accepted".to_owned(),
            });
        }
        let enclosed = entry
            .enclosed_name()
            .ok_or_else(|| MaterializationError::UnsafeEntry {
                entry: name.clone(),
                reason: "path is absolute or escapes the staging root".to_owned(),
            })?;
        let relative = strict_relative_path(&enclosed)?;
        let display = relative_path_text(&relative)?;
        reject_duplicate(&mut seen, &display)?;
        reject_special_zip_mode(&entry, &display)?;

        if entry.is_dir() {
            ensure_directory(destination, &relative)?;
        } else {
            let declared = entry.size();
            validate_declared_size(&display, declared, expanded)?;
            ensure_parent_directories(destination, &relative)?;
            let target = destination.join(&relative);
            let mut output = create_private_file(&target)?;
            copy_entry(&mut entry, &mut output, &display, declared, &mut expanded)?;
            output
                .sync_all()
                .map_err(|error| io_error("synchronize staged file", &target, error))?;
        }
    }
    Ok(())
}

fn reject_special_zip_mode(
    entry: &zip::read::ZipFile<'_, File>,
    name: &str,
) -> Result<(), MaterializationError> {
    let Some(mode) = entry.unix_mode() else {
        return Ok(());
    };
    let file_type = mode & 0o170000;
    let accepted = file_type == 0
        || (!entry.is_dir() && file_type == 0o100000)
        || (entry.is_dir() && file_type == 0o040000);
    if accepted {
        Ok(())
    } else {
        Err(MaterializationError::UnsafeEntry {
            entry: name.to_owned(),
            reason: format!("special ZIP mode {file_type:#o} is not accepted"),
        })
    }
}

fn strict_relative_path(path: &Path) -> Result<PathBuf, MaterializationError> {
    let text = path
        .to_str()
        .ok_or_else(|| MaterializationError::UnsafeEntry {
            entry: path.to_string_lossy().into_owned(),
            reason: "path is not valid UTF-8".to_owned(),
        })?;
    if text.is_empty() || text.len() > MAX_PATH_LENGTH || text.contains('\\') {
        return Err(MaterializationError::UnsafeEntry {
            entry: text.to_owned(),
            reason: "path is empty, too long, or contains a backslash".to_owned(),
        });
    }

    let mut relative = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) if value.as_encoded_bytes().len() <= MAX_COMPONENT_LENGTH => {
                relative.push(value);
            }
            _ => {
                return Err(MaterializationError::UnsafeEntry {
                    entry: text.to_owned(),
                    reason: "only normal relative path components are accepted".to_owned(),
                });
            }
        }
    }
    if relative.as_os_str().is_empty() || relative == Path::new(MANIFEST_NAME) {
        return Err(MaterializationError::UnsafeEntry {
            entry: text.to_owned(),
            reason: "path is empty or reserved by HAZARDS".to_owned(),
        });
    }
    Ok(relative)
}

fn relative_path_text(path: &Path) -> Result<String, MaterializationError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| MaterializationError::UnsafeEntry {
            entry: path.to_string_lossy().into_owned(),
            reason: "path is not valid UTF-8".to_owned(),
        })
}

fn reject_duplicate(seen: &mut HashSet<String>, path: &str) -> Result<(), MaterializationError> {
    if seen.insert(path.to_owned()) {
        Ok(())
    } else {
        Err(MaterializationError::UnsafeEntry {
            entry: path.to_owned(),
            reason: "duplicate archive path".to_owned(),
        })
    }
}

fn validate_declared_size(
    entry: &str,
    declared: u64,
    expanded: u64,
) -> Result<(), MaterializationError> {
    if declared > MAX_ENTRY_SIZE {
        return Err(MaterializationError::EntryTooLarge {
            entry: entry.to_owned(),
            actual: declared,
            maximum: MAX_ENTRY_SIZE,
        });
    }
    if expanded
        .checked_add(declared)
        .is_none_or(|total| total > MAX_EXPANDED_SIZE)
    {
        return Err(MaterializationError::ExpandedTooLarge {
            maximum: MAX_EXPANDED_SIZE,
        });
    }
    Ok(())
}

fn copy_entry(
    reader: &mut dyn Read,
    writer: &mut File,
    entry: &str,
    declared: u64,
    expanded: &mut u64,
) -> Result<(), MaterializationError> {
    let mut buffer = [0_u8; BUFFER_SIZE];
    let mut actual = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| io_error("read archive entry", Path::new(entry), error))?;
        if read == 0 {
            break;
        }
        actual = actual
            .checked_add(read as u64)
            .ok_or(MaterializationError::EntryTooLarge {
                entry: entry.to_owned(),
                actual: u64::MAX,
                maximum: MAX_ENTRY_SIZE,
            })?;
        if actual > declared || actual > MAX_ENTRY_SIZE {
            return Err(MaterializationError::EntryTooLarge {
                entry: entry.to_owned(),
                actual,
                maximum: declared.min(MAX_ENTRY_SIZE),
            });
        }
        *expanded =
            expanded
                .checked_add(read as u64)
                .ok_or(MaterializationError::ExpandedTooLarge {
                    maximum: MAX_EXPANDED_SIZE,
                })?;
        if *expanded > MAX_EXPANDED_SIZE {
            return Err(MaterializationError::ExpandedTooLarge {
                maximum: MAX_EXPANDED_SIZE,
            });
        }
        writer
            .write_all(&buffer[..read])
            .map_err(|error| io_error("write staged file", Path::new(entry), error))?;
    }
    if actual != declared {
        return Err(MaterializationError::PayloadMismatch {
            field: "archive entry size",
            expected: declared.to_string(),
            actual: actual.to_string(),
        });
    }
    Ok(())
}

fn ensure_parent_directories(root: &Path, relative: &Path) -> Result<(), MaterializationError> {
    if let Some(parent) = relative.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_directory(root, parent)?;
        }
    }
    Ok(())
}

fn ensure_directory(root: &Path, relative: &Path) -> Result<(), MaterializationError> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(value) = component else {
            return Err(MaterializationError::UnsafeEntry {
                entry: relative.to_string_lossy().into_owned(),
                reason: "directory path contains a non-normal component".to_owned(),
            });
        };
        current.push(value);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(MaterializationError::UnsafeEntry {
                    entry: relative.to_string_lossy().into_owned(),
                    reason: "directory path collides with a non-directory".to_owned(),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current)
                    .map_err(|error| io_error("create staged directory", &current, error))?;
            }
            Err(error) => return Err(io_error("inspect staged directory", &current, error)),
        }
        set_directory_mode(&current)?;
    }
    Ok(())
}

fn create_private_file(path: &Path) -> Result<File, MaterializationError> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| io_error("create staged file", path, error))?;
    set_private_file_permissions(&file, path)?;
    Ok(file)
}

fn set_directory_mode(path: &Path) -> Result<(), MaterializationError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| io_error("set staged directory permissions", path, error))?;
    }
    Ok(())
}

fn inspect_tree(root: &Path) -> Result<Vec<MaterializedEntry>, MaterializationError> {
    let root_metadata = fs::symlink_metadata(root)
        .map_err(|error| io_error("inspect staging root", root, error))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(MaterializationError::CorruptStage {
            path: root.to_path_buf(),
            reason: "staging root is not a real directory".to_owned(),
        });
    }
    verify_mode(root, &root_metadata, 0o700)?;

    let mut entries = Vec::new();
    inspect_directory(root, root, &mut entries)?;
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    if entries.len() > MAX_ARCHIVE_ENTRIES {
        return Err(MaterializationError::TooManyEntries {
            maximum: MAX_ARCHIVE_ENTRIES,
        });
    }
    let total = entries
        .iter()
        .filter(|entry| entry.kind == MaterializedEntryKind::File)
        .try_fold(0_u64, |total, entry| total.checked_add(entry.size))
        .ok_or(MaterializationError::ExpandedTooLarge {
            maximum: MAX_EXPANDED_SIZE,
        })?;
    if total > MAX_EXPANDED_SIZE {
        return Err(MaterializationError::ExpandedTooLarge {
            maximum: MAX_EXPANDED_SIZE,
        });
    }
    Ok(entries)
}

fn inspect_directory(
    root: &Path,
    directory: &Path,
    entries: &mut Vec<MaterializedEntry>,
) -> Result<(), MaterializationError> {
    for result in fs::read_dir(directory)
        .map_err(|error| io_error("read staged directory", directory, error))?
    {
        let entry = result.map_err(|error| io_error("read staged entry", directory, error))?;
        let path = entry.path();
        if path == root.join(MANIFEST_NAME) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| io_error("inspect staged entry", &path, error))?;
        let relative = path
            .strip_prefix(root)
            .map_err(|error| MaterializationError::Evidence(error.to_string()))?;
        let relative = strict_relative_path(relative)?;
        let display = relative_path_text(&relative)?;

        if metadata.file_type().is_symlink() {
            return Err(MaterializationError::CorruptStage {
                path,
                reason: "symbolic links are not accepted".to_owned(),
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
            inspect_directory(root, &path, entries)?;
        } else if metadata.is_file() {
            verify_mode(&path, &metadata, 0o600)?;
            let digest = hash_file(&path)?;
            entries.push(MaterializedEntry {
                path: display,
                kind: MaterializedEntryKind::File,
                size: metadata.len(),
                sha256: Some(digest),
            });
        } else {
            return Err(MaterializationError::CorruptStage {
                path,
                reason: "entry is not a regular file or directory".to_owned(),
            });
        }
    }
    Ok(())
}

fn verify_mode(
    path: &Path,
    metadata: &fs::Metadata,
    expected: u32,
) -> Result<(), MaterializationError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let actual = metadata.permissions().mode() & 0o777;
        if actual != expected {
            return Err(MaterializationError::CorruptStage {
                path: path.to_path_buf(),
                reason: format!("expected mode {expected:o}, found {actual:o}"),
            });
        }
    }
    Ok(())
}

fn verify_payload(
    root: &Path,
    payload: LockedPayload<'_>,
    architecture: &str,
) -> Result<(), MaterializationError> {
    let path = root.join(payload.path);
    let metadata = fs::symlink_metadata(&path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => {
            MaterializationError::MissingPayloadPath(payload.path.to_owned())
        }
        _ => io_error("inspect staged payload", &path, error),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(MaterializationError::MissingPayloadPath(
            payload.path.to_owned(),
        ));
    }
    if metadata.len() != payload.size {
        return Err(MaterializationError::PayloadMismatch {
            field: "payload size",
            expected: payload.size.to_string(),
            actual: metadata.len().to_string(),
        });
    }
    let actual = hash_file(&path)?;
    if actual != payload.sha256 {
        return Err(MaterializationError::PayloadMismatch {
            field: "payload SHA-256",
            expected: payload.sha256.to_owned(),
            actual,
        });
    }
    verify_elf(&path, architecture)
}

fn verify_elf(path: &Path, architecture: &str) -> Result<(), MaterializationError> {
    let mut file =
        File::open(path).map_err(|error| io_error("open staged payload", path, error))?;
    let mut header = [0_u8; 24];
    file.read_exact(&mut header)
        .map_err(|error| MaterializationError::InvalidElf {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
    if &header[..4] != b"\x7fELF" {
        return Err(invalid_elf(path, "ELF magic is missing"));
    }
    if header[4] != 2 || header[5] != 1 || header[6] != 1 {
        return Err(invalid_elf(
            path,
            "payload is not a 64-bit little-endian ELF version 1 file",
        ));
    }
    let elf_type = u16::from_le_bytes([header[16], header[17]]);
    if !matches!(elf_type, 2 | 3) {
        return Err(invalid_elf(
            path,
            "ELF type is not executable or position-independent executable",
        ));
    }
    let machine = u16::from_le_bytes([header[18], header[19]]);
    let expected = match architecture {
        "x86_64" => 62,
        "aarch64" => 183,
        other => {
            return Err(invalid_elf(
                path,
                &format!("unsupported locked architecture {other}"),
            ));
        }
    };
    if machine != expected {
        return Err(MaterializationError::PayloadMismatch {
            field: "ELF architecture",
            expected: architecture.to_owned(),
            actual: format!("machine {machine}"),
        });
    }
    Ok(())
}

fn invalid_elf(path: &Path, reason: &str) -> MaterializationError {
    MaterializationError::InvalidElf {
        path: path.to_path_buf(),
        reason: reason.to_owned(),
    }
}

fn hash_file(path: &Path) -> Result<String, MaterializationError> {
    let mut file = File::open(path).map_err(|error| io_error("open staged file", path, error))?;
    let mut digest = Sha256::new();
    io::copy(&mut file, &mut digest).map_err(|error| io_error("hash staged file", path, error))?;
    Ok(format!("{:x}", digest.finalize()))
}

fn write_manifest(
    root: &Path,
    manifest: &MaterializationManifest,
) -> Result<(), MaterializationError> {
    let path = root.join(MANIFEST_NAME);
    write_json_noclobber(root, &path, manifest)?;
    sync_directory(root)?;
    Ok(())
}

fn write_json_noclobber(
    directory: &Path,
    path: &Path,
    value: &impl Serialize,
) -> Result<(), MaterializationError> {
    let mut encoded = serde_json::to_vec_pretty(value)
        .map_err(|error| MaterializationError::Evidence(error.to_string()))?;
    encoded.push(b'\n');
    if encoded.len() > MAX_EVIDENCE_SIZE {
        return Err(MaterializationError::Evidence(format!(
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

fn validate_existing_stage(
    path: &Path,
    payload: LockedPayload<'_>,
    artifact: &LockedArtifact,
) -> Result<MaterializationManifest, MaterializationError> {
    let manifest_path = path.join(MANIFEST_NAME);
    let metadata = fs::symlink_metadata(&manifest_path)
        .map_err(|error| io_error("inspect materialization manifest", &manifest_path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(MaterializationError::CorruptStage {
            path: manifest_path,
            reason: "manifest is not a regular file".to_owned(),
        });
    }
    verify_mode(&manifest_path, &metadata, 0o600)?;
    if metadata.len() > MAX_EVIDENCE_SIZE as u64 {
        return Err(MaterializationError::CorruptStage {
            path: manifest_path,
            reason: "manifest is unexpectedly large".to_owned(),
        });
    }
    let encoded = fs::read(&manifest_path)
        .map_err(|error| io_error("read materialization manifest", &manifest_path, error))?;
    let manifest: MaterializationManifest = serde_json::from_slice(&encoded)
        .map_err(|error| MaterializationError::Evidence(error.to_string()))?;
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION
        || manifest.artifact_sha256 != artifact.sha256
        || manifest.payload_path != payload.path
        || manifest.payload_size != payload.size
        || manifest.payload_sha256 != payload.sha256
        || manifest.architecture != artifact.architecture
    {
        return Err(MaterializationError::CorruptStage {
            path: path.to_path_buf(),
            reason: "manifest identity does not match the locked artifact".to_owned(),
        });
    }
    let actual_entries = inspect_tree(path)?;
    if actual_entries != manifest.entries {
        return Err(MaterializationError::CorruptStage {
            path: path.to_path_buf(),
            reason: "staged files do not match their manifest".to_owned(),
        });
    }
    verify_payload(path, payload, &artifact.architecture)?;
    Ok(manifest)
}

fn persist_candidate(
    mut candidate: TempDir,
    staging_path: &Path,
    manifest: &MaterializationManifest,
    payload: LockedPayload<'_>,
    artifact: &LockedArtifact,
) -> Result<MaterializationOutcome, MaterializationError> {
    match fs::rename(candidate.path(), staging_path) {
        Ok(()) => {
            candidate.disable_cleanup(true);
            if let Some(parent) = staging_path.parent() {
                sync_directory(parent)?;
            }
            Ok(MaterializationOutcome::Materialized)
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::AlreadyExists | io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            let existing = validate_existing_stage(staging_path, payload, artifact)?;
            if &existing == manifest {
                Ok(MaterializationOutcome::StageHit)
            } else {
                Err(MaterializationError::CorruptStage {
                    path: staging_path.to_path_buf(),
                    reason: "concurrent staged tree does not match the reproduced locked artifact"
                        .to_owned(),
                })
            }
        }
        Err(error) => Err(io_error(
            "persist materialized staging tree",
            staging_path,
            error,
        )),
    }
}

fn io_error(action: &'static str, path: &Path, source: io::Error) -> MaterializationError {
    MaterializationError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use arsenallspice::{AcquisitionMethod, ArtifactFormat, DigestEvidence, LockedArtifact};
    use tar::{Builder as TarBuilder, EntryType, Header};
    use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

    use super::*;
    use crate::{AcquisitionStatus, ProvisionStatus};

    fn elf(machine: u16, marker: &[u8]) -> Vec<u8> {
        let mut body = vec![0_u8; 64];
        body[..4].copy_from_slice(b"\x7fELF");
        body[4] = 2;
        body[5] = 1;
        body[6] = 1;
        body[16..18].copy_from_slice(&3_u16.to_le_bytes());
        body[18..20].copy_from_slice(&machine.to_le_bytes());
        body.extend_from_slice(marker);
        body
    }

    fn sha256(body: &[u8]) -> String {
        format!("{:x}", Sha256::digest(body))
    }

    fn tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = TarBuilder::new(encoder);
        for (path, body) in entries {
            let mut header = Header::new_gnu();
            let name = path.as_bytes();
            assert!(name.len() < 100, "test tar path should fit in its header");
            header.as_mut_bytes()[..name.len()].copy_from_slice(name);
            header.set_size(body.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append(&header, *body)
                .expect("test tar entry should append");
        }
        let encoder = builder.into_inner().expect("test tar should finish");
        encoder.finish().expect("test gzip should finish")
    }

    fn tar_xz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let encoder = lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(1))
            .expect("test XZ encoder should initialize");
        let mut builder = TarBuilder::new(encoder);
        for (path, body) in entries {
            let mut header = Header::new_gnu();
            header.set_path(path).expect("test tar path should encode");
            header.set_size(body.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append(&header, *body)
                .expect("test tar entry should append");
        }
        let encoder = builder.into_inner().expect("test tar should finish");
        encoder.finish().expect("test XZ should finish")
    }

    fn tar_gz_with_declared_size(path: &str, size: u64) -> Vec<u8> {
        let mut header = Header::new_gnu();
        header.set_path(path).expect("test tar path should encode");
        header.set_size(size);
        header.set_mode(0o644);
        header.set_cksum();
        let mut raw = header.as_bytes().to_vec();
        raw.extend_from_slice(&[0_u8; 1024]);

        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(&raw)
            .expect("test tar header should compress");
        encoder.finish().expect("test gzip should finish")
    }

    fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        for (path, body) in entries {
            writer
                .start_file(*path, options)
                .expect("test ZIP entry should start");
            writer.write_all(body).expect("test ZIP body should write");
        }
        writer
            .finish()
            .expect("test ZIP should finish")
            .into_inner()
    }

    fn item(format: ArtifactFormat, object: &[u8], payload: &[u8]) -> AcquisitionItem {
        AcquisitionItem {
            id: "zellij".to_owned(),
            name: "Zellij".to_owned(),
            provision_status: ProvisionStatus::Missing,
            target_version: "0.44.3".to_owned(),
            destination: "~/.local/bin".to_owned(),
            status: AcquisitionStatus::LockedBinary,
            artifact: Some(LockedArtifact {
                tool_id: "zellij".to_owned(),
                version: "0.44.3".to_owned(),
                os: "linux".to_owned(),
                architecture: "x86_64".to_owned(),
                method: AcquisitionMethod::GithubRelease,
                format,
                name: "zellij.tar.gz".to_owned(),
                size: object.len() as u64,
                sha256: sha256(object),
                url: "https://example.invalid/zellij".to_owned(),
                evidence: DigestEvidence::GithubAssetDigest,
                payload_path: Some("bin/zellij".to_owned()),
                payload_size: Some(payload.len() as u64),
                payload_sha256: Some(sha256(payload)),
            }),
            detail: String::new(),
        }
    }

    fn cache_object(root: &Path, item: &AcquisitionItem, body: &[u8]) {
        let artifact = item.artifact.as_ref().expect("artifact should exist");
        let directory = root
            .join("cache/objects/sha256")
            .join(&artifact.sha256[..2]);
        fs::create_dir_all(&directory).expect("cache directory should exist");
        fs::write(directory.join(&artifact.sha256), body).expect("cache object should write");
    }

    #[test]
    fn materializes_a_locked_tar_payload_without_executable_permissions() {
        let root = tempfile::tempdir().expect("temporary root should exist");
        let payload = elf(62, b"zellij");
        let archive = tar_gz(&[("README.md", b"docs"), ("bin/zellij", &payload)]);
        let selected = item(ArtifactFormat::TarGz, &archive, &payload);
        cache_object(root.path(), &selected, &archive);

        let result = Materializer::new(root.path().join("cache"), root.path().join("state"))
            .materialize(&selected)
            .expect("valid archive should materialize");

        assert_eq!(result.receipt.outcome, MaterializationOutcome::Materialized);
        assert_eq!(
            fs::read(&result.payload_path).expect("payload should be readable"),
            payload
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&result.payload_path)
                    .expect("payload metadata should exist")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn a_stage_hit_is_reproduced_from_the_locked_object() {
        let root = tempfile::tempdir().expect("temporary root should exist");
        let payload = elf(62, b"zellij");
        let archive = tar_gz(&[("bin/zellij", &payload)]);
        let selected = item(ArtifactFormat::TarGz, &archive, &payload);
        cache_object(root.path(), &selected, &archive);
        let materializer = Materializer::new(root.path().join("cache"), root.path().join("state"));

        let first = materializer
            .materialize(&selected)
            .expect("first materialization should succeed");
        let second = materializer
            .materialize(&selected)
            .expect("reproduced stage should match");

        assert_eq!(second.receipt.outcome, MaterializationOutcome::StageHit);
        assert_ne!(first.receipt_path, second.receipt_path);
    }

    #[test]
    fn tampered_staging_fails_closed_even_if_its_manifest_is_unchanged() {
        let root = tempfile::tempdir().expect("temporary root should exist");
        let payload = elf(62, b"zellij");
        let archive = tar_gz(&[("bin/zellij", &payload)]);
        let selected = item(ArtifactFormat::TarGz, &archive, &payload);
        cache_object(root.path(), &selected, &archive);
        let materializer = Materializer::new(root.path().join("cache"), root.path().join("state"));
        let first = materializer
            .materialize(&selected)
            .expect("first materialization should succeed");
        fs::write(&first.payload_path, elf(62, b"tampered"))
            .expect("test should tamper with stage");

        assert!(matches!(
            materializer.materialize(&selected),
            Err(MaterializationError::CorruptStage { .. })
        ));
    }

    #[test]
    fn rejects_traversal_links_duplicates_and_wrong_payload_identity() {
        let root = tempfile::tempdir().expect("temporary root should exist");
        let payload = elf(62, b"zellij");

        let traversal = tar_gz(&[("../escape", b"nope"), ("bin/zellij", &payload)]);
        let selected = item(ArtifactFormat::TarGz, &traversal, &payload);
        cache_object(root.path(), &selected, &traversal);
        assert!(matches!(
            Materializer::new(root.path().join("cache"), root.path().join("state"))
                .materialize(&selected),
            Err(MaterializationError::UnsafeEntry { .. })
        ));
        let artifact = selected.artifact.as_ref().expect("artifact should exist");
        assert!(
            !root
                .path()
                .join("cache/staging/sha256")
                .join(&artifact.sha256[..2])
                .join("escape")
                .exists()
        );

        let mut archive = TarBuilder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        let mut link = Header::new_gnu();
        link.set_entry_type(EntryType::Symlink);
        link.set_size(0);
        link.set_mode(0o777);
        link.set_link_name("../../escape")
            .expect("link should encode");
        link.set_cksum();
        archive
            .append_data(&mut link, "bin/zellij", io::empty())
            .expect("symlink should append");
        let encoder = archive.into_inner().expect("tar should finish");
        let linked = encoder.finish().expect("gzip should finish");
        let selected = item(ArtifactFormat::TarGz, &linked, &payload);
        cache_object(root.path(), &selected, &linked);
        assert!(matches!(
            Materializer::new(root.path().join("cache"), root.path().join("state"))
                .materialize(&selected),
            Err(MaterializationError::UnsafeEntry { .. })
        ));

        let duplicate = tar_gz(&[("bin/zellij", &payload), ("bin/zellij", &payload)]);
        let selected = item(ArtifactFormat::TarGz, &duplicate, &payload);
        cache_object(root.path(), &selected, &duplicate);
        assert!(matches!(
            Materializer::new(root.path().join("cache"), root.path().join("state"))
                .materialize(&selected),
            Err(MaterializationError::UnsafeEntry { .. })
        ));

        let wrong = elf(62, b"wrong");
        let archive = tar_gz(&[("bin/zellij", &wrong)]);
        let selected = item(ArtifactFormat::TarGz, &archive, &payload);
        cache_object(root.path(), &selected, &archive);
        assert!(matches!(
            Materializer::new(root.path().join("cache"), root.path().join("state"))
                .materialize(&selected),
            Err(MaterializationError::PayloadMismatch { .. })
        ));
    }

    #[test]
    fn rejects_wrong_elf_architecture_and_source_archives() {
        let root = tempfile::tempdir().expect("temporary root should exist");
        let payload = elf(183, b"arm");
        let archive = tar_gz(&[("bin/zellij", &payload)]);
        let selected = item(ArtifactFormat::TarGz, &archive, &payload);
        cache_object(root.path(), &selected, &archive);
        assert!(matches!(
            Materializer::new(root.path().join("cache"), root.path().join("state"))
                .materialize(&selected),
            Err(MaterializationError::PayloadMismatch {
                field: "ELF architecture",
                ..
            })
        ));

        let mut source = item(ArtifactFormat::Crate, b"crate", b"unused");
        source
            .artifact
            .as_mut()
            .expect("artifact should exist")
            .method = AcquisitionMethod::CargoRegistry;
        assert!(matches!(
            Materializer::new(root.path().join("cache"), root.path().join("state"))
                .materialize(&source),
            Err(MaterializationError::SourceArtifact(_))
        ));
    }

    #[test]
    fn materializes_xz_zip_and_direct_binary_formats() {
        let xz_root = tempfile::tempdir().expect("temporary root should exist");
        let payload = elf(62, b"xz");
        let archive = tar_xz(&[("bin/zellij", &payload)]);
        let selected = item(ArtifactFormat::TarXz, &archive, &payload);
        cache_object(xz_root.path(), &selected, &archive);
        Materializer::new(xz_root.path().join("cache"), xz_root.path().join("state"))
            .materialize(&selected)
            .expect("XZ-compressed tar should materialize");

        let zip_root = tempfile::tempdir().expect("temporary root should exist");
        let payload = elf(62, b"zip");
        let archive = zip(&[("bin/zellij", &payload)]);
        let selected = item(ArtifactFormat::Zip, &archive, &payload);
        cache_object(zip_root.path(), &selected, &archive);
        Materializer::new(zip_root.path().join("cache"), zip_root.path().join("state"))
            .materialize(&selected)
            .expect("ZIP should materialize");

        let binary_root = tempfile::tempdir().expect("temporary root should exist");
        let mut selected = item(ArtifactFormat::Binary, &payload, &payload);
        let artifact = selected.artifact.as_mut().expect("artifact should exist");
        artifact.payload_path = Some("bin/zellij".to_owned());
        cache_object(binary_root.path(), &selected, &payload);
        Materializer::new(
            binary_root.path().join("cache"),
            binary_root.path().join("state"),
        )
        .materialize(&selected)
        .expect("direct binary should materialize");
    }

    #[test]
    fn missing_cache_is_reported_without_creating_a_stage() {
        let root = tempfile::tempdir().expect("temporary root should exist");
        let payload = elf(62, b"missing");
        let archive = tar_gz(&[("bin/zellij", &payload)]);
        let selected = item(ArtifactFormat::TarGz, &archive, &payload);

        assert!(matches!(
            Materializer::new(root.path().join("cache"), root.path().join("state"))
                .materialize(&selected),
            Err(MaterializationError::MissingCache { .. })
        ));
        assert!(!root.path().join("cache/staging").exists());
    }

    #[test]
    fn zip_traversal_is_rejected() {
        let root = tempfile::tempdir().expect("temporary root should exist");
        let payload = elf(62, b"zip");
        let archive = zip(&[("../escape", b"nope"), ("bin/zellij", &payload)]);
        let selected = item(ArtifactFormat::Zip, &archive, &payload);
        cache_object(root.path(), &selected, &archive);

        assert!(matches!(
            Materializer::new(root.path().join("cache"), root.path().join("state"))
                .materialize(&selected),
            Err(MaterializationError::UnsafeEntry { .. })
        ));
    }

    #[test]
    fn rejects_an_entry_that_declares_excessive_expansion() {
        let root = tempfile::tempdir().expect("temporary root should exist");
        let payload = elf(62, b"zellij");
        let archive = tar_gz_with_declared_size("oversized", MAX_ENTRY_SIZE + 1);
        let selected = item(ArtifactFormat::TarGz, &archive, &payload);
        cache_object(root.path(), &selected, &archive);

        assert!(matches!(
            Materializer::new(root.path().join("cache"), root.path().join("state"))
                .materialize(&selected),
            Err(MaterializationError::EntryTooLarge { .. })
        ));
    }
}
