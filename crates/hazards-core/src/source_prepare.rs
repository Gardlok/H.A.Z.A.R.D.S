use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use arsenallspice::{ArtifactFormat, CargoSourceLock, LockedArtifact};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::{Builder, TempDir};
use thiserror::Error;

use crate::{
    AcquisitionItem, AcquisitionStatus, HazardsPaths,
    acquire::{
        ensure_private_dir, ensure_private_subdirectories, set_private_file_permissions,
        sync_directory, validate_component, verify_cached_object,
    },
    source_build::inspect_source_archive,
};

const BUFFER_SIZE: usize = 64 * 1024;
const MANIFEST_NAME: &str = ".hazards-source-preparation.json";
const MANIFEST_SCHEMA_VERSION: u8 = 1;
const RECEIPT_SCHEMA_VERSION: u8 = 1;
const MAX_ARCHIVE_ENTRIES: usize = 100_000;
const MAX_EXPANDED_SIZE: u64 = 1024 * 1024 * 1024;
const MAX_ENTRY_SIZE: u64 = 512 * 1024 * 1024;
const MAX_PATH_LENGTH: usize = 4096;
const MAX_COMPONENT_LENGTH: usize = 255;
const MAX_EVIDENCE_SIZE: usize = 16 * 1024 * 1024;
static RECEIPT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Whether a verified source tree was created or reproduced and matched.
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

/// Append-only evidence for one verified source preparation.
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

/// Paths and evidence produced by a successful source preparation.
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
    entries: Vec<SourceEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct SourceEntry {
    path: String,
    kind: SourceEntryKind,
    size: u64,
    sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum SourceEntryKind {
    Directory,
    File,
}

/// Reproduces checksum-locked crate sources in inert private staging.
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
        let inspection = inspect_source_archive(&object_path, artifact, source_lock)
            .map_err(SourcePreparationError::Graph)?;
        let staging_parent = self.staging_parent(artifact)?;
        let staging_path = staging_parent.join(&artifact.sha256);
        let (candidate, manifest) = reproduce(
            item,
            artifact,
            source_lock,
            &object_path,
            &staging_parent,
            inspection.registry_packages,
            inspection.local_packages,
        )?;

        let outcome = match fs::symlink_metadata(&staging_path) {
            Ok(_) => {
                let existing = validate_existing_stage(&staging_path, artifact, source_lock)?;
                if existing != manifest {
                    return Err(SourcePreparationError::CorruptStage {
                        path: staging_path,
                        reason:
                            "prepared tree does not match a fresh reproduction from the locked object"
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
                    "inspect prepared source staging",
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
        validate_component("tool identifier", &item.id)?;
        validate_component("version", &item.target_version)?;
        let artifact = item
            .artifact
            .as_ref()
            .ok_or_else(|| SourcePreparationError::Unavailable(item.id.clone()))?;
        if item.status != AcquisitionStatus::LockedSource
            || artifact.format != ArtifactFormat::Crate
        {
            return Err(SourcePreparationError::NotSource(item.id.clone()));
        }
        let source_lock = artifact
            .source_lock
            .as_ref()
            .ok_or_else(|| SourcePreparationError::MissingSourceLock(item.id.clone()))?;
        validate_component("source root", &source_lock.root)?;
        if source_lock.root.len() > MAX_COMPONENT_LENGTH {
            return Err(SourcePreparationError::Graph(format!(
                "source root exceeds {MAX_COMPONENT_LENGTH} bytes"
            )));
        }
        let prefix = artifact.sha256.get(..2).ok_or_else(|| {
            SourcePreparationError::Graph("artifact digest has no two-byte prefix".to_owned())
        })?;
        let object_path = self
            .cache_root
            .join("objects")
            .join("sha256")
            .join(prefix)
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

    fn staging_parent(&self, artifact: &LockedArtifact) -> Result<PathBuf, SourcePreparationError> {
        let prefix = artifact.sha256.get(..2).ok_or_else(|| {
            SourcePreparationError::Graph("artifact digest has no two-byte prefix".to_owned())
        })?;
        Ok(ensure_private_subdirectories(
            &self.cache_root,
            &["sources", "sha256", prefix],
        )?)
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
                .filter(|entry| entry.kind == SourceEntryKind::File)
                .map(|entry| entry.size)
                .sum(),
            outcome,
            verified_at_unix: verified_at.as_secs(),
        };
        let receipt_path = self.write_receipt(&receipt)?;

        Ok(PreparedSource {
            source_path: staging_path.join(&source_lock.root),
            manifest_path: staging_path.join(MANIFEST_NAME),
            staging_path,
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
    NotSource(String),
    #[error("source artifact for {0} has no embedded Cargo lock identity")]
    MissingSourceLock(String),
    #[error("verified source object for {tool} is missing at {path}; acquire it first")]
    MissingCache { tool: String, path: PathBuf },
    #[error("source dependency graph failed verification: {0}")]
    Graph(String),
    #[error("unsafe source entry {entry}: {reason}")]
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
    #[error("source identity mismatch for {field}: expected {expected}, found {actual}")]
    IdentityMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    #[error("prepared source tree failed verification at {path}: {reason}")]
    CorruptStage { path: PathBuf, reason: String },
    #[error("could not process source container: {0}")]
    Archive(String),
    #[error("{action} at {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not serialize or parse source preparation evidence: {0}")]
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
    registry_packages: usize,
    local_packages: usize,
) -> Result<(TempDir, SourcePreparationManifest), SourcePreparationError> {
    let candidate = Builder::new()
        .prefix(".prepare-source-")
        .tempdir_in(staging_parent)
        .map_err(|error| {
            io_error(
                "create temporary source staging directory",
                staging_parent,
                error,
            )
        })?;
    ensure_private_dir(candidate.path())?;

    extract_source_archive(artifact, source_lock, object_path, candidate.path())?;
    let entries = inspect_tree(candidate.path())?;
    verify_source_identity(candidate.path(), source_lock)?;
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
        registry_package_count: registry_packages,
        local_package_count: local_packages,
        entries,
    };
    write_manifest(candidate.path(), &manifest)?;
    Ok((candidate, manifest))
}

fn extract_source_archive(
    artifact: &LockedArtifact,
    source_lock: &CargoSourceLock,
    object_path: &Path,
    destination: &Path,
) -> Result<(), SourcePreparationError> {
    let object = File::open(object_path)
        .map_err(|error| io_error("open verified source object", object_path, error))?;
    let metadata = object
        .metadata()
        .map_err(|error| io_error("inspect opened source object", object_path, error))?;
    if !metadata.is_file() || metadata.len() != artifact.size {
        return Err(SourcePreparationError::IdentityMismatch {
            field: "archive size",
            expected: artifact.size.to_string(),
            actual: metadata.len().to_string(),
        });
    }

    let mut hashing = HashingReader::new(object);
    {
        let decoder = GzDecoder::new(&mut hashing);
        let mut archive = tar::Archive::new(decoder);
        let entries = archive
            .entries()
            .map_err(|error| SourcePreparationError::Archive(error.to_string()))?;
        let mut seen = HashSet::new();
        let mut entry_count = 0_usize;
        let mut expanded = 0_u64;

        for result in entries {
            let mut entry =
                result.map_err(|error| SourcePreparationError::Archive(error.to_string()))?;
            entry_count =
                entry_count
                    .checked_add(1)
                    .ok_or(SourcePreparationError::TooManyEntries {
                        maximum: MAX_ARCHIVE_ENTRIES,
                    })?;
            if entry_count > MAX_ARCHIVE_ENTRIES {
                return Err(SourcePreparationError::TooManyEntries {
                    maximum: MAX_ARCHIVE_ENTRIES,
                });
            }

            let original = entry
                .path()
                .map_err(|error| SourcePreparationError::Archive(error.to_string()))?
                .into_owned();
            let relative = strict_source_path(&original, &source_lock.root)?;
            let display = relative_path_text(&relative)?;
            if !seen.insert(display.clone()) {
                return Err(SourcePreparationError::UnsafeEntry {
                    entry: display,
                    reason: "duplicate archive path".to_owned(),
                });
            }
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
                output.sync_all().map_err(|error| {
                    io_error("synchronize prepared source file", &target, error)
                })?;
            } else {
                return Err(SourcePreparationError::UnsafeEntry {
                    entry: display,
                    reason: format!(
                        "tar entry type {:?} is not a regular file or directory",
                        entry_type.as_byte()
                    ),
                });
            }
        }

        let mut decoder = archive.into_inner();
        io::copy(&mut decoder, &mut io::sink())
            .map_err(|error| SourcePreparationError::Archive(error.to_string()))?;
    }
    let (actual_size, actual_sha256) = hashing.finish();
    if actual_size != artifact.size {
        return Err(SourcePreparationError::IdentityMismatch {
            field: "archive size",
            expected: artifact.size.to_string(),
            actual: actual_size.to_string(),
        });
    }
    if actual_sha256 != artifact.sha256 {
        return Err(SourcePreparationError::IdentityMismatch {
            field: "archive SHA-256",
            expected: artifact.sha256.clone(),
            actual: actual_sha256,
        });
    }
    Ok(())
}

struct HashingReader<R> {
    inner: R,
    digest: Sha256,
    size: u64,
}

impl<R> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            digest: Sha256::new(),
            size: 0,
        }
    }

    fn finish(self) -> (u64, String) {
        (self.size, format!("{:x}", self.digest.finalize()))
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.size = self
            .size
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("source object size overflowed"))?;
        self.digest.update(&buffer[..read]);
        Ok(read)
    }
}

fn strict_source_path(path: &Path, source_root: &str) -> Result<PathBuf, SourcePreparationError> {
    let text = path
        .to_str()
        .ok_or_else(|| SourcePreparationError::UnsafeEntry {
            entry: path.to_string_lossy().into_owned(),
            reason: "path is not valid UTF-8".to_owned(),
        })?;
    if text.is_empty() || text.len() > MAX_PATH_LENGTH || text.contains('\\') {
        return Err(SourcePreparationError::UnsafeEntry {
            entry: text.to_owned(),
            reason: "path is empty, too long, or contains a backslash".to_owned(),
        });
    }
    let mut components = path.components();
    let first = components
        .next()
        .ok_or_else(|| SourcePreparationError::UnsafeEntry {
            entry: text.to_owned(),
            reason: "path is empty".to_owned(),
        })?;
    if first != Component::Normal(source_root.as_ref()) {
        return Err(SourcePreparationError::UnsafeEntry {
            entry: text.to_owned(),
            reason: format!("path escapes locked source root {source_root}"),
        });
    }

    let mut relative = PathBuf::from(source_root);
    for component in components {
        match component {
            Component::Normal(value) if value.as_encoded_bytes().len() <= MAX_COMPONENT_LENGTH => {
                relative.push(value);
            }
            _ => {
                return Err(SourcePreparationError::UnsafeEntry {
                    entry: text.to_owned(),
                    reason: "only bounded normal relative path components are accepted".to_owned(),
                });
            }
        }
    }
    Ok(relative)
}

fn relative_path_text(path: &Path) -> Result<String, SourcePreparationError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| SourcePreparationError::UnsafeEntry {
            entry: path.to_string_lossy().into_owned(),
            reason: "path is not valid UTF-8".to_owned(),
        })
}

fn validate_declared_size(
    entry: &str,
    declared: u64,
    expanded: u64,
) -> Result<(), SourcePreparationError> {
    if declared > MAX_ENTRY_SIZE {
        return Err(SourcePreparationError::EntryTooLarge {
            entry: entry.to_owned(),
            actual: declared,
            maximum: MAX_ENTRY_SIZE,
        });
    }
    if expanded
        .checked_add(declared)
        .is_none_or(|total| total > MAX_EXPANDED_SIZE)
    {
        return Err(SourcePreparationError::ExpandedTooLarge {
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
) -> Result<(), SourcePreparationError> {
    let mut buffer = [0_u8; BUFFER_SIZE];
    let mut actual = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| io_error("read source archive entry", Path::new(entry), error))?;
        if read == 0 {
            break;
        }
        actual = actual
            .checked_add(read as u64)
            .ok_or(SourcePreparationError::EntryTooLarge {
                entry: entry.to_owned(),
                actual: u64::MAX,
                maximum: MAX_ENTRY_SIZE,
            })?;
        if actual > declared || actual > MAX_ENTRY_SIZE {
            return Err(SourcePreparationError::EntryTooLarge {
                entry: entry.to_owned(),
                actual,
                maximum: declared.min(MAX_ENTRY_SIZE),
            });
        }
        *expanded =
            expanded
                .checked_add(read as u64)
                .ok_or(SourcePreparationError::ExpandedTooLarge {
                    maximum: MAX_EXPANDED_SIZE,
                })?;
        if *expanded > MAX_EXPANDED_SIZE {
            return Err(SourcePreparationError::ExpandedTooLarge {
                maximum: MAX_EXPANDED_SIZE,
            });
        }
        writer
            .write_all(&buffer[..read])
            .map_err(|error| io_error("write prepared source file", Path::new(entry), error))?;
    }
    if actual != declared {
        return Err(SourcePreparationError::IdentityMismatch {
            field: "archive entry size",
            expected: declared.to_string(),
            actual: actual.to_string(),
        });
    }
    Ok(())
}

fn ensure_parent_directories(root: &Path, relative: &Path) -> Result<(), SourcePreparationError> {
    if let Some(parent) = relative.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_directory(root, parent)?;
        }
    }
    Ok(())
}

fn ensure_directory(root: &Path, relative: &Path) -> Result<(), SourcePreparationError> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(value) = component else {
            return Err(SourcePreparationError::UnsafeEntry {
                entry: relative.to_string_lossy().into_owned(),
                reason: "directory path contains a non-normal component".to_owned(),
            });
        };
        current.push(value);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(SourcePreparationError::UnsafeEntry {
                    entry: relative.to_string_lossy().into_owned(),
                    reason: "directory path collides with a non-directory".to_owned(),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|error| {
                    io_error("create prepared source directory", &current, error)
                })?;
            }
            Err(error) => {
                return Err(io_error(
                    "inspect prepared source directory",
                    &current,
                    error,
                ));
            }
        }
        set_directory_mode(&current)?;
    }
    Ok(())
}

fn create_private_file(path: &Path) -> Result<File, SourcePreparationError> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| io_error("create prepared source file", path, error))?;
    set_private_file_permissions(&file, path)?;
    Ok(file)
}

fn set_directory_mode(path: &Path) -> Result<(), SourcePreparationError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| io_error("set prepared source directory permissions", path, error))?;
    }
    Ok(())
}

fn inspect_tree(root: &Path) -> Result<Vec<SourceEntry>, SourcePreparationError> {
    let root_metadata = fs::symlink_metadata(root)
        .map_err(|error| io_error("inspect source staging root", root, error))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(SourcePreparationError::CorruptStage {
            path: root.to_path_buf(),
            reason: "source staging root is not a real directory".to_owned(),
        });
    }
    verify_mode(root, &root_metadata, 0o700)?;

    let mut entries = Vec::new();
    inspect_directory(root, root, &mut entries)?;
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    if entries.len() > MAX_ARCHIVE_ENTRIES {
        return Err(SourcePreparationError::TooManyEntries {
            maximum: MAX_ARCHIVE_ENTRIES,
        });
    }
    let total = entries
        .iter()
        .filter(|entry| entry.kind == SourceEntryKind::File)
        .try_fold(0_u64, |total, entry| total.checked_add(entry.size))
        .ok_or(SourcePreparationError::ExpandedTooLarge {
            maximum: MAX_EXPANDED_SIZE,
        })?;
    if total > MAX_EXPANDED_SIZE {
        return Err(SourcePreparationError::ExpandedTooLarge {
            maximum: MAX_EXPANDED_SIZE,
        });
    }
    Ok(entries)
}

fn inspect_directory(
    root: &Path,
    directory: &Path,
    entries: &mut Vec<SourceEntry>,
) -> Result<(), SourcePreparationError> {
    for result in fs::read_dir(directory)
        .map_err(|error| io_error("read prepared source directory", directory, error))?
    {
        let entry =
            result.map_err(|error| io_error("read prepared source entry", directory, error))?;
        let path = entry.path();
        if path == root.join(MANIFEST_NAME) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| io_error("inspect prepared source entry", &path, error))?;
        let relative = path
            .strip_prefix(root)
            .map_err(|error| SourcePreparationError::Evidence(error.to_string()))?;
        let display = relative_path_text(relative)?;

        if metadata.file_type().is_symlink() {
            return Err(SourcePreparationError::CorruptStage {
                path,
                reason: "symbolic links are not accepted".to_owned(),
            });
        }
        if metadata.is_dir() {
            verify_mode(&path, &metadata, 0o700)?;
            entries.push(SourceEntry {
                path: display,
                kind: SourceEntryKind::Directory,
                size: 0,
                sha256: None,
            });
            inspect_directory(root, &path, entries)?;
        } else if metadata.is_file() {
            verify_mode(&path, &metadata, 0o600)?;
            entries.push(SourceEntry {
                path: display,
                kind: SourceEntryKind::File,
                size: metadata.len(),
                sha256: Some(hash_file(&path)?),
            });
        } else {
            return Err(SourcePreparationError::CorruptStage {
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
) -> Result<(), SourcePreparationError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let actual = metadata.permissions().mode() & 0o777;
        if actual != expected {
            return Err(SourcePreparationError::CorruptStage {
                path: path.to_path_buf(),
                reason: format!("expected mode {expected:o}, found {actual:o}"),
            });
        }
    }
    Ok(())
}

fn verify_source_identity(
    root: &Path,
    source_lock: &CargoSourceLock,
) -> Result<(), SourcePreparationError> {
    let source_path = root.join(&source_lock.root);
    let metadata = fs::symlink_metadata(&source_path)
        .map_err(|error| io_error("inspect prepared source root", &source_path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SourcePreparationError::CorruptStage {
            path: source_path,
            reason: "locked source root is not a real directory".to_owned(),
        });
    }
    for (label, relative, expected) in [
        (
            "Cargo.toml SHA-256",
            Path::new("Cargo.toml"),
            source_lock.manifest_sha256.as_str(),
        ),
        (
            "Cargo.lock SHA-256",
            Path::new("Cargo.lock"),
            source_lock.cargo_lock_sha256.as_str(),
        ),
    ] {
        let path = source_path.join(relative);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| io_error("inspect prepared Cargo metadata", &path, error))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(SourcePreparationError::CorruptStage {
                path,
                reason: "locked Cargo metadata is not a regular file".to_owned(),
            });
        }
        let actual = hash_file(&path)?;
        if actual != expected {
            return Err(SourcePreparationError::IdentityMismatch {
                field: label,
                expected: expected.to_owned(),
                actual,
            });
        }
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<String, SourcePreparationError> {
    let mut file =
        File::open(path).map_err(|error| io_error("open prepared source file", path, error))?;
    let mut digest = Sha256::new();
    io::copy(&mut file, &mut digest)
        .map_err(|error| io_error("hash prepared source file", path, error))?;
    Ok(format!("{:x}", digest.finalize()))
}

fn write_manifest(
    root: &Path,
    manifest: &SourcePreparationManifest,
) -> Result<(), SourcePreparationError> {
    let path = root.join(MANIFEST_NAME);
    write_json_noclobber(root, &path, manifest)?;
    sync_directory(root)?;
    Ok(())
}

fn write_json_noclobber(
    directory: &Path,
    path: &Path,
    value: &impl Serialize,
) -> Result<(), SourcePreparationError> {
    let mut encoded = serde_json::to_vec_pretty(value)
        .map_err(|error| SourcePreparationError::Evidence(error.to_string()))?;
    encoded.push(b'\n');
    if encoded.len() > MAX_EVIDENCE_SIZE {
        return Err(SourcePreparationError::Evidence(format!(
            "serialized evidence is {} bytes; limit is {}",
            encoded.len(),
            MAX_EVIDENCE_SIZE
        )));
    }
    let mut temporary = tempfile::NamedTempFile::new_in(directory)
        .map_err(|error| io_error("create temporary source evidence", directory, error))?;
    temporary
        .write_all(&encoded)
        .map_err(|error| io_error("write source evidence", temporary.path(), error))?;
    temporary
        .as_file_mut()
        .sync_all()
        .map_err(|error| io_error("synchronize source evidence", temporary.path(), error))?;
    let file = temporary
        .persist_noclobber(path)
        .map_err(|error| io_error("persist source evidence", path, error.error))?;
    set_private_file_permissions(&file, path)?;
    sync_directory(directory)?;
    Ok(())
}

fn validate_existing_stage(
    path: &Path,
    artifact: &LockedArtifact,
    source_lock: &CargoSourceLock,
) -> Result<SourcePreparationManifest, SourcePreparationError> {
    let root_metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect prepared source root", path, error))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(SourcePreparationError::CorruptStage {
            path: path.to_path_buf(),
            reason: "prepared source root is not a real directory".to_owned(),
        });
    }
    verify_mode(path, &root_metadata, 0o700)?;

    let manifest_path = path.join(MANIFEST_NAME);
    let metadata = fs::symlink_metadata(&manifest_path)
        .map_err(|error| io_error("inspect source preparation manifest", &manifest_path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SourcePreparationError::CorruptStage {
            path: manifest_path,
            reason: "manifest is not a regular file".to_owned(),
        });
    }
    verify_mode(&manifest_path, &metadata, 0o600)?;
    if metadata.len() > MAX_EVIDENCE_SIZE as u64 {
        return Err(SourcePreparationError::CorruptStage {
            path: manifest_path,
            reason: "manifest is unexpectedly large".to_owned(),
        });
    }
    let encoded = fs::read(&manifest_path)
        .map_err(|error| io_error("read source preparation manifest", &manifest_path, error))?;
    let manifest: SourcePreparationManifest = serde_json::from_slice(&encoded)
        .map_err(|error| SourcePreparationError::Evidence(error.to_string()))?;
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION
        || manifest.artifact_sha256 != artifact.sha256
        || manifest.source_root != source_lock.root
        || manifest.manifest_sha256 != source_lock.manifest_sha256
        || manifest.cargo_lock_sha256 != source_lock.cargo_lock_sha256
        || manifest.cargo_lock_version != source_lock.cargo_lock_version
        || manifest.package_count != source_lock.package_count
    {
        return Err(SourcePreparationError::CorruptStage {
            path: path.to_path_buf(),
            reason: "manifest identity does not match the locked source artifact".to_owned(),
        });
    }
    let actual_entries = inspect_tree(path)?;
    if actual_entries != manifest.entries {
        return Err(SourcePreparationError::CorruptStage {
            path: path.to_path_buf(),
            reason: "prepared source files do not match their manifest".to_owned(),
        });
    }
    verify_source_identity(path, source_lock)?;
    Ok(manifest)
}

fn persist_candidate(
    mut candidate: TempDir,
    staging_path: &Path,
    manifest: &SourcePreparationManifest,
    artifact: &LockedArtifact,
    source_lock: &CargoSourceLock,
) -> Result<SourcePreparationOutcome, SourcePreparationError> {
    match fs::rename(candidate.path(), staging_path) {
        Ok(()) => {
            candidate.disable_cleanup(true);
            if let Some(parent) = staging_path.parent() {
                sync_directory(parent)?;
            }
            Ok(SourcePreparationOutcome::Prepared)
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::AlreadyExists | io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            let existing = validate_existing_stage(staging_path, artifact, source_lock)?;
            if &existing == manifest {
                Ok(SourcePreparationOutcome::StageHit)
            } else {
                Err(SourcePreparationError::CorruptStage {
                    path: staging_path.to_path_buf(),
                    reason: "concurrent source tree does not match the reproduced locked artifact"
                        .to_owned(),
                })
            }
        }
        Err(error) => Err(io_error(
            "persist prepared source tree",
            staging_path,
            error,
        )),
    }
}

fn io_error(action: &'static str, path: &Path, source: io::Error) -> SourcePreparationError {
    SourcePreparationError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use arsenallspice::{AcquisitionMethod, DigestEvidence};
    use flate2::{Compression, write::GzEncoder};
    use tar::{Builder as TarBuilder, EntryType, Header};
    use tempfile::TempDir;

    use super::*;
    use crate::ProvisionStatus;

    const REGISTRY: &str = "registry+https://github.com/rust-lang/crates.io-index";
    const CHECKSUM: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn cargo_lock(source: &str) -> String {
        format!(
            "version = 4\n\n[[package]]\nname = \"demo\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"{source}\"\nchecksum = \"{CHECKSUM}\"\n"
        )
    }

    fn archive(cargo_lock: &str, special: bool) -> (Vec<u8>, Vec<u8>) {
        let manifest = b"[package]\nname = \"demo\"\nversion = \"1.0.0\"\n".to_vec();
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = TarBuilder::new(encoder);
        for (path, bytes) in [
            ("demo-1.0.0/Cargo.toml", manifest.as_slice()),
            ("demo-1.0.0/Cargo.lock", cargo_lock.as_bytes()),
            ("demo-1.0.0/src/main.rs", b"fn main() {}\n".as_slice()),
        ] {
            let mut header = Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, path, Cursor::new(bytes))
                .expect("fixture entry should append");
        }
        if special {
            let mut header = Header::new_gnu();
            header.set_entry_type(EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            header
                .set_link_name("../../escape")
                .expect("fixture link should encode");
            header.set_cksum();
            builder
                .append_data(
                    &mut header,
                    "demo-1.0.0/escape",
                    Cursor::new(Vec::<u8>::new()),
                )
                .expect("fixture link should append");
        }
        let encoder = builder.into_inner().expect("fixture TAR should finish");
        (
            encoder.finish().expect("fixture GZip should finish"),
            manifest,
        )
    }

    fn fixture_item(cargo_lock: &str, special: bool) -> (AcquisitionItem, Vec<u8>) {
        let (archive, manifest) = archive(cargo_lock, special);
        let artifact_sha256 = sha256(&archive);
        (
            AcquisitionItem {
                id: "demo".to_owned(),
                name: "Demo".to_owned(),
                provision_status: ProvisionStatus::Missing,
                target_version: "1.0.0".to_owned(),
                destination: "~/.local/bin".to_owned(),
                status: AcquisitionStatus::LockedSource,
                artifact: Some(LockedArtifact {
                    tool_id: "demo".to_owned(),
                    version: "1.0.0".to_owned(),
                    os: "linux".to_owned(),
                    architecture: "*".to_owned(),
                    method: AcquisitionMethod::CargoRegistry,
                    format: ArtifactFormat::Crate,
                    name: "demo-1.0.0.crate".to_owned(),
                    size: archive.len() as u64,
                    sha256: artifact_sha256,
                    url: "https://crates.io/api/v1/crates/demo/1.0.0/download".to_owned(),
                    evidence: DigestEvidence::CratesIoChecksum,
                    payload_path: None,
                    payload_size: None,
                    payload_sha256: None,
                    source_lock: Some(CargoSourceLock {
                        root: "demo-1.0.0".to_owned(),
                        package: "demo".to_owned(),
                        manifest_sha256: sha256(&manifest),
                        cargo_lock_sha256: sha256(cargo_lock.as_bytes()),
                        cargo_lock_version: 4,
                        package_count: 2,
                    }),
                }),
                detail: String::new(),
            },
            archive,
        )
    }

    fn roots(root: &TempDir) -> (PathBuf, PathBuf) {
        (root.path().join("cache"), root.path().join("state"))
    }

    fn persist_object(root: &TempDir, item: &AcquisitionItem, archive: &[u8]) -> PathBuf {
        let (cache, _) = roots(root);
        let artifact = item.artifact.as_ref().expect("fixture artifact");
        let path = cache
            .join("objects")
            .join("sha256")
            .join(&artifact.sha256[..2])
            .join(&artifact.sha256);
        fs::create_dir_all(path.parent().expect("object parent")).expect("object parent");
        fs::write(&path, archive).expect("fixture object");
        path
    }

    fn preparer(root: &TempDir) -> SourcePreparer {
        let (cache, state) = roots(root);
        SourcePreparer::new(cache, state)
    }

    fn sha256(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    #[test]
    fn prepares_a_private_non_executable_checksum_locked_source_tree() {
        let lock = cargo_lock(REGISTRY);
        let (item, archive) = fixture_item(&lock, false);
        let root = tempfile::tempdir().expect("fixture root");
        persist_object(&root, &item, &archive);

        let prepared = preparer(&root).prepare(&item).expect("source preparation");

        assert_eq!(prepared.receipt.outcome, SourcePreparationOutcome::Prepared);
        assert_eq!(prepared.receipt.package_count, 2);
        assert_eq!(prepared.receipt.registry_package_count, 1);
        assert_eq!(prepared.receipt.local_package_count, 1);
        assert_eq!(
            fs::read_to_string(prepared.source_path.join("src/main.rs")).expect("prepared source"),
            "fn main() {}\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(prepared.source_path.join("src/main.rs"))
                .expect("source metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn a_fresh_reproduction_produces_an_idempotent_stage_hit() {
        let lock = cargo_lock(REGISTRY);
        let (item, archive) = fixture_item(&lock, false);
        let root = tempfile::tempdir().expect("fixture root");
        persist_object(&root, &item, &archive);
        let preparer = preparer(&root);

        let first = preparer.prepare(&item).expect("first preparation");
        let second = preparer.prepare(&item).expect("second preparation");

        assert_eq!(first.staging_path, second.staging_path);
        assert_eq!(second.receipt.outcome, SourcePreparationOutcome::StageHit);
    }

    #[test]
    fn a_tampered_prepared_tree_fails_closed() {
        let lock = cargo_lock(REGISTRY);
        let (item, archive) = fixture_item(&lock, false);
        let root = tempfile::tempdir().expect("fixture root");
        persist_object(&root, &item, &archive);
        let preparer = preparer(&root);
        let prepared = preparer.prepare(&item).expect("source preparation");
        fs::write(prepared.source_path.join("src/main.rs"), "tampered\n").expect("tamper fixture");

        let error = preparer
            .prepare(&item)
            .expect_err("tampered source must fail");

        assert!(matches!(error, SourcePreparationError::CorruptStage { .. }));
    }

    #[test]
    fn links_are_rejected_before_a_source_tree_is_persisted() {
        let lock = cargo_lock(REGISTRY);
        let (item, archive) = fixture_item(&lock, true);
        let root = tempfile::tempdir().expect("fixture root");
        persist_object(&root, &item, &archive);

        let error = preparer(&root)
            .prepare(&item)
            .expect_err("link must fail closed");

        assert!(matches!(error, SourcePreparationError::Graph(_)));
        let (cache, _) = roots(&root);
        assert!(!cache.join("sources").exists());
    }

    #[test]
    fn unapproved_dependency_sources_are_rejected_before_preparation() {
        let lock = cargo_lock("git+https://example.invalid/repository");
        let (item, archive) = fixture_item(&lock, false);
        let root = tempfile::tempdir().expect("fixture root");
        persist_object(&root, &item, &archive);

        let error = preparer(&root)
            .prepare(&item)
            .expect_err("Git dependency must fail closed");

        assert!(matches!(error, SourcePreparationError::Graph(_)));
        let (cache, _) = roots(&root);
        assert!(!cache.join("sources").exists());
    }

    #[test]
    fn a_corrupt_cache_object_never_creates_source_staging() {
        let lock = cargo_lock(REGISTRY);
        let (item, archive) = fixture_item(&lock, false);
        let root = tempfile::tempdir().expect("fixture root");
        let object = persist_object(&root, &item, &archive);
        fs::write(&object, vec![0_u8; archive.len()]).expect("corrupt fixture object");

        let error = preparer(&root)
            .prepare(&item)
            .expect_err("corrupt object must fail");

        assert!(matches!(error, SourcePreparationError::Cache(_)));
        let (cache, _) = roots(&root);
        assert!(!cache.join("sources").exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_final_stage_is_rejected_without_following_it() {
        use std::os::unix::fs::symlink;

        let lock = cargo_lock(REGISTRY);
        let (item, archive) = fixture_item(&lock, false);
        let root = tempfile::tempdir().expect("fixture root");
        persist_object(&root, &item, &archive);
        let artifact = item.artifact.as_ref().expect("fixture artifact");
        let (cache, _) = roots(&root);
        let stage_parent = cache
            .join("sources")
            .join("sha256")
            .join(&artifact.sha256[..2]);
        fs::create_dir_all(&stage_parent).expect("stage parent");
        let outside = root.path().join("outside");
        fs::create_dir(&outside).expect("outside directory");
        symlink(&outside, stage_parent.join(&artifact.sha256)).expect("fixture symlink");

        let error = preparer(&root)
            .prepare(&item)
            .expect_err("symlinked stage must fail closed");

        assert!(matches!(error, SourcePreparationError::CorruptStage { .. }));
        assert!(
            fs::read_dir(&outside)
                .expect("outside directory")
                .next()
                .is_none()
        );
    }
}
