use std::{
    collections::HashSet,
    error::Error as StdError,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use arsenallspice::{
    AcquisitionMethod, ArtifactFormat, CargoSourceLock, DigestEvidence, LockedArtifact,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use thiserror::Error;
use ureq::{
    Agent,
    tls::{RootCerts, TlsConfig},
};

use crate::{
    AcquisitionItem, AcquisitionStatus, HazardsPaths, SourcePreparationOutcome, SourcePreparer,
    acquire::{
        ensure_private_subdirectories, set_private_file_permissions, sync_directory,
    },
};

const BUFFER_SIZE: usize = 64 * 1024;
const MAX_CRATE_SIZE: u64 = 512 * 1024 * 1024;
const MAX_LOCK_SIZE: u64 = 16 * 1024 * 1024;
const MAX_EVIDENCE_SIZE: u64 = 16 * 1024 * 1024;
const MAX_REDIRECTS: u32 = 0;
const MANIFEST_SCHEMA_VERSION: u8 = 1;
const RECEIPT_SCHEMA_VERSION: u8 = 1;
const CRATES_IO_REGISTRY: &str = "registry+https://github.com/rust-lang/crates.io-index";
static RECEIPT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// One exact crates.io package required by a locked Cargo graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CargoDependencySpec {
    pub name: String,
    pub version: String,
    pub checksum: String,
    pub source_url: String,
}

/// Whether one checksum-addressed crate archive was downloaded or already cached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CargoDependencyOutcome {
    Downloaded,
    CacheHit,
}

impl std::fmt::Display for CargoDependencyOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Downloaded => formatter.write_str("downloaded"),
            Self::CacheHit => formatter.write_str("cache-hit"),
        }
    }
}

/// Whether a complete dependency graph populated new objects or matched the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CargoDependencyCacheOutcome {
    Populated,
    CacheHit,
}

impl std::fmt::Display for CargoDependencyCacheOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Populated => formatter.write_str("populated"),
            Self::CacheHit => formatter.write_str("cache-hit"),
        }
    }
}

/// One verified crate archive in the HAZARDS-owned dependency object cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CachedCargoDependency {
    pub name: String,
    pub version: String,
    pub checksum: String,
    pub source_url: String,
    pub size: u64,
    pub object_path: PathBuf,
    pub outcome: CargoDependencyOutcome,
}

/// Append-only evidence for one complete dependency-cache operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CargoDependencyReceipt {
    pub schema_version: u8,
    pub receipt_id: String,
    pub tool_id: String,
    pub version: String,
    pub artifact_sha256: String,
    pub cargo_lock_sha256: String,
    pub dependency_count: usize,
    pub downloaded_count: usize,
    pub cache_hit_count: usize,
    pub total_bytes: u64,
    pub manifest_sha256: String,
    pub outcome: CargoDependencyCacheOutcome,
    pub verified_at_unix: u64,
}

/// Paths and evidence produced by a complete checksum-verified dependency cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CachedCargoDependencies {
    pub object_root: PathBuf,
    pub manifest_path: PathBuf,
    pub receipt_path: PathBuf,
    pub packages: Vec<CachedCargoDependency>,
    pub receipt: CargoDependencyReceipt,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct CargoDependencyManifest {
    schema_version: u8,
    tool_id: String,
    version: String,
    artifact_sha256: String,
    cargo_lock_sha256: String,
    cargo_lock_version: u32,
    package_count: usize,
    dependency_count: usize,
    packages: Vec<CargoDependencyManifestEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
struct CargoDependencyManifestEntry {
    name: String,
    version: String,
    checksum: String,
    source_url: String,
    size: u64,
}

/// A bounded response body supplied by a crate archive source.
pub struct CargoDependencyPayload {
    pub content_length: Option<u64>,
    pub reader: Box<dyn Read + Send>,
}

impl CargoDependencyPayload {
    pub fn new(content_length: Option<u64>, reader: impl Read + Send + 'static) -> Self {
        Self {
            content_length,
            reader: Box::new(reader),
        }
    }
}

/// Retrieves exact crate archives without invoking Cargo or extracting source.
pub trait CargoDependencySource {
    fn open(
        &self,
        dependency: &CargoDependencySpec,
    ) -> Result<CargoDependencyPayload, CargoDependencyError>;
}

/// HTTPS-only crates.io source with redirects disabled and response decompression avoided.
pub struct HttpCargoDependencySource {
    agent: Agent,
}

impl HttpCargoDependencySource {
    pub fn new() -> Result<Self, CargoDependencyError> {
        let agent = Agent::config_builder()
            .http_status_as_error(false)
            .https_only(true)
            .max_redirects(MAX_REDIRECTS)
            .max_redirects_will_error(true)
            .timeout_connect(Some(Duration::from_secs(15)))
            .timeout_global(Some(Duration::from_secs(300)))
            .user_agent(concat!("hazards/", env!("CARGO_PKG_VERSION")))
            .tls_config(
                TlsConfig::builder()
                    .root_certs(RootCerts::PlatformVerifier)
                    .build(),
            )
            .build()
            .new_agent();

        Ok(Self { agent })
    }
}

impl CargoDependencySource for HttpCargoDependencySource {
    fn open(
        &self,
        dependency: &CargoDependencySpec,
    ) -> Result<CargoDependencyPayload, CargoDependencyError> {
        if !dependency.source_url.starts_with("https://static.crates.io/crates/") {
            return Err(CargoDependencyError::UnsafeUrl(
                dependency.source_url.clone(),
            ));
        }

        let response = self
            .agent
            .get(&dependency.source_url)
            .call()
            .map_err(network_error)?;
        let status = response.status();
        if !status.is_success() {
            return Err(CargoDependencyError::HttpStatus(status.as_u16()));
        }
        let content_length = response
            .headers()
            .get("content-length")
            .map(|value| {
                value
                    .to_str()
                    .map_err(|error| CargoDependencyError::Network(error.to_string()))?
                    .parse::<u64>()
                    .map_err(|error| CargoDependencyError::Network(error.to_string()))
            })
            .transpose()?;
        let (_, body) = response.into_parts();
        Ok(CargoDependencyPayload {
            content_length,
            reader: Box::new(body.into_reader()),
        })
    }
}

/// Populates a HAZARDS-owned cache from an already prepared, graph-locked source package.
pub struct CargoDependencyAcquirer<S> {
    source: S,
    cache_root: PathBuf,
    state_root: PathBuf,
}

impl CargoDependencyAcquirer<HttpCargoDependencySource> {
    pub fn for_paths(paths: &HazardsPaths) -> Result<Self, CargoDependencyError> {
        Ok(Self::new(
            HttpCargoDependencySource::new()?,
            paths.cache.clone(),
            paths.state.clone(),
        ))
    }
}

impl<S: CargoDependencySource> CargoDependencyAcquirer<S> {
    pub fn new(source: S, cache_root: impl Into<PathBuf>, state_root: impl Into<PathBuf>) -> Self {
        Self {
            source,
            cache_root: cache_root.into(),
            state_root: state_root.into(),
        }
    }

    pub fn acquire(
        &self,
        item: &AcquisitionItem,
    ) -> Result<CachedCargoDependencies, CargoDependencyError> {
        let (artifact, source_lock) = resolve_item(item)?;
        let stage_path = self
            .cache_root
            .join("sources")
            .join("sha256")
            .join(&artifact.sha256[..2])
            .join(&artifact.sha256);
        match fs::symlink_metadata(&stage_path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(CargoDependencyError::MissingPreparedSource {
                    tool: item.id.clone(),
                    path: stage_path,
                });
            }
            Err(error) => {
                return Err(io_error(
                    "inspect prepared source",
                    &stage_path,
                    error,
                ));
            }
            Ok(_) => {}
        }

        let prepared = SourcePreparer::new(self.cache_root.clone(), self.state_root.clone())
            .prepare(item)?;
        if prepared.receipt.outcome != SourcePreparationOutcome::StageHit {
            return Err(CargoDependencyError::Validation(
                "dependency acquisition requires an existing prepared source stage".to_owned(),
            ));
        }

        let lock_path = prepared.source_path.join("Cargo.lock");
        let lock_bytes = read_locked_file(&lock_path, source_lock)?;
        let dependencies = parse_dependencies(
            &lock_bytes,
            &source_lock.package,
            &artifact.version,
            source_lock,
        )?;

        let object_root = ensure_private_subdirectories(
            &self.cache_root,
            &["cargo", "objects", "sha256"],
        )?;
        let mut packages = Vec::with_capacity(dependencies.len());
        for dependency in &dependencies {
            packages.push(self.acquire_package(dependency)?);
        }

        let manifest = CargoDependencyManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            tool_id: item.id.clone(),
            version: item.target_version.clone(),
            artifact_sha256: artifact.sha256.clone(),
            cargo_lock_sha256: source_lock.cargo_lock_sha256.clone(),
            cargo_lock_version: source_lock.cargo_lock_version,
            package_count: source_lock.package_count,
            dependency_count: packages.len(),
            packages: packages
                .iter()
                .map(|package| CargoDependencyManifestEntry {
                    name: package.name.clone(),
                    version: package.version.clone(),
                    checksum: package.checksum.clone(),
                    source_url: package.source_url.clone(),
                    size: package.size,
                })
                .collect(),
        };
        let (manifest_path, manifest_sha256) = self.persist_manifest(&manifest)?;
        let downloaded_count = packages
            .iter()
            .filter(|package| package.outcome == CargoDependencyOutcome::Downloaded)
            .count();
        let cache_hit_count = packages.len() - downloaded_count;
        let outcome = if downloaded_count == 0 {
            CargoDependencyCacheOutcome::CacheHit
        } else {
            CargoDependencyCacheOutcome::Populated
        };
        let total_bytes = packages.iter().map(|package| package.size).sum();
        let receipt = self.make_receipt(
            item,
            artifact,
            source_lock,
            packages.len(),
            downloaded_count,
            cache_hit_count,
            total_bytes,
            manifest_sha256,
            outcome,
        )?;
        let receipt_path = self.write_receipt(&receipt)?;

        Ok(CachedCargoDependencies {
            object_root,
            manifest_path,
            receipt_path,
            packages,
            receipt,
        })
    }

    fn acquire_package(
        &self,
        dependency: &CargoDependencySpec,
    ) -> Result<CachedCargoDependency, CargoDependencyError> {
        let object_dir = ensure_private_subdirectories(
            &self.cache_root,
            &["cargo", "objects", "sha256", &dependency.checksum[..2]],
        )?;
        let object_path = object_dir.join(&dependency.checksum);
        if fs::symlink_metadata(&object_path).is_ok() {
            let size = verify_dependency_object(&object_path, &dependency.checksum)?;
            return Ok(cached_dependency(
                dependency,
                size,
                object_path,
                CargoDependencyOutcome::CacheHit,
            ));
        }

        let mut payload = self.source.open(dependency)?;
        if let Some(content_length) = payload.content_length {
            if content_length == 0 || content_length > MAX_CRATE_SIZE {
                return Err(CargoDependencyError::CrateTooLarge {
                    package: format!("{} {}", dependency.name, dependency.version),
                    actual: content_length,
                    maximum: MAX_CRATE_SIZE,
                });
            }
        }
        let mut temporary = NamedTempFile::new_in(&object_dir)
            .map_err(|error| io_error("create temporary crate object", &object_dir, error))?;
        let (size, checksum) = copy_and_hash_bounded(
            &mut payload.reader,
            temporary.as_file_mut(),
            MAX_CRATE_SIZE,
        )?;
        if size == 0 {
            return Err(CargoDependencyError::Validation(format!(
                "crate archive {} {} is empty",
                dependency.name, dependency.version
            )));
        }
        if checksum != dependency.checksum {
            return Err(CargoDependencyError::DigestMismatch {
                package: format!("{} {}", dependency.name, dependency.version),
                expected: dependency.checksum.clone(),
                actual: checksum,
            });
        }
        temporary.as_file_mut().sync_all().map_err(|error| {
            io_error("synchronize temporary crate object", temporary.path(), error)
        })?;

        match temporary.persist_noclobber(&object_path) {
            Ok(file) => {
                set_private_file_permissions(&file, &object_path)?;
                sync_directory(&object_dir)?;
                Ok(cached_dependency(
                    dependency,
                    size,
                    object_path,
                    CargoDependencyOutcome::Downloaded,
                ))
            }
            Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
                drop(error.file);
                let size = verify_dependency_object(&object_path, &dependency.checksum)?;
                Ok(cached_dependency(
                    dependency,
                    size,
                    object_path,
                    CargoDependencyOutcome::CacheHit,
                ))
            }
            Err(error) => Err(io_error(
                "persist verified crate object",
                &object_path,
                error.error,
            )),
        }
    }

    fn persist_manifest(
        &self,
        manifest: &CargoDependencyManifest,
    ) -> Result<(PathBuf, String), CargoDependencyError> {
        let graph_dir = ensure_private_subdirectories(
            &self.cache_root,
            &[
                "cargo",
                "dependency-graphs",
                "sha256",
                &manifest.cargo_lock_sha256[..2],
            ],
        )?;
        let manifest_path = graph_dir.join(format!("{}.json", manifest.cargo_lock_sha256));
        let encoded = encode_json(manifest)?;
        let digest = hash_bytes(&encoded);

        match fs::symlink_metadata(&manifest_path) {
            Ok(_) => {
                validate_manifest_file(&manifest_path, manifest, &encoded)?;
                return Ok((manifest_path, digest));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(io_error(
                    "inspect Cargo dependency manifest",
                    &manifest_path,
                    error,
                ));
            }
        }

        let mut temporary = NamedTempFile::new_in(&graph_dir)
            .map_err(|error| io_error("create temporary dependency manifest", &graph_dir, error))?;
        temporary.write_all(&encoded).map_err(|error| {
            io_error(
                "write temporary dependency manifest",
                temporary.path(),
                error,
            )
        })?;
        temporary.as_file_mut().sync_all().map_err(|error| {
            io_error(
                "synchronize temporary dependency manifest",
                temporary.path(),
                error,
            )
        })?;
        match temporary.persist_noclobber(&manifest_path) {
            Ok(file) => {
                set_private_file_permissions(&file, &manifest_path)?;
                sync_directory(&graph_dir)?;
            }
            Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
                drop(error.file);
                validate_manifest_file(&manifest_path, manifest, &encoded)?;
            }
            Err(error) => {
                return Err(io_error(
                    "persist Cargo dependency manifest",
                    &manifest_path,
                    error.error,
                ));
            }
        }
        Ok((manifest_path, digest))
    }

    #[allow(clippy::too_many_arguments)]
    fn make_receipt(
        &self,
        item: &AcquisitionItem,
        artifact: &LockedArtifact,
        source_lock: &CargoSourceLock,
        dependency_count: usize,
        downloaded_count: usize,
        cache_hit_count: usize,
        total_bytes: u64,
        manifest_sha256: String,
        outcome: CargoDependencyCacheOutcome,
    ) -> Result<CargoDependencyReceipt, CargoDependencyError> {
        let verified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| CargoDependencyError::Clock(error.to_string()))?;
        Ok(CargoDependencyReceipt {
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
            cargo_lock_sha256: source_lock.cargo_lock_sha256.clone(),
            dependency_count,
            downloaded_count,
            cache_hit_count,
            total_bytes,
            manifest_sha256,
            outcome,
            verified_at_unix: verified_at.as_secs(),
        })
    }

    fn write_receipt(
        &self,
        receipt: &CargoDependencyReceipt,
    ) -> Result<PathBuf, CargoDependencyError> {
        let receipt_dir = ensure_private_subdirectories(
            &self.state_root,
            &[
                "receipts",
                "cargo-dependencies",
                &receipt.tool_id,
                &receipt.version,
            ],
        )?;
        let receipt_path = receipt_dir.join(format!("{}.json", receipt.receipt_id));
        let encoded = encode_json(receipt)?;
        let mut temporary = NamedTempFile::new_in(&receipt_dir)
            .map_err(|error| io_error("create temporary dependency receipt", &receipt_dir, error))?;
        temporary.write_all(&encoded).map_err(|error| {
            io_error(
                "write temporary dependency receipt",
                temporary.path(),
                error,
            )
        })?;
        temporary.as_file_mut().sync_all().map_err(|error| {
            io_error(
                "synchronize temporary dependency receipt",
                temporary.path(),
                error,
            )
        })?;
        let file = temporary.persist_noclobber(&receipt_path).map_err(|error| {
            io_error(
                "persist Cargo dependency receipt",
                &receipt_path,
                error.error,
            )
        })?;
        set_private_file_permissions(&file, &receipt_path)?;
        sync_directory(&receipt_dir)?;
        Ok(receipt_path)
    }
}

#[derive(Debug, Error)]
pub enum CargoDependencyError {
    #[error("artifact for {0} is unavailable")]
    Unavailable(String),
    #[error("artifact for {0} is not a locked crates.io source archive")]
    NotLockedSource(String),
    #[error("source artifact for {0} has no embedded Cargo lock identity")]
    MissingSourceLock(String),
    #[error("prepared source for {tool} is missing at {path}; prepare it first")]
    MissingPreparedSource { tool: String, path: PathBuf },
    #[error("unsafe crate archive URL: {0}")]
    UnsafeUrl(String),
    #[error("crate server returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("crate transfer failed: {0}")]
    Network(String),
    #[error("crate archive {package} has {actual} bytes; limit is {maximum}")]
    CrateTooLarge {
        package: String,
        actual: u64,
        maximum: u64,
    },
    #[error("crate archive {package} SHA-256 mismatch: expected {expected}, found {actual}")]
    DigestMismatch {
        package: String,
        expected: String,
        actual: String,
    },
    #[error("cached crate object failed verification at {path}: {reason}")]
    CorruptObject { path: PathBuf, reason: String },
    #[error("Cargo dependency manifest failed verification at {path}: {reason}")]
    CorruptManifest { path: PathBuf, reason: String },
    #[error("Cargo dependency validation failed: {0}")]
    Validation(String),
    #[error("{action} at {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not serialize or parse Cargo dependency evidence: {0}")]
    Evidence(String),
    #[error("system clock is before the Unix epoch: {0}")]
    Clock(String),
    #[error(transparent)]
    PreparedSource(#[from] crate::SourcePreparationError),
    #[error(transparent)]
    Cache(#[from] crate::VerifiedArtifactError),
}

fn resolve_item(
    item: &AcquisitionItem,
) -> Result<(&LockedArtifact, &CargoSourceLock), CargoDependencyError> {
    let artifact = item
        .artifact
        .as_ref()
        .ok_or_else(|| CargoDependencyError::Unavailable(item.id.clone()))?;
    if item.status != AcquisitionStatus::LockedSource
        || artifact.method != AcquisitionMethod::CargoRegistry
        || artifact.format != ArtifactFormat::Crate
        || artifact.evidence != DigestEvidence::CratesIoChecksum
    {
        return Err(CargoDependencyError::NotLockedSource(item.id.clone()));
    }
    if artifact.tool_id != item.id || artifact.version != item.target_version {
        return Err(CargoDependencyError::Validation(
            "source artifact identity does not match the selected acquisition item".to_owned(),
        ));
    }
    if !valid_sha256(&artifact.sha256) {
        return Err(CargoDependencyError::Validation(
            "source artifact SHA-256 is malformed".to_owned(),
        ));
    }
    let source_lock = artifact
        .source_lock
        .as_ref()
        .ok_or_else(|| CargoDependencyError::MissingSourceLock(item.id.clone()))?;
    if !safe_component(&item.id)
        || !safe_component(&item.target_version)
        || !safe_component(&source_lock.root)
        || !safe_crate_name(&source_lock.package)
        || source_lock.root != format!("{}-{}", source_lock.package, artifact.version)
        || !valid_sha256(&source_lock.cargo_lock_sha256)
        || source_lock.package_count == 0
    {
        return Err(CargoDependencyError::Validation(
            "source lock identity is malformed or inconsistent".to_owned(),
        ));
    }
    Ok((artifact, source_lock))
}

fn read_locked_file(
    path: &Path,
    source_lock: &CargoSourceLock,
) -> Result<Vec<u8>, CargoDependencyError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect prepared Cargo.lock", path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CargoDependencyError::Validation(
            "prepared Cargo.lock is not a regular file".to_owned(),
        ));
    }
    if metadata.len() > MAX_LOCK_SIZE {
        return Err(CargoDependencyError::Validation(format!(
            "prepared Cargo.lock exceeds the {MAX_LOCK_SIZE}-byte limit"
        )));
    }
    let bytes = fs::read(path).map_err(|error| io_error("read prepared Cargo.lock", path, error))?;
    let actual = hash_bytes(&bytes);
    if actual != source_lock.cargo_lock_sha256 {
        return Err(CargoDependencyError::Validation(format!(
            "prepared Cargo.lock SHA-256 mismatch: expected {}, found {actual}",
            source_lock.cargo_lock_sha256
        )));
    }
    Ok(bytes)
}

fn parse_dependencies(
    bytes: &[u8],
    root_name: &str,
    root_version: &str,
    source_lock: &CargoSourceLock,
) -> Result<Vec<CargoDependencySpec>, CargoDependencyError> {
    let source = std::str::from_utf8(bytes).map_err(|error| {
        CargoDependencyError::Validation(format!("Cargo.lock is not UTF-8: {error}"))
    })?;
    let lock: toml::Value = toml::from_str(source).map_err(|error| {
        CargoDependencyError::Validation(format!("Cargo.lock is invalid: {error}"))
    })?;
    let lock_version = lock
        .get("version")
        .and_then(toml::Value::as_integer)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| {
            CargoDependencyError::Validation("Cargo.lock has no supported version".to_owned())
        })?;
    if lock_version != source_lock.cargo_lock_version {
        return Err(CargoDependencyError::Validation(format!(
            "Cargo.lock version mismatch: expected {}, found {lock_version}",
            source_lock.cargo_lock_version
        )));
    }
    let packages = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| {
            CargoDependencyError::Validation("Cargo.lock has no package graph".to_owned())
        })?;
    if packages.len() != source_lock.package_count {
        return Err(CargoDependencyError::Validation(format!(
            "Cargo.lock package count mismatch: expected {}, found {}",
            source_lock.package_count,
            packages.len()
        )));
    }

    let mut local_packages = 0_usize;
    let mut seen = HashSet::new();
    let mut dependencies = Vec::with_capacity(packages.len().saturating_sub(1));
    for package in packages {
        let package = package.as_table().ok_or_else(|| {
            CargoDependencyError::Validation("Cargo.lock package entry is not a table".to_owned())
        })?;
        let name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| {
                CargoDependencyError::Validation("Cargo.lock package has no name".to_owned())
            })?;
        let version = package
            .get("version")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| {
                CargoDependencyError::Validation(format!(
                    "Cargo.lock package {name} has no version"
                ))
            })?;
        if !safe_crate_name(name) || !safe_crate_version(version) {
            return Err(CargoDependencyError::Validation(format!(
                "Cargo.lock package identity {name} {version} is unsafe"
            )));
        }
        match package.get("source").and_then(toml::Value::as_str) {
            None => {
                local_packages += 1;
                if name != root_name || version != root_version {
                    return Err(CargoDependencyError::Validation(format!(
                        "Cargo.lock contains unexpected local package {name} {version}"
                    )));
                }
            }
            Some(source) if source == CRATES_IO_REGISTRY => {
                let checksum = package
                    .get("checksum")
                    .and_then(toml::Value::as_str)
                    .ok_or_else(|| {
                        CargoDependencyError::Validation(format!(
                            "Cargo.lock package {name} {version} has no checksum"
                        ))
                    })?;
                if !valid_sha256(checksum) {
                    return Err(CargoDependencyError::Validation(format!(
                        "Cargo.lock package {name} {version} has an invalid checksum"
                    )));
                }
                if !seen.insert((name.to_owned(), version.to_owned())) {
                    return Err(CargoDependencyError::Validation(format!(
                        "Cargo.lock repeats registry package {name} {version}"
                    )));
                }
                dependencies.push(CargoDependencySpec {
                    name: name.to_owned(),
                    version: version.to_owned(),
                    checksum: checksum.to_owned(),
                    source_url: canonical_crate_url(name, version),
                });
            }
            Some(source) => {
                return Err(CargoDependencyError::Validation(format!(
                    "Cargo.lock package {name} {version} uses unapproved source {source}"
                )));
            }
        }
    }
    if local_packages != 1 {
        return Err(CargoDependencyError::Validation(format!(
            "Cargo.lock must contain exactly one local root package, found {local_packages}"
        )));
    }
    dependencies.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.version.cmp(&right.version))
            .then_with(|| left.checksum.cmp(&right.checksum))
    });
    Ok(dependencies)
}

fn canonical_crate_url(name: &str, version: &str) -> String {
    format!("https://static.crates.io/crates/{name}/{name}-{version}.crate")
}

fn cached_dependency(
    dependency: &CargoDependencySpec,
    size: u64,
    object_path: PathBuf,
    outcome: CargoDependencyOutcome,
) -> CachedCargoDependency {
    CachedCargoDependency {
        name: dependency.name.clone(),
        version: dependency.version.clone(),
        checksum: dependency.checksum.clone(),
        source_url: dependency.source_url.clone(),
        size,
        object_path,
        outcome,
    }
}

fn copy_and_hash_bounded(
    reader: &mut dyn Read,
    writer: &mut File,
    maximum: u64,
) -> Result<(u64, String), CargoDependencyError> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; BUFFER_SIZE];
    let mut total = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| CargoDependencyError::Network(error.to_string()))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| CargoDependencyError::Validation("crate size overflowed".to_owned()))?;
        if total > maximum {
            return Err(CargoDependencyError::CrateTooLarge {
                package: "response body".to_owned(),
                actual: total,
                maximum,
            });
        }
        writer
            .write_all(&buffer[..read])
            .map_err(|error| io_error("write temporary crate object", Path::new("<temporary>"), error))?;
        digest.update(&buffer[..read]);
    }
    Ok((total, format!("{:x}", digest.finalize())))
}

fn verify_dependency_object(path: &Path, expected: &str) -> Result<u64, CargoDependencyError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect cached crate object", path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CargoDependencyError::CorruptObject {
            path: path.to_path_buf(),
            reason: "object is not a regular file".to_owned(),
        });
    }
    if metadata.len() == 0 || metadata.len() > MAX_CRATE_SIZE {
        return Err(CargoDependencyError::CorruptObject {
            path: path.to_path_buf(),
            reason: format!("object size {} is outside accepted bounds", metadata.len()),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(CargoDependencyError::CorruptObject {
                path: path.to_path_buf(),
                reason: "object permissions are not exactly 0600".to_owned(),
            });
        }
    }
    let mut file = File::open(path)
        .map_err(|error| io_error("open cached crate object", path, error))?;
    let actual = hash_reader(&mut file)?;
    if actual != expected {
        return Err(CargoDependencyError::CorruptObject {
            path: path.to_path_buf(),
            reason: format!("SHA-256 mismatch: found {actual}"),
        });
    }
    Ok(metadata.len())
}

fn validate_manifest_file(
    path: &Path,
    expected: &CargoDependencyManifest,
    encoded: &[u8],
) -> Result<(), CargoDependencyError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect Cargo dependency manifest", path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CargoDependencyError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "manifest is not a regular file".to_owned(),
        });
    }
    if metadata.len() > MAX_EVIDENCE_SIZE {
        return Err(CargoDependencyError::CorruptManifest {
            path: path.to_path_buf(),
            reason: format!("manifest exceeds {MAX_EVIDENCE_SIZE} bytes"),
        });
    }
    let actual = fs::read(path)
        .map_err(|error| io_error("read Cargo dependency manifest", path, error))?;
    let parsed: CargoDependencyManifest = serde_json::from_slice(&actual)
        .map_err(|error| CargoDependencyError::Evidence(error.to_string()))?;
    if &parsed != expected || actual != encoded {
        return Err(CargoDependencyError::CorruptManifest {
            path: path.to_path_buf(),
            reason: "manifest does not match the freshly verified dependency graph".to_owned(),
        });
    }
    Ok(())
}

fn encode_json(value: &impl Serialize) -> Result<Vec<u8>, CargoDependencyError> {
    let mut encoded = serde_json::to_vec_pretty(value)
        .map_err(|error| CargoDependencyError::Evidence(error.to_string()))?;
    encoded.push(b'\n');
    if encoded.len() as u64 > MAX_EVIDENCE_SIZE {
        return Err(CargoDependencyError::Evidence(format!(
            "encoded evidence exceeds {MAX_EVIDENCE_SIZE} bytes"
        )));
    }
    Ok(encoded)
}

fn hash_reader(reader: &mut dyn Read) -> Result<String, CargoDependencyError> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; BUFFER_SIZE];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| CargoDependencyError::Network(error.to_string()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains('/')
        && !value.contains('\\')
}

fn safe_crate_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn safe_crate_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_')
        })
}

fn network_error(error: ureq::Error) -> CargoDependencyError {
    let mut detail = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        detail.push_str(": ");
        detail.push_str(&cause.to_string());
        source = cause.source();
    }
    CargoDependencyError::Network(detail)
}

fn io_error(action: &'static str, path: &Path, source: io::Error) -> CargoDependencyError {
    CargoDependencyError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        io::Cursor,
        sync::{Arc, Mutex},
    };

    use tempfile::TempDir;

    use super::*;

    #[derive(Clone, Default)]
    struct MemorySource {
        bodies: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    }

    impl MemorySource {
        fn insert(&self, checksum: &str, body: impl Into<Vec<u8>>) {
            self.bodies
                .lock()
                .expect("memory source lock should not be poisoned")
                .insert(checksum.to_owned(), body.into());
        }
    }

    impl CargoDependencySource for MemorySource {
        fn open(
            &self,
            dependency: &CargoDependencySpec,
        ) -> Result<CargoDependencyPayload, CargoDependencyError> {
            let body = self
                .bodies
                .lock()
                .expect("memory source lock should not be poisoned")
                .get(&dependency.checksum)
                .cloned()
                .ok_or_else(|| CargoDependencyError::Network("missing fixture".to_owned()))?;
            Ok(CargoDependencyPayload::new(
                Some(body.len() as u64),
                Cursor::new(body),
            ))
        }
    }

    fn source_lock(package_count: usize) -> CargoSourceLock {
        CargoSourceLock {
            root: "root-1.0.0".to_owned(),
            package: "root".to_owned(),
            manifest_sha256: "a".repeat(64),
            cargo_lock_sha256: "b".repeat(64),
            cargo_lock_version: 4,
            package_count,
        }
    }

    #[test]
    fn parses_and_sorts_exact_registry_dependencies() {
        let lock = format!(
            r#"version = 4

[[package]]
name = "root"
version = "1.0.0"

[[package]]
name = "zeta"
version = "2.0.0"
source = "{CRATES_IO_REGISTRY}"
checksum = "{}"

[[package]]
name = "alpha"
version = "1.2.3"
source = "{CRATES_IO_REGISTRY}"
checksum = "{}"
"#,
            "c".repeat(64),
            "d".repeat(64)
        );
        let dependencies = parse_dependencies(lock.as_bytes(), "root", "1.0.0", &source_lock(3))
            .expect("locked dependencies should parse");

        assert_eq!(dependencies.len(), 2);
        assert_eq!(dependencies[0].name, "alpha");
        assert_eq!(
            dependencies[0].source_url,
            "https://static.crates.io/crates/alpha/alpha-1.2.3.crate"
        );
        assert_eq!(dependencies[1].name, "zeta");
    }

    #[test]
    fn rejects_non_registry_dependency_sources() {
        let lock = r#"version = 4

[[package]]
name = "root"
version = "1.0.0"

[[package]]
name = "bad"
version = "1.0.0"
source = "git+https://example.invalid/repository"
checksum = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
"#;
        let error = parse_dependencies(lock.as_bytes(), "root", "1.0.0", &source_lock(2))
            .expect_err("Git dependencies must fail closed");

        assert!(error.to_string().contains("unapproved source"));
    }

    #[test]
    fn downloads_then_revalidates_a_content_addressed_crate() {
        let root = TempDir::new().expect("temporary root should be created");
        let source = MemorySource::default();
        let body = b"exact crate archive bytes".to_vec();
        let checksum = hash_bytes(&body);
        source.insert(&checksum, body.clone());
        let acquirer = CargoDependencyAcquirer::new(
            source,
            root.path().join("cache"),
            root.path().join("state"),
        );
        let dependency = CargoDependencySpec {
            name: "alpha".to_owned(),
            version: "1.0.0".to_owned(),
            checksum: checksum.clone(),
            source_url: canonical_crate_url("alpha", "1.0.0"),
        };

        let first = acquirer
            .acquire_package(&dependency)
            .expect("first acquisition should succeed");
        assert_eq!(first.outcome, CargoDependencyOutcome::Downloaded);
        assert_eq!(first.size, body.len() as u64);

        let second = acquirer
            .acquire_package(&dependency)
            .expect("cache hit should be revalidated");
        assert_eq!(second.outcome, CargoDependencyOutcome::CacheHit);
        assert_eq!(second.object_path, first.object_path);
    }

    #[test]
    fn preserves_and_rejects_a_corrupt_cached_crate() {
        let root = TempDir::new().expect("temporary root should be created");
        let source = MemorySource::default();
        let body = b"exact crate archive bytes".to_vec();
        let checksum = hash_bytes(&body);
        source.insert(&checksum, body);
        let acquirer = CargoDependencyAcquirer::new(
            source,
            root.path().join("cache"),
            root.path().join("state"),
        );
        let dependency = CargoDependencySpec {
            name: "alpha".to_owned(),
            version: "1.0.0".to_owned(),
            checksum,
            source_url: canonical_crate_url("alpha", "1.0.0"),
        };
        let cached = acquirer
            .acquire_package(&dependency)
            .expect("fixture acquisition should succeed");
        fs::write(&cached.object_path, b"tampered")
            .expect("cached object should be tampered for the test");

        let error = acquirer
            .acquire_package(&dependency)
            .expect_err("tampered object must fail closed");
        assert!(matches!(error, CargoDependencyError::CorruptObject { .. }));
        assert_eq!(
            fs::read(&cached.object_path).expect("tampered evidence should remain"),
            b"tampered"
        );
    }
}
