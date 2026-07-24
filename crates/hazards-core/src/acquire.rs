use std::{
    error::Error as StdError,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use arsenallspice::LockedArtifact;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use thiserror::Error;
use ureq::{
    Agent,
    tls::{RootCerts, TlsConfig},
};

use crate::{AcquisitionItem, HazardsPaths};

const BUFFER_SIZE: usize = 64 * 1024;
const MAX_ARTIFACT_SIZE: u64 = 512 * 1024 * 1024;
const MAX_REDIRECTS: usize = 5;
const RECEIPT_SCHEMA_VERSION: u8 = 1;
static RECEIPT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Whether verified bytes were retrieved or already existed in the local cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionOutcome {
    Downloaded,
    CacheHit,
}

impl std::fmt::Display for AcquisitionOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Downloaded => formatter.write_str("downloaded"),
            Self::CacheHit => formatter.write_str("cache-hit"),
        }
    }
}

/// Durable evidence that one exact artifact was verified into the cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AcquisitionReceipt {
    pub schema_version: u8,
    pub receipt_id: String,
    pub tool_id: String,
    pub version: String,
    pub artifact_name: String,
    pub source_url: String,
    pub size: u64,
    pub sha256: String,
    pub outcome: AcquisitionOutcome,
    pub verified_at_unix: u64,
}

/// Paths and receipt produced by a successful acquisition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedArtifact {
    pub object_path: PathBuf,
    pub receipt_path: PathBuf,
    pub receipt: AcquisitionReceipt,
}

/// A response body supplied by an artifact source.
pub struct ArtifactPayload {
    pub content_length: Option<u64>,
    pub reader: Box<dyn Read + Send>,
}

impl ArtifactPayload {
    pub fn new(content_length: Option<u64>, reader: impl Read + Send + 'static) -> Self {
        Self {
            content_length,
            reader: Box::new(reader),
        }
    }
}

/// Retrieves bytes without deciding where or whether they may be installed.
pub trait ArtifactSource {
    fn open(&self, artifact: &LockedArtifact) -> Result<ArtifactPayload, VerifiedArtifactError>;
}

/// HTTPS source with bounded, HTTPS-only redirects and no response decompression.
pub struct HttpArtifactSource {
    agent: Agent,
    allow_http: bool,
}

impl HttpArtifactSource {
    pub fn new() -> Result<Self, VerifiedArtifactError> {
        Self::build(false)
    }

    fn build(allow_http: bool) -> Result<Self, VerifiedArtifactError> {
        let agent = Agent::config_builder()
            .http_status_as_error(false)
            .https_only(!allow_http)
            .max_redirects(MAX_REDIRECTS as u32)
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

        Ok(Self { agent, allow_http })
    }

    #[cfg(test)]
    fn for_loopback_tests() -> Result<Self, VerifiedArtifactError> {
        Self::build(true)
    }
}

impl ArtifactSource for HttpArtifactSource {
    fn open(&self, artifact: &LockedArtifact) -> Result<ArtifactPayload, VerifiedArtifactError> {
        let scheme = artifact
            .url
            .split_once(':')
            .map(|(scheme, _)| scheme)
            .ok_or_else(|| VerifiedArtifactError::UnsafeUrl("URL has no scheme".to_owned()))?;
        if !url_scheme_allowed(scheme, self.allow_http) {
            return Err(VerifiedArtifactError::UnsafeUrl(format!(
                "scheme {} is not allowed",
                scheme
            )));
        }

        let response = self
            .agent
            .get(&artifact.url)
            .call()
            .map_err(network_error)?;
        let status = response.status();
        if !status.is_success() {
            return Err(VerifiedArtifactError::HttpStatus(status.as_u16()));
        }

        let content_length = response
            .headers()
            .get("content-length")
            .map(|value| {
                value
                    .to_str()
                    .map_err(|error| VerifiedArtifactError::Network(error.to_string()))?
                    .parse::<u64>()
                    .map_err(|error| VerifiedArtifactError::Network(error.to_string()))
            })
            .transpose()?;
        let (_, body) = response.into_parts();
        Ok(ArtifactPayload {
            content_length,
            reader: Box::new(body.into_reader()),
        })
    }
}

/// Downloads exact locked bytes into a content-addressed cache.
pub struct ArtifactAcquirer<S> {
    source: S,
    cache_root: PathBuf,
    state_root: PathBuf,
}

impl ArtifactAcquirer<HttpArtifactSource> {
    pub fn for_paths(paths: &HazardsPaths) -> Result<Self, VerifiedArtifactError> {
        Ok(Self::new(
            HttpArtifactSource::new()?,
            paths.cache.clone(),
            paths.state.clone(),
        ))
    }
}

impl<S: ArtifactSource> ArtifactAcquirer<S> {
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
    ) -> Result<VerifiedArtifact, VerifiedArtifactError> {
        let artifact = item
            .artifact
            .as_ref()
            .ok_or_else(|| VerifiedArtifactError::Unavailable(item.id.clone()))?;
        validate_component("tool identifier", &item.id)?;
        validate_component("version", &item.target_version)?;
        validate_expected_artifact(artifact)?;

        let object_dir = ensure_private_subdirectories(
            &self.cache_root,
            &["objects", "sha256", &artifact.sha256[..2]],
        )?;
        let object_path = object_dir.join(&artifact.sha256);

        if object_path.exists() {
            verify_cached_object(&object_path, artifact)?;
            return self.finish(item, artifact, object_path, AcquisitionOutcome::CacheHit);
        }

        let mut payload = self.source.open(artifact)?;
        if let Some(actual) = payload.content_length {
            if actual != artifact.size {
                return Err(VerifiedArtifactError::ContentLengthMismatch {
                    expected: artifact.size,
                    actual,
                });
            }
        }

        let mut temporary = NamedTempFile::new_in(&object_dir)
            .map_err(|error| io_error("create temporary artifact", &object_dir, error))?;
        let (actual_size, actual_digest) =
            copy_and_hash(&mut payload.reader, temporary.as_file_mut(), artifact.size)?;

        if actual_size != artifact.size {
            return Err(VerifiedArtifactError::SizeMismatch {
                expected: artifact.size,
                actual: actual_size,
            });
        }
        if actual_digest != artifact.sha256 {
            return Err(VerifiedArtifactError::DigestMismatch {
                expected: artifact.sha256.clone(),
                actual: actual_digest,
            });
        }

        temporary
            .as_file_mut()
            .sync_all()
            .map_err(|error| io_error("synchronize temporary artifact", temporary.path(), error))?;

        match temporary.persist_noclobber(&object_path) {
            Ok(file) => {
                set_private_file_permissions(&file, &object_path)?;
                sync_directory(&object_dir)?;
                self.finish(item, artifact, object_path, AcquisitionOutcome::Downloaded)
            }
            Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
                drop(error.file);
                verify_cached_object(&object_path, artifact)?;
                self.finish(item, artifact, object_path, AcquisitionOutcome::CacheHit)
            }
            Err(error) => Err(io_error(
                "persist verified artifact",
                &object_path,
                error.error,
            )),
        }
    }

    fn finish(
        &self,
        item: &AcquisitionItem,
        artifact: &LockedArtifact,
        object_path: PathBuf,
        outcome: AcquisitionOutcome,
    ) -> Result<VerifiedArtifact, VerifiedArtifactError> {
        let verified_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| VerifiedArtifactError::Clock(error.to_string()))?;
        let receipt = AcquisitionReceipt {
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
            artifact_name: artifact.name.clone(),
            source_url: artifact.url.clone(),
            size: artifact.size,
            sha256: artifact.sha256.clone(),
            outcome,
            verified_at_unix: verified_at.as_secs(),
        };
        let receipt_path = self.write_receipt(&receipt)?;

        Ok(VerifiedArtifact {
            object_path,
            receipt_path,
            receipt,
        })
    }

    fn write_receipt(
        &self,
        receipt: &AcquisitionReceipt,
    ) -> Result<PathBuf, VerifiedArtifactError> {
        let receipt_dir = ensure_private_subdirectories(
            &self.state_root,
            &[
                "receipts",
                "acquisitions",
                &receipt.tool_id,
                &receipt.version,
            ],
        )?;
        let receipt_path = receipt_dir.join(format!("{}.json", receipt.receipt_id));

        let mut encoded = serde_json::to_vec_pretty(receipt)
            .map_err(|error| VerifiedArtifactError::Receipt(error.to_string()))?;
        encoded.push(b'\n');

        let mut temporary = NamedTempFile::new_in(&receipt_dir)
            .map_err(|error| io_error("create temporary receipt", &receipt_dir, error))?;
        temporary
            .write_all(&encoded)
            .map_err(|error| io_error("write acquisition receipt", temporary.path(), error))?;
        temporary.as_file_mut().sync_all().map_err(|error| {
            io_error("synchronize acquisition receipt", temporary.path(), error)
        })?;
        let file = temporary
            .persist_noclobber(&receipt_path)
            .map_err(|error| io_error("persist acquisition receipt", &receipt_path, error.error))?;
        set_private_file_permissions(&file, &receipt_path)?;
        sync_directory(&receipt_dir)?;

        Ok(receipt_path)
    }
}

#[derive(Debug, Error)]
pub enum VerifiedArtifactError {
    #[error("artifact for {0} is unavailable")]
    Unavailable(String),
    #[error("unsafe {field}: {value}")]
    UnsafeComponent { field: &'static str, value: String },
    #[error("unsafe artifact URL: {0}")]
    UnsafeUrl(String),
    #[error("artifact size {actual} exceeds the {maximum} byte safety limit")]
    ArtifactTooLarge { actual: u64, maximum: u64 },
    #[error("artifact server returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("artifact transfer failed: {0}")]
    Network(String),
    #[error("Content-Length mismatch: expected {expected} bytes, received {actual}")]
    ContentLengthMismatch { expected: u64, actual: u64 },
    #[error("artifact size mismatch: expected {expected} bytes, received {actual}")]
    SizeMismatch { expected: u64, actual: u64 },
    #[error("artifact exceeded its locked size of {expected} bytes")]
    OversizedBody { expected: u64 },
    #[error("SHA-256 mismatch: expected {expected}, received {actual}")]
    DigestMismatch { expected: String, actual: String },
    #[error("cached object failed verification at {path}: {reason}")]
    CorruptCache { path: PathBuf, reason: String },
    #[error("unsafe cache or state path {path}: {reason}")]
    UnsafePath { path: PathBuf, reason: String },
    #[error("{action} at {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not serialize acquisition receipt: {0}")]
    Receipt(String),
    #[error("system clock is before the Unix epoch: {0}")]
    Clock(String),
}

fn validate_expected_artifact(artifact: &LockedArtifact) -> Result<(), VerifiedArtifactError> {
    if artifact.size > MAX_ARTIFACT_SIZE {
        return Err(VerifiedArtifactError::ArtifactTooLarge {
            actual: artifact.size,
            maximum: MAX_ARTIFACT_SIZE,
        });
    }
    if artifact.sha256.len() != 64
        || !artifact
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(VerifiedArtifactError::DigestMismatch {
            expected: "64 lowercase hexadecimal characters".to_owned(),
            actual: artifact.sha256.clone(),
        });
    }
    Ok(())
}

fn validate_component(field: &'static str, value: &str) -> Result<(), VerifiedArtifactError> {
    let safe = !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if safe {
        Ok(())
    } else {
        Err(VerifiedArtifactError::UnsafeComponent {
            field,
            value: value.to_owned(),
        })
    }
}

fn copy_and_hash(
    reader: &mut dyn Read,
    writer: &mut File,
    expected_size: u64,
) -> Result<(u64, String), VerifiedArtifactError> {
    let mut buffer = [0_u8; BUFFER_SIZE];
    let mut digest = Sha256::new();
    let mut total = 0_u64;

    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| VerifiedArtifactError::Network(error.to_string()))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(VerifiedArtifactError::OversizedBody {
                expected: expected_size,
            })?;
        if total > expected_size {
            return Err(VerifiedArtifactError::OversizedBody {
                expected: expected_size,
            });
        }
        writer.write_all(&buffer[..read]).map_err(|error| {
            io_error("write temporary artifact", Path::new("<temporary>"), error)
        })?;
        digest.update(&buffer[..read]);
    }

    Ok((total, format!("{:x}", digest.finalize())))
}

fn verify_cached_object(
    path: &Path,
    artifact: &LockedArtifact,
) -> Result<(), VerifiedArtifactError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect cached object", path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(VerifiedArtifactError::CorruptCache {
            path: path.to_path_buf(),
            reason: "object is not a regular file".to_owned(),
        });
    }
    if metadata.len() != artifact.size {
        return Err(VerifiedArtifactError::CorruptCache {
            path: path.to_path_buf(),
            reason: format!("expected {} bytes, found {}", artifact.size, metadata.len()),
        });
    }

    let mut file = File::open(path).map_err(|error| io_error("open cached object", path, error))?;
    let mut digest = Sha256::new();
    io::copy(&mut file, &mut digest)
        .map_err(|error| io_error("hash cached object", path, error))?;
    let actual = format!("{:x}", digest.finalize());
    if actual != artifact.sha256 {
        return Err(VerifiedArtifactError::CorruptCache {
            path: path.to_path_buf(),
            reason: format!("SHA-256 mismatch: found {actual}"),
        });
    }
    Ok(())
}

fn ensure_private_dir(path: &Path) -> Result<(), VerifiedArtifactError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(VerifiedArtifactError::UnsafePath {
                path: path.to_path_buf(),
                reason: "symbolic links are not accepted".to_owned(),
            });
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(VerifiedArtifactError::UnsafePath {
                path: path.to_path_buf(),
                reason: "expected a directory".to_owned(),
            });
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)
                .map_err(|error| io_error("create private directory", path, error))?;
        }
        Err(error) => return Err(io_error("inspect private directory", path, error)),
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| io_error("set private directory permissions", path, error))?;
    }
    Ok(())
}

fn ensure_private_subdirectories(
    root: &Path,
    components: &[&str],
) -> Result<PathBuf, VerifiedArtifactError> {
    ensure_private_dir(root)?;
    let mut current = root.to_path_buf();
    for component in components {
        current.push(component);
        ensure_private_dir(&current)?;
    }
    Ok(current)
}

fn set_private_file_permissions(file: &File, path: &Path) -> Result<(), VerifiedArtifactError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| io_error("set private file permissions", path, error))?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), VerifiedArtifactError> {
    let directory = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|error| io_error("open directory for synchronization", path, error))?;
    directory
        .sync_all()
        .map_err(|error| io_error("synchronize directory", path, error))
}

fn io_error(action: &'static str, path: &Path, source: io::Error) -> VerifiedArtifactError {
    VerifiedArtifactError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

fn url_scheme_allowed(scheme: &str, allow_http: bool) -> bool {
    scheme == "https" || (allow_http && scheme == "http")
}

fn network_error(error: ureq::Error) -> VerifiedArtifactError {
    let mut detail = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        detail.push_str(": ");
        detail.push_str(&cause.to_string());
        source = cause.source();
    }
    VerifiedArtifactError::Network(detail)
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Cursor, ErrorKind},
        net::TcpListener,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };

    use arsenallspice::{AcquisitionMethod, ArtifactFormat, DigestEvidence, LockedArtifact};

    use super::*;
    use crate::{AcquisitionStatus, ProvisionStatus};

    #[derive(Clone)]
    struct MemorySource {
        body: Vec<u8>,
        content_length: Option<u64>,
        opens: Arc<AtomicUsize>,
    }

    impl MemorySource {
        fn new(body: impl Into<Vec<u8>>) -> Self {
            let body = body.into();
            Self {
                content_length: Some(body.len() as u64),
                body,
                opens: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl ArtifactSource for MemorySource {
        fn open(
            &self,
            _artifact: &LockedArtifact,
        ) -> Result<ArtifactPayload, VerifiedArtifactError> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            Ok(ArtifactPayload::new(
                self.content_length,
                Cursor::new(self.body.clone()),
            ))
        }
    }

    struct InterruptedReader {
        emitted: bool,
    }

    impl Read for InterruptedReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.emitted {
                Err(io::Error::new(ErrorKind::ConnectionReset, "interrupted"))
            } else {
                self.emitted = true;
                buffer[..3].copy_from_slice(b"abc");
                Ok(3)
            }
        }
    }

    struct InterruptedSource;

    impl ArtifactSource for InterruptedSource {
        fn open(
            &self,
            _artifact: &LockedArtifact,
        ) -> Result<ArtifactPayload, VerifiedArtifactError> {
            Ok(ArtifactPayload::new(
                None,
                InterruptedReader { emitted: false },
            ))
        }
    }

    fn sha256(body: &[u8]) -> String {
        format!("{:x}", Sha256::digest(body))
    }

    fn item(body: &[u8], url: &str) -> AcquisitionItem {
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
                format: ArtifactFormat::TarGz,
                name: "zellij.tar.gz".to_owned(),
                size: body.len() as u64,
                sha256: sha256(body),
                url: url.to_owned(),
                evidence: DigestEvidence::GithubAssetDigest,
            }),
            detail: String::new(),
        }
    }

    fn acquirer<S: ArtifactSource>(source: S, root: &Path) -> ArtifactAcquirer<S> {
        ArtifactAcquirer::new(source, root.join("cache"), root.join("state"))
    }

    #[test]
    fn valid_bytes_are_persisted_with_a_receipt() {
        let root = tempfile::tempdir().expect("temporary root should exist");
        let body = b"locked artifact bytes";
        let result = acquirer(MemorySource::new(body.as_slice()), root.path())
            .acquire(&item(body, "https://example.invalid/zellij"))
            .expect("valid bytes should be acquired");

        assert_eq!(result.receipt.outcome, AcquisitionOutcome::Downloaded);
        assert_eq!(
            fs::read(&result.object_path).expect("object should be readable"),
            body
        );
        assert!(result.receipt_path.is_file());
        let receipt: serde_json::Value = serde_json::from_slice(
            &fs::read(&result.receipt_path).expect("receipt should be readable"),
        )
        .expect("receipt should be JSON");
        assert_eq!(receipt["sha256"], sha256(body));
        assert_eq!(receipt["outcome"], "downloaded");
    }

    #[test]
    fn a_valid_cache_hit_is_rehashed_without_opening_the_source() {
        let root = tempfile::tempdir().expect("temporary root should exist");
        let body = b"same exact bytes";
        let source = MemorySource::new(body.as_slice());
        let opens = Arc::clone(&source.opens);
        let acquisition = acquirer(source, root.path());
        let selected = item(body, "https://example.invalid/zellij");

        let first = acquisition
            .acquire(&selected)
            .expect("first acquisition should succeed");
        let second = acquisition
            .acquire(&selected)
            .expect("cache hit should succeed");

        assert_eq!(opens.load(Ordering::SeqCst), 1);
        assert_eq!(second.receipt.outcome, AcquisitionOutcome::CacheHit);
        assert_ne!(first.receipt_path, second.receipt_path);
        let first_receipt: serde_json::Value = serde_json::from_slice(
            &fs::read(first.receipt_path).expect("original receipt should remain"),
        )
        .expect("original receipt should be JSON");
        assert_eq!(first_receipt["outcome"], "downloaded");
    }

    #[test]
    fn a_same_size_corrupt_cache_object_fails_closed() {
        let root = tempfile::tempdir().expect("temporary root should exist");
        let body = b"expected";
        let source = MemorySource::new(body.as_slice());
        let opens = Arc::clone(&source.opens);
        let acquisition = acquirer(source, root.path());
        let selected = item(body, "https://example.invalid/zellij");
        let first = acquisition
            .acquire(&selected)
            .expect("first acquisition should succeed");
        fs::write(&first.object_path, b"corrupt!").expect("test should corrupt the cached object");

        let error = acquisition
            .acquire(&selected)
            .expect_err("corrupt cache must fail");

        assert!(matches!(error, VerifiedArtifactError::CorruptCache { .. }));
        assert_eq!(opens.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn digest_mismatch_never_creates_a_cache_object() {
        let root = tempfile::tempdir().expect("temporary root should exist");
        let expected = b"expected";
        let selected = item(expected, "https://example.invalid/zellij");
        let error = acquirer(MemorySource::new(b"tampered".as_slice()), root.path())
            .acquire(&selected)
            .expect_err("tampered bytes must fail");

        assert!(matches!(
            error,
            VerifiedArtifactError::DigestMismatch { .. }
        ));
        let object = root
            .path()
            .join("cache/objects/sha256")
            .join(&sha256(expected)[..2])
            .join(sha256(expected));
        assert!(!object.exists());
    }

    #[test]
    fn truncated_and_oversized_bodies_are_rejected() {
        let root = tempfile::tempdir().expect("temporary root should exist");
        let expected = b"expected";
        let selected = item(expected, "https://example.invalid/zellij");

        let mut truncated = MemorySource::new(b"short".as_slice());
        truncated.content_length = None;
        assert!(matches!(
            acquirer(truncated, root.path()).acquire(&selected),
            Err(VerifiedArtifactError::SizeMismatch { .. })
        ));

        let mut oversized = MemorySource::new(b"expected plus".as_slice());
        oversized.content_length = None;
        assert!(matches!(
            acquirer(oversized, root.path()).acquire(&selected),
            Err(VerifiedArtifactError::OversizedBody { .. })
        ));
    }

    #[test]
    fn contradictory_content_length_is_rejected_before_streaming() {
        let root = tempfile::tempdir().expect("temporary root should exist");
        let body = b"expected";
        let selected = item(body, "https://example.invalid/zellij");
        let mut source = MemorySource::new(body.as_slice());
        source.content_length = Some(999);

        assert!(matches!(
            acquirer(source, root.path()).acquire(&selected),
            Err(VerifiedArtifactError::ContentLengthMismatch { .. })
        ));
    }

    #[test]
    fn interrupted_transfer_leaves_no_final_object() {
        let root = tempfile::tempdir().expect("temporary root should exist");
        let body = b"expected";
        let selected = item(body, "https://example.invalid/zellij");

        assert!(matches!(
            acquirer(InterruptedSource, root.path()).acquire(&selected),
            Err(VerifiedArtifactError::Network(_))
        ));
        let object = root
            .path()
            .join("cache/objects/sha256")
            .join(&sha256(body)[..2])
            .join(sha256(body));
        assert!(!object.exists());
    }

    #[test]
    fn default_http_source_rejects_plaintext_urls() {
        let source = HttpArtifactSource::new().expect("HTTP client should build");
        let selected = item(b"irrelevant", "http://127.0.0.1/artifact");
        let error = match source.open(selected.artifact.as_ref().expect("artifact should exist")) {
            Ok(_) => panic!("plaintext URL should fail before a request"),
            Err(error) => error,
        };
        assert!(matches!(error, VerifiedArtifactError::UnsafeUrl(_)));
    }

    #[test]
    fn acquisition_rejects_path_shaped_identifiers_and_excessive_sizes() {
        let root = tempfile::tempdir().expect("temporary root should exist");
        let body = b"expected";
        let mut unsafe_item = item(body, "https://example.invalid/zellij");
        unsafe_item.id = "../escape".to_owned();
        assert!(matches!(
            acquirer(MemorySource::new(body.as_slice()), root.path()).acquire(&unsafe_item),
            Err(VerifiedArtifactError::UnsafeComponent { .. })
        ));

        let mut huge_item = item(body, "https://example.invalid/zellij");
        huge_item
            .artifact
            .as_mut()
            .expect("artifact should exist")
            .size = MAX_ARTIFACT_SIZE + 1;
        assert!(matches!(
            acquirer(MemorySource::new(body.as_slice()), root.path()).acquire(&huge_item),
            Err(VerifiedArtifactError::ArtifactTooLarge { .. })
        ));
    }

    #[test]
    fn production_redirect_policy_allows_only_https() {
        assert!(url_scheme_allowed("https", false));
        assert!(!url_scheme_allowed("http", false));
        assert!(!url_scheme_allowed("file", false));
    }

    #[test]
    fn loopback_http_fixture_exercises_the_real_streaming_client() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let address = listener.local_addr().expect("address should resolve");
        let body = b"fixture bytes".to_vec();
        let response_body = body.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("fixture should accept");
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).expect("request should be read");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response_body.len()
            )
            .expect("headers should be written");
            stream
                .write_all(&response_body)
                .expect("body should be written");
        });
        let root = tempfile::tempdir().expect("temporary root should exist");
        let source =
            HttpArtifactSource::for_loopback_tests().expect("test HTTP client should build");
        let selected = item(&body, &format!("http://{address}/artifact"));

        let result = acquirer(source, root.path())
            .acquire(&selected)
            .expect("fixture download should verify");

        server.join().expect("fixture server should finish");
        assert_eq!(result.receipt.outcome, AcquisitionOutcome::Downloaded);
        assert_eq!(
            fs::read(result.object_path).expect("object should be readable"),
            body
        );
    }

    #[cfg(unix)]
    #[test]
    fn cache_objects_and_directories_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("temporary root should exist");
        let body = b"private bytes";
        let result = acquirer(MemorySource::new(body.as_slice()), root.path())
            .acquire(&item(body, "https://example.invalid/zellij"))
            .expect("acquisition should succeed");

        assert_eq!(
            fs::metadata(result.object_path)
                .expect("object metadata should exist")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(root.path().join("cache/objects/sha256"))
                .expect("directory metadata should exist")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_hazards_cache_root_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("temporary root should exist");
        let elsewhere = root.path().join("elsewhere");
        fs::create_dir(&elsewhere).expect("target directory should exist");
        let cache = root.path().join("cache");
        symlink(&elsewhere, &cache).expect("cache symlink should exist");
        let body = b"expected";
        let acquisition = ArtifactAcquirer::new(
            MemorySource::new(body.as_slice()),
            cache,
            root.path().join("state"),
        );

        assert!(matches!(
            acquisition.acquire(&item(body, "https://example.invalid/zellij")),
            Err(VerifiedArtifactError::UnsafePath { .. })
        ));
    }
}
