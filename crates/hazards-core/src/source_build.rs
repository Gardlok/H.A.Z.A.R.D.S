use std::{
    collections::HashSet,
    fs::{self, File},
    io::Read,
    path::{Component, Path, PathBuf},
};

use arsenallspice::{ArtifactFormat, CargoSourceLock, LockedArtifact};
use flate2::read::GzDecoder;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tar::Archive;

use crate::{
    AcquisitionItem, AcquisitionStatus, HazardsPaths, Platform, ResolvedProfile,
    acquire::verify_cached_object,
};

const MAX_ARCHIVE_ENTRIES: usize = 100_000;
const MAX_EXPANDED_SIZE: u64 = 1024 * 1024 * 1024;
const MAX_ENTRY_SIZE: u64 = 512 * 1024 * 1024;
const MAX_METADATA_SIZE: u64 = 16 * 1024 * 1024;
const MAX_PATH_LENGTH: usize = 4096;
const MAX_COMPONENT_LENGTH: usize = 255;
const CRATES_IO_REGISTRY: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// Readiness of one source archive for a future controlled Cargo pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceBuildStatus {
    GraphLocked,
    CacheMissing,
    Blocked,
}

impl std::fmt::Display for SourceBuildStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GraphLocked => formatter.write_str("graph-locked"),
            Self::CacheMissing => formatter.write_str("cache-missing"),
            Self::Blocked => formatter.write_str("blocked"),
        }
    }
}

/// Read-only evidence for one crates.io source archive and its Cargo graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceBuildItem {
    pub id: String,
    pub name: String,
    pub target_version: String,
    pub status: SourceBuildStatus,
    pub object_path: PathBuf,
    pub artifact_sha256: String,
    pub source_root: String,
    pub manifest_sha256: String,
    pub cargo_lock_sha256: String,
    pub cargo_lock_version: u32,
    pub package_count: usize,
    pub registry_package_count: Option<usize>,
    pub local_package_count: Option<usize>,
    pub detail: String,
}

/// Profile-specific inspection of source artifacts. Producing this value never
/// extracts source or invokes Cargo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceBuildPlan {
    pub read_only: bool,
    pub execution_enabled: bool,
    pub lock_observed_at: String,
    pub profile: ResolvedProfile,
    pub platform: Platform,
    pub items: Vec<SourceBuildItem>,
}

/// Inspects verified crates.io objects and their embedded transitive locks.
pub struct SourceBuildPlanner<'a> {
    paths: &'a HazardsPaths,
    lock_observed_at: &'a str,
}

impl<'a> SourceBuildPlanner<'a> {
    pub fn new(paths: &'a HazardsPaths, lock_observed_at: &'a str) -> Self {
        Self {
            paths,
            lock_observed_at,
        }
    }

    pub fn plan(
        &self,
        profile: &ResolvedProfile,
        platform: &Platform,
        items: &[AcquisitionItem],
    ) -> SourceBuildPlan {
        SourceBuildPlan {
            read_only: true,
            execution_enabled: false,
            lock_observed_at: self.lock_observed_at.to_owned(),
            profile: profile.clone(),
            platform: platform.clone(),
            items: items.iter().map(|item| self.inspect(item)).collect(),
        }
    }

    fn inspect(&self, item: &AcquisitionItem) -> SourceBuildItem {
        let Some(artifact) = item.artifact.as_ref() else {
            return blocked_item(
                item,
                PathBuf::new(),
                None,
                "source acquisition record is missing",
            );
        };
        if item.status != AcquisitionStatus::LockedSource
            || artifact.format != ArtifactFormat::Crate
        {
            return blocked_item(
                item,
                PathBuf::new(),
                artifact.source_lock.as_ref(),
                "artifact is not a locked crates.io source archive",
            );
        }
        let Some(source_lock) = artifact.source_lock.as_ref() else {
            return blocked_item(
                item,
                PathBuf::new(),
                None,
                "source archive has no embedded Cargo lock identity",
            );
        };
        let object_path = cache_object_path(&self.paths.cache, &artifact.sha256);
        match fs::symlink_metadata(&object_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => SourceBuildItem {
                id: item.id.clone(),
                name: item.name.clone(),
                target_version: item.target_version.clone(),
                status: SourceBuildStatus::CacheMissing,
                object_path,
                artifact_sha256: artifact.sha256.clone(),
                source_root: source_lock.root.clone(),
                manifest_sha256: source_lock.manifest_sha256.clone(),
                cargo_lock_sha256: source_lock.cargo_lock_sha256.clone(),
                cargo_lock_version: source_lock.cargo_lock_version,
                package_count: source_lock.package_count,
                registry_package_count: None,
                local_package_count: None,
                detail: "locked source object is not cached; run provision acquire first"
                    .to_owned(),
            },
            Err(error) => blocked_item(
                item,
                object_path,
                Some(source_lock),
                &format!("could not inspect cached source object: {error}"),
            ),
            Ok(_) => {
                if let Err(error) = verify_cached_object(&object_path, artifact) {
                    return blocked_item(
                        item,
                        object_path,
                        Some(source_lock),
                        &format!("cached source object failed verification: {error}"),
                    );
                }
                match inspect_source_archive(&object_path, artifact, source_lock) {
                    Ok(inspection) => SourceBuildItem {
                        id: item.id.clone(),
                        name: item.name.clone(),
                        target_version: item.target_version.clone(),
                        status: SourceBuildStatus::GraphLocked,
                        object_path,
                        artifact_sha256: artifact.sha256.clone(),
                        source_root: source_lock.root.clone(),
                        manifest_sha256: source_lock.manifest_sha256.clone(),
                        cargo_lock_sha256: source_lock.cargo_lock_sha256.clone(),
                        cargo_lock_version: source_lock.cargo_lock_version,
                        package_count: source_lock.package_count,
                        registry_package_count: Some(inspection.registry_packages),
                        local_package_count: Some(inspection.local_packages),
                        detail: "top-level crate and every registry dependency are checksum-locked"
                            .to_owned(),
                    },
                    Err(error) => blocked_item(
                        item,
                        object_path,
                        Some(source_lock),
                        &format!("source archive inspection failed: {error}"),
                    ),
                }
            }
        }
    }
}

fn blocked_item(
    item: &AcquisitionItem,
    object_path: PathBuf,
    source_lock: Option<&CargoSourceLock>,
    detail: &str,
) -> SourceBuildItem {
    SourceBuildItem {
        id: item.id.clone(),
        name: item.name.clone(),
        target_version: item.target_version.clone(),
        status: SourceBuildStatus::Blocked,
        object_path,
        artifact_sha256: item
            .artifact
            .as_ref()
            .map(|artifact| artifact.sha256.clone())
            .unwrap_or_default(),
        source_root: source_lock
            .map(|source| source.root.clone())
            .unwrap_or_default(),
        manifest_sha256: source_lock
            .map(|source| source.manifest_sha256.clone())
            .unwrap_or_default(),
        cargo_lock_sha256: source_lock
            .map(|source| source.cargo_lock_sha256.clone())
            .unwrap_or_default(),
        cargo_lock_version: source_lock
            .map(|source| source.cargo_lock_version)
            .unwrap_or_default(),
        package_count: source_lock
            .map(|source| source.package_count)
            .unwrap_or_default(),
        registry_package_count: None,
        local_package_count: None,
        detail: detail.to_owned(),
    }
}

fn cache_object_path(cache_root: &Path, sha256: &str) -> PathBuf {
    let prefix = sha256.get(..2).unwrap_or("invalid");
    cache_root
        .join("objects")
        .join("sha256")
        .join(prefix)
        .join(sha256)
}

pub(crate) struct SourceInspection {
    pub(crate) registry_packages: usize,
    pub(crate) local_packages: usize,
}

pub(crate) fn inspect_source_archive(
    path: &Path,
    artifact: &LockedArtifact,
    source_lock: &CargoSourceLock,
) -> Result<SourceInspection, String> {
    let file = File::open(path).map_err(|error| error.to_string())?;
    let mut archive = Archive::new(GzDecoder::new(file));
    let manifest_path = Path::new(&source_lock.root).join("Cargo.toml");
    let lock_path = Path::new(&source_lock.root).join("Cargo.lock");
    let mut manifest = None;
    let mut cargo_lock = None;
    let mut seen = HashSet::new();
    let mut entry_count = 0_usize;
    let mut expanded_size = 0_u64;

    let entries = archive.entries().map_err(|error| error.to_string())?;
    for entry in entries {
        let mut entry = entry.map_err(|error| error.to_string())?;
        entry_count = entry_count
            .checked_add(1)
            .ok_or_else(|| "source archive entry count overflowed".to_owned())?;
        if entry_count > MAX_ARCHIVE_ENTRIES {
            return Err(format!(
                "source archive contains more than {MAX_ARCHIVE_ENTRIES} entries"
            ));
        }
        let entry_path = entry
            .path()
            .map_err(|error| error.to_string())?
            .into_owned();
        validate_archive_path(&entry_path, &source_lock.root)?;
        if !seen.insert(entry_path.clone()) {
            return Err(format!("duplicate source entry {}", entry_path.display()));
        }

        let size = entry.size();
        if size > MAX_ENTRY_SIZE {
            return Err(format!(
                "source entry {} exceeds the {MAX_ENTRY_SIZE}-byte limit",
                entry_path.display()
            ));
        }
        expanded_size = expanded_size
            .checked_add(size)
            .ok_or_else(|| "source archive expansion size overflowed".to_owned())?;
        if expanded_size > MAX_EXPANDED_SIZE {
            return Err(format!(
                "source archive expands beyond {MAX_EXPANDED_SIZE} bytes"
            ));
        }

        let entry_type = entry.header().entry_type();
        if !entry_type.is_file() && !entry_type.is_dir() {
            return Err(format!(
                "source entry {} is not a regular file or directory",
                entry_path.display()
            ));
        }
        if entry_type.is_dir() {
            continue;
        }
        if entry_path == manifest_path || entry_path == lock_path {
            if size > MAX_METADATA_SIZE {
                return Err(format!(
                    "source metadata {} exceeds the {MAX_METADATA_SIZE}-byte limit",
                    entry_path.display()
                ));
            }
            let mut bytes = Vec::with_capacity(size as usize);
            entry
                .read_to_end(&mut bytes)
                .map_err(|error| error.to_string())?;
            if bytes.len() as u64 != size {
                return Err(format!(
                    "source metadata {} was truncated",
                    entry_path.display()
                ));
            }
            if entry_path == manifest_path {
                manifest = Some(bytes);
            } else {
                cargo_lock = Some(bytes);
            }
        }
    }

    let manifest = manifest.ok_or_else(|| "source archive omitted Cargo.toml".to_owned())?;
    let cargo_lock = cargo_lock.ok_or_else(|| "source archive omitted Cargo.lock".to_owned())?;
    require_digest("Cargo.toml", &manifest, &source_lock.manifest_sha256)?;
    require_digest("Cargo.lock", &cargo_lock, &source_lock.cargo_lock_sha256)?;
    validate_manifest(&manifest, &source_lock.package, &artifact.version)?;
    validate_cargo_lock(&cargo_lock, source_lock, &artifact.version)
}

fn validate_archive_path(path: &Path, root: &str) -> Result<(), String> {
    let encoded = path
        .to_str()
        .ok_or_else(|| "source archive path is not UTF-8".to_owned())?;
    if encoded.is_empty() || encoded.len() > MAX_PATH_LENGTH || encoded.contains('\\') {
        return Err(format!("unsafe source archive path {encoded:?}"));
    }
    let mut components = path.components();
    let first = components
        .next()
        .ok_or_else(|| "source archive path is empty".to_owned())?;
    if first != Component::Normal(root.as_ref()) {
        return Err(format!(
            "source entry {} escapes locked root {root}",
            path.display()
        ));
    }
    for component in components {
        match component {
            Component::Normal(name) if name.as_encoded_bytes().len() <= MAX_COMPONENT_LENGTH => {}
            _ => return Err(format!("unsafe source archive path {}", path.display())),
        }
    }
    Ok(())
}

fn require_digest(label: &str, bytes: &[u8], expected: &str) -> Result<(), String> {
    let actual = hash_bytes(bytes);
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{label} SHA-256 mismatch: expected {expected}, found {actual}"
        ))
    }
}

fn validate_manifest(bytes: &[u8], package: &str, version: &str) -> Result<(), String> {
    let manifest_source =
        std::str::from_utf8(bytes).map_err(|error| format!("Cargo.toml is not UTF-8: {error}"))?;
    let manifest: toml::Value = toml::from_str(manifest_source)
        .map_err(|error| format!("Cargo.toml is invalid: {error}"))?;
    let table = manifest
        .get("package")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| "Cargo.toml has no package table".to_owned())?;
    if table.get("name").and_then(toml::Value::as_str) != Some(package)
        || table.get("version").and_then(toml::Value::as_str) != Some(version)
    {
        return Err(format!(
            "Cargo.toml package identity does not match {package} {version}"
        ));
    }
    Ok(())
}

fn validate_cargo_lock(
    bytes: &[u8],
    source_lock: &CargoSourceLock,
    version: &str,
) -> Result<SourceInspection, String> {
    let lock_source =
        std::str::from_utf8(bytes).map_err(|error| format!("Cargo.lock is not UTF-8: {error}"))?;
    let lock: toml::Value =
        toml::from_str(lock_source).map_err(|error| format!("Cargo.lock is invalid: {error}"))?;
    let lock_version = lock
        .get("version")
        .and_then(toml::Value::as_integer)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "Cargo.lock has no supported version".to_owned())?;
    if lock_version != source_lock.cargo_lock_version {
        return Err(format!(
            "Cargo.lock version mismatch: expected {}, found {lock_version}",
            source_lock.cargo_lock_version
        ));
    }
    let packages = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| "Cargo.lock has no package graph".to_owned())?;
    if packages.len() != source_lock.package_count {
        return Err(format!(
            "Cargo.lock package count mismatch: expected {}, found {}",
            source_lock.package_count,
            packages.len()
        ));
    }

    let mut registry_packages = 0_usize;
    let mut local_packages = 0_usize;
    for package in packages {
        let package = package
            .as_table()
            .ok_or_else(|| "Cargo.lock package entry is not a table".to_owned())?;
        let name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| "Cargo.lock package has no name".to_owned())?;
        let package_version = package
            .get("version")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| format!("Cargo.lock package {name} has no version"))?;
        match package.get("source").and_then(toml::Value::as_str) {
            None => {
                local_packages += 1;
                if name != source_lock.package || package_version != version {
                    return Err(format!(
                        "Cargo.lock contains unexpected unlocked local package {name} {package_version}"
                    ));
                }
            }
            Some(source) if source == CRATES_IO_REGISTRY => {
                registry_packages += 1;
                let checksum = package
                    .get("checksum")
                    .and_then(toml::Value::as_str)
                    .ok_or_else(|| {
                        format!(
                            "Cargo.lock registry package {name} {package_version} has no checksum"
                        )
                    })?;
                if !valid_sha256(checksum) {
                    return Err(format!(
                        "Cargo.lock registry package {name} {package_version} has an invalid checksum"
                    ));
                }
            }
            Some(source) => {
                return Err(format!(
                    "Cargo.lock package {name} {package_version} uses unapproved source {source}"
                ));
            }
        }
    }
    if local_packages != 1 {
        return Err(format!(
            "Cargo.lock must contain exactly one local root package, found {local_packages}"
        ));
    }
    Ok(SourceInspection {
        registry_packages,
        local_packages,
    })
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use arsenallspice::{AcquisitionMethod, CargoSourceLock, DigestEvidence, LockedArtifact};
    use flate2::{Compression, write::GzEncoder};
    use tar::{Builder as TarBuilder, Header};
    use tempfile::TempDir;

    use super::*;
    use crate::{HostKind, Persistence, ProvisionStatus, Role};

    const CHECKSUM: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn source_archive(cargo_lock: &str) -> (Vec<u8>, Vec<u8>) {
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
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, path, Cursor::new(bytes))
                .expect("fixture entry should append");
        }
        let encoder = builder.into_inner().expect("fixture TAR should finish");
        (
            encoder.finish().expect("fixture GZip should finish"),
            manifest,
        )
    }

    fn fixture_item(cargo_lock: &str) -> (AcquisitionItem, Vec<u8>) {
        let (archive, manifest) = source_archive(cargo_lock);
        let artifact_sha256 = hash_bytes(&archive);
        let source_lock = CargoSourceLock {
            root: "demo-1.0.0".to_owned(),
            package: "demo".to_owned(),
            manifest_sha256: hash_bytes(&manifest),
            cargo_lock_sha256: hash_bytes(cargo_lock.as_bytes()),
            cargo_lock_version: 4,
            package_count: 2,
        };
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
                    source_lock: Some(source_lock),
                }),
                detail: String::new(),
            },
            archive,
        )
    }

    fn paths(root: &TempDir) -> HazardsPaths {
        HazardsPaths {
            home: root.path().join("home"),
            config: root.path().join("config"),
            data: root.path().join("data"),
            state: root.path().join("state"),
            cache: root.path().join("cache"),
            bin: root.path().join("bin"),
        }
    }

    fn plan(root: &TempDir, item: AcquisitionItem) -> SourceBuildPlan {
        let paths = paths(root);
        SourceBuildPlanner::new(&paths, "2026-07-25").plan(
            &ResolvedProfile::new(HostKind::Desktop, Persistence::Local, Role::Development),
            &Platform::new("linux", "x86_64"),
            &[item],
        )
    }

    fn persist_object(root: &TempDir, item: &AcquisitionItem, archive: &[u8]) {
        let artifact = item.artifact.as_ref().expect("fixture artifact");
        let path = cache_object_path(&paths(root).cache, &artifact.sha256);
        fs::create_dir_all(path.parent().expect("object parent")).expect("object parent");
        fs::write(path, archive).expect("fixture object");
    }

    #[test]
    fn verifies_a_checksum_locked_registry_graph_without_extracting_it() {
        let cargo_lock = format!(
            "version = 4\n\n[[package]]\nname = \"demo\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"{CRATES_IO_REGISTRY}\"\nchecksum = \"{CHECKSUM}\"\n"
        );
        let (item, archive) = fixture_item(&cargo_lock);
        let root = tempfile::tempdir().expect("fixture root");
        persist_object(&root, &item, &archive);

        let plan = plan(&root, item);

        assert!(plan.read_only);
        assert!(!plan.execution_enabled);
        assert_eq!(
            plan.items[0].status,
            SourceBuildStatus::GraphLocked,
            "{}",
            plan.items[0].detail
        );
        assert_eq!(plan.items[0].registry_package_count, Some(1));
        assert_eq!(plan.items[0].local_package_count, Some(1));
    }

    #[test]
    fn reports_a_missing_cache_without_creating_any_directory() {
        let cargo_lock = format!(
            "version = 4\n\n[[package]]\nname = \"demo\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"{CRATES_IO_REGISTRY}\"\nchecksum = \"{CHECKSUM}\"\n"
        );
        let (item, _) = fixture_item(&cargo_lock);
        let root = tempfile::tempdir().expect("fixture root");
        let cache = paths(&root).cache;

        let plan = plan(&root, item);

        assert_eq!(plan.items[0].status, SourceBuildStatus::CacheMissing);
        assert!(!cache.exists());
    }

    #[test]
    fn rejects_git_dependencies_even_when_the_outer_archive_is_locked() {
        let cargo_lock = "version = 4\n\n[[package]]\nname = \"demo\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"dependency\"\nversion = \"1.0.0\"\nsource = \"git+https://example.invalid/repository\"\n";
        let (item, archive) = fixture_item(cargo_lock);
        let root = tempfile::tempdir().expect("fixture root");
        persist_object(&root, &item, &archive);

        let plan = plan(&root, item);

        assert_eq!(plan.items[0].status, SourceBuildStatus::Blocked);
        assert!(
            plan.items[0].detail.contains("unapproved source"),
            "{}",
            plan.items[0].detail
        );
    }

    #[test]
    fn rejects_manifest_or_lock_drift_inside_a_verified_outer_archive() {
        let cargo_lock = format!(
            "version = 4\n\n[[package]]\nname = \"demo\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"{CRATES_IO_REGISTRY}\"\nchecksum = \"{CHECKSUM}\"\n"
        );
        let (mut item, archive) = fixture_item(&cargo_lock);
        item.artifact
            .as_mut()
            .expect("fixture artifact")
            .source_lock
            .as_mut()
            .expect("fixture source lock")
            .cargo_lock_sha256 = CHECKSUM.to_owned();
        let root = tempfile::tempdir().expect("fixture root");
        persist_object(&root, &item, &archive);

        let plan = plan(&root, item);

        assert_eq!(plan.items[0].status, SourceBuildStatus::Blocked);
        assert!(
            plan.items[0].detail.contains("Cargo.lock SHA-256 mismatch"),
            "{}",
            plan.items[0].detail
        );
    }

    #[test]
    fn rejects_paths_outside_the_single_locked_crate_root() {
        assert!(validate_archive_path(Path::new("../escape"), "demo-1.0.0").is_err());
        assert!(validate_archive_path(Path::new("/absolute"), "demo-1.0.0").is_err());
        assert!(validate_archive_path(Path::new("other/Cargo.lock"), "demo-1.0.0").is_err());
        assert!(validate_archive_path(Path::new("demo-1.0.0\\Cargo.lock"), "demo-1.0.0").is_err());
    }
}
