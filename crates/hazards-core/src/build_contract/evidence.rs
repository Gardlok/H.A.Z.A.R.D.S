use std::{fs, io, path::Path};

use crate::{CargoDependencyAcquirer, SourcePreparer};

use super::{
    AcquisitionItem, BuildContractError, BuildDependencyEvidence, BuildSourceEvidence, HazardsPaths,
    MAX_EVIDENCE_SIZE,
};
use super::util::{hash_bytes, valid_release};

pub(super) fn verify_source_evidence(
    paths: &HazardsPaths,
    item: &AcquisitionItem,
) -> Result<BuildSourceEvidence, BuildContractError> {
    let artifact = item
        .artifact
        .as_ref()
        .ok_or_else(|| BuildContractError::NotLockedSource(item.id.clone()))?;
    let source_lock = artifact
        .source_lock
        .as_ref()
        .ok_or_else(|| BuildContractError::NotLockedSource(item.id.clone()))?;
    let staging_path = paths
        .cache
        .join("sources")
        .join("sha256")
        .join(artifact.sha256.get(..2).unwrap_or("invalid"))
        .join(&artifact.sha256);
    if missing(&staging_path)? {
        return Err(BuildContractError::MissingSourceEvidence(staging_path));
    }

    let verified = SourcePreparer::for_paths(paths)
        .verify_existing(item)
        .map_err(|error| BuildContractError::CorruptEvidence {
            path: staging_path,
            reason: error.to_string(),
        })?;
    let manifest_bytes = read_bounded(&verified.cargo_manifest_path, MAX_EVIDENCE_SIZE)?;
    if hash_bytes(&manifest_bytes) != verified.manifest_sha256 {
        return Err(BuildContractError::CorruptEvidence {
            path: verified.cargo_manifest_path,
            reason: "Cargo.toml digest changed after source verification".to_owned(),
        });
    }
    let manifest_source = std::str::from_utf8(&manifest_bytes).map_err(|error| {
        BuildContractError::CorruptEvidence {
            path: verified.cargo_manifest_path.clone(),
            reason: format!("Cargo.toml is not UTF-8: {error}"),
        }
    })?;
    let manifest: toml::Value = toml::from_str(manifest_source).map_err(|error| {
        BuildContractError::CorruptEvidence {
            path: verified.cargo_manifest_path.clone(),
            reason: format!("Cargo.toml is invalid: {error}"),
        }
    })?;
    let package = manifest
        .get("package")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| BuildContractError::CorruptEvidence {
            path: verified.cargo_manifest_path.clone(),
            reason: "Cargo.toml has no package table".to_owned(),
        })?;
    if package.get("name").and_then(toml::Value::as_str) != Some(source_lock.package.as_str())
        || package.get("version").and_then(toml::Value::as_str) != Some(item.target_version.as_str())
    {
        return Err(BuildContractError::CorruptEvidence {
            path: verified.cargo_manifest_path,
            reason: "Cargo.toml package identity does not match the locked source".to_owned(),
        });
    }
    let rust_version = package
        .get("rust-version")
        .and_then(toml::Value::as_str)
        .map(str::to_owned);
    if rust_version
        .as_deref()
        .is_some_and(|version| !valid_release(version))
    {
        return Err(BuildContractError::CorruptEvidence {
            path: verified.cargo_manifest_path,
            reason: "Cargo.toml rust-version is malformed".to_owned(),
        });
    }

    Ok(BuildSourceEvidence {
        staging_path: verified.staging_path,
        source_path: verified.source_path,
        manifest_path: verified.manifest_path,
        cargo_manifest_path: verified.cargo_manifest_path,
        cargo_lock_path: verified.cargo_lock_path,
        artifact_sha256: verified.artifact_sha256,
        cargo_manifest_sha256: verified.manifest_sha256,
        cargo_lock_sha256: verified.cargo_lock_sha256,
        cargo_lock_version: verified.cargo_lock_version,
        package_count: verified.package_count,
        entry_count: verified.entry_count,
        expanded_size: verified.expanded_size,
        rust_version,
    })
}

pub(super) fn verify_dependency_evidence(
    paths: &HazardsPaths,
    item: &AcquisitionItem,
) -> Result<BuildDependencyEvidence, BuildContractError> {
    let source_lock = item
        .artifact
        .as_ref()
        .and_then(|artifact| artifact.source_lock.as_ref())
        .ok_or_else(|| BuildContractError::NotLockedSource(item.id.clone()))?;
    let manifest_path = paths
        .cache
        .join("cargo")
        .join("dependency-graphs")
        .join("sha256")
        .join(source_lock.cargo_lock_sha256.get(..2).unwrap_or("invalid"))
        .join(format!("{}.json", source_lock.cargo_lock_sha256));
    if missing(&manifest_path)? {
        return Err(BuildContractError::MissingDependencyEvidence(manifest_path));
    }

    let verifier = CargoDependencyAcquirer::for_paths(paths).map_err(|error| {
        BuildContractError::CorruptEvidence {
            path: manifest_path.clone(),
            reason: format!("could not initialize dependency verifier: {error}"),
        }
    })?;
    let verified = verifier
        .verify_existing(item)
        .map_err(|error| BuildContractError::CorruptEvidence {
            path: manifest_path,
            reason: error.to_string(),
        })?;

    Ok(BuildDependencyEvidence {
        object_root: verified.object_root,
        manifest_path: verified.manifest_path,
        manifest_sha256: verified.manifest_sha256,
        cargo_lock_sha256: source_lock.cargo_lock_sha256.clone(),
        dependency_count: verified.dependency_count,
        total_bytes: verified.total_bytes,
    })
}

fn missing(path: &Path) -> Result<bool, BuildContractError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(source) => Err(BuildContractError::Io {
            action: "inspect build evidence path",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, BuildContractError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| BuildContractError::Io {
        action: "inspect build evidence file",
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return Err(BuildContractError::CorruptEvidence {
            path: path.to_path_buf(),
            reason: "build evidence is not a bounded regular file".to_owned(),
        });
    }
    fs::read(path).map_err(|source| BuildContractError::Io {
        action: "read build evidence file",
        path: path.to_path_buf(),
        source,
    })
}
