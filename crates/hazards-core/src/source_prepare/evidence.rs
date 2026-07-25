use std::{
    fs::{self, File},
    io::{self, Write},
    path::Path,
};

use arsenallspice::{CargoSourceLock, LockedArtifact};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::archive::strict_tree_path;
use super::{
    MANIFEST_NAME, MANIFEST_SCHEMA_VERSION, MAX_ARCHIVE_ENTRIES, MAX_EVIDENCE_SIZE,
    MAX_EXPANDED_SIZE, PreparedSourceEntry, PreparedSourceEntryKind, SourcePreparationError,
    SourcePreparationManifest, SourcePreparationOutcome, io_error,
};
use crate::acquire::{set_private_file_permissions, sync_directory};

pub(super) fn inspect_tree(
    root: &Path,
) -> Result<Vec<PreparedSourceEntry>, SourcePreparationError> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| io_error("inspect prepared source root", root, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SourcePreparationError::CorruptStage {
            path: root.to_path_buf(),
            reason: "source staging root is not a real directory".to_owned(),
        });
    }
    verify_mode(root, &metadata, 0o700)?;

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
        .filter(|entry| entry.kind == PreparedSourceEntryKind::File)
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
    entries: &mut Vec<PreparedSourceEntry>,
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
        let relative = strict_tree_path(relative)?;
        let display = relative
            .to_str()
            .ok_or_else(|| SourcePreparationError::CorruptStage {
                path: path.clone(),
                reason: "path is not valid UTF-8".to_owned(),
            })?
            .to_owned();

        if metadata.file_type().is_symlink() {
            return Err(SourcePreparationError::CorruptStage {
                path,
                reason: "symbolic links are not accepted".to_owned(),
            });
        }
        if metadata.is_dir() {
            verify_mode(&path, &metadata, 0o700)?;
            entries.push(PreparedSourceEntry {
                path: display,
                kind: PreparedSourceEntryKind::Directory,
                size: 0,
                sha256: None,
            });
            inspect_directory(root, &path, entries)?;
        } else if metadata.is_file() {
            verify_mode(&path, &metadata, 0o600)?;
            entries.push(PreparedSourceEntry {
                path: display,
                kind: PreparedSourceEntryKind::File,
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

fn hash_file(path: &Path) -> Result<String, SourcePreparationError> {
    let mut file =
        File::open(path).map_err(|error| io_error("open prepared source file", path, error))?;
    let mut digest = Sha256::new();
    io::copy(&mut file, &mut digest)
        .map_err(|error| io_error("hash prepared source file", path, error))?;
    Ok(format!("{:x}", digest.finalize()))
}

pub(super) fn write_manifest(
    root: &Path,
    manifest: &SourcePreparationManifest,
) -> Result<(), SourcePreparationError> {
    let path = root.join(MANIFEST_NAME);
    write_json_noclobber(root, &path, manifest)?;
    sync_directory(root)?;
    Ok(())
}

pub(super) fn write_json_noclobber(
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
        .map_err(|error| io_error("create temporary evidence file", directory, error))?;
    temporary
        .write_all(&encoded)
        .map_err(|error| io_error("write source-preparation evidence", temporary.path(), error))?;
    temporary.as_file_mut().sync_all().map_err(|error| {
        io_error(
            "synchronize source-preparation evidence",
            temporary.path(),
            error,
        )
    })?;
    let file = temporary
        .persist_noclobber(path)
        .map_err(|error| io_error("persist source-preparation evidence", path, error.error))?;
    set_private_file_permissions(&file, path)?;
    sync_directory(directory)?;
    Ok(())
}

pub(super) fn validate_existing_stage(
    path: &Path,
    artifact: &LockedArtifact,
    source_lock: &CargoSourceLock,
) -> Result<SourcePreparationManifest, SourcePreparationError> {
    let stage_metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect prepared source stage", path, error))?;
    if stage_metadata.file_type().is_symlink() || !stage_metadata.is_dir() {
        return Err(SourcePreparationError::CorruptStage {
            path: path.to_path_buf(),
            reason: "prepared source path is not a real directory".to_owned(),
        });
    }
    verify_mode(path, &stage_metadata, 0o700)?;

    let manifest_path = path.join(MANIFEST_NAME);
    let metadata = fs::symlink_metadata(&manifest_path)
        .map_err(|error| io_error("inspect source-preparation manifest", &manifest_path, error))?;
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
        .map_err(|error| io_error("read source-preparation manifest", &manifest_path, error))?;
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
    Ok(manifest)
}

pub(super) fn persist_candidate(
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
                    reason:
                        "concurrent prepared source does not match the reproduced locked artifact"
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
