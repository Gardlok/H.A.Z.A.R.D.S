use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};

use arsenallspice::{CargoSourceLock, LockedArtifact};
use flate2::read::GzDecoder;

use super::{
    BUFFER_SIZE, CRATES_IO_REGISTRY, GraphInspection, MAX_ARCHIVE_ENTRIES, MAX_COMPONENT_LENGTH,
    MAX_ENTRY_SIZE, MAX_EXPANDED_SIZE, MAX_METADATA_SIZE, MAX_PATH_LENGTH, SourcePreparationError,
    hash_bytes, io_error, valid_sha256,
};
use crate::acquire::set_private_file_permissions;

pub(super) fn extract_and_validate(
    artifact: &LockedArtifact,
    source_lock: &CargoSourceLock,
    object_path: &Path,
    destination: &Path,
) -> Result<GraphInspection, SourcePreparationError> {
    let object = File::open(object_path)
        .map_err(|error| io_error("open verified source object", object_path, error))?;
    let mut archive = tar::Archive::new(GzDecoder::new(object));
    let entries = archive
        .entries()
        .map_err(|error| SourcePreparationError::Archive(error.to_string()))?;
    let mut seen = HashSet::new();
    let mut entry_count = 0_usize;
    let mut expanded = 0_u64;

    for result in entries {
        let mut entry =
            result.map_err(|error| SourcePreparationError::Archive(error.to_string()))?;
        entry_count = entry_count
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
            .map_err(|error| SourcePreparationError::Archive(error.to_string()))?;
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
            output
                .sync_all()
                .map_err(|error| io_error("synchronize prepared source file", &target, error))?;
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

    let source_path = destination.join(&source_lock.root);
    let metadata = fs::symlink_metadata(&source_path)
        .map_err(|error| io_error("inspect prepared source root", &source_path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SourcePreparationError::Validation(
            "locked source root is not a real directory".to_owned(),
        ));
    }

    let manifest_path = source_path.join("Cargo.toml");
    let cargo_lock_path = source_path.join("Cargo.lock");
    let manifest = read_metadata_file(&manifest_path, "Cargo.toml")?;
    let cargo_lock = read_metadata_file(&cargo_lock_path, "Cargo.lock")?;
    require_digest("Cargo.toml", &manifest, &source_lock.manifest_sha256)?;
    require_digest("Cargo.lock", &cargo_lock, &source_lock.cargo_lock_sha256)?;
    validate_manifest(&manifest, &source_lock.package, &artifact.version)?;
    validate_cargo_lock(&cargo_lock, source_lock, &artifact.version)
}

pub(super) fn strict_source_path(
    path: &Path,
    root: &str,
) -> Result<PathBuf, SourcePreparationError> {
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
    if first != Component::Normal(root.as_ref()) {
        return Err(SourcePreparationError::UnsafeEntry {
            entry: text.to_owned(),
            reason: format!("path escapes locked source root {root}"),
        });
    }

    let mut relative = PathBuf::from(root);
    for component in components {
        match component {
            Component::Normal(value) if value.as_encoded_bytes().len() <= MAX_COMPONENT_LENGTH => {
                relative.push(value);
            }
            _ => {
                return Err(SourcePreparationError::UnsafeEntry {
                    entry: text.to_owned(),
                    reason: "only normal bounded path components are accepted".to_owned(),
                });
            }
        }
    }
    Ok(relative)
}

pub(super) fn strict_tree_path(path: &Path) -> Result<PathBuf, SourcePreparationError> {
    let text = path
        .to_str()
        .ok_or_else(|| SourcePreparationError::CorruptStage {
            path: path.to_path_buf(),
            reason: "path is not valid UTF-8".to_owned(),
        })?;
    if text.is_empty() || text.len() > MAX_PATH_LENGTH || text.contains('\\') {
        return Err(SourcePreparationError::CorruptStage {
            path: path.to_path_buf(),
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
                return Err(SourcePreparationError::CorruptStage {
                    path: path.to_path_buf(),
                    reason: "path contains a non-normal component".to_owned(),
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
        return Err(SourcePreparationError::Validation(format!(
            "source entry {entry} declared {declared} bytes but yielded {actual}"
        )));
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

fn read_metadata_file(path: &Path, label: &'static str) -> Result<Vec<u8>, SourcePreparationError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => SourcePreparationError::MissingMetadata(label),
        _ => io_error("inspect prepared source metadata", path, error),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SourcePreparationError::Validation(format!(
            "{label} is not a regular file"
        )));
    }
    if metadata.len() > MAX_METADATA_SIZE {
        return Err(SourcePreparationError::Validation(format!(
            "{label} exceeds the {MAX_METADATA_SIZE}-byte limit"
        )));
    }
    fs::read(path).map_err(|error| io_error("read prepared source metadata", path, error))
}

fn require_digest(label: &str, bytes: &[u8], expected: &str) -> Result<(), SourcePreparationError> {
    let actual = hash_bytes(bytes);
    if actual == expected {
        Ok(())
    } else {
        Err(SourcePreparationError::Validation(format!(
            "{label} SHA-256 mismatch: expected {expected}, found {actual}"
        )))
    }
}

fn validate_manifest(
    bytes: &[u8],
    package: &str,
    version: &str,
) -> Result<(), SourcePreparationError> {
    let source = std::str::from_utf8(bytes).map_err(|error| {
        SourcePreparationError::Validation(format!("Cargo.toml is not UTF-8: {error}"))
    })?;
    let manifest: toml::Value = toml::from_str(source).map_err(|error| {
        SourcePreparationError::Validation(format!("Cargo.toml is invalid: {error}"))
    })?;
    let table = manifest
        .get("package")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| {
            SourcePreparationError::Validation("Cargo.toml has no package table".to_owned())
        })?;
    if table.get("name").and_then(toml::Value::as_str) != Some(package)
        || table.get("version").and_then(toml::Value::as_str) != Some(version)
    {
        return Err(SourcePreparationError::Validation(format!(
            "Cargo.toml package identity does not match {package} {version}"
        )));
    }
    Ok(())
}

fn validate_cargo_lock(
    bytes: &[u8],
    source_lock: &CargoSourceLock,
    version: &str,
) -> Result<GraphInspection, SourcePreparationError> {
    let source = std::str::from_utf8(bytes).map_err(|error| {
        SourcePreparationError::Validation(format!("Cargo.lock is not UTF-8: {error}"))
    })?;
    let lock: toml::Value = toml::from_str(source).map_err(|error| {
        SourcePreparationError::Validation(format!("Cargo.lock is invalid: {error}"))
    })?;
    let lock_version = lock
        .get("version")
        .and_then(toml::Value::as_integer)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| {
            SourcePreparationError::Validation("Cargo.lock has no supported version".to_owned())
        })?;
    if lock_version != source_lock.cargo_lock_version {
        return Err(SourcePreparationError::Validation(format!(
            "Cargo.lock version mismatch: expected {}, found {lock_version}",
            source_lock.cargo_lock_version
        )));
    }
    let packages = lock
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| {
            SourcePreparationError::Validation("Cargo.lock has no package graph".to_owned())
        })?;
    if packages.len() != source_lock.package_count {
        return Err(SourcePreparationError::Validation(format!(
            "Cargo.lock package count mismatch: expected {}, found {}",
            source_lock.package_count,
            packages.len()
        )));
    }

    let mut registry_packages = 0_usize;
    let mut local_packages = 0_usize;
    for package in packages {
        let package = package.as_table().ok_or_else(|| {
            SourcePreparationError::Validation("Cargo.lock package entry is not a table".to_owned())
        })?;
        let name = package
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| {
                SourcePreparationError::Validation("Cargo.lock package has no name".to_owned())
            })?;
        let package_version = package
            .get("version")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| {
                SourcePreparationError::Validation(format!(
                    "Cargo.lock package {name} has no version"
                ))
            })?;
        match package.get("source").and_then(toml::Value::as_str) {
            None => {
                local_packages += 1;
                if name != source_lock.package || package_version != version {
                    return Err(SourcePreparationError::Validation(format!(
                        "Cargo.lock contains unexpected unlocked local package {name} {package_version}"
                    )));
                }
            }
            Some(source) if source == CRATES_IO_REGISTRY => {
                registry_packages += 1;
                let checksum = package
                    .get("checksum")
                    .and_then(toml::Value::as_str)
                    .ok_or_else(|| {
                        SourcePreparationError::Validation(format!(
                            "Cargo.lock registry package {name} {package_version} has no checksum"
                        ))
                    })?;
                if !valid_sha256(checksum) {
                    return Err(SourcePreparationError::Validation(format!(
                        "Cargo.lock registry package {name} {package_version} has an invalid checksum"
                    )));
                }
            }
            Some(source) => {
                return Err(SourcePreparationError::Validation(format!(
                    "Cargo.lock package {name} {package_version} uses unapproved source {source}"
                )));
            }
        }
    }
    if local_packages != 1 {
        return Err(SourcePreparationError::Validation(format!(
            "Cargo.lock must contain exactly one local root package, found {local_packages}"
        )));
    }
    Ok(GraphInspection {
        registry_packages,
        local_packages,
    })
}
