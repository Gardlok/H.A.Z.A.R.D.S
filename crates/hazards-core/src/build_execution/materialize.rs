use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
};

use flate2::read::GzDecoder;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tar::Archive;

use crate::{
    AcquisitionItem, BuildContractItem, BuildInvocationTemplate, CachedCargoDependency,
    CargoDependencyAcquirer, CargoDependencyError, CargoDependencyPayload, CargoDependencySource,
    CargoDependencySpec, HazardsPaths,
};

use super::{
    SourceBuildError, ensure_private_directory, hash_file_bounded, io_error, set_private_file,
    sync_directory,
};

const MAX_SOURCE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_VENDOR_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_CRATE_ENTRIES: usize = 100_000;
const MAX_CRATE_ENTRY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PATH_LENGTH: usize = 4096;
const MAX_COMPONENT_LENGTH: usize = 255;

#[derive(Debug, Clone, Copy)]
struct NoNetworkSource;

impl CargoDependencySource for NoNetworkSource {
    fn open(
        &self,
        _dependency: &CargoDependencySpec,
    ) -> Result<CargoDependencyPayload, CargoDependencyError> {
        Err(CargoDependencyError::Validation(
            "network access is disabled during controlled build materialization".to_owned(),
        ))
    }
}

pub(super) fn materialize_build_inputs(
    paths: &HazardsPaths,
    item: &AcquisitionItem,
    contract: &BuildContractItem,
    invocation: &BuildInvocationTemplate,
    build_root: &Path,
    maximum_build_bytes: u64,
) -> Result<(), SourceBuildError> {
    match fs::symlink_metadata(build_root) {
        Ok(_) => {
            return Err(SourceBuildError::UnsafePath {
                path: build_root.to_path_buf(),
                reason: "build root already exists; refusing to reuse stale execution state"
                    .to_owned(),
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error("inspect build root", build_root, error)),
    }
    ensure_private_directory(build_root)?;

    let source = contract
        .source
        .as_ref()
        .ok_or(SourceBuildError::MissingSourceEvidence)?;
    let dependencies = contract
        .dependencies
        .as_ref()
        .ok_or(SourceBuildError::MissingDependencyEvidence)?;
    require_child(build_root, &invocation.current_dir, "source directory")?;
    copy_source_tree(&source.source_path, &invocation.current_dir, MAX_SOURCE_BYTES)?;
    require_digest(
        &invocation.current_dir.join("Cargo.toml"),
        &source.cargo_manifest_sha256,
    )?;
    require_digest(
        &invocation.current_dir.join("Cargo.lock"),
        &source.cargo_lock_sha256,
    )?;

    let verified = CargoDependencyAcquirer::new(
        NoNetworkSource,
        paths.cache.clone(),
        paths.state.clone(),
    )
    .verify_existing(item)?;
    if verified.manifest_sha256 != dependencies.manifest_sha256
        || verified.dependency_count != dependencies.dependency_count
        || verified.total_bytes != dependencies.total_bytes
    {
        return Err(SourceBuildError::Validation(
            "dependency evidence changed before build materialization".to_owned(),
        ));
    }

    let vendor_root = build_root.join("vendor");
    ensure_private_directory(&vendor_root)?;
    materialize_vendor(&verified.packages, &vendor_root, MAX_VENDOR_BYTES)?;

    let home = environment_path(invocation, "HOME")?;
    let cargo_home = environment_path(invocation, "CARGO_HOME")?;
    let target_dir = environment_path(invocation, "CARGO_TARGET_DIR")?;
    let tmp_dir = environment_path(invocation, "TMPDIR")?;
    for (label, path) in [
        ("HOME", &home),
        ("CARGO_HOME", &cargo_home),
        ("CARGO_TARGET_DIR", &target_dir),
        ("TMPDIR", &tmp_dir),
    ] {
        require_child(build_root, path, label)?;
        ensure_private_directory(path)?;
    }
    for name in [
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
    ] {
        let path = environment_path(invocation, name)?;
        require_child(build_root, &path, name)?;
        ensure_private_directory(&path)?;
    }

    write_cargo_config(&cargo_home, &vendor_root)?;
    let size = directory_size_bounded(build_root, maximum_build_bytes)?;
    if size > maximum_build_bytes {
        return Err(SourceBuildError::Validation(format!(
            "materialized build root uses {size} bytes; limit is {maximum_build_bytes}"
        )));
    }
    sync_directory(build_root)?;
    Ok(())
}

fn environment_path(
    invocation: &BuildInvocationTemplate,
    name: &str,
) -> Result<PathBuf, SourceBuildError> {
    invocation
        .fixed_environment
        .get(name)
        .map(PathBuf::from)
        .ok_or_else(|| SourceBuildError::Validation(format!("invocation omits {name}")))
}

fn require_child(root: &Path, path: &Path, label: &str) -> Result<(), SourceBuildError> {
    if !path.is_absolute() || !path.starts_with(root) || path == root {
        return Err(SourceBuildError::UnsafePath {
            path: path.to_path_buf(),
            reason: format!("{label} is not an absolute child of the private build root"),
        });
    }
    Ok(())
}

fn copy_source_tree(source: &Path, destination: &Path, maximum: u64) -> Result<(), SourceBuildError> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| io_error("inspect prepared source", source, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SourceBuildError::UnsafePath {
            path: source.to_path_buf(),
            reason: "prepared source is not a real directory".to_owned(),
        });
    }
    ensure_private_directory(destination)?;
    let mut total = 0_u64;
    copy_directory_contents(source, destination, &mut total, maximum)
}

fn copy_directory_contents(
    source: &Path,
    destination: &Path,
    total: &mut u64,
    maximum: u64,
) -> Result<(), SourceBuildError> {
    let mut entries = fs::read_dir(source)
        .map_err(|error| io_error("read source directory", source, error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_error("read source directory entry", source, error))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)
            .map_err(|error| io_error("inspect source entry", &source_path, error))?;
        if metadata.file_type().is_symlink() {
            return Err(SourceBuildError::UnsafePath {
                path: source_path,
                reason: "source copy refuses symbolic links".to_owned(),
            });
        }
        if metadata.is_dir() {
            ensure_private_directory(&destination_path)?;
            copy_directory_contents(&source_path, &destination_path, total, maximum)?;
        } else if metadata.is_file() {
            *total = total
                .checked_add(metadata.len())
                .ok_or_else(|| SourceBuildError::Validation("source size overflowed".to_owned()))?;
            if *total > maximum {
                return Err(SourceBuildError::Validation(format!(
                    "source copy exceeds {maximum} bytes"
                )));
            }
            copy_regular_file(&source_path, &destination_path, source_is_executable(&metadata))?;
        } else {
            return Err(SourceBuildError::UnsafePath {
                path: source_path,
                reason: "source entry is not a regular file or directory".to_owned(),
            });
        }
    }
    Ok(())
}

fn copy_regular_file(
    source: &Path,
    destination: &Path,
    executable: bool,
) -> Result<(), SourceBuildError> {
    let mut input = File::open(source).map_err(|error| io_error("open source file", source, error))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| io_error("create copied source file", destination, error))?;
    io::copy(&mut input, &mut output)
        .map_err(|error| io_error("copy source file", destination, error))?;
    output
        .sync_all()
        .map_err(|error| io_error("synchronize copied source file", destination, error))?;
    set_file_mode(&output, destination, executable)?;
    Ok(())
}

fn materialize_vendor(
    packages: &[CachedCargoDependency],
    vendor_root: &Path,
    maximum: u64,
) -> Result<(), SourceBuildError> {
    let mut total = 0_u64;
    for package in packages {
        let package_component = format!("{}-{}", package.name, package.version);
        if !safe_component(&package_component) {
            return Err(SourceBuildError::Validation(format!(
                "unsafe vendored package path {package_component}"
            )));
        }
        let package_root = vendor_root.join(&package_component);
        ensure_private_directory(&package_root)?;
        extract_crate(package, &package_root, &mut total, maximum)?;
    }
    sync_directory(vendor_root)?;
    Ok(())
}

fn extract_crate(
    package: &CachedCargoDependency,
    destination: &Path,
    total: &mut u64,
    maximum: u64,
) -> Result<(), SourceBuildError> {
    let file = File::open(&package.object_path)
        .map_err(|error| io_error("open verified crate object", &package.object_path, error))?;
    let mut archive = Archive::new(GzDecoder::new(file));
    let expected_root = format!("{}-{}", package.name, package.version);
    let mut seen = BTreeSet::new();
    let mut files = BTreeMap::new();
    let mut entry_count = 0_usize;

    let entries = archive.entries().map_err(|error| {
        SourceBuildError::Validation(format!(
            "could not read crate archive {} {}: {error}",
            package.name, package.version
        ))
    })?;
    for entry in entries {
        let mut entry = entry.map_err(|error| {
            SourceBuildError::Validation(format!(
                "could not read crate entry {} {}: {error}",
                package.name, package.version
            ))
        })?;
        entry_count = entry_count
            .checked_add(1)
            .ok_or_else(|| SourceBuildError::Validation("crate entry count overflowed".to_owned()))?;
        if entry_count > MAX_CRATE_ENTRIES {
            return Err(SourceBuildError::Validation(format!(
                "crate {} {} contains more than {MAX_CRATE_ENTRIES} entries",
                package.name, package.version
            )));
        }
        let archive_path = entry
            .path()
            .map_err(|error| SourceBuildError::Validation(error.to_string()))?
            .into_owned();
        let relative = validated_crate_path(&archive_path, &expected_root)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        if !seen.insert(relative.clone()) {
            return Err(SourceBuildError::Validation(format!(
                "crate {} {} repeats {}",
                package.name,
                package.version,
                relative.display()
            )));
        }
        if relative == Path::new(".cargo-checksum.json") {
            return Err(SourceBuildError::Validation(format!(
                "crate {} {} contains a reserved checksum file",
                package.name, package.version
            )));
        }
        let entry_type = entry.header().entry_type();
        let output_path = destination.join(&relative);
        if entry_type.is_dir() {
            ensure_private_directory(&output_path)?;
            continue;
        }
        if !entry_type.is_file() {
            return Err(SourceBuildError::UnsafePath {
                path: archive_path,
                reason: "crate entry is not a regular file or directory".to_owned(),
            });
        }
        let size = entry.size();
        if size > MAX_CRATE_ENTRY_BYTES {
            return Err(SourceBuildError::Validation(format!(
                "crate entry {} exceeds {MAX_CRATE_ENTRY_BYTES} bytes",
                relative.display()
            )));
        }
        *total = total
            .checked_add(size)
            .ok_or_else(|| SourceBuildError::Validation("vendor size overflowed".to_owned()))?;
        if *total > maximum {
            return Err(SourceBuildError::Validation(format!(
                "vendored dependency tree exceeds {maximum} bytes"
            )));
        }
        let parent = output_path.parent().ok_or_else(|| {
            SourceBuildError::Validation("vendored file has no parent".to_owned())
        })?;
        ensure_private_directory(parent)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output_path)
            .map_err(|error| io_error("create vendored file", &output_path, error))?;
        let (written, digest) = copy_and_hash(&mut entry, &mut output, size, &output_path)?;
        if written != size {
            return Err(SourceBuildError::Validation(format!(
                "vendored file {} was truncated",
                relative.display()
            )));
        }
        output
            .sync_all()
            .map_err(|error| io_error("synchronize vendored file", &output_path, error))?;
        let executable = entry.header().mode().unwrap_or_default() & 0o111 != 0;
        set_file_mode(&output, &output_path, executable)?;
        files.insert(path_key(&relative)?, digest);
    }
    if !destination.join("Cargo.toml").is_file() {
        return Err(SourceBuildError::Validation(format!(
            "crate {} {} omitted Cargo.toml",
            package.name, package.version
        )));
    }
    write_checksum_file(destination, files, &package.checksum)?;
    sync_directory(destination)?;
    Ok(())
}

fn validated_crate_path(path: &Path, root: &str) -> Result<PathBuf, SourceBuildError> {
    let encoded = path
        .to_str()
        .ok_or_else(|| SourceBuildError::UnsafePath {
            path: path.to_path_buf(),
            reason: "crate path is not UTF-8".to_owned(),
        })?;
    if encoded.is_empty() || encoded.len() > MAX_PATH_LENGTH || encoded.contains('\\') {
        return Err(SourceBuildError::UnsafePath {
            path: path.to_path_buf(),
            reason: "crate path is empty, too long, or uses backslashes".to_owned(),
        });
    }
    let mut components = path.components();
    match components.next() {
        Some(Component::Normal(value)) if value.to_str() == Some(root) => {}
        _ => {
            return Err(SourceBuildError::UnsafePath {
                path: path.to_path_buf(),
                reason: format!("crate path escapes locked root {root}"),
            });
        }
    }
    let mut relative = PathBuf::new();
    for component in components {
        match component {
            Component::Normal(value) if value.as_encoded_bytes().len() <= MAX_COMPONENT_LENGTH => {
                relative.push(value)
            }
            _ => {
                return Err(SourceBuildError::UnsafePath {
                    path: path.to_path_buf(),
                    reason: "crate path contains an unsafe component".to_owned(),
                });
            }
        }
    }
    Ok(relative)
}

fn copy_and_hash(
    reader: &mut dyn Read,
    writer: &mut File,
    expected: u64,
    path: &Path,
) -> Result<(u64, String), SourceBuildError> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| io_error("read crate entry", path, error))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| SourceBuildError::Validation("crate entry size overflowed".to_owned()))?;
        if total > expected {
            return Err(SourceBuildError::Validation(format!(
                "crate entry {} exceeded its declared size",
                path.display()
            )));
        }
        writer
            .write_all(&buffer[..read])
            .map_err(|error| io_error("write vendored file", path, error))?;
        digest.update(&buffer[..read]);
    }
    Ok((total, format!("{:x}", digest.finalize())))
}

#[derive(Serialize)]
struct CargoChecksum<'a> {
    files: BTreeMap<String, String>,
    package: &'a str,
}

fn write_checksum_file(
    destination: &Path,
    files: BTreeMap<String, String>,
    package_checksum: &str,
) -> Result<(), SourceBuildError> {
    let path = destination.join(".cargo-checksum.json");
    let encoded = serde_json::to_vec(&CargoChecksum {
        files,
        package: package_checksum,
    })
    .map_err(|error| SourceBuildError::Evidence(error.to_string()))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| io_error("create Cargo checksum file", &path, error))?;
    output
        .write_all(&encoded)
        .map_err(|error| io_error("write Cargo checksum file", &path, error))?;
    output
        .sync_all()
        .map_err(|error| io_error("synchronize Cargo checksum file", &path, error))?;
    set_private_file(&output, &path)
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct CargoSourceConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    replace_with: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    directory: Option<String>,
}

#[derive(Serialize)]
struct CargoNetConfig {
    offline: bool,
}

#[derive(Serialize)]
struct CargoConfig {
    source: BTreeMap<String, CargoSourceConfig>,
    net: CargoNetConfig,
}

fn write_cargo_config(cargo_home: &Path, vendor_root: &Path) -> Result<(), SourceBuildError> {
    let vendor = vendor_root
        .to_str()
        .ok_or_else(|| SourceBuildError::Validation("vendor path is not UTF-8".to_owned()))?;
    let mut source = BTreeMap::new();
    source.insert(
        "crates-io".to_owned(),
        CargoSourceConfig {
            replace_with: Some("hazards-vendor".to_owned()),
            directory: None,
        },
    );
    source.insert(
        "hazards-vendor".to_owned(),
        CargoSourceConfig {
            replace_with: None,
            directory: Some(vendor.to_owned()),
        },
    );
    let encoded = toml::to_string(&CargoConfig {
        source,
        net: CargoNetConfig { offline: true },
    })
    .map_err(|error| SourceBuildError::Evidence(error.to_string()))?;
    let path = cargo_home.join("config.toml");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| io_error("create controlled Cargo config", &path, error))?;
    file.write_all(encoded.as_bytes())
        .map_err(|error| io_error("write controlled Cargo config", &path, error))?;
    file.sync_all()
        .map_err(|error| io_error("synchronize controlled Cargo config", &path, error))?;
    set_private_file(&file, &path)?;
    sync_directory(cargo_home)
}

fn path_key(path: &Path) -> Result<String, SourceBuildError> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => parts.push(value.to_str().ok_or_else(|| {
                SourceBuildError::Validation("vendor path is not UTF-8".to_owned())
            })?),
            _ => {
                return Err(SourceBuildError::Validation(
                    "vendor path contains a non-normal component".to_owned(),
                ));
            }
        }
    }
    Ok(parts.join("/"))
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+')
        })
}

fn source_is_executable(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

fn set_file_mode(file: &File, path: &Path, executable: bool) -> Result<(), SourceBuildError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if executable { 0o700 } else { 0o600 };
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|error| io_error("set materialized file permissions", path, error))?;
    }
    Ok(())
}

fn require_digest(path: &Path, expected: &str) -> Result<(), SourceBuildError> {
    let actual = hash_file_bounded(path, 16 * 1024 * 1024)?;
    if actual == expected {
        Ok(())
    } else {
        Err(SourceBuildError::Validation(format!(
            "copied source digest mismatch at {}: expected {expected}, found {actual}",
            path.display()
        )))
    }
}

pub(super) fn directory_size_bounded(path: &Path, maximum: u64) -> Result<u64, SourceBuildError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect build-tree entry", path, error))?;
    if metadata.file_type().is_symlink() {
        return Err(SourceBuildError::UnsafePath {
            path: path.to_path_buf(),
            reason: "build tree contains a symbolic link".to_owned(),
        });
    }
    if metadata.is_file() {
        return Ok(metadata.len());
    }
    if !metadata.is_dir() {
        return Err(SourceBuildError::UnsafePath {
            path: path.to_path_buf(),
            reason: "build tree contains a special file".to_owned(),
        });
    }
    let mut total = 0_u64;
    for entry in
        fs::read_dir(path).map_err(|error| io_error("read build-tree directory", path, error))?
    {
        let entry = entry.map_err(|error| io_error("read build-tree entry", path, error))?;
        total = total
            .checked_add(directory_size_bounded(&entry.path(), maximum)?)
            .ok_or_else(|| SourceBuildError::Validation("build-tree size overflowed".to_owned()))?;
        if total > maximum {
            return Ok(total);
        }
    }
    Ok(total)
}
