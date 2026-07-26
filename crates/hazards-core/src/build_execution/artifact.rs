use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::{BuildInvocationTemplate, BuildSourceEvidence, HazardsPaths};

use super::{
    BuiltArtifactEvidence, SourceBuildError, ensure_private_directory, hash_file_bounded, io_error,
    sync_directory,
};

const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const ELF_HEADER_BYTES: usize = 64;
const ELF_MACHINE_X86_64: u16 = 62;
const ELF_MACHINE_AARCH64: u16 = 183;

pub(super) fn verify_and_store_artifact(
    paths: &HazardsPaths,
    invocation: &BuildInvocationTemplate,
    _source: &BuildSourceEvidence,
    build_root: &Path,
    expected_binary: &str,
) -> Result<BuiltArtifactEvidence, SourceBuildError> {
    let target_dir = invocation
        .fixed_environment
        .get("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| {
            SourceBuildError::Artifact("invocation omits CARGO_TARGET_DIR".to_owned())
        })?;
    if !target_dir.starts_with(build_root) {
        return Err(SourceBuildError::Artifact(
            "Cargo target directory escapes the private build root".to_owned(),
        ));
    }
    let target = invocation
        .arguments
        .windows(2)
        .find(|window| window[0] == "--target")
        .map(|window| window[1].as_str())
        .ok_or_else(|| SourceBuildError::Artifact("invocation omits --target".to_owned()))?;
    let release_dir = target_dir.join(target).join("release");
    let artifact_path = release_dir.join(expected_binary);
    let metadata = fs::symlink_metadata(&artifact_path)
        .map_err(|error| io_error("inspect built artifact", &artifact_path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SourceBuildError::Artifact(format!(
            "expected output {} is not a regular file",
            artifact_path.display()
        )));
    }
    if metadata.len() == 0 || metadata.len() > MAX_ARTIFACT_BYTES {
        return Err(SourceBuildError::Artifact(format!(
            "expected output has {} bytes; allowed range is 1..={MAX_ARTIFACT_BYTES}",
            metadata.len()
        )));
    }
    let mode = file_mode(&metadata);
    if mode & 0o111 == 0 || mode & 0o6000 != 0 {
        return Err(SourceBuildError::Artifact(format!(
            "expected output mode {mode:o} is not a safe executable mode"
        )));
    }
    reject_unexpected_top_level_executables(&release_dir, &artifact_path)?;
    let elf_machine = verify_elf(&artifact_path, target)?;
    let sha256 = hash_file_bounded(&artifact_path, MAX_ARTIFACT_BYTES)?;
    let object_path = store_result_object(paths, &artifact_path, &sha256, metadata.len())?;

    Ok(BuiltArtifactEvidence {
        name: expected_binary.to_owned(),
        source_path: artifact_path,
        object_path,
        sha256,
        size: metadata.len(),
        mode,
        elf_machine,
        target: target.to_owned(),
    })
}

fn reject_unexpected_top_level_executables(
    release_dir: &Path,
    expected: &Path,
) -> Result<(), SourceBuildError> {
    let entries = fs::read_dir(release_dir)
        .map_err(|error| io_error("read release output directory", release_dir, error))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| io_error("read release output entry", release_dir, error))?;
        let path = entry.path();
        if path == expected {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| io_error("inspect release output entry", &path, error))?;
        if metadata.file_type().is_symlink() {
            return Err(SourceBuildError::Artifact(format!(
                "release output contains unexpected symbolic link {}",
                path.display()
            )));
        }
        if metadata.is_file() && file_mode(&metadata) & 0o111 != 0 {
            return Err(SourceBuildError::Artifact(format!(
                "release output contains unexpected executable {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn verify_elf(path: &Path, target: &str) -> Result<u16, SourceBuildError> {
    let mut file = File::open(path).map_err(|error| io_error("open built ELF", path, error))?;
    let mut header = [0_u8; ELF_HEADER_BYTES];
    file.read_exact(&mut header)
        .map_err(|error| io_error("read built ELF header", path, error))?;
    if &header[..4] != b"\x7fELF" {
        return Err(SourceBuildError::Artifact(
            "built output is not an ELF executable".to_owned(),
        ));
    }
    if header[4] != 2 || header[5] != 1 || header[6] != 1 {
        return Err(SourceBuildError::Artifact(
            "built output is not a 64-bit little-endian ELF version 1 file".to_owned(),
        ));
    }
    let elf_type = u16::from_le_bytes([header[16], header[17]]);
    if elf_type != 2 && elf_type != 3 {
        return Err(SourceBuildError::Artifact(format!(
            "built ELF has unsupported type {elf_type}"
        )));
    }
    let machine = u16::from_le_bytes([header[18], header[19]]);
    let expected = if target.starts_with("x86_64-") {
        ELF_MACHINE_X86_64
    } else if target.starts_with("aarch64-") {
        ELF_MACHINE_AARCH64
    } else {
        return Err(SourceBuildError::Artifact(format!(
            "unsupported ELF target {target}"
        )));
    };
    if machine != expected {
        return Err(SourceBuildError::Artifact(format!(
            "built ELF machine {machine} does not match target {target} ({expected})"
        )));
    }
    Ok(machine)
}

fn store_result_object(
    paths: &HazardsPaths,
    source: &Path,
    sha256: &str,
    size: u64,
) -> Result<PathBuf, SourceBuildError> {
    let object_dir = paths
        .cache
        .join("build-results")
        .join("objects")
        .join("sha256")
        .join(&sha256[..2]);
    ensure_private_directory(&object_dir)?;
    let object_path = object_dir.join(sha256);
    match fs::symlink_metadata(&object_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() != size
                || file_mode(&metadata) & 0o111 == 0
                || file_mode(&metadata) & 0o6000 != 0
            {
                return Err(SourceBuildError::Artifact(format!(
                    "existing result object is invalid at {}",
                    object_path.display()
                )));
            }
            let actual = hash_file_bounded(&object_path, MAX_ARTIFACT_BYTES)?;
            if actual != sha256 {
                return Err(SourceBuildError::Artifact(format!(
                    "existing result object digest mismatch: expected {sha256}, found {actual}"
                )));
            }
            return Ok(object_path);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error("inspect result object", &object_path, error)),
    }

    let mut input =
        File::open(source).map_err(|error| io_error("open built artifact", source, error))?;
    let mut temporary = NamedTempFile::new_in(&object_dir)
        .map_err(|error| io_error("create temporary result object", &object_dir, error))?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|error| io_error("read built artifact", source, error))?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64).ok_or_else(|| {
            SourceBuildError::Artifact("result object size overflowed".to_owned())
        })?;
        if total > MAX_ARTIFACT_BYTES {
            return Err(SourceBuildError::Artifact(format!(
                "result object exceeds {MAX_ARTIFACT_BYTES} bytes"
            )));
        }
        temporary
            .write_all(&buffer[..read])
            .map_err(|error| io_error("write temporary result object", temporary.path(), error))?;
        digest.update(&buffer[..read]);
    }
    let actual = format!("{:x}", digest.finalize());
    if total != size || actual != sha256 {
        return Err(SourceBuildError::Artifact(format!(
            "result object changed while copying: expected {size} bytes and {sha256}, found {total} bytes and {actual}"
        )));
    }
    temporary.as_file_mut().sync_all().map_err(|error| {
        io_error(
            "synchronize temporary result object",
            temporary.path(),
            error,
        )
    })?;
    match temporary.persist_noclobber(&object_path) {
        Ok(file) => {
            set_result_permissions(&file, &object_path)?;
            sync_directory(&object_dir)?;
            Ok(object_path)
        }
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
            drop(error.file);
            let metadata = fs::symlink_metadata(&object_path).map_err(|source| {
                io_error("inspect concurrent result object", &object_path, source)
            })?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() != size
                || file_mode(&metadata) & 0o111 == 0
                || file_mode(&metadata) & 0o6000 != 0
                || hash_file_bounded(&object_path, MAX_ARTIFACT_BYTES)? != sha256
            {
                return Err(SourceBuildError::Artifact(format!(
                    "concurrent result object is invalid at {}",
                    object_path.display()
                )));
            }
            Ok(object_path)
        }
        Err(error) => Err(io_error("persist result object", &object_path, error.error)),
    }
}

fn file_mode(metadata: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o7777
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        0
    }
}

fn set_result_permissions(file: &File, path: &Path) -> Result<(), SourceBuildError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o500))
            .map_err(|error| io_error("set result object permissions", path, error))?;
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn verify_elf_for_test(path: &Path, target: &str) -> Result<u16, SourceBuildError> {
    verify_elf(path, target)
}
