use std::io::Cursor;

use flate2::{Compression, write::GzEncoder};
use tar::{Builder as TarBuilder, EntryType, Header};

use super::{archive::strict_source_path, *};
use crate::ProvisionStatus;

const CHECKSUM: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn cargo_lock(source: &str) -> String {
    format!(
        "version = 4\n\n[[package]]\nname = \"demo\"\nversion = \"1.0.0\"\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"{source}\"\nchecksum = \"{CHECKSUM}\"\n"
    )
}

fn source_archive(lock: &str) -> (Vec<u8>, Vec<u8>) {
    let manifest = b"[package]\nname = \"demo\"\nversion = \"1.0.0\"\n".to_vec();
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = TarBuilder::new(encoder);
    for (path, bytes) in [
        ("demo-1.0.0/Cargo.toml", manifest.as_slice()),
        ("demo-1.0.0/Cargo.lock", lock.as_bytes()),
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
    let encoder = builder.into_inner().expect("fixture TAR should finish");
    (
        encoder.finish().expect("fixture GZip should finish"),
        manifest,
    )
}

fn fixture(lock: &str) -> (AcquisitionItem, Vec<u8>) {
    let (archive, manifest) = source_archive(lock);
    let artifact_sha256 = hash_bytes(&archive);
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
                    manifest_sha256: hash_bytes(&manifest),
                    cargo_lock_sha256: hash_bytes(lock.as_bytes()),
                    cargo_lock_version: 4,
                    package_count: 2,
                }),
            }),
            detail: String::new(),
        },
        archive,
    )
}

fn persist_object(root: &Path, item: &AcquisitionItem, archive: &[u8]) {
    let artifact = item.artifact.as_ref().expect("fixture artifact");
    let directory = root
        .join("cache/objects/sha256")
        .join(&artifact.sha256[..2]);
    fs::create_dir_all(&directory).expect("object directory");
    fs::write(directory.join(&artifact.sha256), archive).expect("fixture object");
}

#[test]
fn prepares_a_locked_source_tree_without_executable_permissions() {
    let root = tempfile::tempdir().expect("temporary root");
    let lock = cargo_lock(CRATES_IO_REGISTRY);
    let (item, archive) = fixture(&lock);
    persist_object(root.path(), &item, &archive);

    let prepared = SourcePreparer::new(root.path().join("cache"), root.path().join("state"))
        .prepare(&item)
        .expect("locked source should prepare");

    assert_eq!(prepared.receipt.outcome, SourcePreparationOutcome::Prepared);
    assert_eq!(prepared.receipt.registry_package_count, 1);
    assert_eq!(prepared.receipt.local_package_count, 1);
    assert!(prepared.source_path.join("Cargo.toml").is_file());
    assert!(prepared.manifest_path.is_file());
    assert!(prepared.receipt_path.is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(prepared.source_path.join("src/main.rs"))
                .expect("source metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&prepared.source_path)
                .expect("source root metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}

#[test]
fn stage_hit_requires_a_fresh_matching_reproduction() {
    let root = tempfile::tempdir().expect("temporary root");
    let lock = cargo_lock(CRATES_IO_REGISTRY);
    let (item, archive) = fixture(&lock);
    persist_object(root.path(), &item, &archive);
    let preparer = SourcePreparer::new(root.path().join("cache"), root.path().join("state"));

    let first = preparer.prepare(&item).expect("first preparation");
    let second = preparer.prepare(&item).expect("matching stage hit");

    assert_eq!(second.receipt.outcome, SourcePreparationOutcome::StageHit);
    assert_ne!(first.receipt_path, second.receipt_path);
}

#[test]
fn tampered_prepared_source_fails_closed() {
    let root = tempfile::tempdir().expect("temporary root");
    let lock = cargo_lock(CRATES_IO_REGISTRY);
    let (item, archive) = fixture(&lock);
    persist_object(root.path(), &item, &archive);
    let preparer = SourcePreparer::new(root.path().join("cache"), root.path().join("state"));
    let first = preparer.prepare(&item).expect("first preparation");
    fs::write(first.source_path.join("src/main.rs"), b"tampered\n").expect("tamper stage");

    assert!(matches!(
        preparer.prepare(&item),
        Err(SourcePreparationError::CorruptStage { .. })
    ));
}

#[test]
fn rejects_a_malformed_artifact_digest_before_building_a_cache_path() {
    let lock = cargo_lock(CRATES_IO_REGISTRY);
    let (mut item, _) = fixture(&lock);
    item.artifact
        .as_mut()
        .expect("fixture artifact")
        .sha256 = "short".to_owned();

    let root = tempfile::tempdir().expect("temporary root");
    let error = SourcePreparer::new(root.path().join("cache"), root.path().join("state"))
        .prepare(&item)
        .expect_err("malformed digest should be rejected");

    assert!(matches!(error, SourcePreparationError::Validation(_)));
    assert!(!root.path().join("cache").exists());
}

#[test]
fn independently_rejects_an_unapproved_dependency_source() {
    let root = tempfile::tempdir().expect("temporary root");
    let lock = cargo_lock("git+https://example.invalid/repository");
    let (item, archive) = fixture(&lock);
    persist_object(root.path(), &item, &archive);

    let error = SourcePreparer::new(root.path().join("cache"), root.path().join("state"))
        .prepare(&item)
        .expect_err("Git dependency should be rejected");

    assert!(error.to_string().contains("unapproved source"));
}

#[test]
fn rejects_links_and_paths_outside_the_locked_root() {
    assert!(strict_source_path(Path::new("../escape"), "demo-1.0.0").is_err());
    assert!(strict_source_path(Path::new("/absolute"), "demo-1.0.0").is_err());
    assert!(strict_source_path(Path::new("other/Cargo.toml"), "demo-1.0.0").is_err());

    let root = tempfile::tempdir().expect("temporary root");
    let lock = cargo_lock(CRATES_IO_REGISTRY);
    let (mut item, _) = fixture(&lock);
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = TarBuilder::new(encoder);
    let mut link = Header::new_gnu();
    link.set_entry_type(EntryType::Symlink);
    link.set_size(0);
    link.set_mode(0o777);
    link.set_link_name("../../escape").expect("link target");
    link.set_cksum();
    builder
        .append_data(&mut link, "demo-1.0.0/link", Cursor::new(Vec::<u8>::new()))
        .expect("link fixture");
    let encoder = builder.into_inner().expect("fixture TAR");
    let archive = encoder.finish().expect("fixture GZip");
    let artifact = item.artifact.as_mut().expect("fixture artifact");
    artifact.size = archive.len() as u64;
    artifact.sha256 = hash_bytes(&archive);
    persist_object(root.path(), &item, &archive);

    assert!(matches!(
        SourcePreparer::new(root.path().join("cache"), root.path().join("state"))
            .prepare(&item),
        Err(SourcePreparationError::UnsafeEntry { .. })
    ));
}
