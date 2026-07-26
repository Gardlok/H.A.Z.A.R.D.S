use std::{fs, io::Write};

use super::artifact::verify_elf_for_test;
use super::*;

#[test]
fn confirmation_is_exact_and_lowercase() {
    let digest = "a".repeat(64);
    assert_eq!(
        parse_confirmation(&format!("sha256:{digest}")).expect("valid confirmation"),
        digest.as_str()
    );
    assert!(matches!(
        parse_confirmation(&format!("SHA256:{digest}")),
        Err(SourceBuildError::MalformedConfirmation)
    ));
    assert!(matches!(
        parse_confirmation(&format!("sha256:{}", "A".repeat(64))),
        Err(SourceBuildError::MalformedConfirmation)
    ));
    assert!(matches!(
        parse_confirmation("sha256:deadbeef"),
        Err(SourceBuildError::MalformedConfirmation)
    ));
}

#[test]
fn elf_machine_must_match_the_pinned_target() {
    let root = tempfile::tempdir().expect("temporary root should exist");
    let path = root.path().join("alacritty");
    let mut header = [0_u8; 64];
    header[..4].copy_from_slice(b"\x7fELF");
    header[4] = 2;
    header[5] = 1;
    header[6] = 1;
    header[16..18].copy_from_slice(&3_u16.to_le_bytes());
    header[18..20].copy_from_slice(&62_u16.to_le_bytes());
    let mut file = fs::File::create(&path).expect("ELF fixture should be created");
    file.write_all(&header)
        .expect("ELF fixture should be written");

    assert_eq!(
        verify_elf_for_test(&path, "x86_64-unknown-linux-gnu").expect("x86_64 ELF should pass"),
        62
    );
    let error = verify_elf_for_test(&path, "aarch64-unknown-linux-gnu")
        .expect_err("wrong machine should fail");
    assert!(error.to_string().contains("does not match"));
}

#[test]
fn default_limits_are_bounded() {
    let limits = BuildExecutionLimits::default();
    assert_eq!(limits.timeout_seconds, 3600);
    assert_eq!(limits.maximum_output_bytes, 16 * 1024 * 1024);
    assert_eq!(limits.maximum_build_bytes, 8 * 1024 * 1024 * 1024);
}
