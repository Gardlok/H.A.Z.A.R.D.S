use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Mutex,
};

use super::probe_support::inspect_environment;
use super::util::version_at_least;
use super::*;

type ProbeKey = (PathBuf, Vec<String>);
type ProbeOutput = Result<String, String>;
type ProbeOutputs = BTreeMap<ProbeKey, ProbeOutput>;

#[derive(Default)]
struct FakeProbe {
    variables: BTreeMap<String, String>,
    paths: BTreeMap<String, PathBuf>,
    outputs: Mutex<ProbeOutputs>,
}

impl BuildEnvironmentProbe for FakeProbe {
    fn variable(&self, name: &str) -> Option<String> {
        self.variables.get(name).cloned()
    }

    fn locate(&self, candidates: &[String]) -> Option<PathBuf> {
        candidates
            .iter()
            .find_map(|candidate| self.paths.get(candidate).cloned())
    }

    fn run(&self, executable: &Path, arguments: &[String]) -> Result<String, String> {
        self.outputs
            .lock()
            .expect("fake outputs lock")
            .get(&(executable.to_path_buf(), arguments.to_vec()))
            .cloned()
            .unwrap_or_else(|| Err("unexpected probe".to_owned()))
    }
}

#[test]
fn embedded_contract_lock_is_valid() {
    let lock = BuildContractLock::embedded().expect("embedded contract should parse");
    assert_eq!(lock.schema_version, 1);
    assert_eq!(lock.contracts.len(), 2);
    assert!(
        lock.select("alacritty", "0.17.0", "linux", "x86_64")
            .is_some()
    );
}

#[test]
fn duplicate_contract_targets_are_rejected() {
    let source = EMBEDDED_BUILD_CONTRACTS
        .replace("architecture = \"aarch64\"", "architecture = \"x86_64\"")
        .replace(
            "target = \"aarch64-unknown-linux-gnu\"",
            "target = \"x86_64-unknown-linux-gnu\"",
        );
    let error = BuildContractLock::parse(&source).expect_err("duplicate should fail");
    assert!(error.to_string().contains("duplicate build contract"));
}

#[test]
fn dangerous_environment_variables_block_without_disclosing_values() {
    let environment = BuildEnvironmentSpec {
        blocked_if_set: vec!["HTTPS_PROXY".to_owned()],
        clear_for_build: vec!["HTTPS_PROXY".to_owned()],
    };
    let mut probe = FakeProbe::default();
    probe.variables.insert(
        "HTTPS_PROXY".to_owned(),
        "https://secret:credential@example.invalid".to_owned(),
    );
    let evidence = inspect_environment(&probe, &environment);
    assert!(!evidence.satisfied);
    assert_eq!(evidence.blocked["HTTPS_PROXY"], "<set; value redacted>");
}

#[test]
fn numeric_versions_compare_without_lexicographic_surprises() {
    assert!(version_at_least("cmake version 3.25.1", "3.13.0"));
    assert!(version_at_least("1.97.1", "1.85.0"));
    assert!(!version_at_least("3.9.0", "3.13.0"));
}

#[test]
fn malformed_command_names_are_rejected() {
    let source = EMBEDDED_BUILD_CONTRACTS.replacen(
        "candidates = [\"rustc\"]",
        "candidates = [\"../rustc\"]",
        1,
    );
    let error = BuildContractLock::parse(&source).expect_err("unsafe command should fail");
    assert!(error.to_string().contains("invalid command requirement"));
}

#[test]
fn blocked_environment_variables_must_be_cleared_for_execution() {
    let source = EMBEDDED_BUILD_CONTRACTS.replacen(
        "clear_for_build = [\"RUSTFLAGS\", \"RUSTDOCFLAGS\"",
        "clear_for_build = [\"RUSTDOCFLAGS\"",
        1,
    );
    let error = BuildContractLock::parse(&source).expect_err("incomplete clearing should fail");
    assert!(
        error
            .to_string()
            .contains("every blocked environment variable")
    );
}
