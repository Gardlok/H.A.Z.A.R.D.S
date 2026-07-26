use std::{
    collections::BTreeMap,
    env, io,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{AcquisitionItem, HazardsPaths, Platform, ResolvedProfile};

mod evidence;
mod planner;
mod probe_support;
#[cfg(test)]
mod tests;
mod util;

use util::{locate_command, run_bounded};

pub use planner::BuildContractPlanner;

const EMBEDDED_BUILD_CONTRACTS: &str =
    include_str!("../../../ingredients/arsenallspice/build-contracts.toml");
const MAX_EVIDENCE_SIZE: u64 = 16 * 1024 * 1024;
const MAX_PROBE_OUTPUT: u64 = 1024 * 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct BuildContractLock {
    pub schema_version: u8,
    pub observed_at: String,
    #[serde(default)]
    pub contracts: Vec<BuildContractSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct BuildContractSpec {
    pub tool_id: String,
    pub version: String,
    pub os: String,
    pub architecture: String,
    pub target: String,
    pub rust_release: String,
    pub rustc_commit_hash: String,
    pub rustc_commit_date: String,
    pub cargo_release: String,
    pub cargo_commit_hash: String,
    pub cargo_commit_date: String,
    pub llvm_major: u32,
    #[serde(default)]
    pub commands: Vec<BuildCommandSpec>,
    #[serde(default)]
    pub pkg_config: Vec<PkgConfigSpec>,
    pub environment: BuildEnvironmentSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct BuildCommandSpec {
    pub id: String,
    pub candidates: Vec<String>,
    pub args: Vec<String>,
    #[serde(default)]
    pub minimum_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PkgConfigSpec {
    pub module: String,
    pub minimum_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct BuildEnvironmentSpec {
    #[serde(default)]
    pub blocked_if_set: Vec<String>,
    #[serde(default)]
    pub clear_for_build: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildContractStatus {
    ContractReady,
    Unsupported,
    SourceEvidenceMissing,
    DependencyEvidenceMissing,
    ToolchainMissing,
    ToolchainMismatch,
    NativeRequirementMissing,
    NativeVersionMismatch,
    EnvironmentBlocked,
    EvidenceCorrupt,
}

impl std::fmt::Display for BuildContractStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::ContractReady => "contract-ready",
            Self::Unsupported => "unsupported",
            Self::SourceEvidenceMissing => "source-evidence-missing",
            Self::DependencyEvidenceMissing => "dependency-evidence-missing",
            Self::ToolchainMissing => "toolchain-missing",
            Self::ToolchainMismatch => "toolchain-mismatch",
            Self::NativeRequirementMissing => "native-requirement-missing",
            Self::NativeVersionMismatch => "native-version-mismatch",
            Self::EnvironmentBlocked => "environment-blocked",
            Self::EvidenceCorrupt => "evidence-corrupt",
        };
        formatter.write_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuildContractPlan {
    pub read_only: bool,
    pub execution_enabled: bool,
    pub lock_observed_at: String,
    pub profile: ResolvedProfile,
    pub platform: Platform,
    pub items: Vec<BuildContractItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuildContractItem {
    pub id: String,
    pub name: String,
    pub target_version: String,
    pub status: BuildContractStatus,
    pub detail: String,
    pub contract_sha256: Option<String>,
    pub source: Option<BuildSourceEvidence>,
    pub dependencies: Option<BuildDependencyEvidence>,
    pub toolchain: Option<RustToolchainEvidence>,
    pub native_commands: Vec<BuildCommandEvidence>,
    pub pkg_config: Vec<PkgConfigEvidence>,
    pub environment: BuildEnvironmentEvidence,
    pub invocation: Option<BuildInvocationTemplate>,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuildSourceEvidence {
    pub staging_path: PathBuf,
    pub source_path: PathBuf,
    pub manifest_path: PathBuf,
    pub cargo_manifest_path: PathBuf,
    pub cargo_lock_path: PathBuf,
    pub artifact_sha256: String,
    pub cargo_manifest_sha256: String,
    pub cargo_lock_sha256: String,
    pub cargo_lock_version: u32,
    pub package_count: usize,
    pub entry_count: usize,
    pub expanded_size: u64,
    pub rust_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuildDependencyEvidence {
    pub object_root: PathBuf,
    pub manifest_path: PathBuf,
    pub manifest_sha256: String,
    pub cargo_lock_sha256: String,
    pub dependency_count: usize,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RustToolchainEvidence {
    pub rustc_path: PathBuf,
    pub cargo_path: PathBuf,
    pub rustc_release: String,
    pub rustc_commit_hash: String,
    pub rustc_commit_date: String,
    pub host: String,
    pub llvm_version: String,
    pub cargo_release: String,
    pub cargo_commit_hash: Option<String>,
    pub cargo_commit_date: Option<String>,
    pub target: String,
    pub target_libdir: PathBuf,
    pub sysroot: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuildCommandEvidence {
    pub id: String,
    pub path: Option<PathBuf>,
    pub version: Option<String>,
    pub minimum_version: Option<String>,
    pub satisfied: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PkgConfigEvidence {
    pub module: String,
    pub version: Option<String>,
    pub minimum_version: String,
    pub satisfied: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuildEnvironmentEvidence {
    pub blocked: BTreeMap<String, String>,
    pub clear_for_build: Vec<String>,
    pub satisfied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuildInvocationTemplate {
    pub program: PathBuf,
    pub arguments: Vec<String>,
    pub current_dir: PathBuf,
    pub clear_environment: bool,
    pub remove_environment: Vec<String>,
    pub fixed_environment: BTreeMap<String, String>,
    pub network_enabled: bool,
}

pub trait BuildEnvironmentProbe {
    fn variable(&self, name: &str) -> Option<String>;
    fn locate(&self, candidates: &[String]) -> Option<PathBuf>;
    fn run(&self, executable: &Path, arguments: &[String]) -> Result<String, String>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemBuildEnvironmentProbe;

impl BuildEnvironmentProbe for SystemBuildEnvironmentProbe {
    fn variable(&self, name: &str) -> Option<String> {
        env::var(name).ok().filter(|value| !value.is_empty())
    }

    fn locate(&self, candidates: &[String]) -> Option<PathBuf> {
        candidates
            .iter()
            .find_map(|candidate| locate_command(candidate))
    }

    fn run(&self, executable: &Path, arguments: &[String]) -> Result<String, String> {
        run_bounded(executable, arguments)
    }
}

#[derive(Debug, Error)]
pub enum BuildContractError {
    #[error("could not parse or validate build contract lock: {0}")]
    Lock(String),
    #[error("artifact for {0} is not a locked crates.io source archive")]
    NotLockedSource(String),
    #[error("prepared source evidence is missing at {0}")]
    MissingSourceEvidence(PathBuf),
    #[error("Cargo dependency evidence is missing at {0}")]
    MissingDependencyEvidence(PathBuf),
    #[error("build evidence failed verification at {path}: {reason}")]
    CorruptEvidence { path: PathBuf, reason: String },
    #[error("{action} at {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not serialize build contract evidence: {0}")]
    Evidence(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ToolchainProbeFailure {
    Missing(String),
    Mismatch(String),
}

impl ToolchainProbeFailure {
    pub(super) fn detail(&self) -> &str {
        match self {
            Self::Missing(detail) | Self::Mismatch(detail) => detail,
        }
    }
}
