use std::collections::{BTreeMap, HashSet};

use super::evidence::{verify_dependency_evidence, verify_source_evidence};
use super::probe_support::{
    hash_contract, inspect_environment, invocation_template, probe_command, probe_pkg_config,
    probe_toolchain,
};
use super::util::{
    safe_command, safe_component, safe_environment_name, safe_module, safe_target, valid_date,
    valid_lower_hex, valid_release, version_at_least,
};
use super::{
    AcquisitionItem, BuildContractError, BuildContractItem, BuildContractLock, BuildContractPlan,
    BuildContractSpec, BuildContractStatus, BuildEnvironmentEvidence, BuildEnvironmentProbe,
    BuildEnvironmentSpec, HazardsPaths, Platform, ResolvedProfile, SystemBuildEnvironmentProbe,
    ToolchainProbeFailure, EMBEDDED_BUILD_CONTRACTS,
};

pub struct BuildContractPlanner<'a, P = SystemBuildEnvironmentProbe> {
    paths: &'a HazardsPaths,
    lock: BuildContractLock,
    probe: P,
}

impl<'a> BuildContractPlanner<'a, SystemBuildEnvironmentProbe> {
    pub fn for_paths(paths: &'a HazardsPaths) -> Result<Self, BuildContractError> {
        Self::with_probe(paths, SystemBuildEnvironmentProbe)
    }
}

impl<'a, P: BuildEnvironmentProbe> BuildContractPlanner<'a, P> {
    pub fn with_probe(paths: &'a HazardsPaths, probe: P) -> Result<Self, BuildContractError> {
        let lock = BuildContractLock::parse(EMBEDDED_BUILD_CONTRACTS)?;
        Ok(Self { paths, lock, probe })
    }

    pub fn from_lock(
        paths: &'a HazardsPaths,
        source: &str,
        probe: P,
    ) -> Result<Self, BuildContractError> {
        let lock = BuildContractLock::parse(source)?;
        Ok(Self { paths, lock, probe })
    }

    pub fn plan(
        &self,
        profile: &ResolvedProfile,
        platform: &Platform,
        items: &[AcquisitionItem],
    ) -> BuildContractPlan {
        BuildContractPlan {
            read_only: true,
            execution_enabled: false,
            lock_observed_at: self.lock.observed_at.clone(),
            profile: profile.clone(),
            platform: platform.clone(),
            items: items
                .iter()
                .map(|item| self.inspect(item, platform))
                .collect(),
        }
    }

    fn inspect(&self, item: &AcquisitionItem, platform: &Platform) -> BuildContractItem {
        let Some(contract) = self.lock.select(
            &item.id,
            &item.target_version,
            &platform.os,
            &platform.architecture,
        ) else {
            return blocked_item(
                item,
                BuildContractStatus::Unsupported,
                format!(
                    "no pinned build contract exists for {}/{}",
                    platform.os, platform.architecture
                ),
            );
        };

        let mut findings = Vec::new();
        let source = match verify_source_evidence(self.paths, item) {
            Ok(source) => Some(source),
            Err(BuildContractError::MissingSourceEvidence(path)) => {
                findings.push(format!("prepared source evidence is missing at {}", path.display()));
                None
            }
            Err(error) => {
                return blocked_item(
                    item,
                    BuildContractStatus::EvidenceCorrupt,
                    error.to_string(),
                );
            }
        };

        let dependencies = if source.is_some() {
            match verify_dependency_evidence(self.paths, item) {
                Ok(dependencies) => Some(dependencies),
                Err(BuildContractError::MissingDependencyEvidence(path)) => {
                    findings.push(format!(
                        "Cargo dependency evidence is missing at {}",
                        path.display()
                    ));
                    None
                }
                Err(error) => {
                    return blocked_item(
                        item,
                        BuildContractStatus::EvidenceCorrupt,
                        error.to_string(),
                    );
                }
            }
        } else {
            None
        };

        let mut native_commands = Vec::new();
        let mut toolchain = None;
        for command in &contract.commands {
            if command.id == "rustc" || command.id == "cargo" {
                continue;
            }
            native_commands.push(probe_command(&self.probe, command));
        }

        let rustc_spec = contract.commands.iter().find(|command| command.id == "rustc");
        let cargo_spec = contract.commands.iter().find(|command| command.id == "cargo");
        let toolchain_result = match (rustc_spec, cargo_spec) {
            (Some(rustc), Some(cargo)) => probe_toolchain(&self.probe, contract, rustc, cargo),
            _ => Err(ToolchainProbeFailure::Mismatch(
                "contract omits rustc or cargo command specification".to_owned(),
            )),
        };
        let toolchain_failure = match toolchain_result {
            Ok(evidence) => {
                toolchain = Some(evidence);
                None
            }
            Err(failure) => {
                findings.push(failure.detail().to_owned());
                Some(failure)
            }
        };

        let pkg_config_path = native_commands
            .iter()
            .find(|command| command.id == "pkg-config" && command.satisfied)
            .and_then(|command| command.path.as_deref());
        let pkg_config = contract
            .pkg_config
            .iter()
            .map(|requirement| probe_pkg_config(&self.probe, pkg_config_path, requirement))
            .collect::<Vec<_>>();
        let environment = inspect_environment(&self.probe, &contract.environment);

        if let Some(source) = &source {
            if let Some(minimum) = &source.rust_version {
                if !version_at_least(&contract.rust_release, minimum) {
                    findings.push(format!(
                        "pinned Rust {} is older than package rust-version {}",
                        contract.rust_release, minimum
                    ));
                }
            }
        }

        let invocation = match (&source, &toolchain) {
            (Some(source), Some(toolchain)) => match invocation_template(
                self.paths,
                contract,
                source,
                toolchain,
                &native_commands,
            ) {
                Ok(invocation) => Some(invocation),
                Err(error) => {
                    findings.push(error);
                    None
                }
            },
            _ => None,
        };

        let status = if source.is_none() {
            BuildContractStatus::SourceEvidenceMissing
        } else if dependencies.is_none() {
            BuildContractStatus::DependencyEvidenceMissing
        } else if matches!(toolchain_failure, Some(ToolchainProbeFailure::Missing(_))) {
            BuildContractStatus::ToolchainMissing
        } else if toolchain_failure.is_some()
            || source
                .as_ref()
                .and_then(|evidence| evidence.rust_version.as_ref())
                .is_some_and(|minimum| !version_at_least(&contract.rust_release, minimum))
        {
            BuildContractStatus::ToolchainMismatch
        } else if native_commands.iter().any(|command| command.path.is_none())
            || pkg_config.iter().any(|module| module.version.is_none())
        {
            BuildContractStatus::NativeRequirementMissing
        } else if native_commands.iter().any(|command| !command.satisfied)
            || pkg_config.iter().any(|module| !module.satisfied)
        {
            BuildContractStatus::NativeVersionMismatch
        } else if !environment.satisfied || invocation.is_none() {
            BuildContractStatus::EnvironmentBlocked
        } else {
            BuildContractStatus::ContractReady
        };

        for command in native_commands.iter().filter(|command| !command.satisfied) {
            findings.push(command.detail.clone());
        }
        for module in pkg_config.iter().filter(|module| !module.satisfied) {
            findings.push(module.detail.clone());
        }
        for name in environment.blocked.keys() {
            findings.push(format!("environment variable {name} is set"));
        }

        let contract_sha256 = if status == BuildContractStatus::ContractReady {
            Some(hash_contract(
                contract,
                source.as_ref().expect("ready source evidence"),
                dependencies.as_ref().expect("ready dependency evidence"),
                toolchain.as_ref().expect("ready toolchain evidence"),
                &native_commands,
                &pkg_config,
                &environment,
                invocation.as_ref().expect("ready invocation template"),
            ))
        } else {
            None
        };

        BuildContractItem {
            id: item.id.clone(),
            name: item.name.clone(),
            target_version: item.target_version.clone(),
            status,
            detail: status_detail(status),
            contract_sha256,
            source,
            dependencies,
            toolchain,
            native_commands,
            pkg_config,
            environment,
            invocation,
            findings,
        }
    }
}

impl BuildContractLock {
    pub fn embedded() -> Result<Self, BuildContractError> {
        Self::parse(EMBEDDED_BUILD_CONTRACTS)
    }

    pub fn parse(source: &str) -> Result<Self, BuildContractError> {
        let lock: Self =
            toml::from_str(source).map_err(|error| BuildContractError::Lock(error.to_string()))?;
        lock.validate()?;
        Ok(lock)
    }

    pub fn select(
        &self,
        tool_id: &str,
        version: &str,
        os: &str,
        architecture: &str,
    ) -> Option<&BuildContractSpec> {
        self.contracts.iter().find(|contract| {
            contract.tool_id == tool_id
                && contract.version == version
                && contract.os == os
                && contract.architecture == architecture
        })
    }

    fn validate(&self) -> Result<(), BuildContractError> {
        if self.schema_version != 1 {
            return Err(BuildContractError::Lock(format!(
                "unsupported build contract schema version {}",
                self.schema_version
            )));
        }
        if !valid_date(&self.observed_at) {
            return Err(BuildContractError::Lock(
                "build contract observation date is invalid".to_owned(),
            ));
        }
        if self.contracts.is_empty() {
            return Err(BuildContractError::Lock(
                "build contract lock contains no contracts".to_owned(),
            ));
        }
        let mut keys = HashSet::new();
        for contract in &self.contracts {
            if !safe_component(&contract.tool_id)
                || !safe_component(&contract.version)
                || !safe_component(&contract.os)
                || !safe_component(&contract.architecture)
                || !safe_target(&contract.target)
                || !contract
                    .target
                    .starts_with(&format!("{}-", contract.architecture))
                || !valid_release(&contract.rust_release)
                || !valid_release(&contract.cargo_release)
                || !valid_lower_hex(&contract.rustc_commit_hash, 40)
                || !valid_date(&contract.rustc_commit_date)
                || contract.llvm_major == 0
            {
                return Err(BuildContractError::Lock(format!(
                    "malformed build contract for {} {} {}/{}",
                    contract.tool_id, contract.version, contract.os, contract.architecture
                )));
            }
            if !keys.insert((
                contract.tool_id.as_str(),
                contract.version.as_str(),
                contract.os.as_str(),
                contract.architecture.as_str(),
            )) {
                return Err(BuildContractError::Lock(format!(
                    "duplicate build contract for {} {} {}/{}",
                    contract.tool_id, contract.version, contract.os, contract.architecture
                )));
            }
            validate_contract_commands(contract)?;
            validate_environment(&contract.environment)?;
        }
        Ok(())
    }
}

fn blocked_item(
    item: &AcquisitionItem,
    status: BuildContractStatus,
    detail: String,
) -> BuildContractItem {
    BuildContractItem {
        id: item.id.clone(),
        name: item.name.clone(),
        target_version: item.target_version.clone(),
        status,
        detail: detail.clone(),
        contract_sha256: None,
        source: None,
        dependencies: None,
        toolchain: None,
        native_commands: Vec::new(),
        pkg_config: Vec::new(),
        environment: BuildEnvironmentEvidence {
            blocked: BTreeMap::new(),
            clear_for_build: Vec::new(),
            satisfied: true,
        },
        invocation: None,
        findings: vec![detail],
    }
}

fn status_detail(status: BuildContractStatus) -> String {
    match status {
        BuildContractStatus::ContractReady => {
            "source, dependency cache, toolchain, native prerequisites, and environment match the pinned read-only build contract".to_owned()
        }
        BuildContractStatus::Unsupported => "no pinned build contract applies".to_owned(),
        BuildContractStatus::SourceEvidenceMissing => {
            "controlled source preparation must complete first".to_owned()
        }
        BuildContractStatus::DependencyEvidenceMissing => {
            "offline checksum-verified Cargo dependency caching must complete first".to_owned()
        }
        BuildContractStatus::ToolchainMissing => {
            "the pinned Rust toolchain is not available".to_owned()
        }
        BuildContractStatus::ToolchainMismatch => {
            "the observed Rust toolchain does not match the pinned identity".to_owned()
        }
        BuildContractStatus::NativeRequirementMissing => {
            "one or more reviewed native build prerequisites are missing".to_owned()
        }
        BuildContractStatus::NativeVersionMismatch => {
            "one or more native build prerequisites do not satisfy the contract".to_owned()
        }
        BuildContractStatus::EnvironmentBlocked => {
            "build-affecting environment variables must be removed before execution".to_owned()
        }
        BuildContractStatus::EvidenceCorrupt => {
            "existing source or dependency evidence failed verification".to_owned()
        }
    }
}

fn validate_contract_commands(contract: &BuildContractSpec) -> Result<(), BuildContractError> {
    let mut ids = HashSet::new();
    for command in &contract.commands {
        if !safe_component(&command.id)
            || command.candidates.is_empty()
            || command.args.is_empty()
            || command.candidates.iter().any(|candidate| !safe_command(candidate))
            || command.args.iter().any(|argument| argument.contains('\0'))
            || command
                .minimum_version
                .as_deref()
                .is_some_and(|version| !valid_release(version))
        {
            return Err(BuildContractError::Lock(format!(
                "invalid command requirement {} for {}",
                command.id, contract.tool_id
            )));
        }
        if !ids.insert(command.id.as_str()) {
            return Err(BuildContractError::Lock(format!(
                "duplicate command requirement {} for {}",
                command.id, contract.tool_id
            )));
        }
    }
    for required in ["rustc", "cargo", "pkg-config"] {
        if !ids.contains(required) {
            return Err(BuildContractError::Lock(format!(
                "build contract for {} omits {required}",
                contract.tool_id
            )));
        }
    }
    let mut modules = HashSet::new();
    for module in &contract.pkg_config {
        if !safe_module(&module.module)
            || !valid_release(&module.minimum_version)
            || !modules.insert(module.module.as_str())
        {
            return Err(BuildContractError::Lock(format!(
                "invalid pkg-config requirement {} for {}",
                module.module, contract.tool_id
            )));
        }
    }
    Ok(())
}

fn validate_environment(environment: &BuildEnvironmentSpec) -> Result<(), BuildContractError> {
    for values in [&environment.blocked_if_set, &environment.clear_for_build] {
        let mut seen = HashSet::new();
        for name in values {
            if !safe_environment_name(name) || !seen.insert(name.as_str()) {
                return Err(BuildContractError::Lock(format!(
                    "invalid or duplicate environment variable {name}"
                )));
            }
        }
    }
    if environment
        .blocked_if_set
        .iter()
        .any(|name| !environment.clear_for_build.contains(name))
    {
        return Err(BuildContractError::Lock(
            "every blocked environment variable must also be cleared for execution".to_owned(),
        ));
    }
    Ok(())
}
