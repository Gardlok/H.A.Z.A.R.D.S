use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    path::Path,
};

use serde::Serialize;

use super::util::{
    canonical_existing_directory, canonical_existing_executable, first_line, first_release,
    hash_bytes, leading_version, parse_verbose_version, version_at_least,
};
use super::{
    BuildCommandEvidence, BuildCommandSpec, BuildContractSpec, BuildDependencyEvidence,
    BuildEnvironmentEvidence, BuildEnvironmentProbe, BuildEnvironmentSpec, BuildInvocationTemplate,
    BuildSourceEvidence, HazardsPaths, PkgConfigEvidence, PkgConfigSpec, RustToolchainEvidence,
    ToolchainProbeFailure,
};

pub(super) fn probe_toolchain<P: BuildEnvironmentProbe>(
    probe: &P,
    contract: &BuildContractSpec,
    rustc_spec: &BuildCommandSpec,
    cargo_spec: &BuildCommandSpec,
) -> Result<RustToolchainEvidence, ToolchainProbeFailure> {
    let rustc_launcher = probe
        .locate(&rustc_spec.candidates)
        .ok_or_else(|| ToolchainProbeFailure::Missing("rustc was not found".to_owned()))?;
    let cargo_launcher = probe
        .locate(&cargo_spec.candidates)
        .ok_or_else(|| ToolchainProbeFailure::Missing("cargo was not found".to_owned()))?;

    let sysroot_arguments = vec!["--print".to_owned(), "sysroot".to_owned()];
    let sysroot_output = probe
        .run(&rustc_launcher, &sysroot_arguments)
        .map_err(|error| {
            ToolchainProbeFailure::Mismatch(format!("rustc sysroot probe failed: {error}"))
        })?;
    let sysroot = canonical_existing_directory(Path::new(sysroot_output.trim()))
        .map_err(ToolchainProbeFailure::Mismatch)?;
    let rustc_path = canonical_existing_executable(&sysroot.join("bin").join("rustc"))
        .map_err(ToolchainProbeFailure::Mismatch)?;
    let cargo_path = canonical_existing_executable(&sysroot.join("bin").join("cargo"))
        .map_err(ToolchainProbeFailure::Mismatch)?;

    let rustc_output = probe
        .run(&rustc_path, &rustc_spec.args)
        .map_err(|error| ToolchainProbeFailure::Mismatch(format!("rustc probe failed: {error}")))?;
    let cargo_output = probe
        .run(&cargo_path, &cargo_spec.args)
        .map_err(|error| ToolchainProbeFailure::Mismatch(format!("cargo probe failed: {error}")))?;
    let rustc = parse_verbose_version(&rustc_output);
    let cargo = parse_verbose_version(&cargo_output);
    let rustc_release = rustc
        .get("release")
        .cloned()
        .or_else(|| first_release(&rustc_output))
        .ok_or_else(|| ToolchainProbeFailure::Mismatch("rustc output has no release".to_owned()))?;
    let rustc_commit_hash = rustc.get("commit-hash").cloned().ok_or_else(|| {
        ToolchainProbeFailure::Mismatch("rustc output has no commit hash".to_owned())
    })?;
    let rustc_commit_date = rustc.get("commit-date").cloned().ok_or_else(|| {
        ToolchainProbeFailure::Mismatch("rustc output has no commit date".to_owned())
    })?;
    let host = rustc
        .get("host")
        .cloned()
        .ok_or_else(|| ToolchainProbeFailure::Mismatch("rustc output has no host".to_owned()))?;
    let llvm_version = rustc
        .get("LLVM version")
        .cloned()
        .or_else(|| rustc.get("llvm version").cloned())
        .ok_or_else(|| {
            ToolchainProbeFailure::Mismatch("rustc output has no LLVM version".to_owned())
        })?;
    let cargo_release = cargo
        .get("release")
        .cloned()
        .or_else(|| first_release(&cargo_output))
        .ok_or_else(|| ToolchainProbeFailure::Mismatch("cargo output has no release".to_owned()))?;
    let cargo_commit_hash = cargo.get("commit-hash").cloned();
    let cargo_commit_date = cargo.get("commit-date").cloned();
    let cargo_host = cargo.get("host").cloned();

    if rustc_release != contract.rust_release
        || rustc_commit_hash != contract.rustc_commit_hash
        || rustc_commit_date != contract.rustc_commit_date
        || cargo_release != contract.cargo_release
        || cargo_commit_hash
            .as_deref()
            .is_some_and(|value| value != contract.rustc_commit_hash)
        || cargo_commit_date
            .as_deref()
            .is_some_and(|value| value != contract.rustc_commit_date)
        || cargo_host
            .as_deref()
            .is_some_and(|value| value != contract.target)
        || host != contract.target
        || leading_version(&llvm_version).first().copied() != Some(u64::from(contract.llvm_major))
    {
        return Err(ToolchainProbeFailure::Mismatch(format!(
            "toolchain identity mismatch: rustc {rustc_release} {rustc_commit_hash} {rustc_commit_date}, cargo {cargo_release} {} {}, host {host}, LLVM {llvm_version}",
            cargo_commit_hash.as_deref().unwrap_or("missing"),
            cargo_commit_date.as_deref().unwrap_or("missing")
        )));
    }

    let target_arguments = vec![
        "--print".to_owned(),
        "target-libdir".to_owned(),
        "--target".to_owned(),
        contract.target.clone(),
    ];
    let target_libdir_output = probe.run(&rustc_path, &target_arguments).map_err(|error| {
        ToolchainProbeFailure::Mismatch(format!("target probe failed: {error}"))
    })?;
    let target_libdir = canonical_existing_directory(Path::new(target_libdir_output.trim()))
        .map_err(ToolchainProbeFailure::Mismatch)?;

    let _ = cargo_launcher;
    Ok(RustToolchainEvidence {
        rustc_path,
        cargo_path,
        rustc_release,
        rustc_commit_hash,
        rustc_commit_date,
        host,
        llvm_version,
        cargo_release,
        cargo_commit_hash,
        cargo_commit_date,
        target: contract.target.clone(),
        target_libdir,
        sysroot,
    })
}

pub(super) fn probe_command<P: BuildEnvironmentProbe>(
    probe: &P,
    spec: &BuildCommandSpec,
) -> BuildCommandEvidence {
    let Some(path) = probe.locate(&spec.candidates) else {
        return BuildCommandEvidence {
            id: spec.id.clone(),
            path: None,
            version: None,
            minimum_version: spec.minimum_version.clone(),
            satisfied: false,
            detail: format!("{} was not found", spec.id),
        };
    };
    match probe.run(&path, &spec.args) {
        Ok(output) => {
            let version = first_release(&output).or_else(|| first_line(&output));
            let satisfied = match (&spec.minimum_version, &version) {
                (Some(minimum), Some(actual)) => version_at_least(actual, minimum),
                (Some(_), None) => false,
                (None, _) => true,
            };
            BuildCommandEvidence {
                id: spec.id.clone(),
                path: Some(path),
                version: version.clone(),
                minimum_version: spec.minimum_version.clone(),
                satisfied,
                detail: if satisfied {
                    format!("{} probe satisfied the contract", spec.id)
                } else {
                    format!(
                        "{} version {} does not satisfy {}",
                        spec.id,
                        version.unwrap_or_else(|| "unknown".to_owned()),
                        spec.minimum_version.as_deref().unwrap_or("the contract")
                    )
                },
            }
        }
        Err(error) => BuildCommandEvidence {
            id: spec.id.clone(),
            path: Some(path),
            version: None,
            minimum_version: spec.minimum_version.clone(),
            satisfied: false,
            detail: format!("{} probe failed: {error}", spec.id),
        },
    }
}

pub(super) fn probe_pkg_config<P: BuildEnvironmentProbe>(
    probe: &P,
    pkg_config: Option<&Path>,
    requirement: &PkgConfigSpec,
) -> PkgConfigEvidence {
    let Some(pkg_config) = pkg_config else {
        return PkgConfigEvidence {
            module: requirement.module.clone(),
            version: None,
            minimum_version: requirement.minimum_version.clone(),
            satisfied: false,
            detail: format!(
                "pkg-config is unavailable for module {}",
                requirement.module
            ),
        };
    };
    let arguments = vec!["--modversion".to_owned(), requirement.module.clone()];
    match probe.run(pkg_config, &arguments) {
        Ok(output) => {
            let version = output.trim().to_owned();
            let satisfied = version_at_least(&version, &requirement.minimum_version);
            PkgConfigEvidence {
                module: requirement.module.clone(),
                version: Some(version.clone()),
                minimum_version: requirement.minimum_version.clone(),
                satisfied,
                detail: if satisfied {
                    format!(
                        "pkg-config module {} satisfied the contract",
                        requirement.module
                    )
                } else {
                    format!(
                        "pkg-config module {} version {version} does not satisfy {}",
                        requirement.module, requirement.minimum_version
                    )
                },
            }
        }
        Err(error) => PkgConfigEvidence {
            module: requirement.module.clone(),
            version: None,
            minimum_version: requirement.minimum_version.clone(),
            satisfied: false,
            detail: format!(
                "pkg-config module {} is unavailable: {error}",
                requirement.module
            ),
        },
    }
}

pub(super) fn inspect_environment<P: BuildEnvironmentProbe>(
    probe: &P,
    environment: &BuildEnvironmentSpec,
) -> BuildEnvironmentEvidence {
    let blocked = environment
        .blocked_if_set
        .iter()
        .filter(|name| probe.variable(name).is_some())
        .map(|name| (name.clone(), "<set; value redacted>".to_owned()))
        .collect::<BTreeMap<_, _>>();
    BuildEnvironmentEvidence {
        satisfied: blocked.is_empty(),
        blocked,
        clear_for_build: environment.clear_for_build.clone(),
    }
}

pub(super) fn invocation_template(
    paths: &HazardsPaths,
    contract: &BuildContractSpec,
    source: &BuildSourceEvidence,
    toolchain: &RustToolchainEvidence,
    commands: &[BuildCommandEvidence],
) -> Result<BuildInvocationTemplate, String> {
    let mut path_entries = BTreeSet::new();
    for path in std::iter::once(&toolchain.rustc_path)
        .chain(std::iter::once(&toolchain.cargo_path))
        .chain(commands.iter().filter_map(|command| command.path.as_ref()))
    {
        if let Some(parent) = path.parent() {
            path_entries.insert(parent.to_path_buf());
        }
    }
    let path = env::join_paths(path_entries)
        .map_err(|error| format!("could not encode controlled PATH: {error}"))?
        .to_string_lossy()
        .into_owned();
    let build_root = paths
        .cache
        .join("builds")
        .join(&source.artifact_sha256[..2])
        .join(&source.artifact_sha256);
    let mut fixed_environment = BTreeMap::new();
    fixed_environment.insert("PATH".to_owned(), path);
    fixed_environment.insert(
        "HOME".to_owned(),
        build_root.join("home").display().to_string(),
    );
    fixed_environment.insert(
        "CARGO_HOME".to_owned(),
        build_root.join("cargo-home").display().to_string(),
    );
    fixed_environment.insert(
        "CARGO_TARGET_DIR".to_owned(),
        build_root.join("target").display().to_string(),
    );
    fixed_environment.insert("CARGO_NET_OFFLINE".to_owned(), "true".to_owned());
    fixed_environment.insert("LANG".to_owned(), "C.UTF-8".to_owned());
    fixed_environment.insert("LC_ALL".to_owned(), "C.UTF-8".to_owned());
    fixed_environment.insert("TZ".to_owned(), "UTC".to_owned());
    fixed_environment.insert("SOURCE_DATE_EPOCH".to_owned(), "0".to_owned());

    Ok(BuildInvocationTemplate {
        program: toolchain.cargo_path.clone(),
        arguments: vec![
            "build".to_owned(),
            "--release".to_owned(),
            "--locked".to_owned(),
            "--offline".to_owned(),
            "--target".to_owned(),
            contract.target.clone(),
        ],
        current_dir: source.source_path.clone(),
        clear_environment: true,
        remove_environment: contract.environment.clear_for_build.clone(),
        fixed_environment,
        network_enabled: false,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn hash_contract(
    contract: &BuildContractSpec,
    source: &BuildSourceEvidence,
    dependencies: &BuildDependencyEvidence,
    toolchain: &RustToolchainEvidence,
    commands: &[BuildCommandEvidence],
    pkg_config: &[PkgConfigEvidence],
    environment: &BuildEnvironmentEvidence,
    invocation: &BuildInvocationTemplate,
) -> String {
    #[derive(Serialize)]
    struct Fingerprint<'a> {
        schema_version: u8,
        contract: &'a BuildContractSpec,
        source: &'a BuildSourceEvidence,
        dependencies: &'a BuildDependencyEvidence,
        toolchain: &'a RustToolchainEvidence,
        commands: &'a [BuildCommandEvidence],
        pkg_config: &'a [PkgConfigEvidence],
        environment: &'a BuildEnvironmentEvidence,
        invocation: &'a BuildInvocationTemplate,
    }
    let encoded = serde_json::to_vec(&Fingerprint {
        schema_version: 1,
        contract,
        source,
        dependencies,
        toolchain,
        commands,
        pkg_config,
        environment,
        invocation,
    })
    .expect("build contract fingerprint serialization is infallible");
    hash_bytes(&encoded)
}
