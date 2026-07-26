use std::{collections::HashSet, error::Error, io, process::ExitCode};

use arsenallspice::{AcquisitionLock, Registry};
use clap::{ArgGroup, Args, Parser};
use hazards_core::{
    AcquisitionItem, AcquisitionPlan, AcquisitionPlanner, AcquisitionStatus, BuildContractItem,
    BuildContractPlan, BuildContractPlanner, BuildContractStatus, HazardsPaths, HostKind,
    Persistence, ProvisionPlan, ProvisionPlanner, ResolvedProfile, Role,
};

#[derive(Debug, Parser)]
#[command(
    name = "hazards-build-contract",
    version,
    about = "Inspect a pinned source-build contract without compiling",
    long_about = "Revalidate prepared source and checksum-locked Cargo dependencies, then inspect one exact Rust toolchain, reviewed native prerequisites, and build-affecting environment policy. This command performs no download, compilation, build-script execution, installation, or activation."
)]
struct Cli {
    #[command(flatten)]
    selection: SelectionArgs,
    #[command(flatten)]
    profile: ProfileArgs,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("selection")
        .required(true)
        .args(["tool", "all"])
))]
struct SelectionArgs {
    /// Select one locked source tool; repeat for multiple tools.
    #[arg(long, value_name = "ID", action = clap::ArgAction::Append)]
    tool: Vec<String>,
    /// Select every locked source artifact in the resolved profile.
    #[arg(long, conflicts_with = "tool")]
    all: bool,
}

#[derive(Debug, Clone, Args)]
struct ProfileArgs {
    #[arg(long, default_value = "desktop")]
    host: HostKind,
    #[arg(long, default_value = "local")]
    persistence: Persistence,
    #[arg(long, default_value = "development")]
    role: Role,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("hazards-build-contract: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, Box<dyn Error>> {
    let registry = Registry::embedded()?;
    let acquisition_lock = AcquisitionLock::embedded(&registry)?;
    let profile = ResolvedProfile::new(cli.profile.host, cli.profile.persistence, cli.profile.role);
    let provision = ProvisionPlanner::new(&registry, &profile).plan();
    let acquisition = AcquisitionPlanner::new(&acquisition_lock, &provision).plan();
    let selected =
        select_source_items(&acquisition_lock, &provision, &acquisition, &cli.selection)?;
    let paths = HazardsPaths::from_env()?;
    let plan =
        BuildContractPlanner::for_paths(&paths)?.plan(&profile, &provision.platform, &selected);

    if cli.profile.json {
        println!("{}", serde_json::to_string_pretty(&plan)?);
    } else {
        print_plan(&plan);
    }
    Ok(ExitCode::SUCCESS)
}

fn select_source_items(
    lock: &AcquisitionLock,
    provision: &ProvisionPlan,
    acquisition: &AcquisitionPlan,
    args: &SelectionArgs,
) -> Result<Vec<AcquisitionItem>, Box<dyn Error>> {
    let planner = AcquisitionPlanner::new(lock, provision);
    let selected = if args.all {
        acquisition
            .items
            .iter()
            .filter(|item| item.status == AcquisitionStatus::LockedSource)
            .cloned()
            .collect()
    } else {
        let mut seen = HashSet::new();
        let mut selected = Vec::with_capacity(args.tool.len());
        for id in &args.tool {
            if !seen.insert(id.as_str()) {
                return Err(cli_error(format!("tool {id} was selected more than once")));
            }
            let item = acquisition
                .items
                .iter()
                .find(|item| item.id == id.as_str())
                .cloned()
                .or_else(|| {
                    provision
                        .items
                        .iter()
                        .find(|item| item.id == id.as_str())
                        .and_then(|item| planner.resolve(item))
                })
                .ok_or_else(|| {
                    cli_error(format!(
                        "tool {id} is not an external application in the resolved profile"
                    ))
                })?;
            if item.status != AcquisitionStatus::LockedSource {
                return Err(cli_error(format!(
                    "tool {id} does not use a locked crates.io source archive"
                )));
            }
            selected.push(item);
        }
        selected
    };
    Ok(selected)
}

fn print_plan(plan: &BuildContractPlan) {
    if plan.items.is_empty() {
        println!("no locked source artifacts matched the resolved profile");
        return;
    }
    for item in &plan.items {
        print_item(item);
    }
    println!(
        "mode: read-only source-build contract inspection; Cargo execution, build scripts, compilation, installation, and activation remain disabled"
    );
}

fn print_item(item: &BuildContractItem) {
    println!(
        "[{:<28}] {:<12} {}",
        item.status, item.id, item.target_version
    );
    if let Some(digest) = &item.contract_sha256 {
        println!("                              contract sha256:{digest}");
    }
    if let Some(toolchain) = &item.toolchain {
        println!(
            "                              rust     {} {}",
            toolchain.rustc_release, toolchain.rustc_commit_hash
        );
        println!(
            "                              target   {}",
            toolchain.target
        );
    }
    if let Some(dependencies) = &item.dependencies {
        println!(
            "                              graph    {} dependencies / {} bytes",
            dependencies.dependency_count, dependencies.total_bytes
        );
    }
    println!("                              detail   {}", item.detail);
    for finding in &item.findings {
        println!("                              finding  {finding}");
    }
    if item.status == BuildContractStatus::ContractReady {
        println!("                              execution disabled; contract is evidence only");
    }
}

fn cli_error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::other(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_explicit_build_contract_request() {
        let cli = Cli::try_parse_from([
            "hazards-build-contract",
            "--tool",
            "alacritty",
            "--host",
            "desktop",
            "--persistence",
            "local",
            "--role",
            "development",
            "--json",
        ])
        .expect("build contract arguments should parse");

        assert_eq!(cli.selection.tool, vec!["alacritty".to_owned()]);
        assert!(!cli.selection.all);
        assert_eq!(cli.profile.host, HostKind::Desktop);
        assert!(cli.profile.json);
    }

    #[test]
    fn build_contract_requires_an_explicit_selection() {
        let error = Cli::try_parse_from(["hazards-build-contract"])
            .expect_err("build contract without selection should fail");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn build_contract_rejects_tool_and_all_together() {
        let error = Cli::try_parse_from(["hazards-build-contract", "--tool", "alacritty", "--all"])
            .expect_err("conflicting selection should fail");
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }
}
