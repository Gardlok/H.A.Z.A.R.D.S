use std::{collections::HashSet, error::Error, io, process::ExitCode};

use arsenallspice::{AcquisitionLock, Registry};
use clap::{ArgGroup, Args, Parser};
use hazards_core::{
    AcquisitionItem, AcquisitionPlan, AcquisitionPlanner, AcquisitionStatus, HazardsPaths, HostKind,
    Persistence, PreparedSource, ProvisionPlan, ProvisionPlanner, ResolvedProfile, Role,
    SourcePreparer,
};

#[derive(Debug, Parser)]
#[command(
    name = "hazards-source-prepare",
    version,
    about = "Prepare locked crates.io source without invoking Cargo",
    long_about = "Reproduce checksum-locked crates.io source in private, content-addressed, non-executable HAZARDS staging. This command performs no network access, Cargo execution, compilation, or installation."
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
            eprintln!("hazards-source-prepare: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, Box<dyn Error>> {
    let registry = Registry::embedded()?;
    let lock = AcquisitionLock::embedded(&registry)?;
    let profile = ResolvedProfile::new(
        cli.profile.host,
        cli.profile.persistence,
        cli.profile.role,
    );
    let provision = ProvisionPlanner::new(&registry, &profile).plan();
    let acquisition = AcquisitionPlanner::new(&lock, &provision).plan();
    let selected = select_source_items(&lock, &provision, &acquisition, &cli.selection)?;
    let paths = HazardsPaths::from_env()?;
    let preparer = SourcePreparer::for_paths(&paths);
    let mut prepared = Vec::with_capacity(selected.len());

    for item in &selected {
        eprintln!(
            "preparing {} {} from its verified source object...",
            item.id, item.target_version
        );
        prepared.push(preparer.prepare(item)?);
    }

    if cli.profile.json {
        println!("{}", serde_json::to_string_pretty(&prepared)?);
    } else if prepared.is_empty() {
        println!("no locked source artifacts matched the resolved profile");
    } else {
        for source in &prepared {
            print_prepared_source(source);
        }
        println!(
            "mode: private non-executable source staging; Cargo, compilation, and installation remain disabled"
        );
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
            if !seen.insert(id) {
                return Err(cli_error(format!("tool {id} was selected more than once")));
            }
            let item = acquisition
                .items
                .iter()
                .find(|item| &item.id == id)
                .cloned()
                .or_else(|| {
                    provision
                        .items
                        .iter()
                        .find(|item| &item.id == id)
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

fn print_prepared_source(source: &PreparedSource) {
    println!(
        "[{:<9}] {:<12} {}",
        source.receipt.outcome, source.receipt.tool_id, source.receipt.artifact_sha256
    );
    println!("            stage    {}", source.staging_path.display());
    println!("            source   {}", source.source_path.display());
    println!("            manifest {}", source.manifest_path.display());
    println!("            receipt  {}", source.receipt_path.display());
    println!(
        "            graph    {} packages ({} registry checksums, {} local root)",
        source.receipt.package_count,
        source.receipt.registry_package_count,
        source.receipt.local_package_count
    );
    println!(
        "            tree     {} entries / {} expanded bytes",
        source.receipt.entry_count, source.receipt.expanded_size
    );
}

fn cli_error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::other(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_explicit_source_preparation() {
        let cli = Cli::try_parse_from([
            "hazards-source-prepare",
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
        .expect("source preparation arguments should parse");

        assert_eq!(cli.selection.tool, vec!["alacritty".to_owned()]);
        assert!(!cli.selection.all);
        assert_eq!(cli.profile.host, HostKind::Desktop);
        assert!(cli.profile.json);
    }

    #[test]
    fn source_preparation_requires_an_explicit_selection() {
        let error = Cli::try_parse_from(["hazards-source-prepare"])
            .expect_err("source preparation without selection should fail");

        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn source_preparation_rejects_tool_and_all_together() {
        let error = Cli::try_parse_from([
            "hazards-source-prepare",
            "--tool",
            "alacritty",
            "--all",
        ])
        .expect_err("conflicting selection should fail");

        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }
}
