use std::{collections::HashSet, error::Error, io, process::ExitCode};

use arsenallspice::{AcquisitionLock, Registry};
use clap::{ArgGroup, Args, Parser};
use hazards_core::{
    AcquisitionItem, AcquisitionPlan, AcquisitionPlanner, AcquisitionStatus, CachedCargoDependencies,
    CargoDependencyAcquirer, HazardsPaths, HostKind, Persistence, ProvisionPlan,
    ProvisionPlanner, ResolvedProfile, Role,
};

#[derive(Debug, Parser)]
#[command(
    name = "hazards-cargo-dependencies",
    version,
    about = "Cache checksum-locked Cargo dependencies without invoking Cargo",
    long_about = "Fetch every crates.io archive named by an already prepared, checksum-locked Cargo graph. Archives remain private, content-addressed, and unextracted. This command does not invoke Cargo, build scripts, a compiler, or an installer."
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
    /// Select one prepared source tool; repeat for multiple tools.
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
            eprintln!("hazards-cargo-dependencies: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, Box<dyn Error>> {
    let registry = Registry::embedded()?;
    let lock = AcquisitionLock::embedded(&registry)?;
    let profile = ResolvedProfile::new(cli.profile.host, cli.profile.persistence, cli.profile.role);
    let provision = ProvisionPlanner::new(&registry, &profile).plan();
    let acquisition = AcquisitionPlanner::new(&lock, &provision).plan();
    let selected = select_source_items(&lock, &provision, &acquisition, &cli.selection)?;
    let paths = HazardsPaths::from_env()?;
    let acquirer = CargoDependencyAcquirer::for_paths(&paths)?;
    let mut cached = Vec::with_capacity(selected.len());

    for item in &selected {
        eprintln!(
            "caching locked Cargo dependencies for {} {}...",
            item.id, item.target_version
        );
        cached.push(acquirer.acquire(item)?);
    }

    if cli.profile.json {
        println!("{}", serde_json::to_string_pretty(&cached)?);
    } else if cached.is_empty() {
        println!("no locked source artifacts matched the resolved profile");
    } else {
        for dependencies in &cached {
            print_cached_dependencies(dependencies);
        }
        println!(
            "mode: private checksum-verified crate cache; archives remain unextracted and Cargo, build scripts, compilation, and installation remain disabled"
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

fn print_cached_dependencies(cached: &CachedCargoDependencies) {
    println!(
        "[{:<9}] {:<12} {}",
        cached.receipt.outcome, cached.receipt.tool_id, cached.receipt.cargo_lock_sha256
    );
    println!("            objects  {}", cached.object_root.display());
    println!("            manifest {}", cached.manifest_path.display());
    println!("            receipt  {}", cached.receipt_path.display());
    println!(
        "            graph    {} dependencies / {} bytes",
        cached.receipt.dependency_count, cached.receipt.total_bytes
    );
    println!(
        "            transfer {} downloaded / {} cache hits",
        cached.receipt.downloaded_count, cached.receipt.cache_hit_count
    );
}

fn cli_error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::other(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_explicit_dependency_cache_request() {
        let cli = Cli::try_parse_from([
            "hazards-cargo-dependencies",
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
        .expect("dependency cache arguments should parse");

        assert_eq!(cli.selection.tool, vec!["alacritty".to_owned()]);
        assert!(!cli.selection.all);
        assert_eq!(cli.profile.host, HostKind::Desktop);
        assert!(cli.profile.json);
    }

    #[test]
    fn dependency_cache_requires_an_explicit_selection() {
        let error = Cli::try_parse_from(["hazards-cargo-dependencies"])
            .expect_err("dependency cache without selection should fail");

        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn dependency_cache_rejects_tool_and_all_together() {
        let error = Cli::try_parse_from([
            "hazards-cargo-dependencies",
            "--tool",
            "alacritty",
            "--all",
        ])
        .expect_err("conflicting selection should fail");

        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }
}
