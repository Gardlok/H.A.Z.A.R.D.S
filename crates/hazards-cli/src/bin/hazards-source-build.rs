use std::{error::Error, io, process::ExitCode};

use arsenallspice::{AcquisitionLock, Registry};
use clap::Parser;
use hazards_core::{
    AcquisitionItem, AcquisitionPlanner, AcquisitionStatus, ControlledBuildOutcome, HazardsPaths,
    HostKind, Persistence, ProvisionPlanner, ResolvedProfile, Role, SourceBuildExecutor,
    SourceBuildResult,
};

#[derive(Debug, Parser)]
#[command(
    name = "hazards-source-build",
    version,
    about = "Execute one confirmed offline source build under the pinned contract",
    long_about = "Recompute one pinned source-build contract, require an exact sha256 confirmation, materialize private source and vendored dependency copies, enter a Bubblewrap filesystem and network sandbox, invoke the exact pinned Cargo command with a cleared environment and strict resource bounds, verify the resulting ELF, store it by digest, and write append-only receipts. This command does not install, activate, or modify PATH."
)]
struct Cli {
    /// Select exactly one locked source tool.
    #[arg(long, value_name = "ID")]
    tool: String,
    /// Confirm the current contract digest as sha256:<digest>.
    #[arg(long, value_name = "sha256:DIGEST")]
    confirm: String,
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
            eprintln!("hazards-source-build: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, Box<dyn Error>> {
    let registry = Registry::embedded()?;
    let acquisition_lock = AcquisitionLock::embedded(&registry)?;
    let profile = ResolvedProfile::new(cli.host, cli.persistence, cli.role);
    let provision = ProvisionPlanner::new(&registry, &profile).plan();
    let acquisition = AcquisitionPlanner::new(&acquisition_lock, &provision).plan();
    let item = select_source_item(&acquisition_lock, &provision, &acquisition.items, &cli.tool)?;
    let paths = HazardsPaths::from_env()?;
    let result = SourceBuildExecutor::for_paths(&paths).execute(
        &profile,
        &provision.platform,
        &item,
        &cli.confirm,
    )?;

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print_result(&result);
    }
    Ok(if result.receipt.outcome == ControlledBuildOutcome::Succeeded {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn select_source_item(
    lock: &AcquisitionLock,
    provision: &hazards_core::ProvisionPlan,
    acquisition: &[AcquisitionItem],
    id: &str,
) -> Result<AcquisitionItem, Box<dyn Error>> {
    let planner = AcquisitionPlanner::new(lock, provision);
    let item = acquisition
        .iter()
        .find(|item| item.id == id)
        .cloned()
        .or_else(|| {
            provision
                .items
                .iter()
                .find(|item| item.id == id)
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
    Ok(item)
}

fn print_result(result: &SourceBuildResult) {
    let receipt = &result.receipt;
    println!(
        "[{:<28}] {:<12} {}",
        receipt.outcome, receipt.tool_id, receipt.version
    );
    println!(
        "                              contract sha256:{}",
        receipt.contract_sha256
    );
    println!(
        "                              receipt  {}",
        result.receipt_path.display()
    );
    println!(
        "                              stdout   {}",
        receipt.stdout_log_path.display()
    );
    println!(
        "                              stderr   {}",
        receipt.stderr_log_path.display()
    );
    if let Some(artifact) = &receipt.artifact {
        println!(
            "                              artifact {}",
            artifact.object_path.display()
        );
        println!("                              sha256   {}", artifact.sha256);
    }
    if receipt.build_root_preserved {
        if let Some(root) = receipt.invocation.current_dir.parent() {
            println!("                              preserved {}", root.display());
        }
    }
    println!("                              detail   {}", receipt.detail);
    println!(
        "mode: controlled build result only; nothing was installed, activated, or added to PATH"
    );
}

fn cli_error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::other(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_confirmed_source_build() {
        let confirmation = format!("sha256:{}", "a".repeat(64));
        let cli = Cli::try_parse_from([
            "hazards-source-build",
            "--tool",
            "alacritty",
            "--confirm",
            confirmation.as_str(),
            "--json",
        ])
        .expect("source-build arguments should parse");
        assert_eq!(cli.tool, "alacritty");
        assert!(cli.confirm.starts_with("sha256:"));
        assert!(cli.json);
    }

    #[test]
    fn source_build_requires_confirmation() {
        let error = Cli::try_parse_from(["hazards-source-build", "--tool", "alacritty"])
            .expect_err("source build without confirmation should fail");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }
}
