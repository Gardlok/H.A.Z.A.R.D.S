use std::{collections::HashSet, error::Error, io, path::PathBuf, process::ExitCode};

use arsenallspice::{AcquisitionLock, Registry};
use clap::{ArgGroup, Args, Parser, Subcommand};
use hazards_core::{
    AcquisitionItem, AcquisitionPlan, AcquisitionPlanner, AcquisitionStatus, ArtifactAcquirer,
    CheckStatus, Doctor, DotfileDeploymentOutcome, DotfileDeploymentPlan, DotfileDeploymentReport,
    DotfileRollbackReport, DotfilesManager, DotterDryRunOutcome, DotterDryRunReport,
    GeneratedDotterProfile, HazardsPaths, HostKind, InstalledArtifact, Installer, Materializer,
    Persistence, ProvisionItem, ProvisionPlan, ProvisionPlanner, ProvisionStatus, ResolvedProfile,
    Role, RolledBackArtifact, SourceBuildItem, SourceBuildPlan, SourceBuildPlanner,
    SourceBuildStatus, StagedArtifact, SystemDotterRunner, VerifiedArtifact,
};
use rhaisour::{RecipeCompiler, SAMPLE_RECIPE};

const STACK_RONYM: &str = "Helix · Alacritty · Zellij · Arsenal · Rhai · Dotter · SurrealDB";

#[derive(Debug, Parser)]
#[command(
    name = "hazards",
    version,
    about = "Portable terminal workspace control plane",
    long_about = "HAZARDS composes a daily-driver terminal workspace for local and remote systems."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Explain the environment and its seven pillars.
    About,
    /// Display XDG-aware HAZARDS paths without creating them.
    Paths {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Inspect the Arsenal pillar and provider registry.
    Arsenal {
        #[command(subcommand)]
        command: ArsenalCommand,
    },
    /// Inspect or resolve composable environment profiles.
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Run read-only environment diagnostics.
    Doctor(DoctorArgs),
    /// Inspect what provisioning would be required without changing the host.
    Provision {
        #[command(subcommand)]
        command: ProvisionCommand,
    },
    /// Generate and inspect profile-aware dotfile deployment.
    Dotfiles {
        #[command(subcommand)]
        command: DotfilesCommand,
    },
    /// Inspect sandboxed Rhaisour recipes.
    Recipe {
        #[command(subcommand)]
        command: RecipeCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ArsenalCommand {
    /// List pillar applications and optionally supporting providers.
    List {
        /// List supporting providers instead of pillar applications.
        #[arg(long)]
        providers: bool,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ProfileCommand {
    /// List each profile dimension.
    List,
    /// Resolve a host, persistence mode, and role into one profile.
    Resolve(ProfileArgs),
}

#[derive(Debug, Subcommand)]
enum ProvisionCommand {
    /// Build a profile-aware, read-only installation plan.
    Plan(ProfileArgs),
    /// Resolve exact integrity-pinned artifacts without retrieving them.
    AcquirePlan(ProfileArgs),
    /// Inspect locked crates.io source graphs without extracting or building them.
    BuildPlan(AcquireArgs),
    /// Download and verify locked artifacts into the private HAZARDS cache.
    Acquire(AcquireArgs),
    /// Safely reproduce verified artifacts in private, non-executable staging.
    Materialize(AcquireArgs),
    /// Transactionally activate staged payloads in the user-local bin directory.
    Install(AcquireArgs),
    /// Restore the activation that preceded the latest matching installation.
    Rollback(RollbackArgs),
}

#[derive(Debug, Subcommand)]
enum DotfilesCommand {
    /// Generate deterministic Dotter configuration in HAZARDS state.
    Generate(DotfilesArgs),
    /// Run Dotter's deploy dry-run and verify every declared target stayed unchanged.
    DryRun(DotfilesArgs),
    /// Classify existing targets and produce a state-bound confirmation token.
    Plan(DotfilesArgs),
    /// Back up conflicts and perform a verified, recoverable Dotter deployment.
    Deploy(DotfilesDeployArgs),
    /// Restore the newest applicable dotfile deployment transaction.
    Rollback(DotfilesArgs),
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

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("selection")
        .required(true)
        .args(["tool", "all"])
))]
struct AcquireArgs {
    #[command(flatten)]
    profile: ProfileArgs,
    /// Select one tool by registry identifier; repeat for multiple tools.
    #[arg(long, value_name = "ID", action = clap::ArgAction::Append)]
    tool: Vec<String>,
    /// Select every actionable artifact in the resolved profile.
    #[arg(long, conflicts_with = "tool")]
    all: bool,
}

#[derive(Debug, Args)]
struct RollbackArgs {
    /// Registry identifier of the HAZARDS-managed command to roll back.
    #[arg(long, value_name = "ID")]
    tool: String,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct DotfilesArgs {
    #[command(flatten)]
    profile: ProfileArgs,
    /// HAZARDS checkout root; discovered from the current directory when omitted.
    #[arg(long, value_name = "PATH")]
    root: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct DotfilesDeployArgs {
    #[command(flatten)]
    dotfiles: DotfilesArgs,
    /// Exact confirmation token emitted by `dotfiles plan`.
    #[arg(long, value_name = "SHA256")]
    confirm: String,
}

#[derive(Debug, Args)]
struct DoctorArgs {
    #[command(flatten)]
    profile: ProfileArgs,
    /// Return a failure code when any required application is missing.
    #[arg(long)]
    strict: bool,
}

#[derive(Debug, Subcommand)]
enum RecipeCommand {
    /// Compile a recipe without running it.
    Check {
        /// Recipe path. The bundled example is checked when omitted.
        path: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("hazards: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, Box<dyn Error>> {
    match cli.command.unwrap_or(Command::About) {
        Command::About => {
            println!("H.A.Z.A.R.D.S");
            println!("{STACK_RONYM}");
            println!();
            println!("A portable daily-driver terminal workspace for local and remote systems.");
            Ok(ExitCode::SUCCESS)
        }
        Command::Paths { json } => {
            let paths = HazardsPaths::from_env()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&paths)?);
            } else {
                println!("home    {}", paths.home.display());
                println!("config  {}", paths.config.display());
                println!("data    {}", paths.data.display());
                println!("state   {}", paths.state.display());
                println!("cache   {}", paths.cache.display());
                println!("bin     {}", paths.bin.display());
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Arsenal { command } => run_arsenal(command),
        Command::Profile { command } => run_profile(command),
        Command::Doctor(args) => run_doctor(args),
        Command::Provision { command } => run_provision(command),
        Command::Dotfiles { command } => run_dotfiles(command),
        Command::Recipe { command } => run_recipe(command),
    }
}

fn run_dotfiles(command: DotfilesCommand) -> Result<ExitCode, Box<dyn Error>> {
    enum Operation {
        Generate,
        DryRun,
        Plan,
        Deploy(String),
        Rollback,
    }

    let registry = Registry::embedded()?;
    let (args, operation) = match command {
        DotfilesCommand::Generate(args) => (args, Operation::Generate),
        DotfilesCommand::DryRun(args) => (args, Operation::DryRun),
        DotfilesCommand::Plan(args) => (args, Operation::Plan),
        DotfilesCommand::Deploy(args) => (args.dotfiles, Operation::Deploy(args.confirm)),
        DotfilesCommand::Rollback(args) => (args, Operation::Rollback),
    };
    let profile = resolve_profile(&args.profile);
    let paths = HazardsPaths::from_env()?;
    let root = match args.root.as_deref() {
        Some(root) => root.to_path_buf(),
        None => {
            DotfilesManager::<SystemDotterRunner>::discover_workspace(std::env::current_dir()?)?
        }
    };
    let manager = DotfilesManager::new(&registry, &profile, &paths, root)?;

    match operation {
        Operation::Generate => {
            let generated = manager.generate()?;
            if args.profile.json {
                println!("{}", serde_json::to_string_pretty(&generated)?);
            } else {
                print_generated_dotter_profile(&generated);
                println!("mode: HAZARDS state only; no dotfile target was read or changed");
            }
            Ok(ExitCode::SUCCESS)
        }
        Operation::DryRun => {
            let activation = verify_dotter_activation(&registry, &paths)?;
            let report = manager.dry_run(&activation)?;
            if args.profile.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_dotter_dry_run(&report);
            }
            Ok(if report.receipt.outcome == DotterDryRunOutcome::Clean {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        Operation::Plan => {
            let plan = manager.adoption_plan()?;
            if args.profile.json {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            } else {
                print_dotfile_deployment_plan(&plan);
            }
            Ok(if plan.ready {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        Operation::Deploy(confirmation) => {
            let activation = verify_dotter_activation(&registry, &paths)?;
            let report = manager.deploy(&activation, &confirmation)?;
            if args.profile.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_dotfile_deployment(&report);
            }
            Ok(
                if report.receipt.outcome == DotfileDeploymentOutcome::Deployed {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                },
            )
        }
        Operation::Rollback => {
            let report = manager.rollback_deployment()?;
            if args.profile.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_dotfile_rollback(&report);
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn verify_dotter_activation(
    registry: &Registry,
    paths: &HazardsPaths,
) -> Result<hazards_core::ManagedActivation, Box<dyn Error>> {
    let (command, version_args) = registry
        .command_spec("dotter")
        .ok_or_else(|| cli_error("Dotter has no external command specification"))?;
    Ok(Installer::for_paths(paths).verify_active("dotter", command, version_args)?)
}

fn run_arsenal(command: ArsenalCommand) -> Result<ExitCode, Box<dyn Error>> {
    let registry = Registry::embedded()?;
    match command {
        ArsenalCommand::List { providers, json } => {
            if json {
                if providers {
                    println!("{}", serde_json::to_string_pretty(&registry.providers)?);
                } else {
                    println!("{}", serde_json::to_string_pretty(&registry.pillars)?);
                }
            } else if providers {
                for provider in registry.providers {
                    println!(
                        "{:<12} {:<12} {}",
                        provider.id, provider.command, provider.summary
                    );
                }
            } else {
                for pillar in registry.pillars {
                    println!(
                        "{}  {:<12} {:<16} {}",
                        pillar.letter, pillar.name, pillar.ingredient, pillar.summary
                    );
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn run_profile(command: ProfileCommand) -> Result<ExitCode, Box<dyn Error>> {
    match command {
        ProfileCommand::List => {
            println!("host         desktop | laptop | remote");
            println!("persistence  local | roaming | ghost");
            println!("role         development | operations | research");
        }
        ProfileCommand::Resolve(args) => {
            let profile = resolve_profile(&args);
            if args.json {
                println!("{}", serde_json::to_string_pretty(&profile)?);
            } else {
                print_profile(&profile);
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn run_doctor(args: DoctorArgs) -> Result<ExitCode, Box<dyn Error>> {
    let registry = Registry::embedded()?;
    let profile = resolve_profile(&args.profile);
    let checks = Doctor::new(&registry, &profile).run();

    if args.profile.json {
        println!("{}", serde_json::to_string_pretty(&checks)?);
    } else {
        println!(
            "profile: {} / {} / {}",
            profile.host, profile.persistence, profile.role
        );
        for check in &checks {
            let marker = match check.status {
                CheckStatus::Pass => "ok",
                CheckStatus::Missing => "missing",
                CheckStatus::Skipped => "skip",
            };
            println!("[{marker:<7}] {:<12} {}", check.id, check.detail);
        }
    }

    let required_missing = checks
        .iter()
        .any(|check| check.required && check.status == CheckStatus::Missing);
    if args.strict && required_missing {
        Ok(ExitCode::FAILURE)
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn run_provision(command: ProvisionCommand) -> Result<ExitCode, Box<dyn Error>> {
    match command {
        ProvisionCommand::Plan(args) => {
            let registry = Registry::embedded()?;
            let profile = resolve_profile(&args);
            let plan = ProvisionPlanner::new(&registry, &profile).plan();

            if args.json {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            } else {
                println!(
                    "profile:  {} / {} / {}",
                    profile.host, profile.persistence, profile.role
                );
                println!(
                    "platform: {} / {}",
                    plan.platform.os, plan.platform.architecture
                );
                println!("mode:     read-only; no changes will be made");
                for item in &plan.items {
                    print_provision_item(item);
                }
            }
        }
        ProvisionCommand::AcquirePlan(args) => {
            let registry = Registry::embedded()?;
            let lock = AcquisitionLock::embedded(&registry)?;
            let profile = resolve_profile(&args);
            let provision = ProvisionPlanner::new(&registry, &profile).plan();
            let plan = AcquisitionPlanner::new(&lock, &provision).plan();

            if args.json {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            } else {
                println!(
                    "profile:  {} / {} / {}",
                    profile.host, profile.persistence, profile.role
                );
                println!(
                    "platform: {} / {}",
                    plan.platform.os, plan.platform.architecture
                );
                println!("lock:     observed {}", plan.lock_observed_at);
                println!("mode:     read-only; no bytes will be retrieved");
                for item in &plan.items {
                    print_acquisition_item(item);
                }
            }
        }
        ProvisionCommand::BuildPlan(args) => {
            let registry = Registry::embedded()?;
            let lock = AcquisitionLock::embedded(&registry)?;
            let profile = resolve_profile(&args.profile);
            let provision = ProvisionPlanner::new(&registry, &profile).plan();
            let acquisition = AcquisitionPlanner::new(&lock, &provision).plan();
            let selected = select_source_items(&lock, &provision, &acquisition, &args)?;
            let paths = HazardsPaths::from_env()?;
            let plan = SourceBuildPlanner::new(&paths, &lock.observed_at).plan(
                &profile,
                &provision.platform,
                &selected,
            );

            if args.profile.json {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            } else {
                print_source_build_plan(&plan);
            }
        }
        ProvisionCommand::Acquire(args) => {
            let registry = Registry::embedded()?;
            let lock = AcquisitionLock::embedded(&registry)?;
            let profile = resolve_profile(&args.profile);
            let provision = ProvisionPlanner::new(&registry, &profile).plan();
            let plan = AcquisitionPlanner::new(&lock, &provision).plan();
            let selected = select_acquisition_items(&plan, &args)?;
            let paths = HazardsPaths::from_env()?;
            let acquirer = ArtifactAcquirer::for_paths(&paths)?;
            let mut verified = Vec::with_capacity(selected.len());

            for item in selected {
                eprintln!(
                    "acquiring {} {} from its locked source...",
                    item.id, item.target_version
                );
                verified.push(acquirer.acquire(item)?);
            }

            if args.profile.json {
                println!("{}", serde_json::to_string_pretty(&verified)?);
            } else if verified.is_empty() {
                println!("no actionable artifacts matched the resolved profile");
            } else {
                for artifact in &verified {
                    print_verified_artifact(artifact);
                }
                println!("mode: verified cache only; nothing was extracted or installed");
            }
        }
        ProvisionCommand::Materialize(args) => {
            let registry = Registry::embedded()?;
            let lock = AcquisitionLock::embedded(&registry)?;
            let profile = resolve_profile(&args.profile);
            let provision = ProvisionPlanner::new(&registry, &profile).plan();
            let plan = AcquisitionPlanner::new(&lock, &provision).plan();
            let selected = select_acquisition_items(&plan, &args)?;
            let paths = HazardsPaths::from_env()?;
            let materializer = Materializer::for_paths(&paths);
            let mut staged = Vec::with_capacity(selected.len());

            for item in selected {
                eprintln!(
                    "materializing {} {} from its verified cache object...",
                    item.id, item.target_version
                );
                staged.push(materializer.materialize(item)?);
            }

            if args.profile.json {
                println!("{}", serde_json::to_string_pretty(&staged)?);
            } else {
                for artifact in &staged {
                    print_staged_artifact(artifact);
                }
                println!(
                    "mode: private staging only; payloads remain non-executable and uninstalled"
                );
            }
        }
        ProvisionCommand::Install(args) => {
            let registry = Registry::embedded()?;
            let lock = AcquisitionLock::embedded(&registry)?;
            let profile = resolve_profile(&args.profile);
            let provision = ProvisionPlanner::new(&registry, &profile).plan();
            let acquisition = AcquisitionPlanner::new(&lock, &provision).plan();
            let selected = select_install_items(&lock, &provision, &acquisition, &args)?;
            let paths = HazardsPaths::from_env()?;
            let installer = Installer::for_paths(&paths);
            let mut installed = Vec::with_capacity(selected.len());

            for item in &selected {
                let (command, version_args) = registry
                    .command_spec(&item.id)
                    .ok_or_else(|| cli_error(format!("tool {} has no executable", item.id)))?;
                eprintln!(
                    "installing {} {} from verified staging...",
                    item.id, item.target_version
                );
                installed.push(installer.install(item, command, version_args)?);
            }

            if args.profile.json {
                println!("{}", serde_json::to_string_pretty(&installed)?);
            } else if installed.is_empty() {
                println!("no actionable binary artifacts matched the resolved profile");
            } else {
                for artifact in &installed {
                    print_installed_artifact(artifact);
                }
                println!(
                    "mode: transactional user-local activation; every command passed version and PATH checks"
                );
            }
        }
        ProvisionCommand::Rollback(args) => {
            let registry = Registry::embedded()?;
            let (command, version_args) = registry.command_spec(&args.tool).ok_or_else(|| {
                cli_error(format!("tool {} has no external executable", args.tool))
            })?;
            let paths = HazardsPaths::from_env()?;
            let installer = Installer::for_paths(&paths);
            eprintln!("rolling back the current {} activation...", args.tool);
            let rolled_back = installer.rollback(&args.tool, command, version_args)?;

            if args.json {
                println!("{}", serde_json::to_string_pretty(&rolled_back)?);
            } else {
                print_rolled_back_artifact(&rolled_back);
                println!("mode: prior activation restored from append-only installation evidence");
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn select_acquisition_items<'a>(
    plan: &'a AcquisitionPlan,
    args: &AcquireArgs,
) -> Result<Vec<&'a AcquisitionItem>, Box<dyn Error>> {
    let selected = if args.all {
        plan.items.iter().collect::<Vec<_>>()
    } else {
        let mut seen = HashSet::new();
        let mut selected = Vec::with_capacity(args.tool.len());
        for id in &args.tool {
            if !seen.insert(id) {
                return Err(cli_error(format!("tool {id} was selected more than once")));
            }
            let item = plan
                .items
                .iter()
                .find(|item| &item.id == id)
                .ok_or_else(|| {
                    cli_error(format!(
                        "tool {id} is not actionable for the resolved profile"
                    ))
                })?;
            selected.push(item);
        }
        selected
    };

    if let Some(item) = selected.iter().find(|item| item.artifact.is_none()) {
        return Err(cli_error(format!(
            "tool {} has no locked artifact for {}/{}",
            item.id, plan.platform.os, plan.platform.architecture
        )));
    }
    Ok(selected)
}

fn select_install_items(
    lock: &AcquisitionLock,
    provision: &ProvisionPlan,
    acquisition: &AcquisitionPlan,
    args: &AcquireArgs,
) -> Result<Vec<AcquisitionItem>, Box<dyn Error>> {
    let planner = AcquisitionPlanner::new(lock, provision);
    let selected = if args.all {
        acquisition.items.clone()
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
            selected.push(item);
        }
        selected
    };

    if let Some(item) = selected
        .iter()
        .find(|item| item.status != AcquisitionStatus::LockedBinary)
    {
        return Err(cli_error(format!(
            "tool {} has no locked prebuilt binary for {}/{}; installation will not build source or invent an artifact",
            item.id, provision.platform.os, provision.platform.architecture
        )));
    }
    Ok(selected)
}

fn select_source_items(
    lock: &AcquisitionLock,
    provision: &ProvisionPlan,
    acquisition: &AcquisitionPlan,
    args: &AcquireArgs,
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

fn print_verified_artifact(artifact: &VerifiedArtifact) {
    println!(
        "[{:<10}] {:<12} {}",
        artifact.receipt.outcome, artifact.receipt.tool_id, artifact.receipt.sha256
    );
    println!("             object  {}", artifact.object_path.display());
    println!("             receipt {}", artifact.receipt_path.display());
}

fn print_staged_artifact(artifact: &StagedArtifact) {
    println!(
        "[{:<12}] {:<12} {}",
        artifact.receipt.outcome, artifact.receipt.tool_id, artifact.receipt.payload_sha256
    );
    println!(
        "               stage    {}",
        artifact.staging_path.display()
    );
    println!(
        "               payload  {}",
        artifact.payload_path.display()
    );
    println!(
        "               manifest {}",
        artifact.manifest_path.display()
    );
    println!(
        "               receipt  {}",
        artifact.receipt_path.display()
    );
}

fn print_installed_artifact(artifact: &InstalledArtifact) {
    println!(
        "[{:<14}] {:<12} {}",
        artifact.receipt.outcome, artifact.receipt.tool_id, artifact.receipt.payload_sha256
    );
    println!(
        "                 store      {}",
        artifact.store_path.display()
    );
    println!(
        "                 payload    {}",
        artifact.payload_path.display()
    );
    println!(
        "                 activation {}",
        artifact.activation_path.display()
    );
    println!(
        "                 receipt    {}",
        artifact.receipt_path.display()
    );
}

fn print_rolled_back_artifact(artifact: &RolledBackArtifact) {
    println!(
        "[{:<14}] {:<12} {}",
        artifact.receipt.outcome, artifact.receipt.tool_id, artifact.receipt.payload_sha256
    );
    println!(
        "                 activation {}",
        artifact.activation_path.display()
    );
    println!(
        "                 target     {}",
        artifact
            .active_target
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<removed>".to_owned())
    );
    println!(
        "                 receipt    {}",
        artifact.receipt_path.display()
    );
}

fn print_source_build_plan(plan: &SourceBuildPlan) {
    println!(
        "profile:  {} / {} / {}",
        plan.profile.host, plan.profile.persistence, plan.profile.role
    );
    println!(
        "platform: {} / {}",
        plan.platform.os, plan.platform.architecture
    );
    println!("lock:     observed {}", plan.lock_observed_at);
    println!("mode:     read-only; no source was extracted and Cargo was not invoked");
    for item in &plan.items {
        print_source_build_item(item);
    }
    println!("execution: disabled; source preparation and builds remain separate phases");
}

fn print_source_build_item(item: &SourceBuildItem) {
    println!(
        "[{:<13}] {:<12} {}",
        item.status, item.id, item.target_version
    );
    println!("                object   {}", item.object_path.display());
    println!("                archive  {}", item.artifact_sha256);
    println!("                root     {}", item.source_root);
    println!("                manifest {}", item.manifest_sha256);
    println!("                lock     {}", item.cargo_lock_sha256);
    if item.status == SourceBuildStatus::GraphLocked {
        println!(
            "                graph    {} packages ({} registry checksums, {} local root)",
            item.package_count,
            item.registry_package_count.unwrap_or_default(),
            item.local_package_count.unwrap_or_default()
        );
    }
    println!("                detail   {}", item.detail);
}

fn print_generated_dotter_profile(generated: &GeneratedDotterProfile) {
    println!(
        "[{:<10}] {}",
        generated.receipt.outcome, generated.manifest.profile_id
    );
    println!(
        "             packages  {}",
        generated.manifest.packages.join(", ")
    );
    println!(
        "             mappings  {}",
        generated.manifest.mappings.len()
    );
    println!(
        "             local     {}",
        generated.local_config_path.display()
    );
    println!(
        "             manifest  {}",
        generated.manifest_path.display()
    );
    println!(
        "             receipt   {}",
        generated.receipt_path.display()
    );
}

fn print_dotter_dry_run(report: &DotterDryRunReport) {
    if !report.stdout.trim().is_empty() {
        println!("{}", report.stdout.trim_end());
    }
    if !report.stderr.trim().is_empty() {
        eprintln!("{}", report.stderr.trim_end());
    }
    println!(
        "[{:<17}] {}",
        report.receipt.outcome, report.receipt.profile_id
    );
    println!(
        "                   dotter    {}",
        report.executable.display()
    );
    println!(
        "                   watched   {} paths",
        report.receipt.watched_path_count
    );
    if !report.receipt.changed_paths.is_empty() {
        println!(
            "                   changed   {}",
            report
                .receipt
                .changed_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    println!(
        "                   receipt   {}",
        report.receipt_path.display()
    );
    println!(
        "mode: Dotter --dry-run completed; declared targets were fingerprinted before and after"
    );
}

fn print_dotfile_deployment_plan(plan: &DotfileDeploymentPlan) {
    println!("profile:  {}", plan.profile_id);
    println!("mode:     read-only; no target or HAZARDS state was changed");
    for item in &plan.items {
        println!(
            "[{:<14}] {:<12} {}",
            item.action,
            item.package,
            item.target.display()
        );
        println!("                 source  {}", item.source.display());
        println!("                 detail  {}", item.detail);
        if let Some(sha256) = &item.target_sha256 {
            println!("                 current {sha256}");
        }
    }
    println!("ready:    {}", plan.ready);
    if plan.ready {
        println!("confirm:  {}", plan.confirmation);
    } else {
        println!("confirm:  <unavailable while blocked>");
    }
}

fn print_dotfile_deployment(report: &DotfileDeploymentReport) {
    if !report.stdout.trim().is_empty() {
        println!("{}", report.stdout.trim_end());
    }
    if !report.stderr.trim().is_empty() {
        eprintln!("{}", report.stderr.trim_end());
    }
    println!(
        "[{:<15}] {}",
        report.receipt.outcome, report.receipt.profile_id
    );
    println!(
        "                  backups     {}",
        report.receipt.backup_count
    );
    println!(
        "                  transaction {}",
        report.transaction_directory.display()
    );
    println!(
        "                  receipt     {}",
        report.receipt_path.display()
    );
    println!(
        "mode: verified Dotter deployment without --force; ordinary failure restores original targets"
    );
}

fn print_dotfile_rollback(report: &DotfileRollbackReport) {
    println!(
        "[{:<11}] {}",
        report.receipt.result, report.receipt.profile_id
    );
    println!(
        "             restored    {} files",
        report.receipt.restored_files
    );
    println!(
        "             removed     {} managed links",
        report.receipt.removed_links
    );
    println!(
        "             transaction {}",
        report.transaction_directory.display()
    );
    println!("             receipt     {}", report.receipt_path.display());
}

fn cli_error(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(io::Error::other(message.into()))
}

fn print_provision_item(item: &ProvisionItem) {
    let marker = match item.status {
        ProvisionStatus::Installed => "installed",
        ProvisionStatus::Outdated => "outdated",
        ProvisionStatus::Missing => "missing",
        ProvisionStatus::Planned => "planned",
        ProvisionStatus::Unsupported => "unsupported",
    };

    let observation = match item.status {
        ProvisionStatus::Installed | ProvisionStatus::Outdated if item.path.is_some() => {
            let command = item.resolved_command.as_deref().unwrap_or("command");
            let version = item
                .installed_version
                .as_deref()
                .map(|version| format!(" {version}"))
                .unwrap_or_default();
            let path = item.path.as_ref().expect("guarded path should exist");
            format!("{command}{version} at {}", path.display())
        }
        _ => item.detail.clone(),
    };

    if matches!(
        item.status,
        ProvisionStatus::Outdated | ProvisionStatus::Missing
    ) {
        let install = item
            .install
            .as_ref()
            .expect("actionable external item should have installation intent");
        println!(
            "[{marker:<11}] {:<12} {}; target {} via {} {} -> {}",
            item.id,
            observation,
            install.target_version,
            install.source,
            install.locator,
            install.destination
        );
    } else if item.status == ProvisionStatus::Unsupported {
        let platforms = item
            .install
            .as_ref()
            .map(|install| install.platforms.join(", "))
            .unwrap_or_else(|| "none".to_owned());
        println!(
            "[{marker:<11}] {:<12} {}; supported platforms: {platforms}",
            item.id, observation
        );
    } else {
        println!("[{marker:<11}] {:<12} {observation}", item.id);
    }
}

fn print_acquisition_item(item: &AcquisitionItem) {
    let marker = match item.status {
        AcquisitionStatus::LockedBinary => "binary",
        AcquisitionStatus::LockedSource => "source",
        AcquisitionStatus::Unavailable => "unavailable",
    };
    let action = match item.provision_status {
        ProvisionStatus::Outdated => "upgrade",
        ProvisionStatus::Missing => "install",
        ProvisionStatus::Unsupported => "resolve",
        ProvisionStatus::Installed | ProvisionStatus::Planned => "inspect",
    };

    println!(
        "[{marker:<11}] {:<12} {action} {} -> {}",
        item.id, item.target_version, item.destination
    );
    if let Some(artifact) = &item.artifact {
        println!(
            "              asset    {} ({})",
            artifact.name,
            format_size(artifact.size)
        );
        println!("              sha256   {}", artifact.sha256);
        println!("              evidence {}", artifact.evidence);
        println!("              source   {}", artifact.url);
    } else {
        println!("              {}", item.detail);
    }
}

fn format_size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    let bytes = bytes as f64;
    if bytes >= MIB {
        format!("{:.1} MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes / KIB)
    } else {
        format!("{bytes:.0} B")
    }
}

fn run_recipe(command: RecipeCommand) -> Result<ExitCode, Box<dyn Error>> {
    match command {
        RecipeCommand::Check { path } => {
            let compiler = RecipeCompiler::default();
            match path {
                Some(path) => {
                    compiler.check_file(&path)?;
                    println!("recipe {} compiled successfully", path.display());
                }
                None => {
                    compiler.check(SAMPLE_RECIPE)?;
                    println!("bundled workspace recipe compiled successfully");
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn resolve_profile(args: &ProfileArgs) -> ResolvedProfile {
    ResolvedProfile::new(args.host, args.persistence, args.role)
}

fn print_profile(profile: &ResolvedProfile) {
    println!("host                {}", profile.host);
    println!("persistence         {}", profile.persistence);
    println!("role                {}", profile.role);
    println!("graphics            {}", profile.graphics);
    println!("persistent state    {}", profile.persistent_state);
    println!("synchronization     {}", profile.synchronization);
    println!(
        "pillars             {}",
        profile.required_pillars.join(", ")
    );
    println!(
        "providers           {}",
        profile.supporting_providers.join(", ")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_defaults_to_about() {
        let cli = Cli::try_parse_from(["hazards"]).expect("empty CLI should parse");
        assert!(cli.command.is_none());
    }

    #[test]
    fn parses_a_composed_remote_ghost_profile() {
        let cli = Cli::try_parse_from([
            "hazards",
            "profile",
            "resolve",
            "--host",
            "remote",
            "--persistence",
            "ghost",
            "--role",
            "operations",
        ])
        .expect("profile arguments should parse");

        let Some(Command::Profile {
            command: ProfileCommand::Resolve(args),
        }) = cli.command
        else {
            panic!("expected profile resolution command");
        };

        assert_eq!(args.host, HostKind::Remote);
        assert_eq!(args.persistence, Persistence::Ghost);
        assert_eq!(args.role, Role::Operations);
    }

    #[test]
    fn explicit_about_command_succeeds() {
        run(Cli {
            command: Some(Command::About),
        })
        .expect("about command should run");
    }

    #[test]
    fn parses_a_read_only_json_provision_plan() {
        let cli = Cli::try_parse_from([
            "hazards",
            "provision",
            "plan",
            "--host",
            "remote",
            "--persistence",
            "ghost",
            "--role",
            "research",
            "--json",
        ])
        .expect("provision plan arguments should parse");

        let Some(Command::Provision {
            command: ProvisionCommand::Plan(args),
        }) = cli.command
        else {
            panic!("expected provision plan command");
        };

        assert_eq!(args.host, HostKind::Remote);
        assert_eq!(args.persistence, Persistence::Ghost);
        assert_eq!(args.role, Role::Research);
        assert!(args.json);
    }

    #[test]
    fn parses_a_read_only_acquisition_plan() {
        let cli = Cli::try_parse_from([
            "hazards",
            "provision",
            "acquire-plan",
            "--host",
            "desktop",
            "--persistence",
            "local",
            "--role",
            "development",
            "--json",
        ])
        .expect("acquisition plan arguments should parse");

        let Some(Command::Provision {
            command: ProvisionCommand::AcquirePlan(args),
        }) = cli.command
        else {
            panic!("expected acquisition plan command");
        };

        assert_eq!(args.host, HostKind::Desktop);
        assert_eq!(args.persistence, Persistence::Local);
        assert_eq!(args.role, Role::Development);
        assert!(args.json);
    }

    #[test]
    fn parses_an_explicit_read_only_source_build_plan() {
        let cli = Cli::try_parse_from([
            "hazards",
            "provision",
            "build-plan",
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
        .expect("source build plan arguments should parse");

        let Some(Command::Provision {
            command: ProvisionCommand::BuildPlan(args),
        }) = cli.command
        else {
            panic!("expected source build plan command");
        };

        assert_eq!(args.tool, ["alacritty"]);
        assert!(!args.all);
        assert_eq!(args.profile.host, HostKind::Desktop);
        assert!(args.profile.json);
    }

    #[test]
    fn parses_an_explicit_verified_acquisition() {
        let cli = Cli::try_parse_from([
            "hazards",
            "provision",
            "acquire",
            "--tool",
            "zellij",
            "--tool",
            "delta",
            "--host",
            "desktop",
            "--persistence",
            "local",
            "--role",
            "development",
            "--json",
        ])
        .expect("acquisition arguments should parse");

        let Some(Command::Provision {
            command: ProvisionCommand::Acquire(args),
        }) = cli.command
        else {
            panic!("expected verified acquisition command");
        };

        assert_eq!(args.tool, ["zellij", "delta"]);
        assert!(!args.all);
        assert!(args.profile.json);
    }

    #[test]
    fn verified_acquisition_requires_an_explicit_selection() {
        let error = Cli::try_parse_from(["hazards", "provision", "acquire"])
            .expect_err("acquisition without a selection should fail");

        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn verified_acquisition_rejects_tool_and_all_together() {
        let error = Cli::try_parse_from([
            "hazards",
            "provision",
            "acquire",
            "--tool",
            "zellij",
            "--all",
        ])
        .expect_err("conflicting selection should fail");

        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn parses_an_explicit_safe_materialization() {
        let cli = Cli::try_parse_from([
            "hazards",
            "provision",
            "materialize",
            "--tool",
            "dotter",
            "--host",
            "desktop",
            "--persistence",
            "local",
            "--role",
            "development",
            "--json",
        ])
        .expect("materialization arguments should parse");

        let Some(Command::Provision {
            command: ProvisionCommand::Materialize(args),
        }) = cli.command
        else {
            panic!("expected safe materialization command");
        };

        assert_eq!(args.tool, ["dotter"]);
        assert!(!args.all);
        assert!(args.profile.json);
    }

    #[test]
    fn parses_an_explicit_transactional_installation() {
        let cli = Cli::try_parse_from([
            "hazards",
            "provision",
            "install",
            "--tool",
            "dotter",
            "--host",
            "desktop",
            "--persistence",
            "local",
            "--role",
            "development",
            "--json",
        ])
        .expect("installation arguments should parse");

        let Some(Command::Provision {
            command: ProvisionCommand::Install(args),
        }) = cli.command
        else {
            panic!("expected transactional installation command");
        };

        assert_eq!(args.tool, ["dotter"]);
        assert!(!args.all);
        assert!(args.profile.json);
    }

    #[test]
    fn parses_an_explicit_installation_rollback() {
        let cli = Cli::try_parse_from([
            "hazards",
            "provision",
            "rollback",
            "--tool",
            "dotter",
            "--json",
        ])
        .expect("rollback arguments should parse");

        let Some(Command::Provision {
            command: ProvisionCommand::Rollback(args),
        }) = cli.command
        else {
            panic!("expected installation rollback command");
        };

        assert_eq!(args.tool, "dotter");
        assert!(args.json);
    }

    #[test]
    fn parses_profile_aware_dotfile_generation() {
        let cli = Cli::try_parse_from([
            "hazards",
            "dotfiles",
            "generate",
            "--host",
            "remote",
            "--persistence",
            "ghost",
            "--role",
            "operations",
            "--root",
            "/tmp/hazards",
            "--json",
        ])
        .expect("dotfile generation arguments should parse");

        let Some(Command::Dotfiles {
            command: DotfilesCommand::Generate(args),
        }) = cli.command
        else {
            panic!("expected dotfile generation command");
        };

        assert_eq!(args.profile.host, HostKind::Remote);
        assert_eq!(args.profile.persistence, Persistence::Ghost);
        assert_eq!(args.profile.role, Role::Operations);
        assert_eq!(args.root, Some(PathBuf::from("/tmp/hazards")));
        assert!(args.profile.json);
    }

    #[test]
    fn parses_profile_aware_dotter_dry_run() {
        let cli = Cli::try_parse_from([
            "hazards",
            "dotfiles",
            "dry-run",
            "--host",
            "desktop",
            "--persistence",
            "local",
            "--role",
            "development",
        ])
        .expect("Dotter dry-run arguments should parse");

        let Some(Command::Dotfiles {
            command: DotfilesCommand::DryRun(args),
        }) = cli.command
        else {
            panic!("expected Dotter dry-run command");
        };

        assert_eq!(args.profile.host, HostKind::Desktop);
        assert_eq!(args.profile.persistence, Persistence::Local);
        assert_eq!(args.profile.role, Role::Development);
        assert!(args.root.is_none());
        assert!(!args.profile.json);
    }

    #[test]
    fn parses_read_only_dotfile_adoption_plan() {
        let cli = Cli::try_parse_from([
            "hazards",
            "dotfiles",
            "plan",
            "--host",
            "desktop",
            "--persistence",
            "local",
            "--role",
            "development",
            "--json",
        ])
        .expect("Dotter adoption plan arguments should parse");

        let Some(Command::Dotfiles {
            command: DotfilesCommand::Plan(args),
        }) = cli.command
        else {
            panic!("expected Dotter adoption plan command");
        };

        assert_eq!(args.profile.host, HostKind::Desktop);
        assert!(args.profile.json);
    }

    #[test]
    fn confirmed_dotfile_deployment_requires_a_token() {
        let cli = Cli::try_parse_from([
            "hazards",
            "dotfiles",
            "deploy",
            "--host",
            "desktop",
            "--confirm",
            "sha256:012345",
        ])
        .expect("confirmed Dotter deployment arguments should parse");

        let Some(Command::Dotfiles {
            command: DotfilesCommand::Deploy(args),
        }) = cli.command
        else {
            panic!("expected Dotter deployment command");
        };

        assert_eq!(args.dotfiles.profile.host, HostKind::Desktop);
        assert_eq!(args.confirm, "sha256:012345");
        assert!(
            Cli::try_parse_from(["hazards", "dotfiles", "deploy", "--host", "desktop"]).is_err()
        );
    }

    #[test]
    fn parses_dotfile_deployment_rollback() {
        let cli = Cli::try_parse_from([
            "hazards",
            "dotfiles",
            "rollback",
            "--host",
            "remote",
            "--persistence",
            "ghost",
            "--role",
            "operations",
        ])
        .expect("Dotter rollback arguments should parse");

        let Some(Command::Dotfiles {
            command: DotfilesCommand::Rollback(args),
        }) = cli.command
        else {
            panic!("expected Dotter rollback command");
        };

        assert_eq!(args.profile.host, HostKind::Remote);
        assert_eq!(args.profile.persistence, Persistence::Ghost);
    }

    #[test]
    fn byte_sizes_are_human_readable() {
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1536), "1.5 KiB");
        assert_eq!(format_size(3 * 1024 * 1024), "3.0 MiB");
    }
}
