use std::{error::Error, path::PathBuf, process::ExitCode};

use arsenallspice::Registry;
use clap::{Args, Parser, Subcommand};
use hazards_core::{
    CheckStatus, Doctor, HazardsPaths, HostKind, Persistence, ResolvedProfile, Role,
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
        Command::Recipe { command } => run_recipe(command),
    }
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
}
