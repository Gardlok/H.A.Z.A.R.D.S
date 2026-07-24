use std::{env, path::PathBuf};

use arsenallspice::{PillarKind, Registry};
use serde::Serialize;

use crate::ResolvedProfile;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Missing,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub id: String,
    pub status: CheckStatus,
    pub required: bool,
    pub detail: String,
}

/// Read-only diagnostics for a resolved profile.
pub struct Doctor<'a> {
    registry: &'a Registry,
    profile: &'a ResolvedProfile,
}

impl<'a> Doctor<'a> {
    pub fn new(registry: &'a Registry, profile: &'a ResolvedProfile) -> Self {
        Self { registry, profile }
    }

    pub fn run(&self) -> Vec<Check> {
        let mut checks = Vec::new();

        for pillar in &self.registry.pillars {
            let required = self.profile.required_pillars.contains(&pillar.id.as_str());
            let (status, detail) = match pillar.kind {
                PillarKind::Internal | PillarKind::Embedded => (
                    CheckStatus::Pass,
                    format!("{} is supplied by HAZARDS", pillar.name),
                ),
                PillarKind::Planned => (
                    CheckStatus::Skipped,
                    format!("{} integration is scaffolded but not active", pillar.name),
                ),
                PillarKind::External if !required => (
                    CheckStatus::Skipped,
                    format!("{} is not required by this profile", pillar.name),
                ),
                PillarKind::External => {
                    let command = pillar
                        .command
                        .as_deref()
                        .expect("validated external pillar should declare a command");
                    match find_command(command) {
                        Some(path) => (
                            CheckStatus::Pass,
                            format!("{command} found at {}", path.display()),
                        ),
                        None => (
                            CheckStatus::Missing,
                            format!("{command} was not found on PATH"),
                        ),
                    }
                }
            };
            checks.push(Check {
                id: pillar.id.clone(),
                status,
                required,
                detail,
            });
        }

        for provider in &self.registry.providers {
            let required = self
                .profile
                .supporting_providers
                .contains(&provider.id.as_str());
            if !required {
                continue;
            }
            let path = find_command(&provider.command);
            checks.push(Check {
                id: provider.id.clone(),
                status: if path.is_some() {
                    CheckStatus::Pass
                } else {
                    CheckStatus::Missing
                },
                required,
                detail: path.map_or_else(
                    || format!("{} was not found on PATH", provider.command),
                    |path| format!("{} found at {}", provider.command, path.display()),
                ),
            });
        }

        checks
    }
}

fn find_command(command: &str) -> Option<PathBuf> {
    let candidate = PathBuf::from(command);
    if candidate.components().count() > 1 {
        return candidate.is_file().then_some(candidate);
    }

    env::var_os("PATH").and_then(|path| {
        env::split_paths(&path)
            .map(|directory| directory.join(command))
            .find(|candidate| candidate.is_file())
    })
}

#[cfg(test)]
mod tests {
    use arsenallspice::Registry;

    use super::*;
    use crate::{HostKind, Persistence, Role};

    #[test]
    fn remote_profile_skips_alacritty() {
        let registry = Registry::embedded().expect("registry should load");
        let profile = ResolvedProfile::new(HostKind::Remote, Persistence::Ghost, Role::Operations);
        let checks = Doctor::new(&registry, &profile).run();
        let alacritty = checks
            .iter()
            .find(|check| check.id == "alacritty")
            .expect("alacritty check should exist");

        assert_eq!(alacritty.status, CheckStatus::Skipped);
        assert!(!alacritty.required);
    }

    #[test]
    fn embedded_pillars_do_not_require_path_commands() {
        let registry = Registry::embedded().expect("registry should load");
        let profile =
            ResolvedProfile::new(HostKind::Desktop, Persistence::Local, Role::Development);
        let checks = Doctor::new(&registry, &profile).run();

        for id in ["arsenal", "rhai"] {
            let check = checks
                .iter()
                .find(|check| check.id == id)
                .expect("embedded pillar check should exist");
            assert_eq!(check.status, CheckStatus::Pass);
        }

        let surrealdb = checks
            .iter()
            .find(|check| check.id == "surrealdb")
            .expect("SurrealDB check should exist");
        assert_eq!(surrealdb.status, CheckStatus::Skipped);
        assert!(surrealdb.required);
    }
}
