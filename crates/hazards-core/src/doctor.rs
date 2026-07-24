use arsenallspice::{PillarKind, Registry};
use serde::Serialize;

use crate::{
    ResolvedProfile,
    probe::{EnvironmentProbe, SystemProbe},
};

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
pub struct Doctor<'a, P = SystemProbe> {
    registry: &'a Registry,
    profile: &'a ResolvedProfile,
    probe: P,
}

impl<'a> Doctor<'a, SystemProbe> {
    pub fn new(registry: &'a Registry, profile: &'a ResolvedProfile) -> Self {
        Self::with_probe(registry, profile, SystemProbe)
    }
}

impl<'a, P: EnvironmentProbe> Doctor<'a, P> {
    pub fn with_probe(registry: &'a Registry, profile: &'a ResolvedProfile, probe: P) -> Self {
        Self {
            registry,
            profile,
            probe,
        }
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
                    let commands = pillar.command_candidates();
                    match self.probe.locate(&commands) {
                        Some(located) => (
                            CheckStatus::Pass,
                            format!("{} found at {}", located.command, located.path.display()),
                        ),
                        None => (
                            CheckStatus::Missing,
                            format!("{} was not found on PATH", commands.join(" or ")),
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
            let commands = provider.command_candidates();
            let located = self.probe.locate(&commands);
            checks.push(Check {
                id: provider.id.clone(),
                status: if located.is_some() {
                    CheckStatus::Pass
                } else {
                    CheckStatus::Missing
                },
                required,
                detail: located.map_or_else(
                    || format!("{} was not found on PATH", commands.join(" or ")),
                    |located| format!("{} found at {}", located.command, located.path.display()),
                ),
            });
        }

        checks
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

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

    struct AliasProbe;

    impl EnvironmentProbe for AliasProbe {
        fn locate(&self, commands: &[&str]) -> Option<crate::probe::LocatedCommand> {
            commands
                .contains(&"fdfind")
                .then(|| crate::probe::LocatedCommand {
                    command: "fdfind".to_owned(),
                    path: PathBuf::from("/usr/bin/fdfind"),
                })
        }

        fn version(&self, _executable: &Path, _args: &[String]) -> Result<String, String> {
            unreachable!("doctor does not probe versions")
        }
    }

    #[test]
    fn doctor_accepts_a_distribution_command_alias() {
        let registry = Registry::embedded().expect("registry should load");
        let profile =
            ResolvedProfile::new(HostKind::Desktop, Persistence::Local, Role::Development);
        let checks = Doctor::with_probe(&registry, &profile, AliasProbe).run();
        let fd = checks
            .iter()
            .find(|check| check.id == "fd")
            .expect("fd check should exist");

        assert_eq!(fd.status, CheckStatus::Pass);
        assert!(fd.detail.contains("/usr/bin/fdfind"));
    }
}
