use std::{cmp::Ordering, path::PathBuf};

use arsenallspice::{InstallSpec, PillarKind, Registry};
use serde::Serialize;

use crate::{
    ResolvedProfile,
    probe::{EnvironmentProbe, SystemProbe},
};

/// Host platform used to decide whether declared installation intent applies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Platform {
    pub os: String,
    pub architecture: String,
}

impl Platform {
    pub fn current() -> Self {
        Self::new(std::env::consts::OS, std::env::consts::ARCH)
    }

    pub fn new(os: impl Into<String>, architecture: impl Into<String>) -> Self {
        Self {
            os: os.into(),
            architecture: architecture.into(),
        }
    }
}

/// Registry role of an item in a provision plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisionKind {
    Pillar,
    Provider,
}

/// Read-only classification of a required tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvisionStatus {
    Installed,
    Outdated,
    Missing,
    Planned,
    Unsupported,
}

/// One deterministic observation and its declared installation intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProvisionItem {
    pub id: String,
    pub name: String,
    pub kind: ProvisionKind,
    pub status: ProvisionStatus,
    pub command_candidates: Vec<String>,
    pub resolved_command: Option<String>,
    pub path: Option<PathBuf>,
    pub installed_version: Option<String>,
    pub install: Option<InstallSpec>,
    pub detail: String,
}

/// A complete profile-specific plan. Producing this value changes nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProvisionPlan {
    pub read_only: bool,
    pub profile: ResolvedProfile,
    pub platform: Platform,
    pub items: Vec<ProvisionItem>,
}

/// Profile-aware read-only provision planner.
pub struct ProvisionPlanner<'a, P = SystemProbe> {
    registry: &'a Registry,
    profile: &'a ResolvedProfile,
    probe: P,
    platform: Platform,
}

impl<'a> ProvisionPlanner<'a, SystemProbe> {
    pub fn new(registry: &'a Registry, profile: &'a ResolvedProfile) -> Self {
        Self::with_probe(registry, profile, SystemProbe, Platform::current())
    }
}

impl<'a, P: EnvironmentProbe> ProvisionPlanner<'a, P> {
    pub fn with_probe(
        registry: &'a Registry,
        profile: &'a ResolvedProfile,
        probe: P,
        platform: Platform,
    ) -> Self {
        Self {
            registry,
            profile,
            probe,
            platform,
        }
    }

    pub fn plan(&self) -> ProvisionPlan {
        let mut items = Vec::new();

        for id in &self.profile.required_pillars {
            let pillar = self
                .registry
                .pillars
                .iter()
                .find(|pillar| pillar.id == *id)
                .expect("resolved profile should only contain registered pillars");
            let commands = pillar.command_candidates();
            let item = match pillar.kind {
                PillarKind::Internal | PillarKind::Embedded => ProvisionItem {
                    id: pillar.id.clone(),
                    name: pillar.name.clone(),
                    kind: ProvisionKind::Pillar,
                    status: ProvisionStatus::Installed,
                    command_candidates: commands.iter().map(|value| (*value).to_owned()).collect(),
                    resolved_command: None,
                    path: None,
                    installed_version: None,
                    install: None,
                    detail: format!("{} is supplied by HAZARDS", pillar.name),
                },
                PillarKind::Planned => ProvisionItem {
                    id: pillar.id.clone(),
                    name: pillar.name.clone(),
                    kind: ProvisionKind::Pillar,
                    status: ProvisionStatus::Planned,
                    command_candidates: commands.iter().map(|value| (*value).to_owned()).collect(),
                    resolved_command: None,
                    path: None,
                    installed_version: None,
                    install: None,
                    detail: format!("{} integration is scaffolded but not active", pillar.name),
                },
                PillarKind::External => self.inspect_external(
                    &pillar.id,
                    &pillar.name,
                    ProvisionKind::Pillar,
                    &commands,
                    &pillar.version_args,
                    pillar
                        .install
                        .as_ref()
                        .expect("validated external pillar should have installation intent"),
                ),
            };
            items.push(item);
        }

        for id in &self.profile.supporting_providers {
            let provider = self
                .registry
                .providers
                .iter()
                .find(|provider| provider.id == *id)
                .expect("resolved profile should only contain registered providers");
            let commands = provider.command_candidates();
            items.push(
                self.inspect_external(
                    &provider.id,
                    &provider.name,
                    ProvisionKind::Provider,
                    &commands,
                    &provider.version_args,
                    provider
                        .install
                        .as_ref()
                        .expect("validated provider should have installation intent"),
                ),
            );
        }

        ProvisionPlan {
            read_only: true,
            profile: self.profile.clone(),
            platform: self.platform.clone(),
            items,
        }
    }

    fn inspect_external(
        &self,
        id: &str,
        name: &str,
        kind: ProvisionKind,
        commands: &[&str],
        version_args: &[String],
        install: &InstallSpec,
    ) -> ProvisionItem {
        let command_candidates = commands.iter().map(|value| (*value).to_owned()).collect();
        let Some(located) = self.probe.locate(commands) else {
            let supported = install
                .platforms
                .iter()
                .any(|platform| platform == &self.platform.os);
            return ProvisionItem {
                id: id.to_owned(),
                name: name.to_owned(),
                kind,
                status: if supported {
                    ProvisionStatus::Missing
                } else {
                    ProvisionStatus::Unsupported
                },
                command_candidates,
                resolved_command: None,
                path: None,
                installed_version: None,
                install: Some(install.clone()),
                detail: if supported {
                    "no command candidate was found on PATH".to_owned()
                } else {
                    format!(
                        "no installation intent is declared for {}",
                        self.platform.os
                    )
                },
            };
        };

        let (status, installed_version, detail) =
            match self.probe.version(&located.path, version_args) {
                Ok(output) => match (
                    LooseVersion::extract(&output),
                    LooseVersion::extract(&install.target_version),
                ) {
                    (Some(installed), Some(target)) if installed < target => (
                        ProvisionStatus::Outdated,
                        Some(installed.display),
                        "installed version is older than the advisory target".to_owned(),
                    ),
                    (Some(installed), Some(_)) => (
                        ProvisionStatus::Installed,
                        Some(installed.display),
                        "installed version meets the advisory target".to_owned(),
                    ),
                    _ => (
                        ProvisionStatus::Installed,
                        None,
                        "command found; version output was not comparable".to_owned(),
                    ),
                },
                Err(error) => (
                    ProvisionStatus::Installed,
                    None,
                    format!("command found; version probe failed: {error}"),
                ),
            };

        ProvisionItem {
            id: id.to_owned(),
            name: name.to_owned(),
            kind,
            status,
            command_candidates,
            resolved_command: Some(located.command),
            path: Some(located.path),
            installed_version,
            install: Some(install.clone()),
            detail,
        }
    }
}

#[derive(Debug, Clone, Eq)]
struct LooseVersion {
    display: String,
    parts: Vec<u64>,
}

impl LooseVersion {
    fn extract(text: &str) -> Option<Self> {
        text.split(|character: char| !character.is_ascii_digit() && character != '.')
            .filter(|candidate| !candidate.is_empty())
            .find_map(|candidate| {
                let candidate = candidate.trim_matches('.');
                let pieces: Vec<_> = candidate.split('.').collect();
                if pieces.len() < 2 || pieces.iter().any(|piece| piece.is_empty()) {
                    return None;
                }
                let parts = pieces
                    .iter()
                    .map(|piece| piece.parse::<u64>())
                    .collect::<Result<Vec<_>, _>>()
                    .ok()?;
                Some(Self {
                    display: candidate.to_owned(),
                    parts,
                })
            })
    }
}

pub(crate) fn version_matches(output: &str, expected: &str) -> bool {
    matches!(
        (LooseVersion::extract(output), LooseVersion::extract(expected)),
        (Some(actual), Some(expected)) if actual == expected
    )
}

impl PartialEq for LooseVersion {
    fn eq(&self, other: &Self) -> bool {
        compare_parts(&self.parts, &other.parts) == Ordering::Equal
    }
}

impl PartialOrd for LooseVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LooseVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_parts(&self.parts, &other.parts)
    }
}

fn compare_parts(left: &[u64], right: &[u64]) -> Ordering {
    let length = left.len().max(right.len());
    (0..length)
        .map(|index| {
            left.get(index)
                .copied()
                .unwrap_or(0)
                .cmp(&right.get(index).copied().unwrap_or(0))
        })
        .find(|ordering| *ordering != Ordering::Equal)
        .unwrap_or(Ordering::Equal)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        path::{Path, PathBuf},
    };

    use arsenallspice::Registry;

    use super::*;
    use crate::{HostKind, Persistence, Role};

    #[derive(Default)]
    struct FakeProbe {
        commands: HashMap<String, (PathBuf, Result<String, String>)>,
    }

    impl FakeProbe {
        fn installed(mut self, command: &str, version: &str) -> Self {
            self.commands.insert(
                command.to_owned(),
                (
                    PathBuf::from(format!("/fake/bin/{command}")),
                    Ok(version.to_owned()),
                ),
            );
            self
        }
    }

    impl EnvironmentProbe for FakeProbe {
        fn locate(&self, commands: &[&str]) -> Option<crate::probe::LocatedCommand> {
            commands.iter().find_map(|command| {
                self.commands
                    .get(*command)
                    .map(|(path, _)| crate::probe::LocatedCommand {
                        command: (*command).to_owned(),
                        path: path.clone(),
                    })
            })
        }

        fn version(&self, executable: &Path, _args: &[String]) -> Result<String, String> {
            self.commands
                .values()
                .find(|(path, _)| path == executable)
                .expect("located fake command should have version output")
                .1
                .clone()
        }
    }

    fn item<'a>(plan: &'a ProvisionPlan, id: &str) -> &'a ProvisionItem {
        plan.items
            .iter()
            .find(|item| item.id == id)
            .expect("planned item should exist")
    }

    #[test]
    fn remote_ghost_plan_only_contains_required_tools() {
        let registry = Registry::embedded().expect("registry should load");
        let profile = ResolvedProfile::new(HostKind::Remote, Persistence::Ghost, Role::Operations);
        let plan = ProvisionPlanner::with_probe(
            &registry,
            &profile,
            FakeProbe::default(),
            Platform::new("linux", "x86_64"),
        )
        .plan();

        assert!(!plan.items.iter().any(|item| item.id == "alacritty"));
        assert!(!plan.items.iter().any(|item| item.id == "atuin"));
        assert!(plan.items.iter().any(|item| item.id == "bottom"));
        assert!(plan.items.iter().any(|item| item.id == "procs"));
        assert!(plan.read_only);
    }

    #[test]
    fn distribution_aliases_are_used_in_registry_order() {
        let registry = Registry::embedded().expect("registry should load");
        let profile =
            ResolvedProfile::new(HostKind::Desktop, Persistence::Local, Role::Development);
        let probe = FakeProbe::default()
            .installed("fdfind", "fd 10.4.2")
            .installed("batcat", "bat 0.26.1");
        let plan = ProvisionPlanner::with_probe(
            &registry,
            &profile,
            probe,
            Platform::new("linux", "x86_64"),
        )
        .plan();

        assert_eq!(
            item(&plan, "fd").resolved_command.as_deref(),
            Some("fdfind")
        );
        assert_eq!(
            item(&plan, "bat").resolved_command.as_deref(),
            Some("batcat")
        );
        assert_eq!(item(&plan, "fd").status, ProvisionStatus::Installed);
        assert_eq!(item(&plan, "bat").status, ProvisionStatus::Installed);
    }

    #[test]
    fn versions_classify_outdated_and_newer_commands() {
        let registry = Registry::embedded().expect("registry should load");
        let profile =
            ResolvedProfile::new(HostKind::Desktop, Persistence::Local, Role::Development);
        let probe = FakeProbe::default()
            .installed("rg", "ripgrep 14.1.1")
            .installed("fd", "fd 99.0.0");
        let plan = ProvisionPlanner::with_probe(
            &registry,
            &profile,
            probe,
            Platform::new("linux", "x86_64"),
        )
        .plan();

        assert_eq!(item(&plan, "ripgrep").status, ProvisionStatus::Outdated);
        assert_eq!(item(&plan, "fd").status, ProvisionStatus::Installed);
    }

    #[test]
    fn absent_tools_are_missing_on_linux_and_unsupported_elsewhere() {
        let registry = Registry::embedded().expect("registry should load");
        let profile =
            ResolvedProfile::new(HostKind::Desktop, Persistence::Local, Role::Development);
        let linux_plan = ProvisionPlanner::with_probe(
            &registry,
            &profile,
            FakeProbe::default(),
            Platform::new("linux", "aarch64"),
        )
        .plan();
        let windows_plan = ProvisionPlanner::with_probe(
            &registry,
            &profile,
            FakeProbe::default(),
            Platform::new("windows", "x86_64"),
        )
        .plan();

        assert_eq!(item(&linux_plan, "helix").status, ProvisionStatus::Missing);
        assert_eq!(
            item(&windows_plan, "helix").status,
            ProvisionStatus::Unsupported
        );
        assert_eq!(
            item(&windows_plan, "arsenal").status,
            ProvisionStatus::Installed
        );
        assert_eq!(
            item(&windows_plan, "surrealdb").status,
            ProvisionStatus::Planned
        );
    }

    #[test]
    fn loose_versions_accept_calver_and_leading_zero_components() {
        let helix =
            LooseVersion::extract("helix 25.07.1 (deadbeef)").expect("Helix version should parse");
        let mise =
            LooseVersion::extract("mise 2026.7.11 linux-x64").expect("mise version should parse");

        assert_eq!(helix.parts, [25, 7, 1]);
        assert_eq!(helix.display, "25.07.1");
        assert_eq!(mise.parts, [2026, 7, 11]);
    }

    #[test]
    fn json_output_is_deterministic_and_explicitly_read_only() {
        let registry = Registry::embedded().expect("registry should load");
        let profile = ResolvedProfile::new(HostKind::Remote, Persistence::Ghost, Role::Research);
        let build_plan = || {
            ProvisionPlanner::with_probe(
                &registry,
                &profile,
                FakeProbe::default(),
                Platform::new("linux", "x86_64"),
            )
            .plan()
        };

        let first = serde_json::to_string(&build_plan()).expect("plan should serialize");
        let second = serde_json::to_string(&build_plan()).expect("plan should serialize again");

        assert_eq!(first, second);
        assert!(first.contains("\"read_only\":true"));
        assert!(!first.contains("\"alacritty\""));
        assert!(!first.contains("\"atuin\""));
    }
}
