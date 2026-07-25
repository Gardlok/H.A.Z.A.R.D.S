use arsenallspice::{AcquisitionLock, AcquisitionMethod, LockedArtifact};
use serde::Serialize;

use crate::{Platform, ProvisionItem, ProvisionPlan, ProvisionStatus, ResolvedProfile};

/// Integrity readiness for one required acquisition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionStatus {
    LockedBinary,
    LockedSource,
    Unavailable,
}

/// Exact acquisition evidence for one missing, outdated, or unsupported tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AcquisitionItem {
    pub id: String,
    pub name: String,
    pub provision_status: ProvisionStatus,
    pub target_version: String,
    pub destination: String,
    pub status: AcquisitionStatus,
    pub artifact: Option<LockedArtifact>,
    pub detail: String,
}

/// Profile-specific acquisition evidence. Producing this value performs no I/O.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AcquisitionPlan {
    pub read_only: bool,
    pub lock_observed_at: String,
    pub profile: ResolvedProfile,
    pub platform: Platform,
    pub items: Vec<AcquisitionItem>,
}

/// Converts host observations into exact, integrity-pinned acquisition records.
pub struct AcquisitionPlanner<'a> {
    lock: &'a AcquisitionLock,
    provision: &'a ProvisionPlan,
}

impl<'a> AcquisitionPlanner<'a> {
    pub fn new(lock: &'a AcquisitionLock, provision: &'a ProvisionPlan) -> Self {
        Self { lock, provision }
    }

    pub fn plan(&self) -> AcquisitionPlan {
        let items = self
            .provision
            .items
            .iter()
            .filter(|item| {
                matches!(
                    item.status,
                    ProvisionStatus::Outdated
                        | ProvisionStatus::Missing
                        | ProvisionStatus::Unsupported
                )
            })
            .filter_map(|item| self.resolve(item))
            .collect();

        AcquisitionPlan {
            read_only: true,
            lock_observed_at: self.lock.observed_at.clone(),
            profile: self.provision.profile.clone(),
            platform: self.provision.platform.clone(),
            items,
        }
    }

    /// Resolve exact evidence for any external provision item, including one
    /// already activated by HAZARDS.
    pub fn resolve(&self, item: &ProvisionItem) -> Option<AcquisitionItem> {
        let install = item.install.as_ref()?;
        let artifact = self.lock.select(
            &item.id,
            &install.target_version,
            &self.provision.platform.os,
            &self.provision.platform.architecture,
        );
        let (status, detail) = match artifact.map(|artifact| artifact.method) {
            Some(AcquisitionMethod::GithubRelease) => (
                AcquisitionStatus::LockedBinary,
                "prebuilt artifact and SHA-256 digest are locked".to_owned(),
            ),
            Some(AcquisitionMethod::CargoRegistry) => (
                AcquisitionStatus::LockedSource,
                "source archive and embedded Cargo graph identities are locked; build prerequisites are not evaluated"
                    .to_owned(),
            ),
            None => (
                AcquisitionStatus::Unavailable,
                format!(
                    "no locked artifact exists for {}/{}",
                    self.provision.platform.os, self.provision.platform.architecture
                ),
            ),
        };

        Some(AcquisitionItem {
            id: item.id.clone(),
            name: item.name.clone(),
            provision_status: item.status,
            target_version: install.target_version.clone(),
            destination: install.destination.clone(),
            status,
            artifact: artifact.cloned(),
            detail,
        })
    }
}

#[cfg(test)]
mod tests {
    use arsenallspice::{AcquisitionLock, AcquisitionMethod, Registry};

    use super::*;
    use crate::{
        HostKind, Persistence, ProvisionItem, ProvisionKind, ProvisionPlan, ProvisionStatus, Role,
    };

    fn provision_item(
        registry: &Registry,
        id: &str,
        name: &str,
        status: ProvisionStatus,
    ) -> ProvisionItem {
        ProvisionItem {
            id: id.to_owned(),
            name: name.to_owned(),
            kind: ProvisionKind::Provider,
            status,
            command_candidates: Vec::new(),
            resolved_command: None,
            path: None,
            installed_version: None,
            install: registry.install_spec(id).cloned(),
            detail: String::new(),
        }
    }

    fn provision_plan(registry: &Registry, architecture: &str) -> ProvisionPlan {
        ProvisionPlan {
            read_only: true,
            profile: ResolvedProfile::new(HostKind::Desktop, Persistence::Local, Role::Development),
            platform: Platform::new("linux", architecture),
            items: vec![
                provision_item(registry, "helix", "Helix", ProvisionStatus::Installed),
                provision_item(
                    registry,
                    "alacritty",
                    "Alacritty",
                    ProvisionStatus::Outdated,
                ),
                provision_item(registry, "zellij", "Zellij", ProvisionStatus::Missing),
                provision_item(registry, "fd", "fd", ProvisionStatus::Installed),
            ],
        }
    }

    fn item<'a>(plan: &'a AcquisitionPlan, id: &str) -> &'a AcquisitionItem {
        plan.items
            .iter()
            .find(|item| item.id == id)
            .expect("acquisition item should exist")
    }

    #[test]
    fn only_actionable_provision_items_receive_acquisition_evidence() {
        let registry = Registry::embedded().expect("registry should load");
        let lock = AcquisitionLock::embedded(&registry).expect("acquisition lock should load");
        let provision = provision_plan(&registry, "x86_64");
        let plan = AcquisitionPlanner::new(&lock, &provision).plan();

        assert_eq!(plan.items.len(), 2);
        assert!(!plan.items.iter().any(|item| item.id == "helix"));
        assert!(!plan.items.iter().any(|item| item.id == "fd"));
        assert_eq!(
            item(&plan, "alacritty").status,
            AcquisitionStatus::LockedSource
        );
        assert_eq!(
            item(&plan, "zellij").status,
            AcquisitionStatus::LockedBinary
        );
        assert_eq!(
            item(&plan, "zellij")
                .artifact
                .as_ref()
                .expect("Zellij artifact should be locked")
                .method,
            AcquisitionMethod::GithubRelease
        );
    }

    #[test]
    fn explicit_resolution_includes_an_already_installed_external_tool() {
        let registry = Registry::embedded().expect("registry should load");
        let lock = AcquisitionLock::embedded(&registry).expect("acquisition lock should load");
        let provision = provision_plan(&registry, "x86_64");
        let planner = AcquisitionPlanner::new(&lock, &provision);
        let installed = provision
            .items
            .iter()
            .find(|item| item.id == "helix")
            .expect("installed Helix provision item should exist");

        let resolved = planner
            .resolve(installed)
            .expect("an external installed tool should still resolve");

        assert_eq!(resolved.id, "helix");
        assert_eq!(resolved.provision_status, ProvisionStatus::Installed);
        assert_eq!(resolved.status, AcquisitionStatus::LockedBinary);
        assert!(resolved.artifact.is_some());
    }

    #[test]
    fn exact_arm_artifacts_are_selected_before_source_fallbacks() {
        let registry = Registry::embedded().expect("registry should load");
        let lock = AcquisitionLock::embedded(&registry).expect("acquisition lock should load");
        let provision = provision_plan(&registry, "aarch64");
        let plan = AcquisitionPlanner::new(&lock, &provision).plan();

        assert_eq!(
            item(&plan, "zellij")
                .artifact
                .as_ref()
                .expect("Zellij artifact should be locked")
                .architecture,
            "aarch64"
        );
        assert_eq!(
            item(&plan, "alacritty")
                .artifact
                .as_ref()
                .expect("Alacritty source should be locked")
                .architecture,
            "*"
        );
    }

    #[test]
    fn unsupported_architecture_is_reported_without_inventing_an_asset() {
        let registry = Registry::embedded().expect("registry should load");
        let lock = AcquisitionLock::embedded(&registry).expect("acquisition lock should load");
        let provision = provision_plan(&registry, "riscv64");
        let plan = AcquisitionPlanner::new(&lock, &provision).plan();

        assert_eq!(item(&plan, "zellij").status, AcquisitionStatus::Unavailable);
        assert!(item(&plan, "zellij").artifact.is_none());
        assert_eq!(
            item(&plan, "alacritty").status,
            AcquisitionStatus::LockedSource
        );
    }

    #[test]
    fn acquisition_json_is_deterministic_and_read_only() {
        let registry = Registry::embedded().expect("registry should load");
        let lock = AcquisitionLock::embedded(&registry).expect("acquisition lock should load");
        let provision = provision_plan(&registry, "x86_64");
        let build = || AcquisitionPlanner::new(&lock, &provision).plan();

        let first = serde_json::to_string(&build()).expect("plan should serialize");
        let second = serde_json::to_string(&build()).expect("plan should serialize again");

        assert_eq!(first, second);
        assert!(first.contains("\"read_only\":true"));
        assert!(first.contains("\"sha256\":"));
    }
}
