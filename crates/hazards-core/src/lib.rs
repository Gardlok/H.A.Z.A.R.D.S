//! Core domain types shared by HAZARDS front ends.

pub mod acquire;
pub mod acquisition;
pub mod build_contract;
pub mod cargo_dependency;
pub mod doctor;
pub mod dotfiles;
pub mod install;
pub mod materialize;
pub mod paths;
pub mod probe;
pub mod profile;
pub mod provision;
pub mod source_build;
pub mod source_prepare;

pub use acquire::{
    AcquisitionOutcome, AcquisitionReceipt, ArtifactAcquirer, ArtifactPayload, ArtifactSource,
    HttpArtifactSource, VerifiedArtifact, VerifiedArtifactError,
};
pub use acquisition::{AcquisitionItem, AcquisitionPlan, AcquisitionPlanner, AcquisitionStatus};
pub use build_contract::{
    BuildCommandEvidence, BuildCommandSpec, BuildContractError, BuildContractItem,
    BuildContractLock, BuildContractPlan, BuildContractPlanner, BuildContractSpec,
    BuildContractStatus, BuildDependencyEvidence, BuildEnvironmentEvidence, BuildEnvironmentProbe,
    BuildEnvironmentSpec, BuildInvocationTemplate, BuildSourceEvidence, PkgConfigEvidence,
    PkgConfigSpec, RustToolchainEvidence, SystemBuildEnvironmentProbe,
};
pub use cargo_dependency::{
    CachedCargoDependencies, CachedCargoDependency, CargoDependencyAcquirer,
    CargoDependencyCacheOutcome, CargoDependencyError, CargoDependencyOutcome,
    CargoDependencyPayload, CargoDependencyReceipt, CargoDependencySource, CargoDependencySpec,
    HttpCargoDependencySource, VerifiedCargoDependencies,
};
pub use doctor::{Check, CheckStatus, Doctor};
pub use dotfiles::{
    DotfileAdoptionAction, DotfileAdoptionItem, DotfileDeploymentOutcome, DotfileDeploymentPlan,
    DotfileDeploymentReceipt, DotfileDeploymentReport, DotfileMapping, DotfileRollbackReceipt,
    DotfileRollbackReport, DotfileRollbackResult, DotfileTargetKind, DotfilesError,
    DotfilesManager, DotterDryRunOutcome, DotterDryRunReport, DotterGenerationOutcome,
    GeneratedDotterProfile, SystemDotterRunner,
};
pub use install::{
    InstallationError, InstallationOutcome, InstallationReceipt, InstalledArtifact, Installer,
    ManagedActivation, RolledBackArtifact, StoreOutcome,
};
pub use materialize::{
    MaterializationError, MaterializationOutcome, MaterializationReceipt, Materializer,
    StagedArtifact,
};
pub use paths::{HazardsPaths, PathsError};
pub use probe::{EnvironmentProbe, LocatedCommand, SystemProbe};
pub use profile::{HostKind, Persistence, ResolvedProfile, Role};
pub use provision::{
    Platform, ProvisionItem, ProvisionKind, ProvisionPlan, ProvisionPlanner, ProvisionStatus,
};
pub use source_build::{SourceBuildItem, SourceBuildPlan, SourceBuildPlanner, SourceBuildStatus};
pub use source_prepare::{
    PreparedSource, SourcePreparationError, SourcePreparationOutcome, SourcePreparationReceipt,
    SourcePreparer, VerifiedPreparedSource,
};
