//! Core domain types shared by HAZARDS front ends.

pub mod acquire;
pub mod acquisition;
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
    SourcePreparer,
};
