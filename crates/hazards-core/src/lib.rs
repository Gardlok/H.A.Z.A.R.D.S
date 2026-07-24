//! Core domain types shared by HAZARDS front ends.

pub mod acquisition;
pub mod doctor;
pub mod paths;
pub mod probe;
pub mod profile;
pub mod provision;

pub use acquisition::{AcquisitionItem, AcquisitionPlan, AcquisitionPlanner, AcquisitionStatus};
pub use doctor::{Check, CheckStatus, Doctor};
pub use paths::{HazardsPaths, PathsError};
pub use probe::{EnvironmentProbe, LocatedCommand, SystemProbe};
pub use profile::{HostKind, Persistence, ResolvedProfile, Role};
pub use provision::{
    Platform, ProvisionItem, ProvisionKind, ProvisionPlan, ProvisionPlanner, ProvisionStatus,
};
