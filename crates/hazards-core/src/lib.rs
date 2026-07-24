//! Core domain types shared by HAZARDS front ends.

pub mod doctor;
pub mod paths;
pub mod profile;

pub use doctor::{Check, CheckStatus, Doctor};
pub use paths::{HazardsPaths, PathsError};
pub use profile::{HostKind, Persistence, ResolvedProfile, Role};
