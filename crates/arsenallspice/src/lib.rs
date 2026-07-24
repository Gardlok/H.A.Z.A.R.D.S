//! Arsenal is the HAZARDS tool and pillar registry.
//!
//! The deliberately ridiculous crate name combines Arsenal with allspice.
//! Naming crimes are acceptable when their schemas are validated.

use std::{collections::HashSet, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const EMBEDDED_REGISTRY: &str = include_str!("../../../ingredients/arsenallspice/pillars.toml");
const EMBEDDED_ACQUISITIONS: &str =
    include_str!("../../../ingredients/arsenallspice/acquisitions.toml");

/// A parsed HAZARDS pillar and provider registry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Registry {
    pub schema_version: u8,
    #[serde(default)]
    pub pillars: Vec<Pillar>,
    #[serde(default)]
    pub providers: Vec<Provider>,
}

/// One application represented by a letter in HAZARDS.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Pillar {
    pub letter: char,
    pub id: String,
    pub name: String,
    pub ingredient: String,
    pub kind: PillarKind,
    pub summary: String,
    pub command: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default = "default_version_args")]
    pub version_args: Vec<String>,
    pub install: Option<InstallSpec>,
}

/// Whether a pillar is a process, part of HAZARDS, linked in, or only scaffolded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PillarKind {
    External,
    Internal,
    Embedded,
    Planned,
}

/// A useful application that does not occupy a letter in HAZARDS.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Provider {
    pub id: String,
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default = "default_version_args")]
    pub version_args: Vec<String>,
    pub summary: String,
    pub install: Option<InstallSpec>,
}

/// Read-only installation intent used by the provision planner.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct InstallSpec {
    pub source: InstallSource,
    pub locator: String,
    pub target_version: String,
    pub destination: String,
    #[serde(default)]
    pub platforms: Vec<String>,
}

/// A source that a future verified installer may know how to resolve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallSource {
    GithubRelease,
    CargoRegistry,
}

impl fmt::Display for InstallSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GithubRelease => formatter.write_str("GitHub release"),
            Self::CargoRegistry => formatter.write_str("crates.io source"),
        }
    }
}

/// Integrity-pinned acquisition records for supported targets.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct AcquisitionLock {
    pub schema_version: u8,
    pub observed_at: String,
    #[serde(default)]
    pub artifacts: Vec<LockedArtifact>,
}

/// Exact bytes that a future acquisition executor may retrieve and verify.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct LockedArtifact {
    pub tool_id: String,
    pub version: String,
    pub os: String,
    pub architecture: String,
    pub method: AcquisitionMethod,
    pub format: ArtifactFormat,
    pub name: String,
    pub size: u64,
    pub sha256: String,
    pub url: String,
    pub evidence: DigestEvidence,
    #[serde(default)]
    pub payload_path: Option<String>,
    #[serde(default)]
    pub payload_size: Option<u64>,
    #[serde(default)]
    pub payload_sha256: Option<String>,
}

/// How the pinned bytes are distributed upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionMethod {
    GithubRelease,
    CargoRegistry,
}

/// Container format of the pinned artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFormat {
    Binary,
    TarGz,
    TarXz,
    Zip,
    Crate,
}

/// Upstream metadata from which the pinned SHA-256 value was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DigestEvidence {
    GithubAssetDigest,
    CratesIoChecksum,
}

impl fmt::Display for AcquisitionMethod {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GithubRelease => formatter.write_str("GitHub release"),
            Self::CargoRegistry => formatter.write_str("crates.io source"),
        }
    }
}

impl fmt::Display for DigestEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GithubAssetDigest => formatter.write_str("GitHub asset digest"),
            Self::CratesIoChecksum => formatter.write_str("crates.io checksum"),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryError {
    #[error("could not parse the Arsenal registry: {0}")]
    Parse(String),
    #[error("unsupported registry schema version {0}")]
    UnsupportedSchema(u8),
    #[error("the pillar letters spell {actual}, not HAZARDS")]
    InvalidAcronym { actual: String },
    #[error("duplicate registry identifier: {0}")]
    DuplicateId(String),
    #[error("duplicate ingredient directory: {0}")]
    DuplicateIngredient(String),
    #[error("external pillar {0} does not declare a command")]
    MissingCommand(String),
    #[error("external tool {0} does not declare installation intent")]
    MissingInstallSpec(String),
    #[error("external tool {id} has invalid installation intent: {reason}")]
    InvalidInstallSpec { id: String, reason: String },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AcquisitionError {
    #[error("could not parse the acquisition lock: {0}")]
    Parse(String),
    #[error("unsupported acquisition lock schema version {0}")]
    UnsupportedSchema(u8),
    #[error("acquisition record references tool without external install intent: {0}")]
    UnknownTool(String),
    #[error(
        "acquisition version {actual} for {id} does not match registry target version {expected}"
    )]
    VersionMismatch {
        id: String,
        expected: String,
        actual: String,
    },
    #[error("duplicate acquisition target for {id}: {os}/{architecture}")]
    DuplicateTarget {
        id: String,
        os: String,
        architecture: String,
    },
    #[error("invalid acquisition record for {id}: {reason}")]
    InvalidArtifact { id: String, reason: String },
    #[error("external tool has no acquisition record: {0}")]
    MissingCoverage(String),
}

impl Registry {
    /// Load the registry shipped with the compiled HAZARDS binary.
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::parse(EMBEDDED_REGISTRY)
    }

    /// Parse and validate a registry document.
    pub fn parse(source: &str) -> Result<Self, RegistryError> {
        let registry: Self =
            toml::from_str(source).map_err(|error| RegistryError::Parse(error.to_string()))?;
        registry.validate()?;
        Ok(registry)
    }

    /// Confirm the stack-ronym and uniqueness invariants.
    pub fn validate(&self) -> Result<(), RegistryError> {
        if self.schema_version != 2 {
            return Err(RegistryError::UnsupportedSchema(self.schema_version));
        }

        let actual: String = self.pillars.iter().map(|pillar| pillar.letter).collect();
        if actual != "HAZARDS" {
            return Err(RegistryError::InvalidAcronym { actual });
        }

        let mut ids = HashSet::new();
        let mut ingredients = HashSet::new();
        for pillar in &self.pillars {
            if !ids.insert(pillar.id.as_str()) {
                return Err(RegistryError::DuplicateId(pillar.id.clone()));
            }
            if !ingredients.insert(pillar.ingredient.as_str()) {
                return Err(RegistryError::DuplicateIngredient(
                    pillar.ingredient.clone(),
                ));
            }
            if pillar.kind == PillarKind::External && pillar.command.is_none() {
                return Err(RegistryError::MissingCommand(pillar.id.clone()));
            }
            if pillar.kind == PillarKind::External {
                validate_install_spec(
                    &pillar.id,
                    pillar
                        .install
                        .as_ref()
                        .ok_or_else(|| RegistryError::MissingInstallSpec(pillar.id.clone()))?,
                )?;
            }
        }

        for provider in &self.providers {
            if !ids.insert(provider.id.as_str()) {
                return Err(RegistryError::DuplicateId(provider.id.clone()));
            }
            validate_install_spec(
                &provider.id,
                provider
                    .install
                    .as_ref()
                    .ok_or_else(|| RegistryError::MissingInstallSpec(provider.id.clone()))?,
            )?;
        }

        Ok(())
    }

    /// Find the install intent for an external pillar or provider.
    pub fn install_spec(&self, id: &str) -> Option<&InstallSpec> {
        self.pillars
            .iter()
            .find(|pillar| pillar.id == id)
            .and_then(|pillar| pillar.install.as_ref())
            .or_else(|| {
                self.providers
                    .iter()
                    .find(|provider| provider.id == id)
                    .and_then(|provider| provider.install.as_ref())
            })
    }
}

impl AcquisitionLock {
    /// Load and validate the acquisition records shipped with HAZARDS.
    pub fn embedded(registry: &Registry) -> Result<Self, AcquisitionError> {
        Self::parse(EMBEDDED_ACQUISITIONS, registry)
    }

    /// Parse acquisition records and cross-check them against registry intent.
    pub fn parse(source: &str, registry: &Registry) -> Result<Self, AcquisitionError> {
        let lock: Self =
            toml::from_str(source).map_err(|error| AcquisitionError::Parse(error.to_string()))?;
        lock.validate(registry)?;
        Ok(lock)
    }

    pub fn validate(&self, registry: &Registry) -> Result<(), AcquisitionError> {
        if self.schema_version != 2 {
            return Err(AcquisitionError::UnsupportedSchema(self.schema_version));
        }
        if self.observed_at.trim().is_empty() {
            return Err(AcquisitionError::InvalidArtifact {
                id: "lock".to_owned(),
                reason: "observation date is empty".to_owned(),
            });
        }

        let mut targets = HashSet::new();
        let mut covered = HashSet::new();
        for artifact in &self.artifacts {
            let install = registry
                .install_spec(&artifact.tool_id)
                .ok_or_else(|| AcquisitionError::UnknownTool(artifact.tool_id.clone()))?;
            if artifact.version != install.target_version {
                return Err(AcquisitionError::VersionMismatch {
                    id: artifact.tool_id.clone(),
                    expected: install.target_version.clone(),
                    actual: artifact.version.clone(),
                });
            }
            if !targets.insert((
                artifact.tool_id.as_str(),
                artifact.os.as_str(),
                artifact.architecture.as_str(),
            )) {
                return Err(AcquisitionError::DuplicateTarget {
                    id: artifact.tool_id.clone(),
                    os: artifact.os.clone(),
                    architecture: artifact.architecture.clone(),
                });
            }
            validate_artifact(artifact, install)?;
            covered.insert(artifact.tool_id.as_str());
        }

        for pillar in external_pillar_ids(registry) {
            if !covered.contains(pillar) {
                return Err(AcquisitionError::MissingCoverage(pillar.to_owned()));
            }
        }
        for provider in &registry.providers {
            if !covered.contains(provider.id.as_str()) {
                return Err(AcquisitionError::MissingCoverage(provider.id.clone()));
            }
        }
        Ok(())
    }

    /// Select an exact architecture record, falling back to an architecture-neutral source.
    pub fn select(
        &self,
        tool_id: &str,
        version: &str,
        os: &str,
        architecture: &str,
    ) -> Option<&LockedArtifact> {
        self.artifacts
            .iter()
            .find(|artifact| {
                artifact.tool_id == tool_id
                    && artifact.version == version
                    && artifact.os == os
                    && artifact.architecture == architecture
            })
            .or_else(|| {
                self.artifacts.iter().find(|artifact| {
                    artifact.tool_id == tool_id
                        && artifact.version == version
                        && artifact.os == os
                        && artifact.architecture == "*"
                })
            })
    }
}

impl Pillar {
    /// Canonical command followed by any distribution-specific aliases.
    pub fn command_candidates(&self) -> Vec<&str> {
        self.command
            .iter()
            .map(String::as_str)
            .chain(self.aliases.iter().map(String::as_str))
            .collect()
    }
}

impl Provider {
    /// Canonical command followed by any distribution-specific aliases.
    pub fn command_candidates(&self) -> Vec<&str> {
        std::iter::once(self.command.as_str())
            .chain(self.aliases.iter().map(String::as_str))
            .collect()
    }
}

fn default_version_args() -> Vec<String> {
    vec!["--version".to_owned()]
}

fn validate_install_spec(id: &str, install: &InstallSpec) -> Result<(), RegistryError> {
    let invalid = |reason: &str| RegistryError::InvalidInstallSpec {
        id: id.to_owned(),
        reason: reason.to_owned(),
    };

    if install.locator.trim().is_empty() {
        return Err(invalid("source locator is empty"));
    }
    if install.target_version.trim().is_empty() {
        return Err(invalid("target version is empty"));
    }
    if install.destination.trim().is_empty() {
        return Err(invalid("destination is empty"));
    }
    if install.platforms.is_empty() {
        return Err(invalid("supported platform list is empty"));
    }
    Ok(())
}

fn external_pillar_ids(registry: &Registry) -> impl Iterator<Item = &str> {
    registry
        .pillars
        .iter()
        .filter(|pillar| pillar.kind == PillarKind::External)
        .map(|pillar| pillar.id.as_str())
}

fn validate_artifact(
    artifact: &LockedArtifact,
    install: &InstallSpec,
) -> Result<(), AcquisitionError> {
    let invalid = |reason: &str| AcquisitionError::InvalidArtifact {
        id: artifact.tool_id.clone(),
        reason: reason.to_owned(),
    };

    if artifact.name.trim().is_empty() {
        return Err(invalid("asset name is empty"));
    }
    if artifact.size == 0 {
        return Err(invalid("asset size is zero"));
    }
    if artifact.architecture.trim().is_empty() {
        return Err(invalid("architecture is empty"));
    }
    if !install.platforms.contains(&artifact.os) {
        return Err(invalid(
            "operating system is not declared by install intent",
        ));
    }
    if artifact.sha256.len() != 64
        || !artifact
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(
            "SHA-256 digest must be 64 lowercase hex characters",
        ));
    }
    if !artifact.url.starts_with("https://") {
        return Err(invalid("source URL must use HTTPS"));
    }

    let payload = match (
        artifact.payload_path.as_deref(),
        artifact.payload_size,
        artifact.payload_sha256.as_deref(),
    ) {
        (Some(path), Some(size), Some(sha256)) => Some((path, size, sha256)),
        (None, None, None) => None,
        _ => {
            return Err(invalid(
                "payload path, size, and SHA-256 must be declared together",
            ));
        }
    };

    match (artifact.method, artifact.format, artifact.evidence) {
        (
            AcquisitionMethod::GithubRelease,
            ArtifactFormat::Crate,
            DigestEvidence::GithubAssetDigest,
        ) => return Err(invalid("GitHub release artifact cannot use crate format")),
        (AcquisitionMethod::GithubRelease, _, DigestEvidence::GithubAssetDigest)
            if install.source == InstallSource::GithubRelease
                && artifact.url.starts_with(&format!(
                    "https://github.com/{}/releases/download/",
                    install.locator
                )) =>
        {
            let Some((path, size, sha256)) = payload else {
                return Err(invalid(
                    "GitHub release artifact must declare an executable payload",
                ));
            };
            if !safe_relative_payload_path(path) {
                return Err(invalid("payload path is not a safe relative path"));
            }
            if size == 0 {
                return Err(invalid("payload size is zero"));
            }
            if !valid_sha256(sha256) {
                return Err(invalid(
                    "payload SHA-256 must be 64 lowercase hex characters",
                ));
            }
            if artifact.format == ArtifactFormat::Binary
                && (size != artifact.size || sha256 != artifact.sha256)
            {
                return Err(invalid(
                    "binary payload size and SHA-256 must equal the artifact",
                ));
            }
        }
        (
            AcquisitionMethod::CargoRegistry,
            ArtifactFormat::Crate,
            DigestEvidence::CratesIoChecksum,
        ) if install.source == InstallSource::CargoRegistry
            && artifact.url
                == format!(
                    "https://crates.io/api/v1/crates/{}/{}/download",
                    install.locator, install.target_version
                ) =>
        {
            if payload.is_some() {
                return Err(invalid(
                    "source artifact cannot declare an executable payload",
                ));
            }
        }
        _ => return Err(invalid("method, format, evidence, and URL do not agree")),
    }

    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_relative_payload_path(value: &str) -> bool {
    use std::path::{Component, Path};

    !value.is_empty()
        && !value.contains('\\')
        && Path::new(value)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_registry_is_valid() {
        let registry = Registry::embedded().expect("embedded registry should parse");

        assert_eq!(registry.schema_version, 2);
        assert_eq!(registry.pillars.len(), 7);
        assert_eq!(
            registry
                .pillars
                .iter()
                .map(|pillar| pillar.letter)
                .collect::<String>(),
            "HAZARDS"
        );
    }

    #[test]
    fn rejects_a_registry_that_does_not_spell_hazards() {
        let source = EMBEDDED_REGISTRY.replacen("letter = \"H\"", "letter = \"X\"", 1);

        let error = Registry::parse(&source).expect_err("invalid acronym should fail");
        assert_eq!(
            error,
            RegistryError::InvalidAcronym {
                actual: "XAZARDS".to_owned()
            }
        );
    }

    #[test]
    fn rejects_duplicate_identifiers() {
        let source = EMBEDDED_REGISTRY.replacen("id = \"atuin\"", "id = \"helix\"", 1);

        let error = Registry::parse(&source).expect_err("duplicate id should fail");
        assert_eq!(error, RegistryError::DuplicateId("helix".to_owned()));
    }

    #[test]
    fn debian_command_aliases_are_registered() {
        let registry = Registry::embedded().expect("embedded registry should parse");

        let fd = registry
            .providers
            .iter()
            .find(|provider| provider.id == "fd")
            .expect("fd provider should exist");
        let bat = registry
            .providers
            .iter()
            .find(|provider| provider.id == "bat")
            .expect("bat provider should exist");

        assert_eq!(fd.command_candidates(), ["fd", "fdfind"]);
        assert_eq!(bat.command_candidates(), ["bat", "batcat"]);
    }

    #[test]
    fn every_external_tool_has_installation_intent() {
        let registry = Registry::embedded().expect("embedded registry should parse");

        assert!(
            registry
                .pillars
                .iter()
                .filter(|pillar| pillar.kind == PillarKind::External)
                .all(|pillar| pillar.install.is_some())
        );
        assert!(
            registry
                .providers
                .iter()
                .all(|provider| provider.install.is_some())
        );
    }

    #[test]
    fn embedded_acquisition_lock_covers_every_external_tool() {
        let registry = Registry::embedded().expect("embedded registry should parse");
        let lock =
            AcquisitionLock::embedded(&registry).expect("embedded acquisition lock should parse");

        assert_eq!(lock.schema_version, 2);
        assert_eq!(lock.artifacts.len(), 24);
        assert_eq!(
            lock.select("zellij", "0.44.3", "linux", "x86_64")
                .expect("Zellij x86_64 artifact should exist")
                .format,
            ArtifactFormat::TarGz
        );
        assert_eq!(
            lock.select("zellij", "0.44.3", "linux", "x86_64")
                .expect("Zellij x86_64 artifact should exist")
                .payload_path
                .as_deref(),
            Some("zellij")
        );
        assert_eq!(
            lock.select("alacritty", "0.17.0", "linux", "aarch64")
                .expect("architecture-neutral Alacritty source should exist")
                .method,
            AcquisitionMethod::CargoRegistry
        );
    }

    #[test]
    fn acquisition_lock_rejects_target_version_drift() {
        let registry = Registry::embedded().expect("embedded registry should parse");
        let source = EMBEDDED_ACQUISITIONS.replacen(
            "tool_id = \"helix\"\nversion = \"25.07.1\"",
            "tool_id = \"helix\"\nversion = \"99.0.0\"",
            1,
        );

        let error =
            AcquisitionLock::parse(&source, &registry).expect_err("version drift should fail");
        assert_eq!(
            error,
            AcquisitionError::VersionMismatch {
                id: "helix".to_owned(),
                expected: "25.07.1".to_owned(),
                actual: "99.0.0".to_owned(),
            }
        );
    }

    #[test]
    fn acquisition_lock_rejects_malformed_digests() {
        let registry = Registry::embedded().expect("embedded registry should parse");
        let source = EMBEDDED_ACQUISITIONS.replacen(
            "sha256 = \"3f08e63ecd388fff657ad39722f88bb03dcf326f1f2da2700d99e1dc40ab2e8b\"",
            "sha256 = \"trust-me-bro\"",
            1,
        );

        let error =
            AcquisitionLock::parse(&source, &registry).expect_err("invalid digest should fail");
        assert_eq!(
            error,
            AcquisitionError::InvalidArtifact {
                id: "helix".to_owned(),
                reason: "SHA-256 digest must be 64 lowercase hex characters".to_owned(),
            }
        );
    }

    #[test]
    fn acquisition_lock_rejects_unsafe_or_partial_payload_identity() {
        let registry = Registry::embedded().expect("embedded registry should parse");
        let unsafe_path = EMBEDDED_ACQUISITIONS.replacen(
            "payload_path = \"zellij\"",
            "payload_path = \"../zellij\"",
            1,
        );
        let error = AcquisitionLock::parse(&unsafe_path, &registry)
            .expect_err("unsafe payload path should fail");
        assert_eq!(
            error,
            AcquisitionError::InvalidArtifact {
                id: "zellij".to_owned(),
                reason: "payload path is not a safe relative path".to_owned(),
            }
        );

        let partial = EMBEDDED_ACQUISITIONS.replacen("payload_size = 51836080\n", "", 1);
        let error =
            AcquisitionLock::parse(&partial, &registry).expect_err("partial payload should fail");
        assert_eq!(
            error,
            AcquisitionError::InvalidArtifact {
                id: "zellij".to_owned(),
                reason: "payload path, size, and SHA-256 must be declared together".to_owned(),
            }
        );
    }
}
