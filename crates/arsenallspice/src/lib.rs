//! Arsenal is the HAZARDS tool and pillar registry.
//!
//! The deliberately ridiculous crate name combines Arsenal with allspice.
//! Naming crimes are acceptable when their schemas are validated.

use std::{collections::HashSet, fmt};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const EMBEDDED_REGISTRY: &str = include_str!("../../../ingredients/arsenallspice/pillars.toml");

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
}

impl fmt::Display for InstallSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GithubRelease => formatter.write_str("GitHub release"),
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
}
