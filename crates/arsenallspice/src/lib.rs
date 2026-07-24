//! Arsenal is the HAZARDS tool and pillar registry.
//!
//! The deliberately ridiculous crate name combines Arsenal with allspice.
//! Naming crimes are acceptable when their schemas are validated.

use std::collections::HashSet;

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
    pub summary: String,
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
        if self.schema_version != 1 {
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
        }

        for provider in &self.providers {
            if !ids.insert(provider.id.as_str()) {
                return Err(RegistryError::DuplicateId(provider.id.clone()));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_registry_is_valid() {
        let registry = Registry::embedded().expect("embedded registry should parse");

        assert_eq!(registry.schema_version, 1);
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
}
