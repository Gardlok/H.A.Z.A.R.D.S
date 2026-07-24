//! Rhaisour is the starter culture for HAZARDS automation recipes.

use std::{fs, path::Path};

use rhai::Engine;
use thiserror::Error;

pub const SAMPLE_RECIPE: &str =
    include_str!("../../../ingredients/rhaisour/recipes/workspace.rhai");

#[derive(Debug, Error)]
pub enum RecipeError {
    #[error("could not read recipe {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("recipe did not compile: {0}")]
    Compile(String),
}

/// A deliberately constrained compiler for untrusted recipe text.
pub struct RecipeCompiler {
    engine: Engine,
}

impl Default for RecipeCompiler {
    fn default() -> Self {
        let mut engine = Engine::new();
        engine.set_max_operations(50_000);
        engine.set_max_expr_depths(64, 32);
        engine.disable_symbol("eval");
        engine.disable_symbol("import");
        Self { engine }
    }
}

impl RecipeCompiler {
    pub fn check(&self, source: &str) -> Result<(), RecipeError> {
        self.engine
            .compile(source)
            .map(|_| ())
            .map_err(|error| RecipeError::Compile(error.to_string()))
    }

    pub fn check_file(&self, path: &Path) -> Result<(), RecipeError> {
        let source = fs::read_to_string(path).map_err(|source| RecipeError::Read {
            path: path.display().to_string(),
            source,
        })?;
        self.check(&source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_recipe_compiles() {
        RecipeCompiler::default()
            .check(SAMPLE_RECIPE)
            .expect("sample recipe should compile");
    }

    #[test]
    fn malformed_recipe_is_rejected() {
        let error = RecipeCompiler::default()
            .check("let = ;")
            .expect_err("malformed recipe should fail");

        assert!(matches!(error, RecipeError::Compile(_)));
    }
}
