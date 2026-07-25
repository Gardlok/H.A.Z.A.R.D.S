use std::{
    env,
    path::{Path, PathBuf},
};

use serde::Serialize;
use thiserror::Error;

/// XDG-aware paths used by HAZARDS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HazardsPaths {
    pub home: PathBuf,
    pub config: PathBuf,
    pub data: PathBuf,
    pub state: PathBuf,
    pub cache: PathBuf,
    pub bin: PathBuf,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PathsError {
    #[error("HOME is not set; HAZARDS cannot resolve user-scoped paths")]
    MissingHome,
}

impl HazardsPaths {
    /// Resolve paths from the process environment without creating them.
    pub fn from_env() -> Result<Self, PathsError> {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or(PathsError::MissingHome)?;

        Ok(Self {
            home: home.clone(),
            config: xdg_path("XDG_CONFIG_HOME", &home.join(".config")).join("hazards"),
            data: xdg_path("XDG_DATA_HOME", &home.join(".local/share")).join("hazards"),
            state: xdg_path("XDG_STATE_HOME", &home.join(".local/state")).join("hazards"),
            cache: xdg_path("XDG_CACHE_HOME", &home.join(".cache")).join("hazards"),
            bin: home.join(".local/bin"),
        })
    }
}

fn xdg_path(variable: &str, fallback: &Path) -> PathBuf {
    env::var_os(variable)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| fallback.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_resolved_path_is_scoped_to_hazards_or_the_user_bin() {
        let paths = HazardsPaths::from_env().expect("test environment should have HOME");

        assert_eq!(
            paths.home,
            env::var_os("HOME")
                .map(PathBuf::from)
                .expect("test environment should have HOME")
        );
        assert_eq!(
            paths.config.file_name().and_then(|name| name.to_str()),
            Some("hazards")
        );
        assert_eq!(
            paths.data.file_name().and_then(|name| name.to_str()),
            Some("hazards")
        );
        assert_eq!(
            paths.state.file_name().and_then(|name| name.to_str()),
            Some("hazards")
        );
        assert_eq!(
            paths.cache.file_name().and_then(|name| name.to_str()),
            Some("hazards")
        );
        assert_eq!(
            paths.bin.file_name().and_then(|name| name.to_str()),
            Some("bin")
        );
    }
}
