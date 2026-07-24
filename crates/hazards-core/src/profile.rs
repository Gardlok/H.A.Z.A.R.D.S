use std::{fmt, str::FromStr};

use serde::Serialize;
use thiserror::Error;

/// Physical or remote host capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKind {
    Desktop,
    Laptop,
    Remote,
}

/// State lifetime and synchronization policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Persistence {
    Local,
    Roaming,
    Ghost,
}

/// Primary workspace purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Development,
    Operations,
    Research,
}

/// A concrete profile composed from independent dimensions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedProfile {
    pub host: HostKind,
    pub persistence: Persistence,
    pub role: Role,
    pub graphics: bool,
    pub persistent_state: bool,
    pub synchronization: bool,
    pub required_pillars: Vec<&'static str>,
    pub supporting_providers: Vec<&'static str>,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("unknown {kind} value {value:?}")]
pub struct ParseProfileError {
    kind: &'static str,
    value: String,
}

impl ResolvedProfile {
    pub fn new(host: HostKind, persistence: Persistence, role: Role) -> Self {
        let graphics = host != HostKind::Remote;
        let persistent_state = persistence != Persistence::Ghost;
        let synchronization = persistence == Persistence::Roaming;

        let mut required_pillars =
            vec!["helix", "zellij", "arsenal", "rhai", "dotter", "surrealdb"];
        if graphics {
            required_pillars.insert(1, "alacritty");
        }

        let mut supporting_providers = vec!["ripgrep", "fd", "bat"];
        if persistent_state {
            supporting_providers.push("atuin");
        }
        match role {
            Role::Development => supporting_providers.extend(["delta", "mise"]),
            Role::Operations => supporting_providers.extend(["bottom", "procs"]),
            Role::Research => supporting_providers.extend(["delta", "tokei"]),
        }

        Self {
            host,
            persistence,
            role,
            graphics,
            persistent_state,
            synchronization,
            required_pillars,
            supporting_providers,
        }
    }
}

macro_rules! string_enum {
    ($type:ty, $kind:literal, {$($variant:ident => $text:literal),+ $(,)?}) => {
        impl fmt::Display for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                let text = match self {
                    $(Self::$variant => $text),+
                };
                formatter.write_str(text)
            }
        }

        impl FromStr for $type {
            type Err = ParseProfileError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($text => Ok(Self::$variant),)+
                    _ => Err(ParseProfileError {
                        kind: $kind,
                        value: value.to_owned(),
                    }),
                }
            }
        }
    };
}

string_enum!(HostKind, "host", {
    Desktop => "desktop",
    Laptop => "laptop",
    Remote => "remote",
});
string_enum!(Persistence, "persistence", {
    Local => "local",
    Roaming => "roaming",
    Ghost => "ghost",
});
string_enum!(Role, "role", {
    Development => "development",
    Operations => "operations",
    Research => "research",
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_ghost_profile_has_no_graphics_or_persistent_history() {
        let profile = ResolvedProfile::new(HostKind::Remote, Persistence::Ghost, Role::Operations);

        assert!(!profile.graphics);
        assert!(!profile.persistent_state);
        assert!(!profile.synchronization);
        assert!(!profile.required_pillars.contains(&"alacritty"));
        assert!(!profile.supporting_providers.contains(&"atuin"));
    }

    #[test]
    fn roaming_laptop_profile_enables_sync_and_local_terminal() {
        let profile =
            ResolvedProfile::new(HostKind::Laptop, Persistence::Roaming, Role::Development);

        assert!(profile.graphics);
        assert!(profile.persistent_state);
        assert!(profile.synchronization);
        assert!(profile.required_pillars.contains(&"alacritty"));
        assert!(profile.supporting_providers.contains(&"atuin"));
    }

    #[test]
    fn profile_dimensions_round_trip_through_strings() {
        assert_eq!("desktop".parse(), Ok(HostKind::Desktop));
        assert_eq!("roaming".parse(), Ok(Persistence::Roaming));
        assert_eq!("research".parse(), Ok(Role::Research));
    }
}
