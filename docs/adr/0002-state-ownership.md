# ADR 0002: State has one authority

## Status

Accepted

## Decision

| State | Authority |
| --- | --- |
| Dotfiles and templates | Git plus Dotter |
| Installed tool versions | HAZARDS tool manifest |
| Live panes and sessions | Zellij |
| Contextual shell history | Atuin |
| Dynamic project/workspace metadata | SurrealDB |
| Automation source | Rhai recipe files |
| Secrets | Host keyring, SSH agent, or a dedicated encrypted provider |

## Consequences

HAZARDS may index or reference another authority's records, but it does not
silently duplicate and mutate them. In particular, SurrealDB is not a dotfile
source, secret store, shell history database, or Zellij session database.
