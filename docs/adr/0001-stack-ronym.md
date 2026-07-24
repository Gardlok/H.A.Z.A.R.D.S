# ADR 0001: HAZARDS stack-ronym

## Status

Accepted

## Decision

The seven pillar applications are:

1. Helix
2. Alacritty
3. Zellij
4. Arsenal
5. Rhai
6. Dotter
7. SurrealDB

Arsenal is a custom Rust application and library that provides HAZARDS-specific
project, profile, provider, diagnostic, and launch behavior.

Atuin remains a supporting provider. Its contextual history is valuable, but
it does not own enough of the environment to displace the control plane.

## Consequences

- Every acronym letter owns a distinct architectural responsibility.
- HAZARDS must implement and maintain Arsenal.
- Supporting tools may change without renaming the environment.
- Rhai and SurrealDB integrations may be compiled into HAZARDS while their
  upstream project names remain represented in the stack-ronym.
