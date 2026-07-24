# ADR 0003: Plan before mutation

## Status

Accepted

## Context

HAZARDS is expected to work on daily-driver Debian hosts, remote systems, and
new machines whose existing tools may have been installed by a distribution,
Cargo, or a previous HAZARDS release. An installer cannot safely decide what to
change until the control plane has a deterministic model of the selected
profile and current host.

Distribution packaging also changes executable names. Debian commonly exposes
fd and bat as `fdfind` and `batcat`, so treating one canonical command as the
entire truth produces theatrically confident nonsense.

## Decision

Arsenal registry schema version 2 records, for each external tool:

- a canonical command and optional aliases;
- the argument vector used for a version probe;
- an advisory target release;
- the release source locator;
- the intended rootless destination;
- supported operating systems.

`hazards provision plan` resolves a profile and returns a read-only observation
for each required item. It invokes executables directly and classifies items as
`installed`, `outdated`, `missing`, `planned`, or `unsupported`. Both human and
JSON output are deterministic.

The planner has no download, extraction, installation, configuration
deployment, or database-writing capability.

## Consequences

- Planning can be tested with a fake host probe without changing the test
  machine.
- Debian command aliases are first-class registry data instead of scattered
  special cases.
- Target versions can guide an operator before the verified installer exists.
- The targets are advisory until release assets and checksums are pinned.
- A future mutating command must consume an explicit plan and add verification,
  approval, rollback, and execution receipts rather than quietly growing side
  effects inside the planner.
