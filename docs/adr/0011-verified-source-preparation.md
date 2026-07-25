# ADR 0011: Prepare locked source as inert content-addressed input

## Status

Accepted

## Context

ADR 0010 established that Alacritty's published crate and complete Cargo
registry graph match embedded HAZARDS evidence. That read-only result does not
create build input. A future controlled build needs an exact source tree, but
using Cargo itself to unpack or prepare the crate would prematurely combine
source handling, dependency resolution, network access, build-script
execution, compilation, and installation.

Source extraction also introduces its own hazards independently of Cargo:
traversal, links, special files, duplicate paths, decompression expansion,
archived permissions, cache races, partial trees, and mutable existing
staging.

## Decision

Add `hazards provision prepare-source` as an explicit mutation boundary for
locked crates.io source artifacts. The operation:

1. requires explicit `--tool` selections or `--all`;
2. revalidates the cached outer object and complete Cargo graph before writing;
3. accepts only regular files and directories beneath the one locked source
   root;
4. enforces entry-count, path, per-entry, and aggregate-expansion limits;
5. discards archived ownership, permissions, and timestamps;
6. writes directories as `0700` and files as non-executable `0600`;
7. hashes the exact compressed stream consumed during extraction;
8. verifies the prepared `Cargo.toml` and `Cargo.lock` identities again;
9. inventories every prepared entry in a deterministic private manifest;
10. atomically persists a content-addressed source tree; and
11. writes append-only preparation evidence.

An existing tree is never accepted by pathname alone. HAZARDS freshly
reproduces the source from the verified object, validates the existing
manifest and actual files, and requires both inventories to match. Corrupt
staging fails closed and is preserved for diagnosis.

## Consequences

- Source archive handling is separate from Cargo and process execution.
- The persisted tree is bound to the exact acquisition digest and Cargo graph.
- Interrupted extraction leaves only an automatically removed temporary
  candidate, never a partial final stage.
- Repeated preparation is idempotent but still independently reproduces and
  verifies the source.
- No prepared file is executable.
- Preparation writes only HAZARDS-owned cache and receipt state.
- This phase does not retrieve dependencies, identify a Rust compiler or
  native library set, run build scripts, compile, install, or activate
  anything.
- A later build phase must revalidate prepared input and establish separate
  policies for dependency bytes, toolchain identity, native inputs, sandboxed
  execution, and output verification.
