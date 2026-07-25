# ADR 0011: Prepare locked source before authorizing Cargo

## Status

Accepted

## Context

`hazards provision build-plan` proves that a verified crates.io archive contains
the separately locked `Cargo.toml`, `Cargo.lock`, package identity, and complete
crates.io dependency graph. Its successful `graph_locked` result is deliberately
read-only. No source tree exists for a later build authority to consume.

Extracting the archive is itself a mutation and a parsing boundary. Reusing the
binary materializer would blur two different authorities: binary staging proves
one exact executable payload and architecture, while source staging must prove
the complete inert tree and its Cargo graph without inventing an executable
identity. Running `cargo install` directly would combine extraction, dependency
retrieval, build-script execution, compilation, and activation in one cheerful
supply-chain séance.

## Decision

Add a separate `hazards-source-prepare` companion command and a
`SourcePreparer` core authority. For every explicitly selected locked source
artifact, source preparation:

1. requires the acquisition planner to classify the item as `locked_source`;
2. requires an existing content-addressed cache object and independently checks
   its type, byte count, and SHA-256 digest;
3. extracts only the locked crates.io TAR/GZip shape beneath its single expected
   source root;
4. accepts only bounded regular files and directories with safe relative UTF-8
   paths;
5. rejects traversal, absolute paths, backslashes, links, special entries,
   duplicates, oversized entries, excessive entry counts, and excessive total
   expansion;
6. discards archived ownership, timestamps, and permissions, creating
   directories as `0700` and files as `0600`;
7. independently rehashes and validates the locked `Cargo.toml` and `Cargo.lock`,
   including package identity, lock version, package count, one local root, the
   crates.io registry source, and every registry checksum;
8. inventories every resulting file and directory in a deterministic manifest;
9. atomically persists the private tree under
   `$XDG_CACHE_HOME/hazards/sources/sha256/<prefix>/<artifact-digest>`; and
10. writes append-only receipts under
    `$XDG_STATE_HOME/hazards/receipts/source-preparations/<tool>/<version>`.

An existing source stage is never trusted by its directory name or stored
manifest alone. HAZARDS freshly reproduces the candidate from the verified
outer object, validates the existing tree, and requires the complete manifests
to match before returning `stage_hit`.

The companion command performs no network access, dependency retrieval,
subprocess execution, Cargo invocation, build-script execution, compilation,
permission elevation, installation, activation, or `PATH` modification.

## Consequences

- Later build work can consume one private, immutable-by-policy source identity
  rather than extracting ad hoc inside an execution phase.
- Tampered source files, permissions, evidence, Cargo metadata, or cached outer
  bytes fail closed.
- Every prepared file remains non-executable.
- Repeated preparation is idempotent only after a fresh independent
  reproduction proves the existing stage still matches.
- The Rust toolchain, dependency downloads, native libraries, build scripts,
  linker, environment, final binary identity, and activation remain separate
  authorization boundaries.
- The companion binary keeps this mutation surface narrower than the general
  binary materialization and installation commands.
