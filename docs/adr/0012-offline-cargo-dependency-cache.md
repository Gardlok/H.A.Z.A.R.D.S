# ADR 0012: Offline checksum-verified Cargo dependency cache

## Status

Accepted for implementation.

## Context

A locked top-level crates.io archive and its embedded `Cargo.lock` identify the
complete Rust package graph, but they do not place the dependency archives
under HAZARDS control. Allowing a later build to contact crates.io through
Cargo would combine dependency retrieval, Cargo registry behavior, build
scripts, compilation, and output production in one opaque authority.

## Decision

HAZARDS provides a dedicated `hazards-cargo-dependencies` companion authority.
For each explicitly selected locked source artifact it:

1. requires an existing controlled source-preparation stage;
2. freshly reproduces and compares that stage to the locked top-level object;
3. rehashes the prepared `Cargo.lock` against its separately pinned identity;
4. requires exactly one local root and only canonical crates.io registry
   dependencies with valid SHA-256 checksums;
5. derives the static crates.io archive URL solely from each locked package
   name and version;
6. disables redirects and bounds every response to 512 MiB;
7. hashes every response while writing it to a private sibling temporary file;
8. persists verified archives by checksum with mode `0600`;
9. rehashes existing objects and preserves corrupt objects as rejected
   evidence;
10. records a deterministic complete-graph manifest keyed by the Cargo lock
    digest; and
11. writes an append-only operation receipt.

The authority does not extract dependency archives or write into Cargo's own
registry directories. HAZARDS owns the cache layout and will explicitly adapt
it for a later offline build contract.

## Consequences

A future build may be denied network access and still receive every exact
registry archive required by the locked graph. Dependency retrieval can be
audited independently from Cargo behavior, toolchain identity, native system
libraries, build-script execution, compilation, result verification,
installation, and activation.

The cache is not yet directly consumable by Cargo. A later authority must
construct a controlled source replacement or other explicit offline input,
pin the Rust toolchain and native prerequisites, sandbox execution, and bind
resulting binaries to reproducible evidence. A directory full of checksummed
archives is useful evidence, not absolution.
