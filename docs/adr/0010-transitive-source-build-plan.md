# ADR 0010: Inspect transitive Cargo locks before source builds

## Status

Accepted

## Context

Alacritty 0.17.0 has no official Linux executable release asset. Its
checksummed crates.io archive is already locked and can be admitted to the
HAZARDS cache, but binary materialization correctly rejects it: source code is
not an executable payload.

Running `cargo install` would resolve and execute a much larger input set than
the one top-level checksum describes. Cargo dependencies, alternate sources,
build scripts, compiler inputs, native libraries, and the resulting executable
would otherwise appear only after crossing the execution boundary.

The published Alacritty and Tokei crates include `Cargo.lock`. Those lockfiles
contain exact versions and crates.io checksums for their complete registry
dependency graphs. They are useful evidence, but only after HAZARDS proves that
the lockfile is the exact one contained by the already reviewed outer archive.

## Decision

Upgrade the acquisition lock to schema 3. Every crates.io source artifact must
declare:

- its single expected archive root and package name;
- the exact published `Cargo.toml` SHA-256;
- the exact published `Cargo.lock` SHA-256 and format version; and
- the exact package count in that lock.

Add `hazards provision build-plan` as an explicitly selected, strictly
read-only operation. It:

1. revalidates the content-addressed cached source object;
2. streams the TAR/GZip archive without extracting it;
3. accepts only bounded regular files and directories beneath the locked root;
4. verifies the separately pinned manifest and lockfile identities;
5. requires the manifest package and version to match the acquisition record;
6. requires exactly one local root package;
7. accepts only the crates.io registry for every dependency;
8. requires a valid SHA-256 checksum for every registry package; and
9. rejects Git dependencies, additional path packages, alternate registries,
   unsafe archive paths, links, special files, duplicates, and size-limit
   violations.

The successful status is `graph_locked`, not `build_ready`. Source preparation,
dependency retrieval, build-script execution, compilation, output identity,
installation, and rollback remain separate authorization boundaries.

## Consequences

- HAZARDS can explain why a source build is or is not eligible before running
  Cargo.
- A changed upstream manifest, lockfile, dependency source, checksum, or graph
  size fails against embedded evidence.
- A missing verified source object is reported without creating cache state.
- The planner performs no extraction, network access, subprocess execution, or
  receipt write.
- Crates.io checksums provide integrity for retrieved dependency bytes, not
  signed publisher identity.
- The Rust compiler, linker, native development libraries, build scripts'
  effects, and final executable are not yet reproducibly locked.
