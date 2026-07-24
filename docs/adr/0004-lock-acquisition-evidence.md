# ADR 0004: Lock acquisition evidence before retrieval

## Status

Accepted

## Context

The provision planner identifies missing and outdated tools, but a repository
name and target version do not identify bytes. Release conventions differ:
some projects publish musl archives, some publish raw binaries, some publish
only platform-specific packages, and some publish no Linux binary at all.

Selecting assets dynamically during installation would make the chosen bytes
depend on mutable network metadata at the moment of execution. It would also
encourage a downloader to become an installer before its trust policy exists,
which is how perfectly ordinary shell scripts become folklore.

## Decision

Arsenal embeds a separately versioned acquisition lock. Each record contains:

- tool and target version;
- operating system and architecture;
- distribution method and container format;
- exact asset name, URL, and byte count;
- SHA-256 digest;
- the upstream metadata class from which the digest was recorded.

The initial lock covers Linux x86_64 and aarch64. Musl release archives are
preferred where upstream publishes them. Alacritty and Tokei have no suitable
Linux release assets at their pinned versions, so their crates.io source
archives and registry checksums are locked instead.

`hazards provision acquire-plan` composes the acquisition lock with the
read-only provision plan. It reports `locked_binary`, `locked_source`, or
`unavailable` and performs no network, download, extraction, build, deployment,
or installation action.

## Consequences

- Code review sees the exact URL and digest before any future retrieval.
- Registry target-version drift invalidates the lock at startup.
- Duplicate targets, malformed digests, source mismatches, and missing tool
  coverage are rejected.
- A future retriever must hash bytes before extraction and fail closed on any
  mismatch.
- GitHub-recorded asset digests and crates.io checksums provide integrity pins,
  not independent signed publisher identity.
- A locked crate covers the top-level source archive only; source-build
  dependencies and native prerequisites need their own later policy.
