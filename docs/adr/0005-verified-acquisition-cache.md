# ADR 0005: Verify into quarantine before materialization

## Status

Accepted

## Context

The acquisition lock identifies exact upstream bytes, but a lock alone does not
retrieve or verify them. Combining retrieval, archive extraction, executable
discovery, replacement, and rollback in one initial executor would make a
network failure indistinguishable from an installation failure and would force
several unrelated trust decisions into one review.

HAZARDS also needs repeatable operation across desktops, laptops, and remote
hosts. Downloading the same immutable artifact for each later action wastes
bandwidth and encourages ad hoc temporary paths whose provenance is difficult
to inspect.

## Decision

HAZARDS introduces a verified acquisition cache as a distinct phase.
`hazards provision acquire`:

1. requires explicit `--tool` selections or `--all`;
2. accepts only actionable artifacts selected by the read-only planners;
3. retrieves only the exact URL embedded in the validated lock;
4. follows at most five HTTPS redirects and applies bounded timeouts;
5. streams into a private temporary file without response decompression;
6. enforces the exact locked byte count and SHA-256 digest;
7. synchronizes and atomically persists successful bytes by digest;
8. rehashes existing objects before reporting a cache hit;
9. records each verification event in an append-only JSON receipt.

Cache and receipt directories use user-private permissions on Unix. A corrupt
existing object fails closed and is preserved; repair or deletion requires a
future explicit cache-maintenance policy.

The acquisition command does not extract, build, execute, install, replace,
chmod, alter shell configuration, or resolve `PATH`.

## Consequences

- Interrupted and rejected transfers cannot become final cache objects.
- Identical content is naturally deduplicated by SHA-256.
- Later materialization can operate without network access while retaining the
  original source and verification evidence.
- Successful objects remain cached if a later item in `--all` fails; this is a
  cache operation, not an all-or-nothing installation transaction.
- A matching digest proves consistency with the reviewed lock, not independent
  publisher identity.
- Archive safety, payload identity, runtime assets, source dependency locking,
  installation replacement, and rollback remain separate decisions.
