# ADR 0006: Materialize locked payloads into inert private staging

## Status

Accepted

## Context

A verified acquisition object proves that cached bytes match the reviewed
lock. It does not prove that an archive is safe to extract, that an expected
program exists inside it, or that the program targets the current
architecture. Treating verification as permission to unpack directly into
`~/.local/bin` would collapse archive parsing, payload discovery, execution
policy, replacement, and rollback into one difficult-to-audit mutation.

Upstream release archives also carry paths, entry types, permissions,
ownership, and timestamps. Those fields are instructions from untrusted input,
not configuration HAZARDS should casually obey.

## Decision

HAZARDS introduces `hazards provision materialize` as a distinct offline phase.
It:

1. requires explicit `--tool` selections or `--all`;
2. accepts only actionable binary artifacts chosen by the existing planners;
3. re-verifies the cache object's type, size, and SHA-256 digest;
4. extracts into a private temporary directory adjacent to final staging;
5. accepts only safe relative UTF-8 paths and regular files/directories;
6. rejects links, special files, duplicates, encrypted ZIP members, and
   excessive entry counts or expansion;
7. ignores archive ownership, timestamps, and permissions;
8. creates files as `0600` and directories as `0700`;
9. verifies the lock's exact payload path, byte count, SHA-256 digest, ELF
   class, endianness, type, and machine architecture;
10. inventories the complete tree in a deterministic private manifest;
11. atomically persists the tree by artifact digest;
12. re-creates and compares existing stages before reporting a cache-like hit;
13. writes an append-only materialization receipt.

The acquisition lock schema records payload path, size, and digest for every
prebuilt binary artifact. Source archives intentionally have no payload
identity and cannot be materialized by this command.

The command performs no network I/O. It does not build source, execute a
payload, grant executable permissions, install or replace a command, modify
`PATH`, or write into `~/.local/bin`.

## Consequences

- Archive traversal and link tricks cannot escape the private staging root.
- Archive metadata cannot grant execution or expose staged files to other
  users.
- A release archive may contain support files, but only an exact reviewed
  payload can satisfy the lock.
- A stage hit is evidence of deterministic reproduction from the verified
  cache object, not blind trust in an existing directory name.
- Source builds require a future transitive dependency and toolchain lock.
- Staged payloads remain deliberately unusable until a separate transactional
  installer defines dependency checks, activation, health validation, and
  rollback.
