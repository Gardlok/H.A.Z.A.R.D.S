# ADR 0007: Transactional user-local installation

## Status

Accepted

## Context

Verified acquisition and safe materialization prove which bytes HAZARDS has
and what executable they contain, but deliberately leave that payload inert.
Turning it into a daily-driver command crosses a wider trust boundary: runtime
assets must remain available, an existing command may belong to the operating
system or the user, the new binary may fail at runtime, `PATH` may ignore the
activation, and evidence persistence may fail after replacement.

Conflating retrieval, extraction, and activation would make those failures
ambiguous and make rollback dependent on partially completed work.

## Decision

Add explicit `hazards provision install` and `hazards provision rollback`
commands for locked prebuilt artifacts.

Installation:

1. requires and independently verifies an existing materialized stage;
2. copies its complete tree to a private content-addressed XDG data store;
3. makes only the locked executable payload executable;
4. validates the exact stored payload with registry-owned version arguments;
5. refuses to replace anything except a fully validated HAZARDS-managed
   activation;
6. activates through a user-local symlink;
7. verifies the activated version and current `PATH` resolution;
8. restores the preceding activation if validation or receipt persistence
   fails; and
9. writes append-only evidence for successful, idempotent, failed-recovered,
   and explicit rollback transitions.

Rollback follows the newest applicable successful install or upgrade receipt.
It restores the recorded prior managed target, or removes the activation when
rolling back an initial install, and verifies the result. A failed rollback
restores the newer target.

Source archives are excluded because their top-level checksum does not pin
compiler inputs or transitive dependencies. Transactions are per tool; a
multi-tool request is a sequence of independently durable operations.

## Consequences

- Installation never opens the network and cannot silently create missing
  staging.
- Existing operating-system, Cargo, or hand-managed commands elsewhere on
  `PATH` remain untouched.
- A conflicting entry in `~/.local/bin` fails closed and requires an operator
  decision.
- Complete application trees support binaries such as Helix that need runtime
  assets beside the executable.
- Explicit rollback is evidence-driven and cannot guess what an unmanaged
  command used to be.
- Content-addressed versions remain available after rollback; garbage
  collection needs a separate retention policy.
- HAZARDS assumes the invoking user controls their own XDG roots. Defending
  against a malicious concurrent process with the same user identity is outside
  this boundary.
