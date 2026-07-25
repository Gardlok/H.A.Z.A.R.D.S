# ADR 0009: Confirm and recover Dotter deployment transactions

## Status

Accepted

## Context

Verified Dotter previews deliberately refused confirmed deployment. Testing on
Orion then found the expected migration case: regular Helix and Zellij
configuration files already occupied two selected targets. Dotter correctly
refused to overwrite them without `--force`.

Using `--force` would erase the distinction between an approved adoption, an
unmanaged symlink, a directory, and an unexpected file change between preview
and execution. A useful daily-driver workspace needs to adopt existing
configuration without treating “the command accepted my flag” as a
transactional guarantee.

## Decision

Add three separate commands:

1. `hazards dotfiles plan` performs a read-only adoption inspection and emits a
   confirmation token.
2. `hazards dotfiles deploy --confirm <token>` performs verified, transactional
   deployment.
3. `hazards dotfiles rollback` restores the newest applicable transaction.

The plan:

- requires real directory ancestors beneath `HOME`;
- classifies absent targets, exact managed links, regular files requiring
  backup, and blocked filesystem objects;
- binds the generated profile, selected sources, targets, and ancestor
  fingerprints into a SHA-256 confirmation token; and
- does not acquire a lock, create a receipt, or write HAZARDS state.

Confirmed deployment:

1. recalculates the plan while holding the per-profile lock;
2. refuses a stale token or any blocked target;
3. verifies the HAZARDS-managed Dotter activation and locked version;
4. copies every adopted regular file into private transaction state and
   verifies its digest before removing any target;
5. writes immutable prepared evidence before target mutation;
6. removes only files still matching the confirmed fingerprints;
7. performs a second bounded and independently mutation-checked dry-run;
8. invokes Dotter directly without a shell, hooks, prompts, or `--force`;
9. requires every deployed target to resolve to its canonical ingredient; and
10. automatically restores original targets after ordinary execution or
    verification failure.

Rollback reads the newest committed or interrupted transaction. It rehashes
every backup and preflights all targets before changing any of them. Exact
managed links may be removed, unchanged original files may be retained, and
backed-up regular files may be restored. Any unrelated later target blocks
rollback rather than being overwritten.

## Consequences

- Existing configuration has durable recovery evidence before adoption.
- A copied confirmation token is invalidated by source, profile, target, or
  ancestor changes.
- Unmanaged symlinks, directories, special files, and symlink ancestors are not
  silently adopted.
- Deployment depends on both Dotter’s result and HAZARDS’ independent link
  verification.
- Ordinary failures return the machine to its original target state.
- Process termination after prepared evidence may require explicit
  `dotfiles rollback`; the next deployment refuses an incomplete transaction.
- Restored regular files retain their bytes and permission mode. Their
  modification timestamp may reflect restoration time.
- Transaction evidence and backups consume private HAZARDS state until a later
  explicit retention policy is designed.
