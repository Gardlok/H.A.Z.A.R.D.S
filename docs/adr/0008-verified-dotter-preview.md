# ADR 0008: Generate profiles and verify Dotter dry-runs

## Status

Accepted

## Context

HAZARDS profiles already determine whether configuration belongs on a graphical
local host or an SSH target. The original Dotter starter required operators to
copy and edit a package list manually, allowing that local file to drift from
the profile model.

Dotter 0.13.5 provides `--dry-run`, but invoking an external configuration
manager crosses a more important boundary than formatting a package list.
HAZARDS needs to know which source and target paths are in scope, which exact
Dotter activation ran, whether execution completed sanely, and whether the
declared target tree actually remained unchanged.

## Decision

Add separate `hazards dotfiles generate` and `hazards dotfiles dry-run`
commands.

Generation:

1. canonicalizes a discovered or explicitly selected HAZARDS checkout;
2. maps required Arsenal pillars to packages in the version-controlled Dotter
   global configuration;
3. permits only regular sources inside that checkout and safe targets beneath
   `HOME`;
4. binds selected source sizes and hashes, and rejects duplicate targets and
   unsupported mapping shapes;
5. writes deterministic profile configuration and an identity manifest only
   beneath HAZARDS state; and
6. records append-only generated or unchanged evidence.

Dry-run:

1. regenerates the expected profile in memory and refuses missing or edited
   generated files;
2. requires Dotter to pass the transactional installer’s managed activation,
   store, payload, version, and current-`PATH` checks;
3. invokes Dotter directly without a shell using explicit configuration,
   disposable cache, disabled-hook, dry-run, and noninteractive arguments;
4. bounds process time and captured output;
5. fingerprints every declared target and its parent paths before and after
   execution; and
6. records clean, command-failed, or mutation-detected evidence.

This phase does not provide a confirmed deployment command. It does not infer
that a clean preview authorizes a later write.

## Consequences

- Remote profiles cannot accidentally select the client-side Alacritty package.
- Generated local configuration has one authority and can be reproduced rather
  than hand-maintained.
- Dotter hooks and persistent Dotter cache are excluded from preview execution.
- A successful process is insufficient if target fingerprints changed.
- Dry-run receipts intentionally mutate HAZARDS state; configuration targets
  must remain unchanged.
- Fingerprints are defense in depth around the exact locked Dotter binary, not
  a general-purpose operating-system sandbox.
- Confirmed deployment still requires backup, approval, transactional
  replacement, and rollback policy.
