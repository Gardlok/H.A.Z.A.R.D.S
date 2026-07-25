# H.A.Z.A.R.D.S

**H**elix · **A**lacritty · **Z**ellij · **A**rsenal · **R**hai ·
**D**otter · **S**urrealDB

HAZARDS is a portable, SSH-capable terminal workspace intended to be a daily
driver on desktops and laptops as well as a familiar operating environment on
remote hosts. It combines proven Rust-based terminal applications with a small
Rust control plane instead of attempting to replace the shell, SSH, Git, or
other perfectly serviceable system primitives.

The foundation includes a read-only provision planner, exact acquisition
evidence, a verified quarantine cache, safe private staging, and transactional
user-local activation. It can report what a profile needs, retrieve only
reviewed bytes, materialize a locked payload without executing it, and install
that payload with health checks and rollback. Profile-aware Dotter
configuration and independently verified deployment previews form the first
configuration-management boundary.

## The pantry

Pillar configuration lives under intentionally questionable ingredient names:

| Pillar | Ingredient | Responsibility |
| --- | --- | --- |
| Helix | `helixer` | Editing and language tooling |
| Alacritty | `alacarte` | Local terminal presentation |
| Zellij | `zellijuice` | Sessions, panes, layouts, and remote continuity |
| Arsenal | `arsenallspice` | HAZARDS control plane and tool registry |
| Rhai | `rhaisour` | Sandboxed recipes and automation |
| Dotter | `dotterbatter` | Profile-aware configuration deployment |
| SurrealDB | `surrelish` | Project, host, workspace, and run metadata |

Atuin remains a first-class supporting provider for contextual shell history,
but it is not forced into the stack-ronym merely because there was an `A`
available.

## Current commands

```console
$ cargo run -p hazards-cli -- about
$ cargo run -p hazards-cli -- paths
$ cargo run -p hazards-cli -- arsenal list
$ cargo run -p hazards-cli -- profile list
$ cargo run -p hazards-cli -- profile resolve \
    --host desktop \
    --persistence local \
    --role development
$ cargo run -p hazards-cli -- doctor \
    --host desktop \
    --persistence local \
    --role development
$ cargo run -p hazards-cli -- provision plan \
    --host desktop \
    --persistence local \
    --role development
$ cargo run -p hazards-cli -- provision plan \
    --host remote \
    --persistence ghost \
    --role operations \
    --json
$ cargo run -p hazards-cli -- provision acquire-plan \
    --host desktop \
    --persistence local \
    --role development
$ cargo run -p hazards-cli -- provision acquire \
    --tool zellij \
    --host desktop \
    --persistence local \
    --role development
$ cargo run -p hazards-cli -- provision materialize \
    --tool zellij \
    --host desktop \
    --persistence local \
    --role development
$ cargo run -p hazards-cli -- provision install \
    --tool zellij \
    --host desktop \
    --persistence local \
    --role development
$ cargo run -p hazards-cli -- provision rollback \
    --tool zellij
$ cargo run -p hazards-cli -- dotfiles generate \
    --host desktop \
    --persistence local \
    --role development
$ cargo run -p hazards-cli -- dotfiles dry-run \
    --host desktop \
    --persistence local \
    --role development
$ cargo run -p hazards-cli -- dotfiles plan \
    --host desktop \
    --persistence local \
    --role development
$ cargo run -p hazards-cli -- dotfiles deploy \
    --host desktop \
    --persistence local \
    --role development \
    --confirm 'sha256:<token-from-plan>'
$ cargo run -p hazards-cli -- dotfiles rollback \
    --host desktop \
    --persistence local \
    --role development
$ cargo run -p hazards-cli -- recipe check
```

The profile model is composed from three independent dimensions:

- host: `desktop`, `laptop`, or `remote`;
- persistence: `local`, `roaming`, or `ghost`;
- role: `development`, `operations`, or `research`.

This avoids breeding a herd of nearly identical configuration files. Ghost
profiles disable persistent and synchronized state; remote profiles omit
Alacritty because the terminal emulator belongs on the client machine.

The provision planner resolves only the applications selected by that profile,
then classifies each as `installed`, `outdated`, `missing`, `planned`, or
`unsupported`. It probes executables directly with argument vectors from the
validated Arsenal registry—never through a shell—and recognizes Debian's
`fdfind` and `batcat` command names. Release versions in the registry are
advisory planning targets. No archive is downloaded and no command, dotfile, or
database is modified.

The acquisition planner narrows missing and outdated tools to exact locked
bytes for the current operating system and architecture. Linux x86_64 and
aarch64 release artifacts are pinned by SHA-256. When upstream does not publish
a Linux binary—currently Alacritty and Tokei—the lock records the checksummed
crates.io source archive and reports `locked_source` rather than inventing a
binary. `hazards provision acquire-plan` performs no network or filesystem I/O.

`hazards provision acquire` is the deliberately mutating boundary. It requires
one or more explicit `--tool ID` selections or `--all`, retrieves only the URL
embedded in the validated acquisition lock, and accepts bytes only when their
exact size and SHA-256 digest match. Verified objects are stored by digest
under `~/.cache/hazards/objects/sha256`; append-only acquisition receipts live
under `~/.local/state/hazards/receipts/acquisitions`. Existing cache objects are
rehashed before use. Corrupt objects fail closed instead of being silently
replaced.

Acquisition is not installation. The command does not unpack an archive, build
a crate, set an executable bit, run a subprocess, modify `PATH`, or write into
`~/.local/bin`. It has merely admitted some bytes into quarantine after checking
their paperwork.

`hazards provision materialize` is the next deliberately narrow mutation. It
requires the same explicit selection, rehashes the locked cache object, and
reproduces its contents in a private content-addressed staging directory under
`~/.cache/hazards/staging/sha256`. Archive paths must be safe relative UTF-8
paths; links, devices, duplicate entries, encrypted ZIP members, and excessive
entry or expanded sizes are rejected. HAZARDS ignores archived ownership,
timestamps, and permissions.

The lock names the exact executable payload path, size, and SHA-256 digest.
After extraction, HAZARDS verifies that identity and the expected Linux ELF
architecture, inventories the complete staged tree in
`.hazards-materialization.json`, and records an append-only materialization
receipt under `~/.local/state/hazards/receipts/materializations`. Existing
stages are re-created from the verified cache object and compared before a
`stage_hit` is reported.

Materialization is still not installation. Every staged file is mode `0600`,
every directory is mode `0700`, and the payload deliberately remains
non-executable. Nothing is run, replaced, added to `PATH`, or written to
`~/.local/bin`. Checksummed source crates are refused because they have no
locked executable payload; reproducible source builds require their own trust
policy.

`hazards provision install` consumes an existing verified stage; it never
downloads or silently materializes one. The complete staged tree is copied to
the content-addressed application store under
`~/.local/share/hazards/apps/<tool>/<version>/<artifact-sha256>`, preserving
runtime assets while granting execute permission only to the locked payload.
HAZARDS runs that exact payload's registered version probe before activation,
then atomically points `~/.local/bin/<command>` at it and verifies the version,
activation path, and the command that `PATH` actually resolves.

An existing regular file, directory, foreign symlink, malformed store, or
group/world-writable user bin directory is refused rather than adopted or
overwritten. Successful transitions and failed recoveries receive append-only
receipts under
`~/.local/state/hazards/receipts/installations/<tool>/<version>`. If a
post-activation check or receipt write fails, HAZARDS restores the preceding
activation before returning an error. Installation is transactional per tool;
`--all` does not pretend several independent applications form one
all-or-nothing filesystem transaction.

`hazards provision rollback --tool <id>` restores the activation recorded
before the newest applicable successful install or upgrade. Rolling back a
first installation removes the HAZARDS symlink. The restored command must pass
its recorded version and `PATH` checks or the newer activation is put back.
Already-active installations are verified and receipted without replacing the
link. Locked source archives remain ineligible: a checksum is not a
reproducible compiler supply chain, however confidently one squints at it.

`hazards dotfiles generate` discovers the HAZARDS checkout, parses the
version-controlled `ingredients/dotterbatter/global.toml`, and selects only
packages belonging to the resolved profile. Desktop and laptop profiles select
Helix, Alacritty, and Zellij; remote profiles omit Alacritty because it belongs
on the SSH client. Source paths must be regular files inside the checkout,
targets must remain beneath `HOME`, and duplicate targets are rejected.

Generation writes a deterministic `local.toml` and identity manifest under
`$XDG_STATE_HOME/hazards/dotter/profiles/<host>-<persistence>-<role>`.
The manifest binds configuration hashes, selected source paths and hashes,
resolved targets, and all three profile axes. Append-only generation receipts
live under the HAZARDS state root. Repeating the same generation reports
`unchanged`; operators edit the profile model or version-controlled global
mapping, never the generated file.

`hazards dotfiles dry-run` refuses missing or edited generated profiles and
requires the installed command to pass the complete HAZARDS managed-activation
check. It then invokes the exact Dotter 0.13.5 activation directly—never through
a shell—with explicit global/local configuration, disposable cache locations,
disabled hook paths, `--dry-run`, and `--noconfirm`. Execution is bounded to 60
seconds and 8 MiB of captured output.

HAZARDS fingerprints every declared target and its parent path before and after
Dotter exits. A clean exit with identical fingerprints produces a
`dry-run-clean` receipt. A nonzero exit is `dry-run-failed`; any target or
parent change is `mutation-detected`, regardless of what Dotter reports.
Dry-run receipts are intentional HAZARDS state writes. No configuration target
is supposed to change, because apparently software needs independent witnesses
before the phrase “dry run” may be admitted into evidence.

`hazards dotfiles plan` is a strictly read-only adoption inspection. It
classifies absent targets, already-managed links, regular files requiring
backup, and blocked filesystem objects. Real directory ancestors beneath
`HOME` are required; an ancestor symlink is refused rather than followed. A
ready plan emits a SHA-256 confirmation token binding the generated profile,
ingredient hashes, and current target and ancestor fingerprints.

`hazards dotfiles deploy --confirm <token>` recalculates that plan under the
per-profile lock and refuses stale confirmation. It verifies the managed Dotter
activation, privately copies and rehashes every displaced regular file, writes
durable prepared transaction evidence, and only then removes adopted files.
With conflicts out of the way it performs another bounded, mutation-checked
Dotter dry-run. Actual deployment proceeds only after that preview succeeds.
The deploy invocation remains shell-free, noninteractive, hook-disabled, and
does not use `--force`.

Every declared target must finish as a symlink to its exact selected ingredient.
A command or link-verification failure automatically restores backed-up files
and removes links created over previously absent targets. Successful and
restored outcomes are append-only transaction events.
`hazards dotfiles rollback` restores the newest committed or interrupted
transaction only after verifying its backups and proving no target contains
unrelated later data. Original file bytes and permission modes are restored;
unexpected edits are never overwritten.

## Build and validate

HAZARDS uses Rust 2024 and supports Rust 1.85 or newer.

```console
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

For a source checkout, the bootstrap helper installs the `hazards` binary into
`~/.local/bin` by default:

```console
./bootstrap/install.sh --dry-run
./bootstrap/install.sh \
    --host desktop \
    --persistence local \
    --role development
```

The bootstrap helper intentionally refuses to download or execute a release.
Verified retrieval is available only through the explicit acquisition command;
materialization, activation, and rollback remain separate explicit phases
rather than features smuggled into a bootstrap script wearing a fake
moustache.

## Design documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Kitchen lexicon](docs/LEXICON.md)
- [Roadmap](docs/ROADMAP.md)
- [Stack-ronym decision](docs/adr/0001-stack-ronym.md)
- [State ownership decision](docs/adr/0002-state-ownership.md)
- [Planning before mutation decision](docs/adr/0003-planning-before-mutation.md)
- [Acquisition evidence decision](docs/adr/0004-lock-acquisition-evidence.md)
- [Verified acquisition cache decision](docs/adr/0005-verified-acquisition-cache.md)
- [Safe materialization decision](docs/adr/0006-safe-materialization.md)
- [Transactional user installation decision](docs/adr/0007-transactional-user-installation.md)
- [Verified Dotter preview decision](docs/adr/0008-verified-dotter-preview.md)
- [Transactional Dotter deployment decision](docs/adr/0009-transactional-dotter-deployment.md)

## Status

The CLI, registry, profile resolver, diagnostic model, read-only provision and
acquisition planners, verified acquisition cache, Rhai recipe compiler, starter
pillar configurations, safe payload materialization, and state schema are
functional. Transactional installation and rollback of locked prebuilt
applications, profile-aware Dotter generation, and verified deployment dry-runs
are also functional. Read-only adoption planning, confirmed transactional
Dotter deployment, automatic recovery, and explicit rollback are functional.
SurrealDB runtime wiring, Zellij automation, and the Ratatui Arsenal interface
follow in later phases.
