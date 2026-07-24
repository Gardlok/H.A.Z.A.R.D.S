# H.A.Z.A.R.D.S

**H**elix · **A**lacritty · **Z**ellij · **A**rsenal · **R**hai ·
**D**otter · **S**urrealDB

HAZARDS is a portable, SSH-capable terminal workspace intended to be a daily
driver on desktops and laptops as well as a familiar operating environment on
remote hosts. It combines proven Rust-based terminal applications with a small
Rust control plane instead of attempting to replace the shell, SSH, Git, or
other perfectly serviceable system primitives.

The foundation includes a read-only provision planner, exact acquisition
evidence, a verified quarantine cache, and safe private staging. It can report
what a profile needs, retrieve only reviewed bytes, and materialize a locked
payload without executing or installing it.

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
extraction, replacement, and rollback remain separate phases rather than
features smuggled into a bootstrap script wearing a fake moustache.

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

## Status

The CLI, registry, profile resolver, diagnostic model, read-only provision and
acquisition planners, verified acquisition cache, Rhai recipe compiler, starter
pillar configurations, safe payload materialization, and state schema are
functional. Transactional installation of external applications, Dotter-driven
deployment, SurrealDB runtime wiring, Zellij automation, and the Ratatui Arsenal
interface follow in later phases.
