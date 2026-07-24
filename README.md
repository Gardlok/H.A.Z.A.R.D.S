# H.A.Z.A.R.D.S

**H**elix · **A**lacritty · **Z**ellij · **A**rsenal · **R**hai ·
**D**otter · **S**urrealDB

HAZARDS is a portable, SSH-capable terminal workspace intended to be a daily
driver on desktops and laptops as well as a familiar operating environment on
remote hosts. It combines proven Rust-based terminal applications with a small
Rust control plane instead of attempting to replace the shell, SSH, Git, or
other perfectly serviceable system primitives.

The foundation includes a read-only provision planner. It can report what a
profile needs and what the current host already has; it cannot yet install
anything or pretend that a version string is a supply-chain policy.

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

It intentionally refuses to download and execute an unverified release. A
checksummed binary-release path belongs to the release phase, not to a
foundation PR wearing a fake moustache.

## Design documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Kitchen lexicon](docs/LEXICON.md)
- [Roadmap](docs/ROADMAP.md)
- [Stack-ronym decision](docs/adr/0001-stack-ronym.md)
- [State ownership decision](docs/adr/0002-state-ownership.md)
- [Planning before mutation decision](docs/adr/0003-planning-before-mutation.md)

## Status

The CLI, registry, profile resolver, diagnostic model, read-only provision
planner, Rhai recipe compiler, starter pillar configurations, and state schema
are functional. Verified installation of external applications, Dotter-driven
deployment, SurrealDB runtime wiring, Zellij automation, and the Ratatui Arsenal
interface follow in later phases.
