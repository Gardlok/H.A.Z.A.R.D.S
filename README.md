# H.A.Z.A.R.D.S

**H**elix · **A**lacritty · **Z**ellij · **A**rsenal · **R**hai ·
**D**otter · **S**urrealDB

HAZARDS is a portable, SSH-capable terminal workspace intended to be a daily
driver on desktops and laptops as well as a familiar operating environment on
remote hosts. It combines proven Rust-based terminal applications with a small
Rust control plane instead of attempting to replace the shell, SSH, Git, or
other perfectly serviceable system primitives.

This branch establishes the foundation. It does not yet install every pillar or
pretend that an empty module is an orchestration platform.

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
$ cargo run -p hazards-cli -- recipe check
```

The profile model is composed from three independent dimensions:

- host: `desktop`, `laptop`, or `remote`;
- persistence: `local`, `roaming`, or `ghost`;
- role: `development`, `operations`, or `research`.

This avoids breeding a herd of nearly identical configuration files. Ghost
profiles disable persistent and synchronized state; remote profiles omit
Alacritty because the terminal emulator belongs on the client machine.

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

## Status

The CLI, registry, profile resolver, diagnostic model, Rhai recipe compiler,
starter pillar configurations, and state schema are functional. Installation
of external applications, Dotter-driven deployment, SurrealDB runtime wiring,
Zellij automation, and the Ratatui Arsenal interface follow in later phases.
