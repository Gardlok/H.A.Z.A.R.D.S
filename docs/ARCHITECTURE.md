# Architecture

## Principles

1. Local daily-driver use is the primary experience; SSH access reuses the same
   core without requiring a graphical terminal on the remote host.
2. Configuration remains declarative and version controlled.
3. Each kind of state has one authority.
4. Rhai recipes receive registered capabilities rather than an implicit raw
   shell.
5. External applications remain replaceable providers behind Arsenal.
6. Installation is rootless by default and follows XDG paths.

## Runtime shape

On a desktop or laptop, Alacritty starts the HAZARDS control plane and Zellij
workspace. On a remote host, the SSH client's terminal replaces Alacritty.
Helix, Zellij, Arsenal, Rhaisour, and the supporting CLI tools otherwise behave
the same way.

Arsenal is the custom HAZARDS control plane. The foundation implements its
validated pillar/provider registry as a Rust crate. A Ratatui launcher and
system dashboard will build on that registry without moving process execution,
state ownership, or installation logic into UI widgets.

## Profile composition

A concrete profile is the product of three dimensions:

| Dimension | Values | Controls |
| --- | --- | --- |
| Host | desktop, laptop, remote | Graphics and host capabilities |
| Persistence | local, roaming, ghost | State lifetime and synchronization |
| Role | development, operations, research | Supporting provider selection |

Ghost mode excludes Atuin and persistent SurrealDB storage. A future Surrelish
adapter will use an in-memory engine for Ghost mode.

## Provision planning

`hazards provision plan` is the observation layer between profile composition
and future installation. It:

1. resolves pillar and provider identifiers from the selected profile;
2. finds canonical commands or registered distribution aliases on `PATH`;
3. invokes trusted version arguments directly, without a shell;
4. compares loose numeric versions, including calendar versions and components
   with leading zeroes;
5. reports installation intent from the registry.

The resulting plan is deterministic and serializable as JSON. `installed`,
`outdated`, `missing`, `planned`, and `unsupported` are observations, not
instructions. The plan contains an advisory target, source locator, and
destination, but there is deliberately no executor behind it yet.

## Acquisition evidence

`hazards provision acquire-plan` composes the host observation with the
embedded Arsenal acquisition lock. It emits only missing, outdated, or
unsupported tools and selects an exact operating-system/architecture record.
The lock currently covers Linux x86_64 and aarch64:

- upstream prebuilt assets are locked to their exact URL, byte count, archive
  format, and GitHub-recorded SHA-256 digest;
- tools without upstream Linux binaries use an architecture-neutral crates.io
  source archive and registry checksum;
- a target without either record is reported as `unavailable`.

The acquisition plan is pure and deterministic. It neither queries upstream
services nor retrieves the URL it reports. `locked_source` means only that the
top-level crate bytes are pinned; it does not claim that build dependencies,
native libraries, or compiler inputs have been resolved.

## Trust boundaries

- Recipe text is untrusted until compiled and approved.
- Rhaisour disables dynamic `eval` and imports and enforces operation/depth
  limits.
- Environment probes accept an executable plus argument vector from the
  validated registry rather than shell text.
- A future retriever must hash downloaded bytes and compare them to the lock
  before any archive is unpacked or executable is replaced.
- A digest copied from upstream metadata provides integrity after review, not
  independent publisher identity. Signed provenance remains a separate layer.
- Source-archive checksums do not lock a transitive Cargo dependency graph.
- Dotfiles never contain secrets.
- SurrealDB never becomes a credential vault.
- Remote Zellij control remains bound to the authenticated host session.
