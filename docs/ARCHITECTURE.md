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
destination. Later commands cross separate, explicit mutation boundaries for
acquisition, materialization, and installation.

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

## Verified acquisition cache

`hazards provision acquire` is the first mutating provision operation. Its
authority stops at two HAZARDS-owned XDG locations:

- content-addressed objects under
  `$XDG_CACHE_HOME/hazards/objects/sha256/<prefix>/<digest>`;
- append-only JSON receipts under
  `$XDG_STATE_HOME/hazards/receipts/acquisitions/<tool>/<version>`.

The command requires explicit tool selection or `--all`. Before any request,
the complete selection is checked against the acquisition plan. The HTTP client
uses normal certificate validation, accepts only HTTPS URLs and HTTPS
redirects, limits redirect depth, and applies connection and transfer
timeouts. Response decompression is disabled so the hashed bytes are the bytes
named by the lock.

Bytes stream into a private temporary file while HAZARDS enforces the locked
size and computes SHA-256. Only an exact match is synchronized and atomically
persisted. Interrupted, truncated, oversized, and digest-mismatched transfers
leave no final object. A cache hit is not trusted by name: its type, size, and
digest are checked again without opening the network source. A corrupt cached
object is preserved as evidence and rejected; this phase does not invent an
implicit repair policy.

Acquisition receipts describe verification events. They are not installation
receipts and do not claim that an archive is safe to extract or that a payload
can execute on the host. Multi-tool acquisition is not transactional: each
successfully verified content-addressed object remains useful if a later
network request fails.

## Transitive source-build planning

Upstream does not publish suitable Linux binaries for every selected tool.
Alacritty and Tokei therefore enter the acquisition lock as
architecture-neutral crates.io archives. Their top-level registry checksums
identify the outer archives, but a future build also needs an explicit
dependency-graph boundary.

Acquisition-lock schema 3 records the expected source root, package name,
published `Cargo.toml` digest, published `Cargo.lock` digest, lockfile version,
and exact package count for every source artifact. `hazards provision
build-plan` is a read-only inspection of those identities. It first revalidates
the cached outer object, then walks its compressed TAR stream without extracting
anything. Path, type, entry-count, per-entry size, and aggregate expansion
restrictions are enforced.

The embedded manifest must name the selected package and target version. The
embedded lock must contain exactly one source-less root package and only
crates.io registry dependencies with valid SHA-256 checksums. Git dependencies,
additional path packages, alternate registries, missing checksums, graph-count
drift, links, special entries, duplicate paths, and traversal fail closed.

`graph_locked` means the upstream Cargo graph has fixed versions and registry
checksums. It does not authorize execution and does not claim that the Rust
toolchain, native system libraries, build scripts, or final executable are
reproducible. This phase creates no directories, extracts no source, performs
no network request, invokes no subprocess, and writes no receipt. Source
preparation, dependency acquisition, build-script execution, compilation,
result identity, and transactional activation remain separate future
boundaries.

## Verified source preparation

`hazards provision prepare-source` converts an explicitly selected,
graph-locked crates.io object into inert private source staging. Its authority
stops at:

- content-addressed trees under
  `$XDG_CACHE_HOME/hazards/sources/sha256/<prefix>/<artifact-digest>`;
- append-only JSON receipts under
  `$XDG_STATE_HOME/hazards/receipts/source-preparations/<tool>/<version>`.

Before creating staging state, the command revalidates the cached object's
type, byte count, SHA-256 digest, archive shape, pinned manifest and lockfile,
package identity, registry sources, dependency checksums, and graph counts.
Extraction then hashes the exact compressed stream it consumes, so the
prepared tree remains bound to the outer acquisition identity even if the
cache path changes between earlier observations.

Only bounded regular files and directories beneath the exact locked source
root are accepted. Absolute paths, parent components, backslashes, links,
special entries, duplicate paths, excessive entry sizes, and excessive
aggregate expansion fail closed. Archived ownership, permissions, and
timestamps are discarded. Directories are `0700`; files are `0600` and
therefore non-executable.

A deterministic manifest binds the acquisition digest, Cargo identities,
dependency counts, and every staged file's relative path, size, and SHA-256.
Persistence is an atomic rename from a private sibling candidate. Existing
staging is never trusted by its content-addressed name: HAZARDS reproduces a
fresh candidate from the verified object and requires the complete manifests
and actual tree to match before reporting `stage_hit`. Changed or malformed
staging is preserved as evidence and rejected rather than silently repaired.

This phase performs no network request, Cargo invocation, dependency
retrieval, build-script execution, compiler or linker execution, executable
permission change, application-store write, activation, or `PATH` mutation.
The resulting source is inert build input. Dependency acquisition, toolchain
identity, native libraries, build sandboxing, output identity, installation,
and rollback remain separate authorization boundaries.

## Safe materialization

`hazards provision materialize` converts an actionable, verified cache object
into inert private staging. Its authority stops at:

- content-addressed trees under
  `$XDG_CACHE_HOME/hazards/staging/sha256/<prefix>/<artifact-digest>`;
- append-only JSON receipts under
  `$XDG_STATE_HOME/hazards/receipts/materializations/<tool>/<version>`.

The command requires explicit `--tool` selections or `--all`, uses the same
profile and acquisition planners as retrieval, and performs no network I/O.
Before use, the cache object's type, size, and digest are verified again.

Archive extraction accepts locked binary, TAR/GZip, TAR/XZ, and ZIP formats.
Every entry must be a safe relative UTF-8 path. Absolute paths, parent
components, backslashes, links, special files, duplicates, encrypted ZIP
members, excessive entry counts, oversized entries, and excessive aggregate
expansion fail closed. Archived permissions, ownership, and timestamps are
discarded. HAZARDS creates directories as `0700` and files as `0600`; staged
payloads therefore cannot execute.

The acquisition lock separately identifies the exact payload by relative path,
byte count, and SHA-256 digest. The materializer verifies all three after
extraction, then checks that the payload is a 64-bit little-endian Linux ELF of
the locked architecture. Source artifacts are rejected because they do not
contain a locked executable identity.

A deterministic manifest inventories the resulting tree. Persistence is an
atomic rename from a private sibling temporary directory. An existing stage is
not trusted by its content-addressed name: HAZARDS reproduces a fresh candidate
from the locked object, validates the existing tree and manifest, and requires
the two manifests to match before reporting a stage hit. Successful events
produce append-only materialization receipts.

This phase does not execute a payload, set executable permissions, install or
replace a command, modify `PATH`, or write to `~/.local/bin`.

## Transactional user-local installation

`hazards provision install` activates one or more explicitly selected locked
binary artifacts. It requires an existing verified materialization and performs
no network access or implicit extraction. Before installation, the materializer
freshly reproduces the locked cache object and requires the staged tree and
manifest to match it.

The installer copies the complete verified tree into:

`$XDG_DATA_HOME/hazards/apps/<tool>/<version>/<artifact-digest>`.

Directories are `0700`, support files are `0600`, and only the exact
lock-identified payload is `0700`. A private installation manifest binds the
tool, canonical command, target version, artifact identity, payload identity,
architecture, and complete tree. Existing stores are fully revalidated and
corruption fails closed.

Activation is a managed symlink at `~/.local/bin/<canonical-command>`. The
canonical command is registry-validated as a single safe filename. The
installer refuses non-symlinks, symlinks outside the HAZARDS application store,
and managed-looking symlinks whose manifest, tree, payload, tool, or command do
not validate. It also refuses a group- or world-writable user bin directory.

Before replacing an activation, HAZARDS runs the registered version probe
against the exact stored payload. After replacement, it probes through the
activation, requires the expected version, and requires command lookup on the
current `PATH` to resolve to that activation. Failure restores the preceding
activation. A receipt-write failure is likewise an activation failure and
triggers recovery.

Per-tool advisory locks serialize HAZARDS installers. Receipts are append-only
under
`$XDG_STATE_HOME/hazards/receipts/installations/<tool>/<version>`. They record
the previous and resulting targets, the path that resolved before activation,
store and payload identities, checks, outcome, failures, and relationships
between install and recovery events.

Explicit rollback finds the newest applicable successful install or upgrade
whose resulting target is still active. It restores the recorded previous
managed target or removes the activation for an initial install, then reruns
version and `PATH` checks. A failed rollback check restores the newer target.
Installation is transactional per tool, not across a multi-tool `--all`
operation.

## Profile-aware Dotter lifecycle

The Dotter boundary has five explicit operations:

1. `hazards dotfiles generate` derives deterministic local configuration from
   the resolved HAZARDS profile and version-controlled global mappings.
2. `hazards dotfiles dry-run` executes the verified managed Dotter activation
   with `--dry-run` and independently checks target immutability.
3. `hazards dotfiles plan` classifies existing targets without writing and
   binds their state into an explicit confirmation token.
4. `hazards dotfiles deploy` backs up adoptable conflicts, re-previews, deploys,
   verifies links, and automatically restores ordinary failures.
5. `hazards dotfiles rollback` restores the newest applicable transaction
   without invoking Dotter.

Generation discovers and canonicalizes the HAZARDS checkout. Each selected
Arsenal pillar contributes its ingredient name only when that package exists in
`ingredients/dotterbatter/global.toml`. This naturally selects `helixer`,
`alacarte`, and `zellijuice` for graphical hosts and excludes `alacarte` from
remote hosts. Every selected source must be a regular non-symlink file whose
canonical path remains inside the checkout. Every target must use a safe `~/`
path beneath the resolved home directory, and two sources may not claim the
same target.

Generated `local.toml` and manifest files live under:

`$XDG_STATE_HOME/hazards/dotter/profiles/<profile-id>`.

The manifest binds the profile axes, canonical workspace root, global and local
configuration hashes, selected packages, source sizes and hashes, and resolved
targets. Generation is serialized per profile, atomically replaces only
HAZARDS-owned state, uses private permissions, and records append-only
generated/unchanged receipts.

Dry-run regenerates the expected profile in memory and requires both stored
files to match exactly. It then requires the `~/.local/bin/dotter` activation
to pass the installer’s managed-store, payload, version, activation, and
current-`PATH` checks. Dotter is invoked directly with argument vectors and:

- explicit generated local and version-controlled global configuration;
- disposable cache file and directory paths;
- nonexistent explicit pre/post hook paths;
- `--dry-run --noconfirm deploy`;
- null standard input, a 60-second deadline, and an 8 MiB output bound.

Before execution, HAZARDS fingerprints every declared target and each parent
path below `HOME`, including existence, kind, permissions, size, modification
time, content hash, or symlink destination as applicable. It repeats the
fingerprints after Dotter exits. A nonzero exit is not clean, and any changed
fingerprint is a mutation regardless of exit status. The command writes an
append-only receipt containing outcome, output hashes, exit evidence, and
changed paths.

Adoption planning requires every ancestor beneath `HOME` to be either absent or
a real directory. Targets are classified as absent, regular files requiring
backup, exact managed links, or blocked objects. The confirmation token hashes
the generated profile identity, selected source hashes, plan items, and target
plus ancestor fingerprints. Planning does not acquire a lock or create state;
the token is the compare-and-swap boundary when deployment later recalculates
the plan under the profile lock.

Confirmed deployment verifies the same HAZARDS-managed Dotter activation used
for previews. Before target mutation, every adopted regular file is copied into
a private transaction directory, rehashed, and described by durable prepared
evidence. Deployment removes only regular files whose complete fingerprints
still match the confirmed plan. It then runs another bounded dry-run against
the post-adoption state. Only a clean, mutation-free preview permits the real
shell-free `--noconfirm deploy`; `--force` is never passed.

Post-deployment verification requires every selected target to be a symlink
resolving to its exact canonical ingredient. Nonzero execution or link mismatch
removes managed links and restores the original regular files automatically.
Committed and automatically restored results are append-only terminal events.
Explicit rollback selects the newest committed or interrupted transaction,
verifies backup hashes, and preflights every target before mutation. A target
containing unrelated later data blocks the entire rollback.

## Trust boundaries

- Recipe text is untrusted until compiled and approved.
- Rhaisour disables dynamic `eval` and imports and enforces operation/depth
  limits.
- Environment probes accept an executable plus argument vector from the
  validated registry rather than shell text.
- The acquisition retriever hashes downloaded bytes and compares them to the
  lock before admitting them to the private cache.
- Cached artifacts remain untrusted input. The materializer enforces archive
  path and type rules, expansion bounds, exact payload identity, and ELF
  architecture before admitting an inert private staging tree.
- Staged artifacts remain untrusted for execution. The installer reproduces
  them from locked cache bytes, copies them to a private immutable-by-policy
  application store, runs exact version probes, validates activation and
  `PATH`, and automatically restores the prior activation on failure.
- HAZARDS trusts the invoking user and the user's private XDG roots. It does
  not claim to defend against another process running concurrently as that same
  user and deliberately rewriting those roots outside HAZARDS.
- Dotter global mappings are trusted only after selected sources stay inside
  the canonical checkout and targets stay beneath `HOME`. A Dotter dry-run is
  not trusted by its flag alone: declared targets and parents are fingerprinted
  around bounded execution of the verified managed activation.
- Target fingerprinting covers declared paths and their home-directory
  ancestors. It is not a general filesystem sandbox; the exact locked Dotter
  binary and the invoking user remain inside the trust boundary.
- Dotfile deployment confirmation is valid only for the exact generated profile
  and observed target tree. Backups are private and hash-verified before use;
  rollback refuses ambiguous ownership rather than overwriting later changes.
- A digest copied from upstream metadata provides integrity after review, not
  independent publisher identity. Signed provenance remains a separate layer.
- A validated embedded Cargo lock pins crates.io dependency versions and
  checksums, but does not pin the compiler, linker, native libraries, build
  scripts' effects, or the resulting binary.
- Dotfiles never contain secrets.
- SurrealDB never becomes a credential vault.
- Remote Zellij control remains bound to the authenticated host session.
