# Offline Cargo dependency cache

`hazards-cargo-dependencies` populates a HAZARDS-owned cache with the exact
crates.io archives named by an already prepared and checksum-locked
`Cargo.lock`.

```console
cargo run -p hazards-cli --bin hazards-cargo-dependencies -- \
  --tool alacritty \
  --host desktop \
  --persistence local \
  --role development
```

The command requires the top-level source object to have been acquired and
prepared first. It freshly reproduces that prepared source before reading its
pinned lockfile; a missing source stage is an error rather than an invitation
to silently cross an earlier authority boundary.

For every registry package, HAZARDS requires:

- the canonical crates.io registry source;
- a safe crate name and version;
- a 64-character lowercase SHA-256 checksum;
- the canonical static archive URL derived from that exact identity;
- an archive no larger than 512 MiB;
- bytes whose calculated SHA-256 equals the lockfile checksum.

Verified archives are stored without extraction under:

```text
$XDG_CACHE_HOME/hazards/cargo/objects/sha256/<prefix>/<checksum>
```

Complete graph manifests are stored under:

```text
$XDG_CACHE_HOME/hazards/cargo/dependency-graphs/sha256/<prefix>/<cargo-lock-sha256>.json
```

Append-only operation receipts are written under:

```text
$XDG_STATE_HOME/hazards/receipts/cargo-dependencies/<tool>/<version>
```

Existing objects are rehashed before use. A corrupt object is preserved and
rejected; HAZARDS does not quietly replace inconvenient evidence. Existing
graph manifests must exactly equal a freshly reconstructed manifest.

This boundary performs network retrieval, but it does not invoke Cargo,
extract an archive, run a build script, compile or link code, grant executable
permissions, install an application, activate a command, or modify `PATH`.
The result is inert input for a later offline build authority.
