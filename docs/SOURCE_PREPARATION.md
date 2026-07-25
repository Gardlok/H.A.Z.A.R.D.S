# Controlled source preparation

HAZARDS does not treat `cargo install` as an acquisition, provenance, build, and
installation policy compressed into two words and a prayer.

After a locked source archive has been acquired and its transitive graph has
passed `hazards provision build-plan`, prepare the inert source tree explicitly:

```console
cargo run -p hazards-cli --bin hazards-source-prepare -- \
    --tool alacritty \
    --host desktop \
    --persistence local \
    --role development
```

Use `--all` instead of repeated `--tool ID` arguments to select every locked
source artifact in the resolved profile. Add `--json` for machine-readable
results.

The command requires the exact cached outer crate and performs no network
access. It rechecks the archive digest, hashes and counts the exact compressed
stream consumed during extraction, safely extracts the single locked crate root,
independently revalidates the published manifest and Cargo lock, hashes the
complete source tree, and writes append-only evidence.

Prepared trees live under:

```text
$XDG_CACHE_HOME/hazards/sources/sha256/<prefix>/<artifact-sha256>
```

Receipts live under:

```text
$XDG_STATE_HOME/hazards/receipts/source-preparations/<tool>/<version>
```

Every directory is mode `0700`; every file is mode `0600`. Cargo is not run,
dependencies are not downloaded, build scripts are not executed, no compiler or
linker is invoked, and nothing is installed. The output is quarantined source
input for a later trust boundary, not a build result wearing a convincing hat.
