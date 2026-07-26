# Controlled source builds

`hazards-source-build` is the first HAZARDS authority permitted to run Cargo,
build scripts, native compilers, and linkers for a locked source artifact. It
accepts that risk only after every earlier source-build boundary has completed:

1. the exact upstream source archive is acquired and verified;
2. the source tree is safely prepared and inventoried;
3. every crates.io dependency archive named by `Cargo.lock` is cached and
   checksum-verified;
4. `hazards-build-contract` reports `contract_ready` and emits a SHA-256 digest.

The build command requires the operator to repeat that digest exactly:

```console
hazards-source-build \
  --tool alacritty \
  --host desktop \
  --persistence local \
  --role development \
  --confirm 'sha256:<current-contract-digest>'
```

A confirmation is not a reusable approval. The executor recomputes the complete
contract immediately before creating build state. Changed source evidence,
dependency objects, toolchain identity, native requirements, environment policy,
or invocation details change the digest and invalidate stale confirmation.

## Sandbox boundary

The pinned contract includes Bubblewrap as a reviewed native requirement. Cargo
runs through the exact observed Bubblewrap executable with:

- a cleared caller environment;
- private user, PID, network, IPC, and UTS namespaces;
- no network namespace interfaces inherited from the host;
- read-only system paths and Rust toolchain sysroot;
- no bind of the caller's home directory;
- one private writable HAZARDS build root;
- private HOME, Cargo, target, temporary, and XDG directories;
- deterministic locale, timezone, and source-date settings;
- `cargo build --release --locked --offline --target <pinned-target>`.

This protects more than Cargo's registry resolution. A build script that ignores
`CARGO_NET_OFFLINE` still has no host network, and a build script cannot wander
through the operator's home directory because it is absent from the sandbox.
Read-only system libraries and configuration remain visible because native Linux
builds need them; their exact prerequisites are separately probed and bound into
the contract.

## Input materialization

The executor never builds in the immutable prepared-source cache. It creates a
new private source copy and independently rechecks the copied `Cargo.toml` and
`Cargo.lock` digests. Every verified `.crate` object is extracted into a private
Cargo vendor tree with bounded sizes and counts. Traversal, duplicate entries,
links, devices, sockets, FIFOs, unsafe components, and reserved checksum metadata
are rejected. HAZARDS writes Cargo's checksum files from the extracted bytes and
configures crates.io replacement to use only that private vendor directory.

The source and dependency authorities are re-run in verification-only mode before
materialization. They cannot perform network access and emit no new acquisition,
preparation, or dependency-cache receipts.

## Process limits and outcomes

The default execution limits are:

- 3,600 seconds elapsed time;
- 16 MiB combined stdout and stderr;
- 8 GiB for the complete private build tree.

HAZARDS starts the sandbox in its own process group. A timeout or limit breach
sends termination to the group, waits briefly, then escalates to a kill signal.
If process state or termination cannot be observed with confidence, the outcome
is `ambiguous`. Ambiguous effects are never retried automatically.

The durable outcomes are:

- `succeeded`;
- `failed`;
- `timed_out`;
- `output_limit_exceeded`;
- `filesystem_limit_exceeded`;
- `artifact_rejected`;
- `evidence_changed`;
- `ambiguous`.

Completed ordinary success and failure build roots are removed after logs and the
receipt are durable. Roots for `ambiguous`, `artifact_rejected`, and
`evidence_changed` are preserved for operator investigation.

## Post-build verification

After Cargo exits, HAZARDS recomputes the complete build contract. Any changed
input or environment evidence invalidates the result. A successful Cargo exit is
not sufficient by itself.

For Alacritty, the expected output must be one regular executable named
`alacritty` in the pinned target's release directory. It must:

- have a nonzero bounded size;
- have executable permission without set-user-ID or set-group-ID bits;
- be a 64-bit little-endian ELF executable or shared-object form;
- carry the ELF machine identity matching the pinned target;
- be the only top-level executable in the release output directory.

The accepted binary is hashed and copied into the content-addressed result store:

```text
$XDG_CACHE_HOME/hazards/build-results/objects/sha256/<prefix>/<sha256>
```

The result object is private and inert. This command does not install it, create a
user command symlink, alter `PATH`, activate it, publish it, or declare its source
provenance signed.

## Evidence

Append-only receipts are written beneath:

```text
$XDG_STATE_HOME/hazards/receipts/source-builds/<tool>/<version>/
```

Bounded stdout and stderr logs are written beneath:

```text
$XDG_STATE_HOME/hazards/build-logs/<tool>/<version>/<receipt-id>/
```

A receipt binds the contract digest, complete sandbox invocation, limits, timing,
exit information, log paths and hashes, final outcome, preserved-state decision,
and accepted artifact identity when available.

## Remaining boundary

A verified source-build result is still not an installed application. Installation
and activation of source-built results require a later authority that consumes the
result object and receipt without weakening the existing transactional installation
and rollback rules. Signed provenance policy is also intentionally separate.
