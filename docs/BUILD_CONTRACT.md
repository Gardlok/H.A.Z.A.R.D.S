# Pinned source-build contract

`hazards-build-contract` is the read-only gate between verified source inputs and any future Cargo execution.

```console
cargo run -p hazards-cli --bin hazards-build-contract -- \
  --tool alacritty \
  --host desktop \
  --persistence local \
  --role development \
  --json
```

The command does not download, extract, compile, link, install, activate, or modify the source tree. It emits no receipt. Its purpose is to prove whether one exact host environment can be bound to the already verified inputs.

## Required evidence

The planner requires both earlier authorities to have completed:

1. the top-level crates.io source object must still exist and match its pinned SHA-256;
2. the private prepared source tree and its full inventory must still match;
3. `Cargo.toml` and `Cargo.lock` must retain their separately pinned identities;
4. every crates.io dependency archive and the deterministic dependency-graph manifest must still verify.

The build-contract planner calls the existing read-only source and dependency validators. It does not reproduce their rules independently and cannot fetch missing evidence.

## Pinned Rust identity

The embedded lock currently binds Alacritty 0.17.0 to:

- Rust and Cargo 1.97.1;
- rustc commit `8bab26f4f68e0e26f0bb7960be334d5b520ea452`;
- rustc commit date `2026-07-14`;
- Cargo commit `c980f4866141969fab6254a680546a277789d6f0` dated `2026-06-30`;
- LLVM major version 22;
- the host-specific GNU/Linux target triple.

HAZARDS first locates the `rustc` and `cargo` launchers, asks rustc for its sysroot, and then resolves the real executables beneath that sysroot. The final contract therefore binds immutable toolchain binaries rather than a rustup proxy whose selected channel may later move.

The package's declared `rust-version` is read from the already verified `Cargo.toml` and compared with the pinned compiler release.

## Native prerequisites

The Alacritty contract directly probes reviewed command candidates for:

- a C compiler;
- a C++ compiler;
- `ar` and `ld`;
- CMake 3.13 or newer;
- pkg-config 0.29 or newer;
- Python 3.8 or newer.

It also requires these pkg-config modules:

- `fontconfig` 2.13 or newer;
- `freetype2` 2.10 or newer;
- `xkbcommon` 1.0 or newer;
- `xcb-xfixes` 1.13 or newer.

Probe commands are executed directly with reviewed argument vectors. No shell is involved. Each probe is limited to ten seconds and one MiB of combined output.

Native command paths and observed versions become part of the contract hash. HAZARDS does not install missing packages or pretend that differing host toolchains are identical.

## Environment policy

The lock names environment variables that may change compiler, linker, pkg-config, library search, or network behavior. A set variable blocks readiness. Values are never serialized; JSON reports only the variable name and a redacted marker.

A future build authority must start from a cleared environment and supply only the fixed values in the invocation template. That template includes:

- the exact Cargo executable;
- `build --release --locked --offline`;
- the pinned target triple;
- a private HAZARDS build root;
- an isolated `HOME`, `CARGO_HOME`, and `CARGO_TARGET_DIR`;
- offline Cargo mode;
- deterministic locale, timezone, and source-date settings;
- a PATH assembled only from verified probe locations.

The invocation is evidence, not an action. This command never executes it.

When testing from a development checkout, note that `cargo run` may set variables such as dynamic-library search paths. Build the CLI and execute the resulting `hazards-build-contract` binary under a cleaned environment when assessing `contract_ready`.

## Outcomes

- `contract_ready`: all evidence, toolchain identity, native requirements, and environment policy match; a contract SHA-256 is emitted.
- `source_evidence_missing`: controlled source preparation has not completed.
- `dependency_evidence_missing`: the checksum-verified dependency cache has not completed.
- `toolchain_missing`: rustc or Cargo cannot be located.
- `toolchain_mismatch`: release, commit, date, host, target support, LLVM, or package MSRV does not match.
- `native_requirement_missing`: a required native command or pkg-config module is absent.
- `native_version_mismatch`: a native prerequisite is present but does not satisfy policy.
- `environment_blocked`: build-affecting environment state is present or a controlled invocation cannot be represented safely.
- `evidence_corrupt`: an existing source tree, object, or manifest fails verification.
- `unsupported`: no reviewed contract exists for the selected target.

Only `contract_ready` includes `contract_sha256`. The digest binds the versioned lock, source evidence, dependency evidence, exact toolchain, native observations, environment result, and future invocation template.
