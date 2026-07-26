# ADR 0013: Pin and inspect the source-build contract before execution

## Status

Proposed

## Context

HAZARDS can now acquire a checksum-locked crates.io source archive, prepare a private inert source tree, and cache every checksummed registry dependency without invoking Cargo. Those controls establish exact input bytes, but they do not establish the identity of the compiler, linker, native libraries, build helpers, target support, or environment that would transform those bytes into an executable.

Running `cargo build` immediately would collapse several trust boundaries into one opaque operation. Rustup proxies can select a moving channel. Native development packages vary by host. Environment variables can inject compiler wrappers, flags, search paths, and network behavior. Cargo build scripts execute arbitrary package code during compilation.

## Decision

Introduce a separate read-only build-contract planner before any source-build executor.

The contract lock is version controlled and target specific. It pins the Rust and Cargo release, rustc commit and date, LLVM major, target triple, reviewed native command candidates, minimum helper versions, required pkg-config modules, and blocked build-affecting environment variables.

The planner:

1. reuses the existing read-only validators for prepared source and Cargo dependency evidence;
2. performs no network request and creates no receipt;
3. resolves the real rustc and Cargo binaries beneath the probed sysroot rather than retaining rustup proxy paths;
4. invokes only reviewed direct argument vectors with bounded output and timeouts;
5. redacts environment values;
6. emits a deterministic contract digest only when every prerequisite matches;
7. produces a future offline Cargo invocation template but never executes it.

A ready contract does not authorize compilation by itself. A later source-build authority must revalidate the contract and require explicit confirmation bound to its digest.

## Consequences

The source-build pipeline gains another explicit step, but compiler and native-tool drift become visible rather than silently changing artifacts. Missing system packages are reported instead of installed. The same source and dependency graph may yield different contract hashes on hosts with different native toolchains, preserving provenance rather than claiming bit-for-bit reproducibility that has not been demonstrated.

The exact Rust release used to build managed source is independent from HAZARDS' own Rust 1.85 MSRV. HAZARDS remains compilable with its declared MSRV while inspecting newer reviewed toolchains.

The planner deliberately refuses to execute Cargo, build scripts, compilers, linkers, package managers, installers, or activation operations. Controlled build execution remains a separate future ADR and implementation boundary.
