# ADR 0014: Controlled source-build execution

- Status: Accepted
- Date: 2026-07-25

## Context

HAZARDS can already identify a checksum-locked crates.io source artifact, prepare
its source tree, cache every checksummed registry dependency, and emit a pinned
build contract covering source evidence, dependency evidence, Rust and Cargo
identity, native prerequisites, environment policy, and a future invocation.

The next boundary must actually execute untrusted upstream build logic. Cargo
builds may run procedural macros and build scripts, which can invoke native tools,
read files, open network connections, create arbitrary outputs, and persist side
effects outside Cargo's target directory. `--locked` and `--offline` constrain
dependency resolution but are not a sandbox. Running Cargo directly against the
operator's home directory would therefore collapse the trust boundaries established
by the earlier phases.

The execution also needs a stale-proof authorization model. An operator's approval
of one source tree and toolchain cannot silently authorize later bytes, a different
native environment, or a changed command line.

## Decision

HAZARDS will provide one explicit `hazards-source-build` authority with the
following rules.

1. The operator selects exactly one locked source artifact and supplies a
   `sha256:<digest>` confirmation.
2. The executor recomputes the complete build contract immediately before mutation.
   Only `contract_ready` may proceed, and the supplied digest must match exactly.
3. Source and dependencies are copied into a new private build root. Cargo consumes
   a HAZARDS-generated vendor directory assembled from already verified crate
   objects; no dependency retrieval is allowed during execution.
4. Bubblewrap is a pinned native contract requirement. Cargo executes inside fresh
   user, PID, network, IPC, and UTS namespaces. System and toolchain paths are
   read-only, the caller's home directory is absent, and only the private build root
   is writable.
5. The caller environment is cleared. The contract supplies the complete PATH,
   private HOME/Cargo/target/temp/XDG paths, deterministic locale and time settings,
   and offline Cargo controls.
6. Execution uses direct argument vectors and its own process group. Elapsed time,
   output, and build-tree size are bounded. The complete process group is terminated
   on a breach.
7. The complete build contract is recomputed after execution. Changed evidence
   rejects the result.
8. The expected ELF output is verified for path, file type, safe executable mode,
   target machine, size, and SHA-256. Unexpected top-level executable outputs are
   rejected.
9. Accepted binaries are copied into a content-addressed result store. Append-only
   receipts and bounded logs record every completed execution outcome.
10. Ambiguous outcomes are preserved for investigation and are never replayed
    automatically.
11. This authority does not install, activate, publish, modify PATH, or create a
    provenance signature.

## Alternatives considered

### Run Cargo directly with `--locked --offline`

Rejected. Those flags constrain Cargo's resolver but do not stop build scripts from
reading the host filesystem, contacting the network directly, or writing outside
the target directory.

### Use only a network namespace

Rejected. Network isolation prevents one class of exfiltration but still exposes
the operator's filesystem. The build needs a filesystem view that omits user data
and limits writable state.

### Build in the prepared-source cache

Rejected. The prepared tree is immutable evidence. Allowing Cargo to mutate it
would destroy the ability to revalidate the exact reviewed source and would mix
inputs with outputs.

### Invoke `cargo vendor`

Rejected for this boundary. The dependency cache already contains every exact
checksummed archive. Reinvoking Cargo to construct its own input tree would add an
unnecessary executable step before the controlled execution boundary and could
introduce network or configuration ambiguity. HAZARDS instead constructs the
standard directory source and checksum metadata directly from verified objects.

### Treat a successful Cargo exit as success

Rejected. Exit status does not establish that inputs remained unchanged, that the
expected artifact exists, that its architecture is correct, or that no surprising
executable output appeared.

### Automatically retry interrupted builds

Rejected. An interrupted external effect may have completed partially or escaped
observation. Automatic replay would violate HAZARDS's conservative ambiguous-outcome
policy.

## Consequences

The source-build boundary is more complex and slower than a plain Cargo command.
It consumes additional disk space for private source, vendor, and target trees and
requires Bubblewrap with usable unprivileged user namespaces.

In return, operator approval is bound to exact current evidence, dependency access
is local and checksummed, upstream build code cannot see the operator's home or host
network, process effects are bounded and recorded, and the produced binary is an
explicit verified object rather than an unexamined side effect.

Source-built result activation and signed provenance remain separate future
decisions.
