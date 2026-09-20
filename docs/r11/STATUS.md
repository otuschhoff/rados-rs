# R11 Snapshots and Specialized I/O Status

R11 implements named and self-managed snapshots, immutable snapshot views,
specialized object operations, and replicated/erasure-coded qualification.
Fresh Rust and native librados interoperability evidence passed against the
frozen Go P10 contract and pinned Ceph 20.2.4 three-OSD profile.

## Implemented Scope

- Named snapshots support create, remove, list, lookup, immutable read views,
  and object rollback with owned names and timestamps.
- Self-managed snapshots support allocation, removal, immutable write-context
  views, immutable read views, and rollback. Snapshot IDs are strictly
  descending and bounded by the sequence; malformed contexts remain invalid
  for every mutation while reads omit write-only context.
- Sparse reads return bounded owned extents. Checksums validate algorithm seed,
  chunk geometry, count, width, and exact response length.
- Writesame, allocation hints, copy-from, and copy-from2 use server operations;
  copy source identity includes pool, locator, namespace, version, and the
  copy-from2 truncate suffix.
- Pool views report erasure coding and required stripe alignment from the OSD
  map. EC behavior is server-qualified rather than client-emulated.
- Named and self-managed monitor mutations are serialized and correlated before
  send. Cancellation or deadline after dispatch returns `OutcomeUnknown` and
  resets the monitor session so late replies cannot satisfy later commands.

## Qualification

[`live-qualification-report.json`](live-qualification-report.json) binds the
complete R11 source closure, schema, Rust revision/tree, pinned compiler image,
frozen Go revision/tree/toolchain, transformed P10 native driver, Rust/native
probe binaries, Ceph image/server binary, and native librados package. The
canonical run used two replicated pools and one `k=2,m=1` jerasure pool with an
8 KiB stripe width. It covered named and self-managed snapshots, immutable
context validation, specialized I/O, EC capability reporting, EC full-write
success, partial-overwrite/writesame/OMAP rejection, and bidirectional native
interoperability.

Three parser campaigns in
[`fuzz-validation-report.json`](fuzz-validation-report.json) run for at least 60
seconds each against monitor snapshot replies, sparse/checksum results, and
specialized MOSDOp request/reply codecs. Exact corpus, target, output,
toolchain, and final source hashes are retained. This is task-validation
evidence; the longer release-candidate campaign remains an R13 gate.

Reproduce and verify with:

```sh
integration/r11/reproduce.sh --go-root /tmp/rados-r05-go-oracle \
  --report docs/r11/live-qualification-report.json
cargo run -p rados-r11-tools --bin rados-r11-verify -- \
  . docs/r11/live-qualification-report.json

integration/r11/validate-fuzz.sh \
  --report docs/r11/fuzz-validation-report.json --seconds 60
cargo run -p rados-r11-tools --bin rados-r11-verify-fuzz -- \
  . docs/r11/fuzz-validation-report.json
```

Ordinary Cargo tests remain offline and require neither Go, Docker, Ceph, nor a
sibling checkout. R11 tools, live-only adapters, integration metadata, logs,
and reports are excluded from the production crate package.

## Explicit Deviations

Rust models mutable native ioctx snapshot state as owned immutable `Pool`
views. Rust also reports uncertain post-dispatch monitor mutation outcomes
instead of silently retrying them.

Ten native-only P10 variants have no runtime conformance claim because they are
absent from the certified Go contract: allocation-hint2 in C and C++ forms,
`IoCtx::list_snaps`, `IoCtx::mapext`, deprecated C++ alignment accessors,
`ObjectReadOperation::list_snaps`, and
`Rados::get_inconsistent_snapsets`. Their parity-ledger rows remain explicit
intentional omissions rather than implemented R11 claims.

R11 does not claim cache-tier snapshot enumeration, inconsistency repair,
administrative APIs, performance parity, or release approval. R12 is the next
implementation phase.