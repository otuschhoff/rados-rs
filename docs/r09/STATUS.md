# R09 Metadata, Compound and Enumeration Status

R09 implements binary-safe metadata, bounded atomic operation builders and
namespace-aware object enumeration. Fresh Rust, frozen-Go and native librados
qualification passed against the pinned Ceph 20.2.4 replicated profile on
2026-09-19. No erasure-coded, performance-parity or later-phase API claim is
made.

## Implemented Scope

- Direct xattr get/set/remove/list and OMAP header, keyed lookup and paginated
  listing return caller-owned binary data with bounded decoding.
- Consuming `ReadOp` and `WriteOp` builders cap compounds at 16 operations,
  copy caller inputs, preserve order, support assertions/comparisons and expose
  only the qualified `FAIL_OK` sub-operation flag.
- Multi-operation requests set Ceph's `RETURN_VECTOR` flag and return ordered
  signed per-operation results. Write compounds require a true mutation and
  execute as one server-side request.
- Enumeration uses native `hobject_t` ordering, raw-hash routing and opaque,
  pool/namespace-scoped cursors. Pagination tolerates overfull server pages,
  resumes at the first omitted entry and follows the current OSD map.
- Cursor splitting uses reversed-hash partitions and validates canonical begin,
  end, ownership and forward progress.

## Qualification

[`live-qualification-report.json`](live-qualification-report.json) binds the
complete Rust R09 source closure, schema, pinned Rust compiler image, frozen Go
commit/tree, probe binaries, Ceph image/server binary and native librados
package. Rust and frozen Go each passed the same ten metadata, compound,
contention and enumeration scenarios in isolated pools. Native librados seeded
binary xattrs/OMAP and verified each client's metadata and namespace listings.

Both clients paused after the first enumeration page while their pool changed
from 16 to 32 PGs, then completed without duplicate partition entries. Failed
compare compounds left earlier mutations unapplied, and exactly one of two
concurrent compare-and-write clients succeeded.

Three parser campaigns in
[`fuzz-validation-report.json`](fuzz-validation-report.json) ran for at least
60 seconds each against metadata containers, compound request/reply codecs and
PGNLS/cursor pages. The report retains exact corpus, target, output, toolchain
and final source hashes. This is task-validation evidence; the release-candidate
campaign remains the longer R13 gate.

Reproduce and verify with:

```sh
integration/r09/reproduce.sh --go-root /tmp/rados-r05-go-oracle \
  --report docs/r09/live-qualification-report.json
cargo run -p rados-r09-tools --bin rados-r09-verify -- \
  . docs/r09/live-qualification-report.json

integration/r09/validate-fuzz.sh \
  --report docs/r09/fuzz-validation-report.json --seconds 60
cargo run -p rados-r09-tools --bin rados-r09-verify-fuzz -- \
  . docs/r09/fuzz-validation-report.json
```

Ordinary Cargo tests remain offline and require neither Go, Docker nor Ceph.
R09 qualification tools, live-only source, integration metadata and reports are
excluded from the production crate package.

## Boundary And Handoff

R09 certifies the frozen P08 contract on replicated pools. It does not certify
generic class execution, locks, watches, snapshots, erasure-coded writes,
deprecated native aliases absent from the Go contract, or R10 and later APIs.
R10 is the next phase.

Replay identity matches native librados: ambiguous transport loss, reconnect,
OSD-map change and failover preserve the client global ID, incarnation and
transaction ID; only authoritative redirect or `-EAGAIN` allocates a new
transaction ID. The frozen rados-go implementation follows the same rule, so
this qualification found no rados-go replay divergence to report.