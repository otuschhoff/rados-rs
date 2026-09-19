# R10 Classes, Locks and Watches Status

R10 implements server-side class calls, advisory locks, and durable watch/notify
coordination. Fresh Rust, frozen-Go, and native librados qualification passed
against the pinned Ceph 20.2.4 three-OSD replicated profile. No erasure-coded,
performance-parity, snapshot, or later-phase API claim is made.

## Implemented Scope

- `ObjectRef::exec` and compound class operations preserve signed server return
  codes and owned binary output. Ambiguous class outcomes are never replayed.
- Exclusive and shared locks support acquisition, renewal, expiry, contention,
  listing, release, and administrative break with owned holder metadata.
  Ambiguous lock mutations return `OutcomeUnknown` without replay.
- Watches expose a stable nonzero cookie, bounded notification delivery,
  acknowledgments, explicit close, disconnect observability, and automatic
  re-registration after remap or OSD-session loss.
- Notify preserves acknowledgments and timed-out watchers together with the
  server result. Watch workers bound recovery operations to the lease and client
  shutdown joins them within the configured deadline.
- Independent clients use distinct nonzero address nonces so concurrent
  messenger identities do not evict each other.

## Qualification

[`live-qualification-report.json`](live-qualification-report.json) binds the
complete Rust R10 source closure, report schema, Rust revision/tree, pinned
compiler image, frozen Go revision/tree/toolchain, native driver and probe,
Ceph image/server binary, and native librados package. The canonical run used
three OSDs with two replicas and covered class execution; exclusive/shared lock
interoperability, renewal, expiry, contention, and break; bidirectional
watch/notify delivery and acknowledgment; partial timeout results; remap and OSD
restart recovery; explicit unregister; lost-watch observability; and bounded
shutdown.

Three parser campaigns in
[`fuzz-validation-report.json`](fuzz-validation-report.json) run for at least 60
seconds each against class MOSDOp requests/replies, lock-info replies, and watch
notifications/results/watcher lists. The report retains exact corpus, target,
output, toolchain, and final source hashes. This is task-validation evidence;
the release-candidate campaign remains the longer R13 gate.

Reproduce and verify with:

```sh
integration/r10/reproduce.sh --go-root /tmp/rados-r05-go-oracle \
  --report docs/r10/live-qualification-report.json
cargo run -p rados-r10-tools --bin rados-r10-verify -- \
  . docs/r10/live-qualification-report.json

integration/r10/validate-fuzz.sh \
  --report docs/r10/fuzz-validation-report.json --seconds 60
cargo run -p rados-r10-tools --bin rados-r10-verify-fuzz -- \
  . docs/r10/fuzz-validation-report.json
```

Ordinary Cargo tests remain offline and require neither Go, Docker, nor Ceph.
R10 qualification tools, live-only source, integration metadata, and reports are
excluded from the production crate package.

## Explicit Deviations

Rust notify returns `(NotifyReply, Result<()>)`, preserving partial timeout data
and the server error simultaneously; frozen Go returns `(NotifyReply, error)`.
Rust uses one bounded client-wide broadcast and observably terminates a lagging
watch, while frozen Go dispatches by cookie into per-watch queues. Rust also
conservatively does not replay class, lock, notify, or acknowledgment operations
after an ambiguous transport outcome and returns `OutcomeUnknown`; frozen Go
may retry outcome-sensitive operations after a primary change with the same
transaction identity. This deliberate divergence avoids duplicate coordination
effects.

R10 certifies the frozen P09 contract on replicated pools. It does not certify
snapshots, erasure-coded operations, deprecated native aliases absent from the
Go contract, or R11 and later APIs. R11 is the next phase.
