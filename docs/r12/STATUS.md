# R12 Administration and Parity Closure Status

R12 implements the frozen Go P11 administration contract and closes every
remaining R12 parity-ledger row. Qualification uses independent Rust, frozen-Go,
and native librados probes against pinned Ceph 20.2.4.

## Implemented Scope

- Cluster and per-pool statistics return owned, checked counters.
- Pool creation and deletion are correlated monitor mutations. Cancellation or
  deadline after a dispatched mutation returns `OutcomeUnknown` rather than
  replaying a possibly committed request.
- Pool application enable, list, metadata get/list/set/remove, and immutable
  map refresh semantics match the frozen Go contract.
- Session addresses preserve canonical messenger address identity, including
  IPv4-compatible IPv6 addresses.
- Blocklist updates validate addresses and durations, preserve a known monitor
  commit across later timeout/cancellation, and wait for a newer OSD map.
- Monitor, active-manager, OSD and PG commands preserve partial status and
  output with server errors. Manager authority changes and monitor failover use
  fresh sessions; foreign-FSID replies poison the affected monitor session.
- Inconsistent PG and object inspection uses bounded JSON and wire decoding,
  canonical PG parsing, current-primary routing, and bounded pagination.

## Migration Notes

Frozen Go `Client` administration methods map to snake-case Rust methods on
`Client`; Go `Pool` application and statistics methods map to `Pool`. Every
fallible method takes `OperationOptions`, while `session_addresses` is an owned
snapshot. Command methods return `(CommandResult, Result<()>)` so callers must
inspect or retain the result object even when the outcome is an error.

Rust exposes `blocklist` only; the deprecated blacklist spelling is omitted.
Native command-target variants, deprecated completion-safe aliases, legacy
iterator/watch aliases, and AUID/full-try APIs have no frozen-Go behavior and
remain explicit intentional omissions. Cache-tier, monitor-log, service-status,
and hit-set APIs remain deferred outside v1.

See [`../../examples/r12_administration.rs`](../../examples/r12_administration.rs)
for a compile-checked administration example.

## Qualification

[`live-qualification-report.json`](live-qualification-report.json) binds the
complete R12 source closure, schema, Rust revision/tree, pinned compiler image,
frozen Go revision/tree/toolchain, Rust and native probes, Ceph image/server
binary, and native librados package. The live matrix covers least-privilege
rejection, statistics, pool/application administration, session addresses,
blocklisting, all four command paths, inconsistent-object queries, manager
failover, OSD recovery, and partial command status.

Three parser campaigns in
[`fuzz-validation-report.json`](fuzz-validation-report.json) run for at least 60
seconds each against command, statistics, and inconsistency decoders. Exact
corpus, target, output, toolchain, and final source hashes are retained. This is
task-validation evidence; the longer release-candidate campaign remains an R13
gate.

Reproduce and verify with:

```sh
integration/r12/reproduce.sh --go-root /tmp/rados-r05-go-oracle \
  --report docs/r12/live-qualification-report.json
cargo run -p rados-r12-tools --bin rados-r12-verify -- \
  . docs/r12/live-qualification-report.json

integration/r12/validate-fuzz.sh \
  --report docs/r12/fuzz-validation-report.json --seconds 60
cargo run -p rados-r12-tools --bin rados-r12-verify-fuzz -- \
  . docs/r12/fuzz-validation-report.json
```

Ordinary Cargo tests remain offline and require neither Go, Docker, Ceph, nor a
sibling checkout. R12 tools, live-only adapters, integration metadata, logs,
and reports are excluded from the production crate package.

## Closure

The 163 rows assigned to R12 are closed as 57 implemented R12 behaviors, 29
earlier lifecycle/configuration adaptations finalized by the parity review, 58
intentional native-only omissions, and 19 deferred cache-tier/service APIs.
This completes implementation of the frozen Go public contract. It does not
claim performance parity, release approval, the 24-hour soak, or any R13
release-candidate review.