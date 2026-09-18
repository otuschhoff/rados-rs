# R08 Mutation Qualification Status

R08 implements bounded durable mutations and passed fresh Rust/Go/native live
qualification against the pinned Ceph 20.2.4 replicated profile on 2026-09-18.
No performance parity or speedup is claimed.

## Qualification Harness

The qualification layer includes:

- `tools/r08` provides a strict typed `deny_unknown_fields` report verifier, a
  source-closure digest and a verifier CLI.
- `integration/r08/report.schema.json` defines the matching report contract.
- `integration/r08/reproduce.sh` builds three probes from isolated source
  contexts and runs them against an isolated three-OSD, three-replica Ceph
  20.2.4 cluster.
- Rust, frozen-Go and native librados probes exercise the mutation primitives
  and a cross-client CRUD chain. The Rust probe also drives a fail-closed,
  append-once lost-reply scenario using an isolated traffic-control rule.
- `integration/r08/prepare-fuzz-corpus.sh` recreates deterministic seeds for
  all three R08 fuzz targets.
- `integration/r08/validate-fuzz.sh` runs the three targets for at least 60
  seconds each and records source, corpus, target, output, toolchain and result
  hashes in `fuzz-validation-report.json`.
- The contract pins Rust 1.98.0, Ceph 20.2.4 and the frozen Go revision
  `c8bb148a1379b51ef87256c27f366a05f8da4dc4` with tree
  `c5039b6b50a05b942a902f70dc2fcb090463e8c7`.
- Required passing statuses cover create, write, write-full, append, truncate,
  zero, remove, cross-client CRUD, append-once failover/lost-reply behavior,
  ACK versus commit, flush watermarks, cancellation/drop boundaries and the
  performance baseline. CRUD, pre-admission cancellation and failover are live
  observations. The ACK, exact-watermark and admitted-worker drop statuses are
  assigned only after their named Rust tests pass in the pinned build image;
  the probes do not emit unconditional booleans for those invariants.
- Each implementation/workload performance record carries payload bytes,
  concurrency, operation count, elapsed seconds, operations per second,
  p50/p95/p99 latency in microseconds, CPU user/system seconds, a named
  language-specific allocation metric, retained bytes and peak RSS.
- The verifier requires exactly one fixed 4096-byte, concurrency-one,
  128-operation Rust/Go/native baseline and positive measurements. It does not
  compare values or claim parity.

Verifier tests use generated in-memory reports and reject stale source, pin,
scenario, shape and performance tampering. They supplement rather than replace
the live report.

## Live Evidence

[`live-qualification-report.json`](live-qualification-report.json) is a
source-bound report from an isolated three-OSD cluster. Rust, frozen Go and
native librados each passed create, write, write-full, append, truncate, zero
and remove. A Rust-created object was updated by Go, updated by native librados,
then read and removed by Rust.

The fault scenario delayed only replies from the acting primary, observed the
append committed through an independent native read, killed that primary, and
required Rust to recover on the promoted primary with the original transaction
identity. The final object contained `base-once`, proving the append was not
duplicated.

The first fixed baseline used 128 sequential 4096-byte write-full operations at
concurrency one. Observed throughput was 174.60 operations/s for Rust, 129.00
for Go and 227.48 for native librados. These single-run values establish the
R08 baseline only; they are not budgets or parity claims.

Allocation metrics are deliberately language-specific: Rust records bytes
owned for admitted mutation payloads, Go records runtime total allocated bytes,
and the native probe records its explicit payload-buffer allocation. Retained
bytes are the maximum explicit payload bytes held by the sequential workload;
peak RSS remains a separate process measurement. The verifier checks throughput
arithmetic but does not compare unlike allocation metrics.

The stored report binds the complete tracked and untracked Rust/R08 build
closure, schema, pinned compiler and server image digests, frozen Go commit and
tree, exact Ceph server binary, native package version, and all three probe
binaries. Probe binaries are ephemeral qualification artifacts; the script
rebuilds them from that closure and verifies their hashes before publishing the
report. Reproduction therefore depends on the pinned images and RPM URLs still
being available, rather than on an unstored executable being recoverable from
its digest alone.

Run the live gate with:

```sh
integration/r08/reproduce.sh --go-root /tmp/rados-r05-go-oracle \
  --report docs/r08/live-qualification-report.json
```

Once a real report exists, verify it with:

```sh
cargo run -p rados-r08-tools --bin rados-r08-verify -- \
  . docs/r08/live-qualification-report.json
```

Reproduce and verify the task-validation fuzz report with:

```sh
integration/r08/validate-fuzz.sh \
  --report docs/r08/fuzz-validation-report.json --seconds 60
cargo run -p rados-r08-tools --bin rados-r08-verify-fuzz -- \
  . docs/r08/fuzz-validation-report.json
```

Ordinary Cargo tests remain offline and require neither Go, Docker nor Ceph.
The R08 tools, integration metadata, documentation and live-only Rust source
are excluded from the root crate package.

The checked-in fuzz report is task-validation evidence, not the distinct
release-candidate campaign. The latter remains fixed at at least ten minutes
per enumerated target as required by the port specification.

## Boundary And Review

R08 certifies the seven individual mutations on the pinned replicated profile.
It does not certify compound writes, metadata operations, enumeration,
erasure-coded writes or later-phase coordination APIs.

Independent implementation audits found and repaired admission cancellation,
worker-abort accounting, sticky unknown outcomes, admission notification,
payload-retention and multi-epoch remap defects. The port specification still
requires accountable human distributed-systems review of cancellation and
replay invariants before R09 broadens writes; no automated or AI review is
represented as that approval.
