# R07 Execution and Handoff

R07 implements bounded read-only object I/O over authenticated OSD sessions.
Fresh Rust/frozen-Go/native qualification passed against the pinned Ceph 20.2.4
cluster on 2026-09-18.

## Delivered

- Public immutable `ObjectRef::read` and `ObjectRef::stat` operations with
  owned results, operation versions, binary object identities, namespaces and
  locator keys.
- Bounded MOSDOp read/stat request and reply codecs with strict correlation,
  operation-count, length, result and trailing-byte validation.
- Shared monitor authentication authority for OSD CephX tickets and bounded
  OSD session caching, invalidation and shutdown.
- Placement-aware dispatch with map refresh, redirect/remap recovery, deadline
  propagation and serialized OSD backoff admission.
- Cancellation-on-drop for admitted reads. Dropped callers release supervisor
  state without cancelling unrelated requests or desynchronizing a session.
- Synthetic lifecycle coverage for block/unblock, reconnect, cancellation,
  malformed replies and bounded shutdown.
- Two production-backed libFuzzer targets for OSD replies and backoff messages.
  Each completed a 10-second pinned-nightly campaign without a crash, sanitizer
  finding, timeout or non-zero exit.

## Live Evidence

`live-integration-report.json` is a source-bound report from one isolated
three-OSD replicated cluster. Native `rados` writes full, empty, namespaced and
locator-keyed objects. Rust and the frozen Go oracle then run concurrently,
cross the same acting-primary loss, and produce identical JSON outcomes for
ranged/full/empty/namespace/locator reads, stat metadata, missing-object errors,
operation version and remap recovery.

The controller requires the clean Go oracle at revision
`c8bb148a1379b51ef87256c27f366a05f8da4dc4`, tree
`c5039b6b50a05b942a902f70dc2fcb090463e8c7`, Go 1.26.8, pinned Rust and Ceph
images, and the exact Ceph source anchor. The typed verifier rejects unknown
fields, stale Rust source, invalid provenance, failed scenarios and Rust/Go
probe differences.

```sh
integration/r07/reproduce.sh \
  --go-root /tmp/rados-r05-go-oracle \
  --report docs/r07/live-integration-report.json
cargo run -p rados-r07-tools --bin rados-r07-verify -- \
  . docs/r07/live-integration-report.json
```

The controller also invokes the verifier with the temporary Rust and Go probe
paths and clean Go checkout before cleanup, binding both reported executable
hashes to the binaries used for the run.

Ordinary Cargo tests remain offline and require neither Go, Docker nor Ceph.
The live report and integration tooling are excluded from package contents.

## Boundaries

R07 certifies reads and stat on the pinned replicated profile. It does not
certify erasure-coded object I/O, arbitrary CRUSH profiles, mutation replay,
ACK-as-commit behavior, flush watermarks, compound operations, metadata,
listing, snapshots or administrative operations.

The two live-discovered placement corrections are separately pinned by unit
tests: omitted MSR tunables decode to native defaults `100/100`, and RJenkins
tail bytes 9-11 retain Ceph's alignment. Neither broadens the R06 certified
placement profile.

## R08 Handoff

R08 may build mutation ownership and unknown-outcome semantics on the shared
OSD session machinery. Read retry success is not evidence that mutations are
safe to replay; mutation request identity, ACK/commit state, flush watermarks
and every dropped-future boundary remain R08 work.