# R13 Migration Notes

Status: **non-normative guidance for consumers**. This document maps the
frozen Go `github.com/otuschhoff/go-librados` P12 surface to the current
Rust `rados` crate at the R13 window. It is a courtesy for callers
familiar with the Go client; it is not a compatibility promise and it does
not cover every symbol.

The R13 exit gate is not a Rust distribution event. Nothing here should be
read as guidance for adopting Rust in place of the Go client in
production. The intent is to help reviewers and prospective callers
understand *how the Rust surface differs from the Go surface* so they can
audit R13 evidence against a familiar reference.

## General mapping principles

- **Method names**: Go's `MixedCase` becomes Rust `snake_case`.
- **Errors**: Go's returned `error` becomes Rust
  `Result<T, rados::Error>`. Every fallible method takes
  `OperationOptions` (deadline, cancellation, retries) as the last
  argument.
- **Ownership**: Go interfaces are Rust concrete types with clear ownership.
  `Client` is a `Send + Sync` handle; dropping it releases the underlying
  session.
- **Async**: Go's blocking API becomes Rust `async fn`. The R13 endurance
  probe uses Tokio (`macros`, `rt-multi-thread`, `time`, `sync`).
- **Bytes and buffers**: Go `[]byte` becomes `bytes::Bytes` on read paths
  and `impl AsRef<[u8]>` on write paths.
- **Options structs**: Go's option-function pattern becomes Rust builder
  types (`OperationOptions::builder`) or dedicated request structs.
- **Cancellation**: Go `context.Context` becomes `OperationOptions` with
  a deadline plus a cancellation token; a dispatched mutation that is
  cancelled after send returns `Err(Error::OutcomeUnknown)` rather than
  being replayed.

## Symbol groups

### Cluster and authentication

| Frozen Go P12 | Rust `rados` |
| --- | --- |
| `rados.Config` | `rados::Config` |
| `rados.SecretKey` | `rados::SecretKey` |
| `rados.SecurityMode` | `rados::SecurityMode` |
| `rados.Client` | `rados::Client` |
| `rados.Client.Shutdown` | `rados::Client::shutdown` |
| `rados.Client.OpenPool` | `rados::Client::open_pool` |

CephX authenticators, ticket TTL, and secure/CRC transport selection are
identical to the Go contract; the R13 candidate cluster fixes the ticket
TTL at 900 s (`CANDIDATE_CLUSTER_TICKET_TTL_SECONDS`).

### Pool and object

| Frozen Go P12 | Rust `rados` |
| --- | --- |
| `rados.Pool` | `rados::Pool` |
| `rados.ObjectRef` | `rados::ObjectRef` |
| `rados.ObjectRef.Write` / `WriteFull` | `rados::ObjectRef::write_full`, `write_offset` |
| `rados.ObjectRef.Read` | `rados::ObjectRef::read`, `read_offset` |
| `rados.ObjectRef.Stat` | `rados::ObjectRef::stat` |
| `rados.ObjectRef.Append` | `rados::ObjectRef::append` |
| `rados.ObjectRef.Remove` | `rados::ObjectRef::remove` |
| `rados.OperationOptions` | `rados::OperationOptions` |

The R13 endurance probe iterates `write_full → read → stat → append →
exactly-once verification → remove` per iteration on unique object IDs,
which is the shape the Go P12 endurance harness used.

### Administration (R12 surface)

| Frozen Go P12 | Rust `rados` |
| --- | --- |
| `rados.Client.ClusterStats` / `PoolStats` | `rados::Client::cluster_stats`, `Pool::stats` |
| `rados.Client.MonitorCommand` / `ManagerCommand` / `OsdCommand` / `PgCommand` | `rados::Client::{monitor,manager,osd,pg}_command` |
| `rados.Client.Blacklist*` | Renamed to `blocklist` (deprecated spelling omitted). |
| `rados.Client.SessionAddresses` | `rados::Client::session_addresses` (owned snapshot) |
| `rados.Client.PoolApplication*` | `rados::Pool::application_*` |

`(CommandResult, error)` becomes `(CommandResult, Result<()>)` so callers
must inspect the result object even when the outcome is `Err`.

### Snapshots, classes, locks, watches

R10 and R11 introduced the class/lock/watch/snapshot/specialized-I/O
surface; the mappings are documented in the corresponding phase docs.
See [`docs/r10/STATUS.md`](../r10/STATUS.md),
[`docs/r11/STATUS.md`](../r11/STATUS.md).

### Deliberate omissions

The following Go surfaces are **not** implemented in the R13 window and
will not be added under R13. They are recorded in the parity ledger with
their exact disposition:

- **`deferred-r12`** (19 rows) — cache-tier, monitor-log, service-status,
  and hit-set APIs. Future R14 work, explicitly outside the R13 v1 exit
  gate.
- **`intentional-omission-r12`** (118 rows) — native-only C entry points,
  C++ handle importers, deprecated completion-safe aliases, legacy
  AUID/full-try APIs, cmpxattr/OMAP-cmp builders, hash-position
  diagnostics, alloc-hint2 variants, list_snaps read-op,
  inconsistent-snapset dumps, and the R13 build-tag P12 diagnostic
  surface. No frozen Go P12 behaviour survives into v1.
- **`adapted-r12`** (40 rows) — `PoolAsyncCompletion` folded into the R08
  `OperationOptions`/`Result` model and OMAP-keys read-op builders folded
  into the R09 OMAP get-vals surface.
- **`planned-not-implemented`** (0 rows) — every previously deferred row
  has been resolved to an owning-phase implementation, an `adapted-r12`
  adaptation, or an `intentional-omission-r12` omission. R13 no longer
  carries any row awaiting a disposition.

See [`compatibility.md`](compatibility.md#deliberate-omissions-from-the-frozen-go-p12-surface)
for the full statement.

### Renamed and reshaped APIs

- Go `Blacklist` becomes Rust `blocklist`. The old spelling is not exposed.
- Go `Client.Flush` semantics are preserved but exposed as a public method
  returning `Result<()>` with cancellation as `Err(Error::OutcomeUnknown)`
  for previously-dispatched mutations.
- Go option-functions become Rust builder types on `OperationOptions`,
  `WriteOptions`, and command-request structs.
- `Session addresses` return an owned Rust `Vec<rados::EntityAddress>`;
  the Go pointer-into-live-state pattern is not exposed.

## Cancellation and unknown outcomes

Both clients preserve the frozen Go P12 rule: **a dispatched mutation
cancelled or timed out after send returns `OutcomeUnknown`**. This is
essential for correctness on retryable transports and is exercised by
the R13 endurance probe's per-iteration exactly-once verification.

## Feature flags

Live-integration adapters (R04..R12) are gated behind
`r04-integration` through `r12-integration`. The default build compiles
without any of them; consumers who need to run a live cluster path enable
the relevant feature explicitly (see
[`compatibility.md`](compatibility.md#feature-sets)).

## What is intentionally NOT in this document

- No Rust binding for private wire codecs. Callers must not depend on
  types under `rados::wire`, `rados::msgr`, `rados::cephx`,
  `rados::crush`, `rados::maps`, `rados::mgr`, `rados::mon`, or
  `rados::osd` — those are private crate modules exposed only for
  qualification.
- No release schedule, no crate publish plan, no crate version bump plan.
  Until the R13 gate closes and the release owner authorizes a tag, the
  crate stays at `version = "0.0.0"` with `publish = false`.
