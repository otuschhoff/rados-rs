# R13 Compatibility

Status: **claims are contingent on the R13 exit gate being satisfied**. The
API surface described here is the code checked in for the R13 window; no
compatibility guarantee, semver commitment, or supported-release claim is
in force until the R13 gate closes and an authorized release process
completes.

## Rust toolchain

- MSRV: `1.98.0` (`rust-version` in `[workspace.package]` in
  [`Cargo.toml`](../../Cargo.toml); pinned in
  [`rust-toolchain.toml`](../../rust-toolchain.toml) as channel `1.98.0`,
  profile `minimal`, components `clippy`, `llvm-tools-preview`, `rustfmt`).
- Latest pinned toolchain for R13 qualification: `1.98.0` (same as MSRV).
  There is no separate "latest stable" channel until the next MSRV bump is
  contracted; the qualification runtime observation records
  `rustc 1.98.0 (88d9e12ae 2026-08-18)` on every observed platform.
- Fuzz nightly (unshipped, qualification-only):
  `nightly-2026-09-01` with `cargo-fuzz 0.13.2`.
- Edition: 2024. Resolver: 3.
- Enforced lints (workspace): `unsafe_code = "forbid"`, `clippy = "deny"`,
  `clippy::pedantic = "deny"`.

## Supported target platforms

Runtime observations required by the R13 qualification report cover four
native targets:

- `linux/amd64`
- `linux/arm64`
- `darwin/amd64`
- `darwin/arm64`

`rados-r13-qualify --verify` rejects a report that omits any of these
platforms (see
[`tools/r13/src/qualify.rs`](../../tools/r13/src/qualify.rs) and the
`KNOWN_PLATFORMS` constant). Producers that cannot honestly observe a
platform emit `docs/r13/qualification-report.failed.json` and exit
non-zero.

Ceph server runtime targets covered by the endurance and benchmark harness
are `linux/amd64` and `linux/arm64` only (native probe RPMs are the
`librados-devel-20.2.4` set from centos-stream); `CANDIDATE_KNOWN_SERVER_PLATFORMS`
enforces this.

## Feature sets

The shipped crate name is `rados-rs`; the library name is `rados`.
`publish = false`. Public features are declared in
[`Cargo.toml`](../../Cargo.toml):

| Feature | Purpose |
| --- | --- |
| (default, no features) | Bounded read/stat operations against the pinned replicated profile. |
| `r04-integration` | Enables the R04 live CephX/monitor-session integration binary and adapters (adds `serde`, `tokio/net`, `tokio/rt-multi-thread`). |
| `r05-integration` | Enables the R05 configuration/maps live adapter. |
| `r06-integration` | Enables the R06 exact-placement live adapter. |
| `r07-integration` | Enables the R07 read-only object live adapter (adds `serde`, `tokio/rt-multi-thread`). |
| `r08-integration` | Enables the R08 mutation live adapter. |
| `r09-integration` | Enables the R09 metadata/compound/enumeration live adapter. |
| `r10-integration` | Enables the R10 class/lock/watch live adapter. |
| `r11-integration` | Enables the R11 snapshot/specialized-I/O live adapter. |
| `r12-integration` | Enables the R12 administration live adapter. |

All `*-integration` features are gates for live-cluster adapters that are
not part of the default public API surface. The default build (no
features) exercises only the offline, deterministic subset. The R12
example [`examples/r12_administration.rs`](../../examples/r12_administration.rs)
is compile-checked in default configuration; live paths remain gated.

## Public API compatibility

R13 does not introduce a new public API surface. The R08..R12 crate surface
is the R13 candidate surface. The R13 endurance probe and benchmark
consume only the public
`rados` crate types
(`Config`, `SecretKey`, `SecurityMode`, `Client`, `Pool`, `ObjectRef`,
`OperationOptions`) and the public `bytes::Bytes` alias re-exported by the
crate. If the R13 probe compiles today, the shipped API supports the
lifecycle the probe exercises.

Semver commitment status: **none**. The crate is `version = "0.0.0"` and
`publish = false`. Until the R13 gate closes and the release owner
authorizes a tag, callers must treat every symbol as unstable.

## Deliberate omissions from the frozen Go P12 surface

R13 does not silently implement the following surfaces. They are recorded
in the parity ledger with an explicit disposition. The final global
distribution of the 905-row ledger is:

| Status | Rows |
| --- | --- |
| `implemented-r02` | 204 |
| `implemented-r05` | 34 |
| `implemented-r07` | 24 |
| `implemented-r08` | 63 |
| `implemented-r09` | 205 |
| `implemented-r10` | 66 |
| `implemented-r11` | 75 |
| `implemented-r12` | 57 |
| `adapted-r12` | 40 |
| `intentional-omission-r12` | 118 |
| `deferred-r12` | 19 |
| `planned-not-implemented` | 0 |

- **`deferred-r12`** (19 rows). Cache-tier, monitor-log, service-status, and
  hit-set APIs from `github.com/otuschhoff/go-librados` P12. These remain
  future R14 work and are explicitly outside the R13 v1 exit gate. The R13
  verifier accepts `deferred-r12` as a resolved ledger status but the R13
  exit gate does not require their implementation.
- **`intentional-omission-r12`** (118 rows). Native-only C entry points
  and C++ handle importers with no distributed-client behaviour,
  deprecated completion-safe aliases, legacy AUID/full-try APIs, cmpxattr
  and OMAP-cmp read/write-op builders, hash-position diagnostics, alloc-hint2
  variants, list_snaps read-op, inconsistent-snapset dumps, and the R13
  build-tag P12 diagnostic surface (`NewP12DiagnosticClient`,
  `P12DiagnosticObserver`, `P12SessionDiagnostic` and its seven fields).
  These have no frozen Go P12 behaviour that survives into v1 and will
  not be added under R13.
- **`adapted-r12`** (40 rows). Native/Go surfaces preserved with adapted
  Rust ergonomics, including the seven `PoolAsyncCompletion` symbols
  (subsumed by the `OperationOptions` + `Result`/completion model in the
  Rust R08 client) and the four OMAP-keys read-op builders (folded into
  the R09 OMAP get-vals surface with owned Rust results).
- **`planned-not-implemented`** (0 rows). Every previously deferred row
  has been resolved to an owning-phase implementation status, an
  `adapted-r12` R08/R09 adaptation, or an `intentional-omission-r12`
  documented omission. No row remains awaiting an R13-window disposition.

The parity ledger is [`docs/r00/parity-ledger.csv`](../r00/parity-ledger.csv).
Its allowed statuses are captured in the
[`LEDGER_ALLOWED_STATUSES`](../../tools/r13/src/constants.rs) constant.
The R13 inventory verifier
(`rados-r13-qualify --check-inventory`) requires exactly 623 rows in the
frozen native inventory and exactly 905 rows in the ledger, each row
carrying an allow-list status. R13 does not introduce a new ledger
column: doing so would create a self-reference where R13 evidence
depends on data that R13 itself produced.

## Behavioural compatibility notes

- Every fallible client operation takes `OperationOptions`. The R13
  endurance probe uses only the public shutdown/reconnect lifecycle
  (`Client::shutdown` followed by a fresh `Client::connect`); no private
  renewal is exercised, and completed renewal telemetry is honestly
  reported as `null` in the endurance report (see
  `INFLIGHT_MEASUREMENT_SENTINEL` and `RENEWAL_MEASUREMENT_SENTINEL` in
  [`tools/r13/src/candidate.rs`](../../tools/r13/src/candidate.rs)).
- Command methods return `(CommandResult, Result<()>)`; the R13 candidate
  binaries and the R12 administration example both consume the pair
  explicitly.
- `session_addresses` is an owned snapshot; the R13 endurance probe does
  not depend on live mutation of that snapshot.
- Rust exposes `blocklist` only; the deprecated `blacklist` spelling from
  the Go surface is an intentional omission.

## Non-normative migration guidance

See [`migration.md`](migration.md) for symbol-level mapping from the frozen
Go `github.com/otuschhoff/go-librados` P12 surface to the current Rust
crate. The mapping is provided for consumer convenience; it does not
constitute a compatibility promise.
