# R13 — Automated Qualification, Endurance, Release, and Detached Review

Status: **blocked and pending**. R13 tooling, schemas, verifiers, and
reproducers are landed and pass their own strict unit tests; the R13 exit
gate itself has not been satisfied. The four independent gates that R13
requires — passed certifying fuzz report, passed four-platform qualification
report, 24-hour endurance candidate, and four detached Ed25519 human-review
signatures — are all outstanding. No R13 approval, release tag, or crate
publication is authorized by this document.

This README is the R13 index. It cross-links every schema, verifier, script,
and companion document, and tells the reader whether each artefact is *ready
to accept evidence* or *waiting for evidence*.

## Table of Contents

- [State summary](#state-summary)
- [Design and identity](#design-and-identity)
- [Landed automation](#landed-automation)
- [Quick vs certifying commands](#quick-vs-certifying-commands)
- [What is still outstanding](#what-is-still-outstanding)
- [Companion documents](#companion-documents)

## State summary

| Gate | Verifier | Certifying evidence path | Current on-disk state |
| --- | --- | --- | --- |
| Fuzz (42 targets, 600 s each, nightly-2026-09-01) | `rados-r13-fuzz --profile certifying --verify` | `docs/r13/fuzz-report.json` | **not produced**; only [`fuzz-report.pending.json`](fuzz-report.pending.json) is checked in |
| Automated qualification (24 check ids, four platforms) | `rados-r13-qualify --verify` | `docs/r13/qualification-report.json` | **not produced**; only [`qualification-report.pending.json`](qualification-report.pending.json) is checked in |
| Endurance candidate (24 h probes, benchmark matrix, deterministic release) | `rados-r13-candidate --verify` | `integration/r13/report.json` | **not produced**; only [`report.pending.json`](report.pending.json) is checked in |
| Detached human review (four Ed25519 signatures) | `rados-r13-verify` | `docs/r13/human-review.json` | **pending**; [`human-review.json`](human-review.json) is a pending envelope with zero reviews, [`reviewer-trust.json`](reviewer-trust.json) enrols zero active keys |

None of the four evidence documents currently satisfies its verifier. The
verifiers refuse to promote pending or non-certifying documents, so the R13
exit gate remains explicitly closed.

## Design and identity

R13's exit-gate design and every immutable identity constant are recorded in
[ADR 0002](../decisions/0002-r13-qualification-contract.md). Constants live
in [`tools/r13/src/constants.rs`](../../tools/r13/src/constants.rs) and are
not restated exhaustively here; the essentials:

- Rust MSRV `1.98.0`, stable observed `rustc 1.98.0 (88d9e12ae 2026-08-18)`.
  Both the MSRV and the latest pinned toolchain for R13 evidence are the
  same `1.98.0`; there is no separate "latest" channel until an MSRV bump
  is contracted.
- Pinned compiler image
  `rust:1.98.0-bookworm@sha256:82150a…39922`. Digest is multi-arch.
- Ceph 20.2.4 (commit `7f793731…b964`), amd64 image
  `quay.io/ceph/ceph@sha256:09ee90…f8b8`, arm64 image
  `quay.io/ceph/ceph@sha256:6e6bc7…48aa`.
- Auxiliary tool pins: `cargo-audit 0.22.2`, `cargo-deny 0.20.2`,
  `cargo-fuzz 0.13.2`, fuzz nightly `nightly-2026-09-01`.
- Endurance cluster: FSID `41111111-2222-4333-8444-131313131313`, network
  `172.30.114.0/24`, monitor `v2:172.30.114.10:3300`, pool `r13-data`
  (`size=2 min_size=1 pg_num=16`), three BlueStore OSDs, 900 s auth
  ticket TTL, secure and CRC transports.
- Benchmark matrix: 4 sizes × 3 concurrencies × 3 workloads = 36 rows per
  run, 4 runs per certifying candidate (rust and native × secure and CRC).
- R08-derived immutable budget: minimum native throughput ratio `0.10`,
  maximum native p99 ratio `8.0`, RSS `<=2 684 354 560` bytes (2.5 GiB),
  allocations `<=1 000 000`, allocated bytes `<=42 949 672 960` (40 GiB).

Rust `unsafe_code = "forbid"` and clippy pedantic = deny are workspace-wide;
`allocations` / `allocated_bytes` are therefore honestly reported as `null`
for the `rust` implementation and only enforced for the `native`
implementation of the paired benchmark.

## Landed automation

R13 tooling is `rados-r13-tools` in
[`tools/r13/`](../../tools/r13/Cargo.toml); its binaries are excluded from the
`rados-rs` crate archive by the root `Cargo.toml` `include` list.

- Schemas in [`integration/r13/`](../../integration/r13/):
  - `qualification-report.schema.json` — automated qualification contract.
  - `fuzz-report.schema.json` — fuzz report contract (42-target matrix,
    three profiles).
  - `report.schema.json` — endurance candidate contract (probes, churn,
    benchmark budget, release evidence).
  - `human-review.schema.json`, `reviewer-trust.schema.json` — detached
    human-review contract.
- Rust modules under [`tools/r13/src/`](../../tools/r13/src/):
  - `constants.rs`, `source.rs`, `hash.rs`, `inventory.rs`, `qualify.rs`,
    `fuzz.rs`, `candidate.rs`, `budget.rs`, `release.rs`, `lib.rs`.
- Rust binaries under
  [`tools/r13/src/bin/`](../../tools/r13/src/bin/):
  - `rados-r13-qualify` — canonical check list, source-artifact/digest
    printer, inventory verifier, report verifier.
  - `rados-r13-fuzz` — inventory verifier, target/check printers, shape
    and profile-bound verifiers.
  - `rados-r13-candidate` — schema digest, shape, and strict verifier.
  - `rados-r13-release` — deterministic release-artifact producer.
  - `rados-r13-verify` — detached-review verifier + canonical payload
    printer.
  - `rados-r13-probe`, `rados-r13-bench` — live endurance probe and
    benchmark, both using only the public `rados` crate API.
- Native paired benchmark in
  [`tools/r13/native-bench/`](../../tools/r13/native-bench/) —
  `bench.cpp` compiled inside the parameterised Dockerfile against the
  same `librados-devel-20.2.4` and `libradospp-devel-20.2.4` RPMs used
  by the R08 native probe.
- Reproducers in [`integration/r13/`](../../integration/r13/):
  - `qualify.sh` — automated qualification producer.
  - `validate-fuzz.sh` — fuzz orchestrator with `pending`, `smoke`, and
    `certifying` profiles.
  - `prepare-fuzz-corpus.sh` — deterministic seed corpus writer for the
    42 targets.
  - `reproduce.sh` — endurance reproducer (`--quick` non-certifying,
    default 24 h certifying).
- Companion documents live under `docs/r13/` (see
  [Companion documents](#companion-documents)).

## Quick vs certifying commands

R13 always ships two command surfaces per stage; the non-certifying one is
explicitly non-promotable. See ADR 0002 for the full matrix. Common
commands:

```sh
# Offline shape checks (safe to run without Docker or a Ceph cluster).
cargo run --locked -p rados-r13-tools --bin rados-r13-fuzz -- \
	--verify-shape --report docs/r13/fuzz-report.pending.json
cargo run --locked -p rados-r13-tools --bin rados-r13-candidate -- \
	--verify-shape --report docs/r13/report.pending.json --allow-non-certifying

# Read-only inventory check (native inventory + parity ledger).
cargo run --locked -p rados-r13-tools --bin rados-r13-qualify -- \
	--check-inventory --root .

# Deterministic release dry-run (no publication implied).
cargo run --locked -p rados-r13-tools --bin rados-r13-release -- \
	--input . --output /tmp/rados-r13-release-dry-run \
	--version v0.0.0-dry-run

# Certifying producers (require Docker, pinned Ceph runtimes, and 24 h of
# host time; do not run casually).
integration/r13/qualify.sh
integration/r13/validate-fuzz.sh --profile certifying
integration/r13/reproduce.sh
```

Every certifying producer writes to a temporary path, invokes the strict
verifier, and only then atomically renames into the checked-in evidence
path. Failure evidence is retained at the sibling `.failed.json` path (see
`docs/r13/qualification-report.failed.json` for the automated qualification
producer) or under `docs/r13/failure-diagnostics/` for probe container
logs.

## What is still outstanding

The exit gate is closed because none of the four required certifying
artefacts exists yet:

1. **Certifying fuzz report**. Needs the pinned nightly on the host and
   ~7 hours of continuous single-threaded runtime for 42×600 s campaigns.
2. **Four-platform qualification report**. Needs a Docker daemon that can
   run `linux/amd64`, `linux/arm64`, `darwin/amd64`, and `darwin/arm64`.
   Darwin platforms cannot be reached from a Linux host; the producer
   deterministically emits `docs/r13/qualification-report.failed.json`
   when it cannot honestly observe every platform.
3. **24-hour endurance candidate**. Needs the pinned Ceph amd64+arm64
   images reachable from a two-arch host and continuous 24-hour host
   time. Must pass the R08-derived benchmark budget and produce four
   deterministic release artefacts under
   `docs/r13/release-artifacts/`.
4. **Four detached Ed25519 signatures**. Held by four externally accountable
   reviewers (`security`, `distributed-systems`, `license/notices`,
   `release-owner`), whose keys are enrolled in
   [`reviewer-trust.json`](reviewer-trust.json) and whose approval URIs
   are recorded in [`human-review.json`](human-review.json).

Nothing in this repository — including this document, the schemas, the
verifiers, and CI — can substitute for any of the four gates. The R13
verifiers refuse to promote pending or non-certifying evidence, refuse to
accept a review report they can only reprint, and refuse to fabricate
runtime observations that were not actually made.

No release tag, no crate publish, no GitHub Release, and no CI badge is
authorized by R13. Any of those actions require a separate, explicit
authorization outside R13.

## Companion documents

- [`STATUS.md`](STATUS.md) — engineering log of what landed and when.
- [`compatibility.md`](compatibility.md) — public API compatibility, MSRV
  policy, feature set semantics, and deliberate omissions from the frozen
  Go P12 surface.
- [`api-coverage.md`](api-coverage.md) — final 905-row parity-ledger
  disposition distribution, R13 audit closure summary, and per-phase
  reclassification of the 121 previously `planned-not-implemented`
  rows.
- [`dependencies.md`](dependencies.md) — production, tool, fuzz, and dev
  dependency graph with pinned versions and licences.
- [`performance.md`](performance.md) — R08-derived budget rationale,
  matrix shape, and honesty caveats (allocations/allocated_bytes null for
  the Rust implementation).
- [`migration.md`](migration.md) — non-normative notes for consumers
  migrating from the frozen Go `github.com/otuschhoff/go-librados` P12
  surface, including deliberately omitted APIs.
- [`troubleshooting.md`](troubleshooting.md) — recurring reproduce/qualify
  failure modes and their honest diagnoses.
- [`release.md`](release.md) — deterministic release-artefact contract,
  externally held signing keys, and the boundary between certifying
  evidence and publication.
- [`automated-review.md`](automated-review.md) — statement of what the
  detached review verifier can and cannot do; how it interacts with the
  pending state; how role reviewers should treat the automated
  narrative.
- [`human-review.md`](human-review.md) — long-form contract for the four
  human reviewers (already landed).
- [`review-template.md`](review-template.md) — working form each reviewer
  fills in before appending a signed record (already landed).
- [`qualification-report.pending.json`](qualification-report.pending.json),
  [`fuzz-report.pending.json`](fuzz-report.pending.json),
  [`report.pending.json`](report.pending.json) — canonical shape-passing
  placeholders that the strict verifiers deliberately refuse to promote.
