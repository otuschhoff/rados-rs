# ADR 0002: R13 Qualification, Endurance, and Release Contract

Status: accepted contract decision for the R13 phase of the pinned Rust port.
Supersedes no earlier decision. Complements [ADR
0001](0001-separate-repository.md).

Repository: https://github.com/otuschhoff/rados-rs. R13 remains on the private
main branch of that repository. No third repository is introduced.

## Context

R00–R12 landed the native Rust API surface, private wire and CephX
machinery, deterministic placement, read-only object I/O, mutation, metadata,
compound/enumeration, classes/locks/watches, snapshots/specialized I/O and
administration, each with its own live-integration or live-qualification
report. R13 must close the port with an *automated* qualification harness, a
soak endurance candidate, an exhaustive fuzz gate, deterministic release
artefacts, and a detached human review contract before any Rust distribution
or release approval could be considered.

R13 is the exit gate for the port. It is not the moment of publication.

## Decision

The R13 exit gate is the AND of four independent verifiers, all reproducible
from the checked-in source:

1. `rados-r13-qualify --verify` accepts a strict qualification report that
   bound the current source digest, exactly 24 qualification check ids in
   canonical order, prior R03..R12 report SHA-256s, a deterministic-release
   twice-run byte comparison, and runtime observations for every
   [`KNOWN_PLATFORMS`](../../tools/r13/src/constants.rs) entry
   (`linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`).
2. `rados-r13-fuzz --profile certifying --verify` accepts a strict fuzz
   report that ran every one of the 42 targets in
   [`FUZZ_TARGETS`](../../tools/r13/src/constants.rs) for at least 600
   seconds on the pinned `nightly-2026-09-01` toolchain and `cargo-fuzz
   0.13.2`, bound to the source digest, the schema digest, per-target Rust
   source, per-target corpus tree, and per-target log SHA-256s.
3. `rados-r13-candidate --verify` accepts a strict endurance candidate
   report whose two 24-hour probes (secure and CRC transports) each ran
   `>=86_400_000_000_000` ns wall-clock, kept the longest connection
   strictly above 15 minutes, recorded at least 24 credential-refresh
   reconnects, exercised monitor and every-OSD churn with recovery, produced
   four benchmark runs (two transports × two implementations, `rust` and
   `native`) satisfying the immutable R08-derived budget, and retained
   exactly four deterministic release artefacts under
   `docs/r13/release-artifacts/`.
4. `rados-r13-verify` accepts a fully approved
   `docs/r13/human-review.json` bound to the passed candidate/qualification/
   fuzz reports and the release artefact SHA-256s, with one detached
   Ed25519 signature per required role (`security`, `distributed-systems`,
   `license/notices`, `release-owner`), each verified against an active key
   in `docs/r13/reviewer-trust.json`.

The four verifiers are decoupled on purpose. A failure in any one of them
holds the exit gate; no verifier can be substituted, elided, or replaced by
an automated approval. Reproducing evidence is a technical prerequisite;
approving it is a human act.

### R13 identity

Frozen constants live in [`tools/r13/src/constants.rs`](../../tools/r13/src/constants.rs):

- Rust MSRV `1.98.0`, stable observed `rustc 1.98.0 (88d9e12ae 2026-08-18)`.
  Latest pinned toolchain is the same 1.98.0; there is no separate "latest"
  channel until the next MSRV bump is contracted.
- Pinned compiler image
  `rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922`.
  The digest is multi-arch (amd64+arm64) so a single reference selects the
  matching layer at `docker run --platform`.
- Ceph image amd64
  `quay.io/ceph/ceph@sha256:09ee90f6f3e0c7b9954f71d214ee05e9bbaaaea3716b1dd619603283b829f8b8`,
  arm64
  `quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa`,
  Ceph anchor commit `7f793731f1b39eb4f465e960113d2363c311b964`, server
  version `ceph version 20.2.4 (7f793731f1b39eb4f465e960113d2363c311b964) tentacle (stable)`.
- Auxiliary tool pins: `cargo-audit 0.22.2`, `cargo-deny 0.20.2`,
  `cargo-fuzz 0.13.2`.
- Endurance cluster: FSID `41111111-2222-4333-8444-131313131313`, network
  `172.30.114.0/24`, monitor `v2:172.30.114.10:3300`, pool `r13-data`
  (`size=2`, `min_size=1`, `pg_num=16`), three BlueStore OSDs, two managers
  when manager behaviour is exercised, 900 s auth ticket TTL, secure and
  CRC transports.
- Benchmark matrix: sizes `[4096, 65536, 1_048_576, 4_194_304]` bytes,
  concurrencies `[1, 16, 64]`, workloads `[read, write, mixed]` — 36 rows
  per run, four runs per candidate.

### Package boundary

The shipped crate `rados-rs` (library `rados`) is `publish = false` and its
`Cargo.toml` `include` list excludes every `tools/r{06..13}/**`,
`integration/r{06..13}/**`, `docs/r{06..13}/**`, and the R04..R12
`src/r*_integration.rs` files. R13 tooling — the automated qualification
harness, endurance probes, benchmark producers, fuzz orchestrator, release
producer, and human-review verifier — is qualification-only and never
enters the crate archive. The R13 release-artefact enumerator refuses to
package `.git`, `target`, `fuzz/artifacts`, `fuzz/target`, `fuzz/corpus`,
`docs/r13/release-artifacts`, and the excluded phase subtrees; the crate
`include` list mirrors that exclusion.

### Self-reference boundary

The source digest excludes the artefacts it generates so certifying evidence
can never rehash itself:

- `docs/r13/qualification-report.json` and its `pending` sibling,
- `docs/r13/fuzz-report.json` and its `pending` sibling,
- `docs/r13/human-review.json`, `docs/r13/reviewer-trust.json`,
- `docs/r13/report.pending.json`, `integration/r13/report.json`,
- and the entire `docs/r13/release-artifacts/` subtree.

Exclusion lists live in
[`tools/r13/src/source.rs::SELF_REFERENCE_EXCLUSIONS`](../../tools/r13/src/source.rs)
and are consumed unchanged by every producer and verifier through
`rados-r13-qualify --print-source-artifacts` / `--print-source-digest`.

### Automated vs certifying commands

Two command surfaces exist for every R13 stage, and they are distinct
outputs:

| Stage         | Quick / smoke                                                     | Certifying                                                      |
| ------------- | ----------------------------------------------------------------- | --------------------------------------------------------------- |
| Qualification | `cargo run -p rados-r13-tools --bin rados-r13-qualify -- --verify-shape --report docs/r13/qualification-report.pending.json` | `integration/r13/qualify.sh` producing `docs/r13/qualification-report.json` verified by `rados-r13-qualify --verify` |
| Fuzz          | `integration/r13/validate-fuzz.sh --profile smoke` (≥60 s/target)  | `integration/r13/validate-fuzz.sh --profile certifying` (≥600 s/target) verified by `rados-r13-fuzz --profile certifying --verify` |
| Endurance     | `integration/r13/reproduce.sh --quick` (non-certifying)            | `integration/r13/reproduce.sh` (24 h certifying) verified by `rados-r13-candidate --verify` |
| Release       | `cargo run -p rados-r13-tools --bin rados-r13-release -- --input . --output /tmp/dry-run --version v0.0.0-drynrun` | Two-run byte-compare embedded in `reproduce.sh`, artefacts atomically retained under `docs/r13/release-artifacts/` |
| Review        | `rados-r13-verify --pending` (canonical pending doc)               | `rados-r13-verify` (four detached Ed25519 signatures)           |

The verifiers refuse to promote a non-certifying artefact. `reproduce.sh`
carries the literal command `./integration/r13/reproduce.sh --quick` (or the
`R13_DURATION=... ./integration/r13/reproduce.sh`) into non-certifying
reports, and the strict verifier refuses to accept it as a candidate.

### Release, signing, and publication

Release artefact production is deterministic and content-addressed
([`tools/r13/src/release.rs`](../../tools/r13/src/release.rs)): mode `0644`
ustar+gzip crate, DOS-date-1980 STORED zip, SPDX 2.3 document with
`created = 1970-01-01T00:00:00Z`, and a `SHA256SUMS` file. Two invocations
with the same input produce byte-identical outputs. The endurance
reproducer runs the producer twice and byte-compares every artefact before
atomically renaming into `docs/r13/release-artifacts/`.

Detached human-review signatures are Ed25519 (RFC 8032) over the canonical
19-field payload emitted by `rados-r13-verify print-review-payload <role>`.
Private keys are held externally by the four named reviewers, never in
this repository. Automated tools cannot substitute for any human gate,
and this ADR does not authorize a release tag or crate publication. Any
future `git tag`, `git push --tags`, or `cargo publish` requires a
separate, explicit authorization outside R13.

### LGPL-2.1-only guidance

The distribution licence declared in `Cargo.toml` is `LGPL-2.1-only`. R13
documentation records this as a technical constraint (LICENSE, notices,
per-file provenance, upstream attributions) rather than legal advice. The
`license/notices` reviewer role is the accountable human gate for the
notices and dependency review. No LGPL-2.1-only obligation is treated as
discharged by this ADR or by any automated verifier.

## Consequences

- R13 keeps its automated harnesses honest by refusing to fabricate
  evidence for platforms, runtimes, or reviewers that were not actually
  observed. Producers atomically write to `.failed.json` sibling paths on
  any missing observation.
- Any future adjustment to identity constants (MSRV, image digests, cluster
  cluster identity, fuzz nightly, tool pins) requires updating
  `tools/r13/src/constants.rs` and the docs in `docs/r13/`, and re-running
  all four verifiers.
- `deferred-r12` remains a legitimate parity-ledger disposition. It is
  closed **outside** the R13 v1 exit gate as future R14 work; the 19
  rows are not silently implemented, and the R13 verifier deliberately
  accepts the status without demoting it.
- No performance parity, speedup, or feature superiority claim is made by
  passing the R13 gate. Passing evidence records that Rust functions within
  the R08-derived conservative budget against native under the pinned
  matrix.
- No release tag, crate publish, or GitHub Release is authorized by this
  ADR.
