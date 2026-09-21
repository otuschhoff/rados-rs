# R13 Automated Qualification & Deterministic Release — Core

Status: **implementation landed; live qualification report not yet generated**.

## Landed

- `tools/r13/src/constants.rs` — frozen R13 identity constants
  (MSRV 1.98.0, stable observed rustc 1.98.0 (88d9e12ae 2026-08-18),
  compiler image, Ceph amd64/arm64 digests, cargo-audit 0.22.2,
  cargo-deny 0.20.2, cargo-fuzz 0.13.2).
- `tools/r13/src/source.rs` — deterministic source inventory. Walks a
  fixed pathspec list via `git ls-files -co --exclude-standard` and excludes
  `docs/r13/qualification-report*.json`, `docs/r13/human-review.json`,
  `docs/r13/fuzz-report.json`, `docs/r13/reviewer-trust.json`, and
  `integration/r13/report.json` from the aggregate SHA-256 to avoid
  self-reference.
- `tools/r13/src/inventory.rs` — read-only check that the frozen native
  inventory has exactly 623 rows and the current parity ledger has exactly
  905 rows with every status on the R13 v1 allow-list. `deferred-r12` remains
  a valid disposition; it is closed **outside** the R13 v1 exit gate and is
  not implemented in this phase.
- `tools/r13/src/release.rs` — deterministic release-artefact core.
  Produces `rados-rs-vX.Y.Z.crate` (ustar + gzip, mode 0644, gzip OS 0xff),
  `rados-rs-vX.Y.Z.zip` (STORED, DOS date 1980-01-01), the SPDX 2.3
  document with `created = 1970-01-01T00:00:00Z`, and `SHA256SUMS`. Rejects
  absolute paths, `..`/`.` segments, backslashes, control characters,
  case-insensitive collisions, and empty file sets. Symlinks are refused by
  the `rados-r13-release` binary during enumeration.
- `tools/r13/src/qualify.rs` — strict qualification report types and
  verifier. Records timestamps, command ids, argv, exit codes, stdout /
  stderr SHA-256s, runtime observations, exact prior R03–R12 report
  bindings, source digest, deterministic-release comparison, inventory
  summary. Verifier rejects tampering, staleness, missing checks, unknown
  fields, and release nondeterminism.
- `integration/r13/qualification-report.schema.json` — the machine-readable
  contract that mirrors the Rust type.
- `docs/r13/qualification-report.pending.json` — placeholder so tooling can
  target a file path deterministically. Verifier deliberately rejects it.
- `tools/r13/src/bin/rados-r13-qualify.rs` — verifier binary with
  `--check-inventory` and `--print-checks` sub-modes.
- `tools/r13/src/bin/rados-r13-release.rs` — deterministic-release binary.

## Fuzz qualification contract (landed 2026-09-21)

- `tools/r13/src/fuzz.rs` — strict fuzz report types, profile machinery,
  and inventory guard. Verifier binds a report to the current tree
  (source digest, schema digest, per-target Rust source SHA-256,
  per-target corpus tree SHA-256, per-target log SHA-256). Three
  profiles: `pending` (no run), `smoke` (>=60 s per target), `certifying`
  (>=600 s per target). Every profile except `pending` requires the full
  42-target matrix in the canonical alphabetical order.
- `tools/r13/src/bin/rados-r13-fuzz.rs` — CLI with `--verify`,
  `--verify-shape`, `--check-inventory`, `--print-targets`, and
  `--print-checks` modes. `--profile` selects the gate.
- `tools/r13/src/bin/rados-r13-qualify.rs` grows a
  `--require-fuzz-certifying` mode that binds the current tree to a
  passed certifying fuzz report.
- `integration/r13/fuzz-report.schema.json` — JSON Schema draft 2020-12
  contract for the fuzz report. `additionalProperties: false` throughout.
- `integration/r13/prepare-fuzz-corpus.sh` — deterministic corpus
  preparation for every one of the 42 targets. Imports existing
  `fuzz/corpus/<target>/` seeds and pinned `testdata/p01/*.bin` fixtures
  where they apply, then emits a small bounded default seed set so no
  target is ever started with an empty corpus.
- `integration/r13/validate-fuzz.sh` — orchestration script. Runs one
  sequential libFuzzer campaign per target using nightly-2026-09-01 and
  cargo-fuzz 0.13.2. Records per-target executions, exec/sec, timestamps,
  hashes, and status. Handles interrupted (SIGINT/SIGTERM) and failed
  campaigns as first-class report evidence rather than silent skip.
- `docs/r13/fuzz-report.pending.json` — canonical placeholder. Passes
  shape verification and the `--profile pending` gate; rejected by
  `--profile smoke` and `--profile certifying`.

Frozen fuzz identity constants:

- 42 targets (see `crate::constants::FUZZ_TARGETS`).
- Toolchain: nightly-2026-09-01 + cargo-fuzz 0.13.2.
- Per-target minimum wall clock: smoke 60 s, certifying 600 s.
- Report byte limit: 1 MiB.

## Deferred (outside R13 v1)

- Live qualification report generation (`docs/r13/qualification-report.json`)
  requires the pinned compiler image and Ceph amd64+arm64 runtimes with
  reachable Docker daemons.
- Human approvals, fuzz certifying campaigns, and soak are out of scope
  for this task and are handled by earlier landed contracts (R13 human
  review) and future work.
- `deferred-r12` ledger rows.

## Notes

- `rados-r13-qualify` will refuse to sign off on any report whose runtime
  observations do not match its claims. The current single-host run
  therefore cannot produce a `passed` report until every required
  runtime is observed by the harness that runs it.

## Candidate / endurance harness (landed 2026-09-21)

- `integration/r13/report.schema.json` — strict JSON Schema (draft
  2020-12, `additionalProperties: false` throughout) for the R13
  endurance candidate report. Certifying branch requires 24-hour probes,
  monitor and every-OSD churn, four benchmark runs and reproducible
  four-artefact release; non-certifying branch forbids the reproduce
  command, sets qualification/fuzz to null, empty benchmark runs, and no
  release.
- `tools/r13/src/candidate.rs` — candidate types + verifier. Binds source
  artefacts to the workspace via `crate::source::source_artifacts`,
  qualification hash to `docs/r13/qualification-report.json`,
  fuzz hash to `docs/r13/fuzz-report.json` (certifying profile), release
  artefacts to `docs/r13/release-artifacts/`, and the schema digest via
  `candidate::schema_digest`. Certifying gate enforces >=24h elapsed per
  probe, >=15m longest connection, >=24 reconnects, exact cluster
  identity (FSID `41111111-2222-4333-8444-131313131313`, subnet
  `172.30.114.0/24`, `r13-data` pool, 900s auth ticket TTL,
  secure+crc), monitor and every-OSD churn with recovery, and the
  R08-derived benchmark budget.
- `tools/r13/src/budget.rs` — 4x3x3 (sizes 4 KiB..4 MiB x concurrencies
  1/16/64 x workloads read/write/mixed = 36 rows) matrix shape and the
  approved conservative budget: throughput ratio >=0.10, p99 ratio
  <=8.0, RSS <=2.5 GiB, allocations <=1_000_000, allocated bytes
  <=40 GiB.
- `tools/r13/src/bin/rados-r13-candidate.rs` — candidate verifier CLI.
  Modes: `--verify` (default; refuses non-certifying without
  `--allow-non-certifying`), `--verify-shape`, `--schema-digest`.
- `tools/r13/src/bin/rados-r13-probe.rs` — live endurance probe. Uses
  only the public `rados` API (`Config`, `SecretKey`, `SecurityMode`,
  `Client`, `Pool`, `ObjectRef`, `OperationOptions`) with a Tokio
  multi-threaded runtime. Accepts `--duration`, `--reconnect-interval`,
  `--sample-interval` as Go-style strings (`24h`, `50m`, `10s`) or bare
  seconds, plus `*-ns` aliases for integer nanoseconds. Iterates
  `write_full`, byte-verified `read`, `stat`, `append`, exactly-once
  post-append verification, `remove` on unique object IDs; drops the
  `Client` at `--reconnect-interval` and reconstructs it (the only
  reconnect lifecycle the public API exposes). Collects true counters,
  monotonic elapsed, reconnect count, longest connection, and bounded
  `/proc/self/status` samples (RSS/threads/heap). Renewal telemetry
  (`session_renewals`, `credential_renewals`) is honestly reported as
  `null` — the public `rados` crate does not expose completed renewal
  generation numbers, so the schema requires `null` plus the sentinel
  `renewal_measurement`. The 24-hour certifying gate is preserved via
  the reconnect-count, longest-connection, and churn requirements.
- `tools/r13/src/bin/rados-r13-bench.rs` — Rust endurance benchmark.
  Runs the 4x3x3 (sizes 4 KiB..4 MiB × concurrencies 1/16/64 × workloads
  read/write/mixed) matrix with `concurrency` parallel Tokio tasks each
  performing exactly two operations, capturing per-operation latency
  percentiles and elapsed throughput. Always labels its output
  `implementation = "rust"`; `--implementation native` is rejected.
- `tools/r13/native-bench/` — paired native C++ librados benchmark
  (`bench.cpp` + `Dockerfile` + `centos-stream.repo`). Compiled as
  `rados-r13-native` from the same pinned `librados-devel-20.2.4` RPMs
  and `libradospp-devel-20.2.4` RPMs used by the R08 native probe.
  Emits the same benchmark_run JSON shape with
  `implementation = "native"`.
- `integration/r13/reproduce.sh` — orchestration script.
  `--quick` is explicitly non-certifying (command carries `--quick`,
  status is `non-certifying`, no qualification/fuzz/benchmark/release)
  but drives a real short live scenario (three-minute default). The
  certifying default REFUSES to proceed unless the current source-bound
  42-target certifying fuzz report AND the passed qualification report
  both verify. The probe and Rust benchmark binaries are `cargo build
  --release` staged into the temporary mount as `probe` and `bench`;
  the native benchmark image is `docker build`-produced from
  `tools/r13/native-bench/` and its binary is `docker cp`-extracted so
  the reproducer runs it under the same ceph runtime as the probe.
  Probes launch as detached containers; churn observes probe liveness,
  performs monitor and per-OSD restarts with health recovery, and
  cannot certify unless every OSD was touched. Two release runs are
  generated and byte-compared; only the certifying branch atomically
  retains exactly four artefacts under `docs/r13/release-artifacts/`.
- `docs/r13/report.pending.json` — schema-valid non-certifying
  placeholder. Verifier rejects it as final (`--allow-non-certifying`
  required even to shape-check it).
- Self-reference exclusions extended in `tools/r13/src/source.rs`:
  `docs/r13/report.pending.json` and the entire
  `docs/r13/release-artifacts/` subtree are excluded from the source
  digest so certifying evidence cannot re-hash its own outputs.
- Tests: candidate module holds cases for duration downgrade, missing
  monitor and OSD churn, duplicate mutation, resource growth bound,
  benchmark budget, stale qualification/fuzz bindings, release mismatch,
  quick-vs-certifying, unknown fields, and report size. Budget module
  holds throughput/p99 ratio, RSS/allocation/allocated-bytes budget, and
  matrix shape cases. Probe binary tests cover Go-style duration
  parsing (seconds integer, `24h`/`15m`/`500ms`/`2h30m`, invalid unit
  and empty rejection) and payload determinism. Bench binary tests
  cover the 4x3x3 matrix shape, percentile indexing, seeded payload
  determinism, and rejection of `--implementation native`. Shell
  syntax check via `sh -n` covers all `integration/r13/*.sh` scripts.

## Automated-producer audit remediations (landed 2026-09-21)

- **C1** — `tools/r13/native-bench/Dockerfile` accepts a
  `CEPH_IMAGE` build arg for both the build and runtime stages, so the
  reproducer passes the same pinned amd64 or arm64 digest as the live
  Ceph cluster instead of the previously hard-coded arm64 image.
- **C2** — `integration/r13/reproduce.sh` cross-builds
  `rados-r13-probe` and `rados-r13-bench` inside the pinned
  `rust:1.98.0-bookworm@sha256:82150a…` compiler image via
  `docker run --platform` (the digest is multi-arch, so a single
  reference selects the matching architecture layer). This retires the
  previous host-side `cargo build --release`, which produced Mach-O on
  darwin hosts and failed inside the Linux Ceph containers.
- **C3** — new `integration/r13/qualify.sh` producer executes the
  canonical `CHECK_IDS` matrix (`--print-checks`), captures each
  check's `stdout`/`stderr`/timings/exit code, computes SHA-256s of
  the captured transcripts, records the R03..R12 prior report hashes,
  the source digest, inventory counts, deterministic-release
  comparison (two runs, byte-compared), and runtime observations for
  each native platform (host directly; other three via Docker
  `--platform` probes of the compiler image). Atomically writes to
  `docs/r13/qualification-report.json` only when the full R13
  verifier accepts the report; otherwise emits failure evidence to
  `docs/r13/qualification-report.failed.json` and exits non-zero. The
  qualification verifier now REQUIRES observations for every R13
  platform (`darwin/amd64`, `darwin/arm64`, `linux/amd64`,
  `linux/arm64`) — a producer that cannot exercise one must emit
  `status: "failed"` rather than shrink the set.
- **C4** — fuzz corpus root unified at repository path
  `fuzz/corpus/` via new constant
  `crate::constants::FUZZ_CORPUS_ROOT`, consumed by
  `candidate::validate_fuzz_binding`,
  `integration/r13/validate-fuzz.sh` (default corpus root),
  `integration/r13/prepare-fuzz-corpus.sh` (writes into
  `fuzz/corpus` by default; skips the self-copy loop when the
  destination is the seed root), and `integration/r13/reproduce.sh`.
  The libFuzzer run in `validate-fuzz.sh` now takes a per-target work
  corpus under `$temporary/work-corpus/<target>/` and passes the
  fixed seed corpus as a read-only secondary, so certifying campaigns
  never mutate the byte-stable seed tree the R13 verifier hashes.
- **C5** — `integration/r13/reproduce.sh` calls
  `rados-r13-candidate --verify` on the temporary report before the
  atomic `mv` into `integration/r13/report.json`.
  `--allow-non-certifying` is added only for `--quick`. Probe
  container exit codes are now checked explicitly (`docker wait`
  return value), and container logs are retained at
  `docs/r13/failure-diagnostics/` when the probe exits non-zero so
  post-mortem survives temporary-directory teardown.
- **M1** — `rados-r13-qualify --print-source-artifacts` prints a
  canonical `{path: sha256}` JSON object and `--print-source-digest`
  prints the aggregate digest, so `reproduce.sh` and
  `validate-fuzz.sh` no longer duplicate the git-ls-files exclusion
  set.
- **M2** — `tools/r13/src/bin/rados-r13-release.rs` refuses to
  package a documented `RELEASE_EXCLUDED_PREFIXES` set (`.git`,
  `target`, `fuzz/artifacts`, `fuzz/target`, `fuzz/corpus`,
  `docs/r13/release-artifacts`, and all R06..R13
  `tools/`/`integration/`/`docs/` subtrees plus the R04..R12
  `src/r*_integration.rs` files) that the crate `include` list also
  excludes. A new `end_to_end_repository_root_release_excludes_generated_evidence`
  test walks the workspace root and asserts the enumerator never
  leaks any excluded prefix, and does include `README.md` for a
  positive assertion.
- **M3** — the probe binary imports
  `INFLIGHT_MEASUREMENT_SENTINEL` and `RENEWAL_MEASUREMENT_SENTINEL`
  from `rados_r13_tools::candidate`, so the probe emitter and the
  candidate verifier share the exact string literals rather than
  keeping parallel copies.
- **M4** — `candidate::validate_churn` accepts a HEALTH_OK cluster
  with muted or purely informational (`INFO`-severity) checks and
  still rejects any live `WARN`/`WARNING`/`HEALTH_WARN` or
  `ERR`/`ERROR`/`HEALTH_ERR` severity check.
- **M5** — `integration/r13/qualify.sh` consumes
  `rados-r13-qualify --print-checks` as its check-id source of
  truth; the decorative API is now the producer's oracle.

## Documentation, CI policy, and ledger disposition (landed 2026-09-21)

- Companion docs added under `docs/r13/`:
  [`README.md`](README.md), [`compatibility.md`](compatibility.md),
  [`dependencies.md`](dependencies.md), [`performance.md`](performance.md),
  [`migration.md`](migration.md),
  [`troubleshooting.md`](troubleshooting.md), [`release.md`](release.md),
  and [`automated-review.md`](automated-review.md). Each doc records the
  R13 gate as blocked/pending; none claims completion.
- New ADR [`docs/decisions/0002-r13-qualification-contract.md`](../decisions/0002-r13-qualification-contract.md)
  captures the four-verifier exit gate, identity pins, package boundary,
  self-reference boundary, quick/certifying command split, release
  workflow, and LGPL-2.1-only guidance (as technical, not legal, advice).
- Root [`README.md`](../../README.md) grew an R13 landing paragraph and
  index links for every R13 companion doc and the new ADR.
- [`RUST_THIRD_PARTY_NOTICES`](../../RUST_THIRD_PARTY_NOTICES) rewritten
  from actual production dependencies; qualification-only tool crates
  listed separately with verified licences and upstream sources.
- CI (`.github/workflows/ci.yml`) gained an R13 non-certifying section
  that runs `--check-inventory`, `--print-checks`, `--print-source-digest`,
  `--print-source-artifacts`, candidate `--schema-digest` +
  `--verify-shape` (pending), fuzz `--verify --profile pending`, and
  `rados-r13-verify --pending`, plus a two-run deterministic release
  dry-run byte-comparison. The existing sentinel fuzz smoke
  (`primitive_decoder`, `banner`, `r12_command` at 60 s each) is
  retained. No multi-hour job is introduced.
- New `tools/r13/src/docs_tests.rs` module (16 tests) asserts that every
  R13 doc references a real workspace path, mentions the pinned
  MSRV/tool/toolchain/nightly/Ceph digests, records the exact
  4×3×3 benchmark matrix and R08-derived budget floors, lists every
  production dep from the root Cargo.toml, and matches the live
  parity-ledger disposition counts (19 `deferred-r12`,
  118 `intentional-omission-r12`, 0 `planned-not-implemented`).
- Parity-ledger `planned-not-implemented` audit closed: every one of the
  121 previously deferred rows has been reclassified per its owning
  phase's on-disk implementation status. Final global distribution:
  204 `implemented-r02`, 34 `implemented-r05`, 24 `implemented-r07`,
  63 `implemented-r08`, 205 `implemented-r09`, 66 `implemented-r10`,
  75 `implemented-r11`, 57 `implemented-r12`, 40 `adapted-r12`,
  118 `intentional-omission-r12`, 19 `deferred-r12`,
  0 `planned-not-implemented` (total 905). The 19 `deferred-r12` rows
  remain explicit future R14 work outside the R13 v1 exit gate; no other
  status remains open. No new ledger column was introduced (that would
  create self-reference).
- All CI R13 commands are documented as explicitly non-certifying in
  their `run:` block header; they do not produce a passed
  qualification, fuzz, candidate, or human-review report.
- Test totals after doc/CI landing: 135 rados-r13-tools unit tests
  (119 pre-existing + 16 new doc verifiers), workspace tests green,
  clippy pedantic clean at the pinned 1.98.0 toolchain.

## External blockers (remaining)

- No Docker daemon on this host, so no automated qualification report
  covering all four native runtimes can be produced here; the producer
  emits the failed evidence path deterministically when any runtime
  cannot be observed.
- amd64 and arm64 quay.io Ceph images reachable from a live
  two-architecture host required for real live probe/bench evidence.
- Continuous 24-hour host time and stable Docker daemon required for a
  certifying reproduce.
- Four accountable human reviewers with role authorization and
  externally held Ed25519 private keys required for signature evidence.
