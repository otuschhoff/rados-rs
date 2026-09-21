# R13 Automated Review (What This Is And Is Not)

Status: **automated tooling never approves R13**. This document exists so
reviewers, auditors, and future maintainers can tell exactly what the
automated R13 harness can and cannot do, and what a human reviewer must
still do.

## What automated R13 tooling does

R13's `rados-r13-tools` crate ships six qualification binaries and a
detached-review verifier:

- `rados-r13-qualify` reproduces the fixed check matrix and verifies a
  submitted qualification report.
- `rados-r13-fuzz` inventories the 42 targets and verifies a submitted
  fuzz report at the chosen profile.
- `rados-r13-candidate` verifies a submitted endurance candidate report
  against the schema, budget, and on-disk release artefacts.
- `rados-r13-release` deterministically produces the four release
  artefacts.
- `rados-r13-probe` and `rados-r13-bench` are the live endurance probe
  and Rust benchmark.
- `rados-r13-verify` prints the canonical review payload for each role
  and verifies detached Ed25519 signatures.

The four verifiers combine strict schema decoding (`deny_unknown_fields`,
trailing-content rejection), source-digest binding to the current tree,
and content-addressed cross-binding between reports. Every producer
atomically writes to a temporary path, invokes the strict verifier, and
only then renames into the checked-in evidence path. Failed producers
write to `.failed.json` siblings or `docs/r13/failure-diagnostics/` for
container logs; they do **not** overwrite a passed evidence path.

The verifiers also print canonical materials that reviewers need:

- `rados-r13-qualify --print-checks` — canonical ordered check ids.
- `rados-r13-qualify --print-source-artifacts` — canonical `{path:
  sha256}` map.
- `rados-r13-qualify --print-source-digest` — aggregate source SHA-256.
- `rados-r13-fuzz --print-targets` — canonical alphabetical target list.
- `rados-r13-verify print-review-payload <role>` — the 19-field
  canonical payload a reviewer signs offline.

## What automated R13 tooling does NOT do

- It does **not** approve any human review. `verify_pending_review`
  refuses any status other than `pending`, and the strict verifier
  refuses to promote a review the harness itself produced.
- It does **not** hold any Ed25519 private key. Only the printed
  canonical payload is written; signing happens externally on a
  reviewer's own workstation.
- It does **not** fabricate runtime observations. If a producer cannot
  honestly reach a required native platform (e.g. `darwin/amd64` from a
  Linux host without a Rosetta daemon), it marks the report as
  `failed` and emits the `.failed.json` sibling. Nothing rewrites the
  failed evidence into the pass path.
- It does **not** fabricate benchmark rows. The Rust producer runs the
  real 36-row matrix; when a row falls outside the R08-derived budget the
  strict verifier rejects the entire report by design.
- It does **not** create release tags, push branches, or publish crates.
  No R13 tool invokes `git tag`, `git push`, or `cargo publish`.
- It does **not** claim legal review of the LGPL-2.1-only obligations.
  The `license/notices` reviewer is the accountable human gate. Automated
  documentation is technical guidance only.

## How the automated narrative interacts with human review

The written docs under `docs/r13/` (this file, `README.md`,
`compatibility.md`, `dependencies.md`, `performance.md`, `migration.md`,
`troubleshooting.md`, `release.md`, and `STATUS.md`) are inputs to human
review, not evidence of approval. In particular:

- Each reviewer should treat the automated narrative as an aid for
  navigating source and evidence, and independently verify claims against
  the checked-in schemas, constants, and reproducers.
- Anywhere a doc says "landed" (schemas, verifiers, constants, tests),
  the reviewer should confirm via `cargo test --workspace --locked`
  and by re-running the printed canonical materials against a clean
  checkout.
- Anywhere a doc says "pending" or "blocked" (four-platform qualification,
  certifying fuzz, 24 h candidate, human signatures), that is the exact
  outstanding item the reviewer must resolve by producing certifying
  evidence and signing detachedly.
- Anywhere a doc references a fact about the frozen Go P12 oracle
  (constants, cluster identity, benchmark budget origin), the reviewer
  should cross-check the frozen archive under
  `reference/archives/go-*.tar.gz` before accepting the mapping.

## Detached review workflow (summary)

The workflow is documented in [`release.md`](release.md#externally-held-signing-workflow)
and [`human-review.md`](human-review.md). Recapping the invariants:

- Signatures are Ed25519 over a canonical 19-field payload printed by
  `rados-r13-verify print-review-payload`.
- Signatures are produced **outside** this repository and this host.
- Public keys are enrolled in `docs/r13/reviewer-trust.json` with
  `status = active` at the time of verification.
- Each reviewer's `started_at` must be strictly greater than the
  candidate report's `finished_at`. No signature can predate its
  candidate.
- The four required roles are exact strings, exact order: `security`,
  `distributed-systems`, `license/notices`, `release-owner`.

## Sentinel non-substitutions

The following automated behaviours specifically exist to prevent
substitution:

- `check_pending_review_envelope` refuses any pending review that
  references a candidate or contains any review entry.
- `verify_pending` requires both the human-review and reviewer-trust
  documents to be pending envelopes.
- `verify_approved` (default `rados-r13-verify` mode) verifies four
  independently signed records against four independently active
  enrolled keys.
- The R13 candidate verifier's certifying branch refuses the
  `./integration/r13/reproduce.sh --quick` command string or any
  `R13_DURATION=...` variant; the reproducer sets that command on
  non-certifying output on purpose.
- The R13 fuzz verifier's certifying profile refuses `pending` or
  `smoke` profile reports.

## Why an AI assistant cannot substitute

R13's automated harness was built and refined with AI assistance (see
`AGENTS.md` and the session memory attached to this repository). That
assistance is scoped to writing, refining, and testing code and
documentation. The AI assistant:

- Cannot hold a reviewer's Ed25519 private key.
- Cannot sit at a keyboard 24 hours to observe a live probe.
- Cannot serve as an accountable human under legal or organisational
  obligations.
- Cannot approve LGPL-2.1-only distribution.

The automated R13 gate deliberately refuses AI-produced approvals. The
verifiers, schemas, and constants are structured so that even a
sophisticated automated attacker cannot silently promote a pending
evidence document, add a review record without a matching enrolled key,
or shrink the four-platform observation set to only what an automated
harness can reach.

## Where to look next

- [`STATUS.md`](STATUS.md) — engineering log.
- [`README.md`](README.md) — R13 index.
- [`human-review.md`](human-review.md) — full contract for the four
  human reviewers.
- [`review-template.md`](review-template.md) — reviewer working form.
- [`troubleshooting.md`](troubleshooting.md) — failure-mode reference.
