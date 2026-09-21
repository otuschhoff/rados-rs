# R13 Release Contract

Status: **release artefact producer is deterministic and reproducible; no
release is authorized**. The R13 gate does not authorize a `git tag`,
`git push --tags`, `cargo publish`, or a GitHub Release. This document
describes the contract that a release *must* satisfy before any such action
could be taken; whether such an action ever happens is outside R13.

## Deliverables per release

Every release version `vX.Y.Z` (optionally with `-pre` or `+build`
semver suffixes) produces exactly four content-addressed artefacts:

1. `rados-rs-vX.Y.Z.crate` — reproducible ustar+gzip archive of the
   packaged file set. Mode `0644`, mtime `0`, PAX-compatible ustar
   header, gzip OS byte `0xFF`.
2. `rados-rs-vX.Y.Z.zip` — reproducible STORED zip of the same set.
   DOS date `1980-01-01T00:00:00`, no compression.
3. `rados-rs-vX.Y.Z.spdx.json` — SPDX 2.3 document with
   `created = 1970-01-01T00:00:00Z`. Per-file SHA-256 and SHA-1
   checksums.
4. `SHA256SUMS` — `<sha256>  <name>\n` lines for the three artefacts
   above, sorted by name.

Two invocations of `rados-r13-release` against the same input produce
byte-identical outputs (encoder in
[`tools/r13/src/release.rs`](../../tools/r13/src/release.rs)). The
strict R13 candidate verifier requires this determinism and byte-compares
every artefact of two consecutive runs during a certifying reproduce.

## Producer boundary

`rados-r13-release` is the only supported producer. It:

- Enumerates the file set with the workspace's crate `include` list and
  refuses to package the [`RELEASE_EXCLUDED_PREFIXES`](../../tools/r13/src/release.rs) —
  `.git`, `target`, `fuzz/artifacts`, `fuzz/target`, `fuzz/corpus`,
  `docs/r13/release-artifacts`, every `tools/r{06..13}/`,
  `integration/r{06..13}/`, `docs/r{06..13}/`, and the R04..R12
  `src/r*_integration.rs` files.
- Rejects absolute paths, `..`/`.` segments, backslashes, control
  characters, case-insensitive collisions, empty file sets, and any
  symbolic link during enumeration.
- Rejects a version string that is not `vX.Y.Z` shaped.

The enumerator uses the same `Cargo.toml` `include` list that governs
`cargo package`; R13 tooling therefore never accidentally ships
qualification-only source. A dedicated test
(`end_to_end_repository_root_release_excludes_generated_evidence`) walks
the workspace root and asserts no excluded prefix leaks and that
`README.md` is packaged.

## Source and evidence boundary

- The source digest inputs (`SOURCE_PATHSPECS` in
  [`tools/r13/src/source.rs`](../../tools/r13/src/source.rs)) intentionally
  exclude the retained release artefacts and every R13 evidence document.
  If the certifying release atomically writes into
  `docs/r13/release-artifacts/`, the next source digest computed after
  the move still matches the digest observed by the endurance report,
  because the subtree is excluded from the digest.
- The R13 endurance report binds
  `docs/r13/release-artifacts/*` by SHA-256 (release-artefact map) and by
  path (`docs/r13/release-artifacts` as `release.path`). The verifier
  checks the on-disk artefacts against the map before accepting the
  report as a certifying candidate.
- The R13 detached review payload also binds each release artefact
  SHA-256 (canonical payload field
  `release_artifact_sha256`). Reviewer signatures cover the exact
  artefact set that the candidate report referenced.

## Externally held signing workflow

The R13 detached review contract requires four Ed25519 signatures produced
by externally accountable reviewers. Signing follows this workflow:

1. The candidate reproducer emits a passed candidate report at
   `integration/r13/report.json`.
2. For each of the four roles (`security`, `distributed-systems`,
   `license/notices`, `release-owner`), the reviewer runs:

   ```sh
   cargo run -p rados-r13-tools --bin rados-r13-verify -- \
       print-review-payload <role> \
       --candidate integration/r13/report.json \
       --qualification docs/r13/qualification-report.json \
       --fuzz docs/r13/fuzz-report.json
   ```

   which prints the exact 19-field canonical payload (SHA-256-bound to the
   candidate/qualification/fuzz reports and the release-artefact map).
3. The reviewer signs the payload with an **externally held** Ed25519
   private key. The key never enters this repository, never traverses this
   host, and is not written by any R13 tool. The signature is
   base64-encoded (`[A-Za-z0-9+/]{86}==`, exactly 88 characters).
4. The reviewer's public key must appear in
   `docs/r13/reviewer-trust.json` with `status = active` and matching
   `role`, `reviewer_identity`, `reviewer_affiliation`, and `key_id`.
5. The reviewer appends one record to `docs/r13/human-review.json`
   binding the exact candidate, qualification, fuzz, and release
   artefacts SHA-256s, with `decision = approved`, zero unresolved
   critical/high findings, an absolute HTTP(S) approval reference URI,
   and the base64 detached signature over the canonical payload.

`rados-r13-verify` (default mode) verifies:

- Both the review and trust documents parse strictly.
- Each of the four required roles is present exactly once, with a
  matching active key.
- Every canonical field on the review matches the on-disk candidate.
- Every detached signature verifies against its declared public key over
  the canonical payload.
- No two reviews share a role, key ID, normalized reviewer identity,
  affiliation, or public key.
- Each review's `started_at` is strictly after the candidate's
  `finished_at`.

The verifier prints canonical payloads and reports pass/fail; it does
not, and cannot, produce a signature.

## Publication is a separate authorization

Once the four verifiers pass, the R13 exit gate is closed **for the R13
port**. It is not an authorization to release. In particular:

- No `git tag` is created by any R13 tool.
- No `git push`, `git push --tags`, or `cargo publish` is invoked by any
  R13 tool.
- No GitHub Release is drafted or published by any R13 tool.
- The crate remains `version = "0.0.0"` with `publish = false` until an
  explicit authorization is granted.

A future release authorization is a separate decision by the
`release-owner` reviewer, taken outside the R13 exit gate. That decision
would include: choosing a release version, tagging the commit,
constructing an actual release, mirroring the artefacts, and satisfying
the LGPL-2.1-only obligations documented below.

## LGPL-2.1-only obligations

The crate declares `license = "LGPL-2.1-only"` in
[`Cargo.toml`](../../Cargo.toml) (via `[workspace.package]`) and preserves
upstream notices in [`LICENSE`](../../LICENSE),
[`RUST_THIRD_PARTY_NOTICES`](../../RUST_THIRD_PARTY_NOTICES), and
[`THIRD_PARTY_NOTICES`](../../THIRD_PARTY_NOTICES).

This documentation is **technical guidance, not legal advice**. It
enumerates the technical prerequisites a release must satisfy so the
LGPL-2.1-only obligations *can* be reviewed by the `license/notices`
reviewer. Specifically:

- The distributed source archive (the `.crate` and `.zip`) must include
  `LICENSE`, `RUST_THIRD_PARTY_NOTICES`, and `THIRD_PARTY_NOTICES` — the
  `include` list in the shipped `Cargo.toml` enforces this.
- The SPDX document must record the licence identifier
  `LGPL-2.1-only` for the primary work and preserve
  per-dependency licence identifiers for direct and transitive
  dependencies.
- Every direct dependency's licence must appear on the
  [`deny.toml`](../../deny.toml) `licenses.allow` list (currently
  `Apache-2.0`, `LGPL-2.1-only`, `MIT`, `Unicode-3.0`, `Unlicense`);
  `ed25519-dalek 2.1.1` is `BSD-3-Clause` and appears only in
  qualification-only tool crates that are excluded from the crate
  archive.
- Upstream file provenance for imported fixtures and native drivers is
  preserved in `reference/README.md`.
- Notices for the shipped runtime graph appear in
  `RUST_THIRD_PARTY_NOTICES`; qualification-only crates are recorded in
  [`dependencies.md`](dependencies.md) rather than in the shipped
  notices.

The `license/notices` reviewer is the accountable human gate. The
technical checks above enable that review; they do not conclude it.

## Reproducing the release artefacts

Non-authorizing dry run (safe locally; does not touch checked-in
evidence):

```sh
cargo run --locked -p rados-r13-tools --bin rados-r13-release -- \
    --input . --output /tmp/rados-r13-release-dry-run \
    --version v0.0.0-dry-run
```

Certifying release (executed only inside `integration/r13/reproduce.sh`
after the candidate report has been shape-verified):

```sh
R13_RELEASE_VERSION=vX.Y.Z integration/r13/reproduce.sh
```

`R13_RELEASE_VERSION` is required for a certifying reproduce; the
reproducer refuses to certify without a valid semver-shaped version.
`--quick` never produces a release; its report explicitly records
`release.performed = false`.
