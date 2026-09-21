# R13 Detached Human Review Contract

Status: **pending and unsigned**.

No independent human review of the Rust R13 release-documentation slice is
recorded here. `docs/r13/human-review.json` is the authoritative
machine-readable record and intentionally contains no reviewer identity, no
signature, no approval decision, and no completion date. `docs/r13/reviewer-trust.json`
is likewise pending and lists no active Ed25519 keys. The R13 verifier
(`tools/r13/src/bin/rados-r13-verify.rs`) cannot manufacture approvals: it
verifies detached Ed25519 signatures produced by external reviewer key holders
against a canonical payload it can only reprint, never sign.

## Required Reviews

| Gate | Minimum scope | Reviewer | Reviewed commit | Decision |
| --- | --- | --- | --- | --- |
| Security | CephX, messenger framing/transcript/AEAD, secret handling, malformed input, downgrade resistance | Pending named accountable human | Pending | Pending |
| Distributed systems | request identity, retry/replay, remap, completion, flush/shutdown, cancellation and unknown outcomes | Pending named accountable human | Pending | Pending |
| License/release notices | project identity, upstream provenance, generated inventory/fixtures/native tooling, dependency notices and distribution bundle | Pending named accountable human | Pending | Pending |
| Release owner | compatibility claims, all qualification evidence, soak, findings, artifacts, tag/version and publication | Pending named accountable human | Pending | Pending |

Each reviewer must use [`review-template.md`](review-template.md) as a working
form, then append one record to `human-review.json`. An approved record must:

- state each of the four required roles exactly once, in the declared order
  `security`, `distributed-systems`, `license/notices`, `release-owner`;
- bind the exact candidate `integration/r13/report.json` SHA-256, the passed
  `docs/r13/qualification-report.json`, the passed certifying
  `docs/r13/fuzz-report.json`, the release version, and exactly four release
  artifact SHA-256 hashes;
- match a role-authorized identity, affiliation, key ID, and Ed25519 public key
  in `reviewer-trust.json`, whose status must be `active` (never `pending`) at
  the moment of verification;
- start strictly after the candidate report's `finished_at` timestamp;
- record `decision: approved` and zero unresolved critical/high findings;
- include an absolute, whitespace-free `http` or `https` approval reference URL
  that a third party can audit; and
- carry a valid detached Ed25519 signature over the canonical 19-field payload
  produced by `rados-r13-verify print-review-payload <role>`, base64-encoded
  with the exact 88-character `[A-Za-z0-9+/]{86}==` form.

The verifier further enforces that no two reviews share a role, key ID,
reviewer identity (case- and whitespace-normalized), affiliation binding, or
public key. Automated tools (including this repository's AI-assisted work)
cannot substitute for any of the four human gates.

## Canonical Source Inventory Exclusions

To break the hash cycle, the R13 qualification source inventory excludes only
`.git` metadata, the generated `docs/r13/qualification-report.json`, the
detached `docs/r13/human-review.json`, the detached
`docs/r13/reviewer-trust.json`, the retained `docs/r13/release-artifacts/`
directory, and the final `integration/r13/report.json`. The candidate source
map excludes only its own report, retained release artifacts, and the
subsequently generated detached review record. All schemas, templates, verifier
code, and narrative review documents remain part of the qualified source
inventory.

## Other Open Evidence

- No reproducible 24-hour soak report is present in this documentation slice.
- The checked-in non-live qualification report is not currently passed, and no
  candidate endurance report is recorded here.
- No release tag or completed release artifact is recorded here.
- The reviewer trust policy is pending; no active Ed25519 keys are enrolled.
