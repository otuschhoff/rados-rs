# Required Human Review

Status: **pending and unsigned**.

No independent human review is recorded by this P12 documentation change.
`human-review.json` is the authoritative machine-readable record and
intentionally contains no reviewer name, signature, approval, or completion
date because no such evidence was supplied.

## Required Reviews

| Gate | Minimum scope | Reviewer | Reviewed commit | Decision |
| --- | --- | --- | --- | --- |
| Security | CephX, messenger framing/transcript/AEAD, secret handling, malformed input, downgrade resistance | Pending named accountable human | Pending | Pending |
| Distributed systems | request identity, retry/replay, remap, completion, flush/shutdown, cancellation and unknown outcomes | Pending named accountable human | Pending | Pending |
| License/release notices | project identity, upstream provenance, generated inventory/fixtures/native tooling, dependency notices and distribution bundle | Pending named accountable human | Pending | Pending |
| Release owner | compatibility claims, all qualification evidence, soak, findings, artifacts, tag/version and publication | Pending named accountable human | Pending | Pending |

Each reviewer should use [review-template.md](review-template.md), then add one
record to `human-review.json`. An approved record must contain each exact role
once; bind the exact candidate report, qualification, release version, and four
release artifact hashes; match a role-authorized identity and affiliation in
`reviewer-trust.json`; postdate candidate completion; state `approved`; record
zero unresolved critical/high findings; include an absolute auditable HTTP(S)
reference; and carry a valid detached Ed25519 signature. The automated AI review in `automated-review.md` is supplementary
and cannot be substituted for any role.

The qualification source inventory excludes only `.git` metadata, generated
`docs/p12/qualification-report.json`, `docs/p12/human-review.json`, the retained
`docs/p12/release-artifacts` directory, and the final
`integration/p12/report.json`. This avoids cycles because the human review
binds the qualification hash and retained release output is created later. The
inventory includes release-control dotfiles such as `.gitignore` and the P00
workflow. The candidate source map excludes only its own report, retained
release artifacts, and the subsequently generated detached `human-review.json`.
The trust policy and both review schemas remain current-tree hashed inputs.
Schemas, templates, verifier code, and narrative review documents remain part
of the qualified source inventory.

## Other Open Evidence

- No reproducible 24-hour soak report is present in this documentation slice.
- The checked-in non-live qualification report is not currently passed, and no
	candidate endurance report is recorded here.
- No release tag or completed release artifact is recorded here.