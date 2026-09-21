# R13 Release Review Template

This template is completed separately by accountable humans. It is a working
form and does not by itself satisfy any required gate. The completed approval
is recorded in `docs/r13/human-review.json` and is verified by
`rados-r13-verify` against `docs/r13/reviewer-trust.json` and the candidate
`integration/r13/report.json`. Automated tools cannot sign a human section.

## Review Identity

- Required role: security / distributed-systems / license/notices / release-owner
- Reviewer identity and affiliation exactly as authorized in `reviewer-trust.json`:
- Authorized key ID and role binding:
- Passed `docs/r13/qualification-report.json` SHA-256:
- Passed certifying `docs/r13/fuzz-report.json` SHA-256:
- Candidate `integration/r13/report.json` SHA-256:
- Release version (matching the SemVer pattern in the schema):
- Four release artifact filenames and SHA-256 values (exact set):
- Review start and completion timestamps (RFC 3339 `Z`, start strictly after
  the candidate `finished_at`):
- Scope and excluded paths:
- Tools, versions, and commands used:

## Evidence

- Unit/build/vet/module verification results:
- Live qualification report identities and source-hash checks:
- 24-hour soak report identity, duration, workload, and resource bounds:
- Dependency graph and license notices checked:
- Security areas inspected:
- Replay/completion/failure areas inspected:

## Findings

| ID | Severity | File/component | Reproduction or evidence | Required action | Disposition |
| --- | --- | --- | --- | --- | --- |

State explicitly when no findings were identified; do not interpret that as
proof of absence. Record unresolved questions and evidence gaps.

## Decision

- Decision: approved / reject / pending (only `approved` is verifiable)
- Conditions or blockers:
- Follow-up owner and due point:
- Auditable approval reference (required absolute `http`/`https` URI, no
  whitespace, that a third party can retrieve):
- Unresolved critical findings (must be zero for approval):
- Unresolved high findings (must be zero for approval):
- Canonical payload for signing: reproduce with

  ```sh
  rados-r13-verify print-review-payload <role> \
      --review docs/r13/human-review.json \
      --report integration/r13/report.json > payload.bin
  ```

- Detached Ed25519 signature (base64, 88 characters, `[A-Za-z0-9+/]{86}==`;
  the private key remains entirely outside this repository and is never
  supplied to any automated tool):

## Notes for Reviewers

`rados-r13-verify` never generates signatures. It only prints the canonical
19-field payload that the accountable human signs on a separate,
network-isolated host with a hardware-backed or otherwise externally held
Ed25519 private key. The base64 signature and populated review record are then
pasted into `docs/r13/human-review.json`. The verifier's default mode reads
`docs/r13/human-review.json`, `docs/r13/reviewer-trust.json`, and
`integration/r13/report.json`; it fails when either detached record is still
pending and never treats absence of evidence as approval.
