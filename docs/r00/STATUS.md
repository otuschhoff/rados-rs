# R00 Execution and Handoff

R00 repository/reference work is complete; this is not a Rust implementation,
conformance certification or release approval. The private GitHub remote and
initial commit identify publication. R01 is the next implementation phase.
Open items below gate their owning phases, not completed evidence.

## Completed Deliverables

- Separate project `rados-rs`, owner `otuschhoff`, private visibility, main
  default branch, independent CI/release policy and no submodule. See
  [ADR 0001](../decisions/0001-separate-repository.md).
- [Port spec](../RUST_PORT_SPEC.md) transferred with project identity and
  local links to unchanged reference copies. The original spec remains
  preserved in the archive and imported evidence.
- [Go baseline](../../reference/go-baseline.json): 384 tracked/untracked,
  nonignored regular source files captured, including uncommitted implementation.
  Original HEAD `061df4d7eab779eee2bb7c069ad43aec3e455981` is provenance, not a
  claim that it contains those changes. No Go source/index/branch was modified.
- Archive SHA-256:
  `fca14fbb7bc8193d8081b48f83f655034d580e89232301f945ecd67001afa7cf`.
  A second capture produced an identical baseline manifest. Every included
  source file has a digest, length and executable mode.
- [Import manifest](../../reference/imports.json): 71 unchanged imports,
  including selected source/spec anchors, P00/P01 knowledge and native driver,
  six P01 binary fixtures with original sidecars, and license/notices.
- [Parity ledger](parity-ledger.csv): 623 native rows plus 282 Go exported
  declarations, including fields/constants and config/lifecycle helpers.
  Stable IDs, planned phases, adaptations, prerequisites and future test IDs
  are recorded. This is 905 coverage records, not implemented Rust APIs.
  Exact Rust signatures/finer mappings remain R02/owning-phase work. Native
  omissions/deferred entries are explicitly inherited; no blanket parity claim.
- [Public declaration index](../../reference/go-public-api.json), generated
  with Go's AST parser. Verification re-extracts it from the archive and
  regenerates every ledger row, checking content and unique IDs.
- [Decisions and gates](decisions.md), [knowledge index](knowledge-index.md)
  and [reference workflow](../../reference/README.md).

## Observed Checks

[Prerequisite/dependency observations](observations.json) preserve commands,
exit codes, output hashes and registry metadata. Eleven prerequisite commands
and seventeen registry queries completed without unexpected failure. Both Ceph
commits exist, and baseline/qualification multi-platform image manifests are
available. Qualification amd64/arm64 digests match the Go evidence pins.

[Native fixture report](native-fixtures.json): fresh pinned-container
reproduction of all six P01 fixtures, six matches and zero mismatches. The IPv6
generator uses a seed from the verified archive mounted read-only. No expected
fixture was rewritten and no live cluster was started.

The verifier and tamper tests pass without the Go checkout or Docker:

```sh
GO111MODULE=off go test ./tools/r00 -count=1
GO111MODULE=off go run ./tools/r00/main.go -root . -verify
```

These are Go development evidence tools, not the planned library. R01 ordinary
Cargo tests must not invoke them or require Go.

The first observation recorder attempt failed on Ruby open-uri argument
handling. Its [failed report](observations-failed-ruby-options.json) is retained;
the corrected observations file is authoritative. An initial direct native
invocation stopped at the IPv6 manifest's literal `$PWD`; the committed runner
resolves only that documented mount, without eval. Neither failed attempt is
represented as successful evidence.

## Open Gates and Owners

| ID | Gate | Owner and Required Action | Blocks |
| --- | --- | --- | --- |
| R00-G01 | Type-2 CephX crypto | R04 implementer and security reviewer: verify maintained RFC 8009 AES256-CTS-HMAC-SHA384-192 support with Ceph key usages; no handwritten primitive or omission | R04 type-2 completion |
| R00-G02 | Rust dependency graph | R01 implementer: resolve/pin features and targets; audit native code, advisories, licenses and lockfile; registry metadata is not build/security evidence | R01 dependency gate |
| R00-G03 | Translation/distribution obligations | Owner appoints license reviewer before direct translation/distribution; preserve LGPL/per-file notices and address static-link/relink obligations | Affected port tasks and distribution |
| R00-G04 | Live/platform qualification | Harness and phase owners: verify privileged network/volume/runtime behavior and four targets in isolation; no R00 cluster faults or soak | Live phase and R13 claims |
| R00-G05 | Candidate approvals | Owner appoints security, distributed-systems, license and release reviewers for fresh Rust evidence; no copied Go signatures | R13 release |

Responsible roles are explicit; no person is represented as approving Rust
without participation. R00 records stop conditions rather than inventing reviews.

## Next Task: R01-T01

Create the root Cargo workspace with package `rados-rs`, library `rados`, Rust
1.98.0, edition 2024 and MSRV 1.98.0. Preserve license/notices and reviewed
package boundaries. Begin with a minimal crate and one bounded P01 fixture
loader; do not scaffold every module. Use decisions.md and its stop conditions.

First discriminating check: a Rust test reads a P01 vector and independently
checks expected fields/bytes. Cargo unit tests must work without Go, a sibling
checkout, Ceph libraries or network. Add Cargo CI only in this repository.
R01-T02 builds the opt-in bridge against the verified temporary Go reference,
not moving Go HEAD.