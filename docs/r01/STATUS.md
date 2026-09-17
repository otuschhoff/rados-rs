# R01 Execution and Handoff

R01 implementation is complete. Release/distribution approval is not claimed.

## Delivered

- Root package `rados-rs`, library `rados`, edition 2024, Rust/MSRV 1.98.0,
  lockfile, package allowlist, workspace lint policy and project-owned
  `unsafe_code = "forbid"`.
- Private signed entity-name codec with exact 9-byte bounds and independent
  semantic/byte checks against both imported native entity-name fixtures.
- Unpublished R01 tooling crate with strict bounded JSON Lines Rust probe,
  temporary-module Go adapter, explicit controller, report schema and verifier.
- Negative tests for oversized/unknown requests, changed fixture identity,
  changed bounds, stale fixture/candidate hashes, missing or substituted
  probes, wrong implementation IDs and impossible calendar timestamps. The Go
  adapter independently rejects oversized and unknown-field requests.
- Four native CI runner targets, package/docs/features/lint/profile gates,
  pinned advisory/license policy tools, and an opt-in differential workflow.
- Dependency and protocol decisions in this directory. Production code has no
  external dependency and no Go/Ceph/native library path.

## Observed Locally

The pinned Rust 1.98.0 toolchain passed debug tooling tests and the opt-in bridge
against a temporary clone of Go commit
`c8bb148a1379b51ef87256c27f366a05f8da4dc4`. Rust and Go independently decoded
entity type 8 and signed number 1, reproduced the fixture bytes, and matched
SHA-256 `0ea9e19802a23c4674e289fabeaa6e600262fb9ad25ae64fd4fb927651b6abe9`.
The report verifier passed. `cargo audit` found no lockfile advisories.

Local validation passed formatting, debug/release tests, default/no-default
checks, clippy with warnings denied, warning-free rustdoc, `cargo audit`, all
`cargo deny` policy groups and `cargo package` verification from packaged
source. R00 verification and the complete cgo-disabled pure-Go test suite also
passed; the Go worktree remained clean. A missing Rust probe was rejected before
Go execution, and a fresh bridge report passed strict recomputation.

Remote CI results are not preclaimed; its first run must execute all four native
runner jobs. The manual differential workflow pins Go 1.26.8 and immutable
checkout action commits, disables persisted checkout credentials, and requires
private-repository secret `RADOS_GO_TOKEN`. A missing secret fails rather than
selecting another implementation.

## R02 Handoff

R02 freezes the public API/errors/options/ownership contracts and begins bounded
wire families. Keep `entity_name` private, preserve signed IDs and exact bytes,
and extend the bridge by a versioned case rather than weakening the R01 schema.
Do not add network code to satisfy R02 codec gates.