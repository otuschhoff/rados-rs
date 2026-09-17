# R02 Execution and Handoff

R02 implementation is complete. Release/distribution approval is not claimed.

## Delivered

- Bounded owned byte identities, zeroizing/redacted credentials, immutable
  client/pool/object handles, explicit cancellation and monotonic deadlines,
  consuming compound-operation builders, opaque cursor/watch handles and owned
  result DTOs.
- Structured public errors that preserve signed Ceph/Linux wire errno values
  and outcome-unknown causes without host-OS errno conversion.
- Private bounded little-endian primitives, versioned envelopes, entity names,
  legacy/modern addresses and vectors, distinct feature namespaces and Ceph
  CRC32C handling.
- Exact tests for all six P01 fixture binaries, independent decoded semantics,
  malformed/truncated/overflow/limit cases and CRC vectors.
- Four isolated fuzz targets over the exact production codec/address sources.
- A strict bounded R02 JSON Lines differential bridge for a newer-compatible
  versioned envelope, with a pinned Go 1.26.8 oracle, negative adapter/verifier
  tests, source/artifact hashes and clean-tree enforcement.
- Four-target native CI, package/docs/features/lint/policy gates, a pinned fuzz
  smoke job and an opt-in R01/R02 differential workflow.

## Observed Locally

Rust 1.98.0 passed the workspace debug suite (42 tests), focused root suite (22
tests), strict Clippy and the standalone fuzz-package build. The R00 offline
verifier passed with 384 archived files, 72 byte-identical imports, 282 public
Go declarations and all 905 parity rows.

The R02 bridge passed from outside the repository against clean pinned Go
commit `c8bb148a1379b51ef87256c27f366a05f8da4dc4`, tree
`c5039b6b50a05b942a902f70dc2fcb090463e8c7`, before clean-candidate enforcement
was added. The strengthened controller rejects an uncommitted Rust candidate;
the final report must therefore be regenerated after the R02 commit.

Using `cargo-fuzz 0.13.2`, `libfuzzer-sys 0.4.13` and
`nightly-2026-09-01` on `aarch64-apple-darwin`, fixture-seeded 60-second
campaigns completed for primitive decoding (49,224,921 executions), versioned
envelopes (52,228,256), entity addresses (38,381,372) and address vectors
(16,942,667). A first strict byte-identity assertion found accepted legacy
padding canonicalization; the final harness checks complete consumption and
stable canonical re-encoding instead. The bounded machine-readable campaign
record in [`fuzz-campaign.json`](fuzz-campaign.json) binds the targets, exact
source and seed-corpus bytes, command, budget, toolchain, results and raw-output
hashes. Generated corpus mutations and raw logs are not shipped.

The production dependency review is in `docs/r02/dependencies.md`; Rust notices
are separate from the byte-frozen upstream `THIRD_PARTY_NOTICES`. Remote CI and
release approval are not preclaimed.

## R03 Handoff

R03 implements bounded messenger framing and session transitions behind the
frozen handles. Preserve the no-side-effect-before-poll rule, never cancel an
in-progress frame write and reuse the stream, and keep admitted work supervised
after caller-future drop. Replace the explicit `NotConnected` lifecycle
boundaries only when their transport state exists; do not weaken local
cancellation, deadline, close or ownership behavior.