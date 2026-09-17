# R03 Execution and Handoff

R03 implementation and committed-tree differential verification are complete.
Release/distribution approval and live Ceph authentication are not claimed.

## Delivered

- Private bounded messenger v2.1 banner, control, message, CRC and AES-128-GCM
  secure-frame codecs.
- A pure generation-tagged session state machine covering admission, sequence
  and transaction assignment, ACK handling, reset/retry/wait/reconnect,
  credential-renewal transitions and bounded terminal failure.
- Tokio reader/writer supervision with bounded queues, fragmented-read support,
  close interruption, partial-write stream discard and invalid-frame rejection
  before dispatch.
- Exact checks for all 12 P02 binaries and adjacent provenance sidecars,
  including synthetic-secret secure vectors and original upstream vectors.
- Six production-source fuzz targets for banners, CRC frames, secure frames,
  controls, messages and bounded session scripts.
- A strict six-case Rust/Go differential bridge with clean-tree and pinned-Go
  enforcement, bounded/time-limited subprocesses, controlled Rust builds,
  replay verification and negative tests.

## Observed Locally

Rust 1.98.0 passed focused codec, session, supervisor, transport and bridge
tests while R03 was developed. The final full validation matrix is run before
the phase commit. Dependency advisory and policy checks remain release gates.

Using `cargo-fuzz 0.13.2`, `libfuzzer-sys 0.4.13` and
`nightly-2026-09-01` on `aarch64-apple-darwin`, fresh isolated 60-second
campaigns are recorded for all six R03 targets in
[`fuzz-campaign.json`](fuzz-campaign.json). The tracked
[`prepare-fuzz-corpus.sh`](../../integration/r03/prepare-fuzz-corpus.sh)
recreates every initial corpus byte used by local campaigns and CI. Generated
mutations and raw logs remain disposable validation artifacts.

The deterministic bridge compares banner, CRC frame, secure frame, ACK control,
message and session-transition semantics with pinned Go commit
`c8bb148a1379b51ef87256c27f366a05f8da4dc4` and tree
`c5039b6b50a05b942a902f70dc2fcb090463e8c7`. Its controller only certifies a
clean committed Rust tree. The post-commit regenerated report passes, completing
the phase evidence gate. CI retains that report as a workflow artifact.
Ordinary Cargo tests neither require nor invoke Go.

The 905-row R00 public parity ledger contains no R03 rows. R03 adds private
implementation machinery and therefore does not invent public API coverage.
The public client connection boundary continues to return `NotConnected`.

## R04 Handoff

R04 owns credential/keyring parsing, CephX negotiation, challenge/ticket and
authorizer processing, negotiated connection secrets, authenticated identity,
ticket expiry and live secure monitor sessions. It may connect the existing
private messenger to the frozen public handles only after those authentication
contracts are implemented and tested. R03 synthetic secrets, identity fields
and renewal signals are protocol scaffolding, not evidence of live
authentication.
