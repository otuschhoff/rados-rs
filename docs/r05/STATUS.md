# R05 Execution And Handoff

R05 implements public configuration loading and the public client path through
monitor bootstrap, map publication, failover, and pool discovery. Deterministic
Rust/Go parity, digest-pinned live qualification, and bounded sanitizer fuzz
campaigns passed on 2026-09-18.

## Delivered

- A fourteen-case Rust/Go bridge over the actual configuration implementations:
  defaults, global/entity section precedence, explicit environment loading,
  arguments and remainder, direct-key/keyring precedence and expansion, Go
  duration syntax, monitor vector/v1 filtering, unknown-option behavior,
  exclusions/errors, and representative monitor bounds.
- Actual Rust and Go decoding of all three P04 `ceph-dencoder` fixtures, with
  matched stable semantic summaries and canonical-output SHA-256 values.
- Strict single-request and newline-delimited result JSON, fixed case ordering,
  input/output/report limits, subprocess deadlines, and exact source, tree,
  adapter, schema, controller, stdout, and executable hash binding.
- Negative verifier tests for stale records, malformed source hashes,
  substituted binary hashes, and case-set tampering.
- Rust unit evidence for synthetic full-plus-incremental convergence and bounded
  map history in `full_and_incremental_maps_converge_and_history_is_bounded`.
- An additive three-monitor Ceph v20.2.4 live harness and strict verifier under
  `integration/r05`, with fixed scenarios, exact source artifact/hash binding,
  bounded subprocess output and time, wrong-FSID negative execution, tamper
  tests, and measured container/network cleanup. It uses
  `quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa`.
- A passing live report covering initial map readiness, pool create/delete map
  updates, one-monitor loss with quorum retained, post-loss map updates,
  configured-FSID rejection, and cleanup.
- Seven production-backed libFuzzer targets covering configuration, direct map
  decoders, and monitor map-message envelopes. Each completed 2,000 executions
  under the pinned nightly without a crash or sanitizer finding; exact results
  are recorded in `docs/r05/fuzz-campaign.json`.

## Boundaries

The P04 full OSDMap and incremental files are independent default
`ceph-dencoder` fixtures. They are decoded separately by both implementations;
they are not represented as a valid sequential pair. Convergence is therefore
Rust-only synthetic unit evidence, not cross-language fixture convergence.

The live path authenticates to monitors and completes the msgr2 client/server
identification transition before publishing readiness. It does not exercise
manager or OSD service authorization. Fuzz counters are bounded campaign
observations and are not a statement of exhaustive parser coverage.

## R06 Handoff

R06 should build on the qualified monitor path to implement CRUSH placement and
map-derived OSD authorization, then exercise object I/O against a digest-pinned
cluster. Manager service authorization and the pending P04 fixture
redistribution review also remain explicit follow-up work.