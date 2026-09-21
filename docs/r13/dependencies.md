# R13 Dependencies

Status: **verified against the checked-in Cargo manifests**. Every pinned
version below is a `=X.Y.Z` requirement in the source manifest or `Cargo.lock`
lockfile. Third-party notices in
[`RUST_THIRD_PARTY_NOTICES`](../../RUST_THIRD_PARTY_NOTICES) list the shipped
runtime graph; qualification-only tool crates are recorded separately and
excluded from the crate archive.

R13 does not add any *shipped* runtime dependency to `rados-rs`. All new
crates are consumed only by the R13 qualification tools
(`rados-r13-tools`) and never end up inside the `rados-rs` crate package.

## Shipped runtime dependencies (crate `rados-rs`)

Source: [`Cargo.toml`](../../Cargo.toml) `[dependencies]`. Every crate is
exactly pinned with `=`; every unshipped feature is disabled.

| Crate | Version | Licence | Features | Purpose |
| --- | --- | --- | --- | --- |
| `aes` | `=0.9.3` | Apache-2.0 OR MIT | default | AES-GCM primitive |
| `aes-gcm` | `=0.11.1` | Apache-2.0 OR MIT | `aes`, `alloc`, `zeroize` (no default) | Messenger secure-transport AEAD |
| `base64` | `=0.22.1` | Apache-2.0 OR MIT | default | Wire-format encoding |
| `cbc` | `=0.2.1` | Apache-2.0 OR MIT | `alloc` | CephX credential transport CBC block mode |
| `crc32c` | `=0.6.8` | Apache-2.0 OR MIT | default | Messenger CRC frame checksum |
| `getrandom` | `=0.4.3` | Apache-2.0 OR MIT | default | Nonce and ticket entropy |
| `hickory-resolver` | `=0.26.3` | MIT OR Apache-2.0 | `system-config`, `tokio` (no default) | Monitor discovery |
| `hmac` | `=0.13.0` | Apache-2.0 OR MIT | default | CephX authenticators |
| `serde` | `=1.0.229` | Apache-2.0 OR MIT | `derive`, `std` (no default) | Live-integration adapters (optional; only enabled by `r0*-integration` features) |
| `serde_json` | `=1.0.151` | Apache-2.0 OR MIT | `std` (no default) | Wire-format helpers |
| `sha2` | `=0.11.0` | Apache-2.0 OR MIT | default | CephX ticket and session hashes |
| `tokio` | `=1.47.1` | MIT | `io-util`, `macros`, `net`, `rt`, `sync`, `time` (no default) | Async runtime |
| `zeroize` | `=1.9.0` | Apache-2.0 OR MIT | `alloc` (no default) | Secret material scrubbing |

`serde` is optional and only enters the shipped graph when a caller
enables one of the `r04..r12-integration` features. The live-integration
binaries themselves are excluded from the packaged crate via the
`Cargo.toml` `include` list.

## Development dependencies (crate `rados-rs`)

Source: [`Cargo.toml`](../../Cargo.toml) `[dev-dependencies]`.

| Crate | Version | Licence | Purpose |
| --- | --- | --- | --- |
| `loom` | `=0.7.2` | MIT | Concurrency model tests |
| `serde_json` | `=1.0.151` | Apache-2.0 OR MIT | Fixture and evidence parsing |
| `tokio` | `=1.47.1` | MIT | Test runtime with `test-util` |

## Fuzz workspace (`fuzz/`)

Source: [`fuzz/Cargo.toml`](../../fuzz/Cargo.toml). Excluded from the root
workspace via `exclude = ["fuzz"]` and from the crate archive via the
`Cargo.toml` `include` list.

| Crate | Version | Licence | Purpose |
| --- | --- | --- | --- |
| `aes` | `=0.9.3` | Apache-2.0 OR MIT | Reuse of production primitive |
| `aes-gcm` | `=0.11.1` | Apache-2.0 OR MIT | Reuse of production AEAD |
| `base64` | `=0.22.1` | Apache-2.0 OR MIT | Wire fixtures |
| `cbc` | `=0.2.1` | Apache-2.0 OR MIT | Reuse of production block mode |
| `crc32c` | `=0.6.8` | Apache-2.0 OR MIT | Reuse of production CRC |
| `hmac` | `=0.13.0` | Apache-2.0 OR MIT | Reuse of production HMAC |
| `libfuzzer-sys` | `=0.4.13` | MIT OR Apache-2.0 OR NCSA | libFuzzer runner bindings |
| `sha2` | `=0.11.0` | Apache-2.0 OR MIT | Reuse of production hashes |
| `tokio` | `=1.47.1` | MIT | `io-util` for fuzz drivers |
| `zeroize` | `=1.9.0` | Apache-2.0 OR MIT | Secret scrubbing under fuzz |

## R13 qualification tools (`rados-r13-tools`)

Source: [`tools/r13/Cargo.toml`](../../tools/r13/Cargo.toml). Excluded from
the crate archive via the `Cargo.toml` `include` list. These crates power
`rados-r13-{verify,qualify,fuzz,candidate,release,probe,bench}` and are
not part of any shipped Rust distribution.

| Crate | Version | Licence | Purpose |
| --- | --- | --- | --- |
| `base64` | `=0.22.1` | Apache-2.0 OR MIT | Ed25519 signature encoding |
| `ed25519-dalek` | `=2.1.1` | BSD-3-Clause | Detached-review Ed25519 verifier |
| `rados-rs` | path dep, `0.0.0` | LGPL-2.1-only | R13 probe/bench uses the public rados API |
| `serde` | `=1.0.229` | Apache-2.0 OR MIT | Report (de)serialization |
| `serde_json` | `=1.0.151` | Apache-2.0 OR MIT | Report parsing |
| `sha1` | `=0.11.0` | Apache-2.0 OR MIT | SPDX 2.3 checksums |
| `sha2` | `=0.11.0` | Apache-2.0 OR MIT | Source, report, and artefact digests |
| `tokio` | `=1.47.1` | MIT | Probe/bench async runtime (`macros`, `rt-multi-thread`, `time`, `sync`) |

The `ed25519-dalek 2.1.1` transitive graph includes `curve25519-dalek 4.1.3`
and an older RustCrypto stack (`sha2 0.10`, `digest 0.10`). These are
recorded as multiple-version duplicates by
`cargo deny check bans --workspace`; R13 CI runs `cargo deny check` at the
top-level scope only (matching every earlier phase) so this drift is
declared and inspected via the `deny.toml`
[`skip`](../../deny.toml) list.

## Server, container, and reproduction dependencies

External to the Rust dependency graph, R13 qualification and endurance
reproducers require the following pinned external artefacts:

- Pinned compiler image
  `rust:1.98.0-bookworm@sha256:82150a…39922`.
- Pinned Ceph 20.2.4 amd64 image
  `quay.io/ceph/ceph@sha256:09ee90…f8b8`.
- Pinned Ceph 20.2.4 arm64 image
  `quay.io/ceph/ceph@sha256:6e6bc7…48aa`.
- CentOS Stream repository pin in
  [`tools/r13/native-bench/centos-stream.repo`](../../tools/r13/native-bench/centos-stream.repo)
  for the native benchmark image.
- `librados-devel-20.2.4` and `libradospp-devel-20.2.4` RPMs (identical
  digests to the R08 native probe).
- Ceph anchor commit `7f793731f1b39eb4f465e960113d2363c311b964`.

None of these external artefacts enter the shipped `rados-rs` crate; they
are qualification-only.

## Third-party notices

- [`RUST_THIRD_PARTY_NOTICES`](../../RUST_THIRD_PARTY_NOTICES) — shipped
  Rust runtime graph. Excludes qualification-only tool crates.
- [`THIRD_PARTY_NOTICES`](../../THIRD_PARTY_NOTICES) — historical Go
  reference notices for the pinned Go P12 oracle.

Any additional dependency introduced after R13 lands must (a) be justified
in the phase document that owns it, (b) pass `cargo audit --deny warnings`
and `cargo deny check` at the R13 pins, (c) preserve LGPL-2.1-only
compatibility, and (d) be recorded in this document with the correct
purpose and features. R13 does not silently take dependencies.
