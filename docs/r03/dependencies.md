# R03 Dependency Review

Review date: 2026-09-17. Toolchain/MSRV: Rust 1.98.0. Direct versions are exact
pins and both lockfiles use lockfile version 4.

## Production

| Crate | Version | License | R03 purpose |
| --- | --- | --- | --- |
| `aes-gcm` | 0.11.1 | Apache-2.0 OR MIT | AES-128-GCM secure records |
| `crc32c` | 0.6.8 | Apache-2.0 OR MIT | Ceph CRC32C framing |
| `tokio` | 1.47.1 | MIT | bounded async I/O, channels and task supervision |
| `zeroize` | 1.8.2 | Apache-2.0 OR MIT | erase owned authentication keys |

`aes-gcm` is built without default features and with `aes`, `alloc` and
`zeroize`. The implementation is used through the safe `Aead` and `KeyInit`
APIs; the crate remains subject to its own constant-time and platform support
claims. R03 uses synthetic 64-byte secrets and does not claim review of a live
CephX key derivation.

Tokio is built only with `io-util`, `macros`, `rt` and `sync`; tests additionally
use `test-util`. No network, process, filesystem or multi-thread runtime feature
is enabled for the production library. The production crate remains
`#![forbid(unsafe_code)]`; transitive dependencies may contain their separately
licensed and audited unsafe implementations.

## Tooling And Fuzzing

The unpublished R03 tools also pin `base64 0.23.1`, `command-group 5.0.1`,
`serde 1.0.229`, `serde_json 1.0.151` and `sha2 0.11.0`. `command-group` ensures
timed-out verifier probes and their descendants are terminated. The
workspace-excluded fuzz package pins `libfuzzer-sys 0.4.13` and uses
`nightly-2026-09-01` with `cargo-fuzz 0.13.2`. Neither bridge nor fuzz tooling
is reachable from the shipped library graph.

`RUST_THIRD_PARTY_NOTICES` records Rust dependency notices separately from the
byte-frozen upstream `THIRD_PARTY_NOTICES`. `cargo audit` and every `cargo deny`
policy group remain release gates. This review is technical inventory, not
legal certification or distribution approval.
