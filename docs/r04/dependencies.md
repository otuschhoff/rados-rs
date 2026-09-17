# R04 Dependency Review

Review date: 2026-09-17. Toolchain/MSRV: Rust 1.98.0. Direct versions are exact
pins and both lockfiles use lockfile version 4.

## Production

| Crate | Version | License | R04 purpose |
| --- | --- | --- | --- |
| `aes` | 0.9.3 | Apache-2.0 OR MIT | Ceph-compatible AES-128 and AES-256 primitives |
| `cbc` | 0.2.1 | Apache-2.0 OR MIT | legacy Ceph AES-CBC payloads |
| `hmac` | 0.13.0 | Apache-2.0 OR MIT | challenge, transcript and RFC 8009 authentication |
| `sha2` | 0.11.0 | Apache-2.0 OR MIT | SHA-256/SHA-384 digests |
| `base64` | 0.22.1 | Apache-2.0 OR MIT | credential decoding |
| `getrandom` | 0.4.3 | Apache-2.0 OR MIT | connector nonce generation |
| `tokio` | 1.47.1 | MIT | bounded connector I/O and deadlines |
| `zeroize` | 1.9.0 | Apache-2.0 OR MIT | erase owned keys and plaintexts |

R04 uses the safe RustCrypto APIs for Ceph-compatible AES-CBC and RFC 8009
AES256-CTS-HMAC-SHA384-192. CBC is retained for protocol compatibility and is
accepted only inside checked CephX envelopes. The implementation remains
subject to the dependencies' own constant-time and platform support claims.

Tokio is built only with `io-util`, `macros`, `rt`, `sync` and `time`; tests additionally
use `test-util`. No network, process, filesystem or multi-thread runtime feature
is enabled for the production library. The production crate remains
`#![forbid(unsafe_code)]`; transitive dependencies may contain their separately
licensed and audited unsafe implementations.

## Tooling And Fuzzing

The unpublished R04 tools also pin `command-group 5.0.1`, `serde 1.0.229` and
`serde_json 1.0.151`. `command-group` ensures
timed-out verifier probes and their descendants are terminated. The
workspace-excluded fuzz package pins `libfuzzer-sys 0.4.13` and uses
`nightly-2026-09-01` with `cargo-fuzz 0.13.2`. Neither bridge nor fuzz tooling
is reachable from the shipped library graph.

`RUST_THIRD_PARTY_NOTICES` records Rust dependency notices separately from the
byte-frozen upstream `THIRD_PARTY_NOTICES`. `cargo audit` and every `cargo deny`
policy group remain release gates. This review is technical inventory, not
legal certification or distribution approval.

The deny policy retains two exact, reviewed duplicate exceptions rather than
rewriting dependencies frozen by earlier phases: build-time `syn 2.0.119` for
Tokio macros alongside Serde derive's `syn 3.0.6`, and target-only
`windows-sys 0.59.0` retained by Tokio alongside `0.61.2` used by Mio and
Socket2. Neither exception implements Ceph protocol or cryptographic behavior;
all other duplicate versions remain denied.
