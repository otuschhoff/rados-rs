# R00 Technical and License Decisions

## Identity and Toolchain

- GitHub project/package: `otuschhoff/rados-rs` / `rados-rs`; library: `rados`.
  Registry HTTP 404 on 2026-09-16 means unoccupied when observed, not reserved
  and not authorization to publish.
- Rust 1.98.0, edition 2024, initial MSRV 1.98.0. Compiler commit
  `88d9e12ae178fab0fb5cc050a94da85685d449ea`, Cargo 1.98.0 were observed.
  This is a selected support floor, not a claim older versions fail. R01 pins
  the toolchain/Cargo configuration and verifies it in CI.
- Targets: `aarch64-apple-darwin`, `x86_64-apple-darwin`,
  `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu`. GNU aarch64 is not
  locally installed. R01/runtime qualification must provision it; an installed
  musl target is not a silent substitute.
- Tokio async-first, no hidden runtime or blocking facade in v1. No Cargo
  scaffolding or registry publication in R00.

## Authentication and Configuration

The Go connector negotiates CephX (method 2), not a separate Kerberos auth
method. The Kerberos dependency supplies cryptographic primitives for CephX
type-2 keys: AES256-CTS-HMAC-SHA384-192 (RFC 8009). Type-1 uses AES-128 CBC;
Messenger v2.1 secure transport is a separate construction.

Archive anchors: internal/cephx/core.go, connector.go, service_connector.go,
docs/p03/README.md, testdata/p03/crypto-vectors.json and Ceph key-usage constants.
Verifying Rust type-2 support is a stop condition before completing R04.

Actual root config.go and docs/p04/configuration.md supersede older README
claims of absent config/keyring loaders. Port supported grammar, defaults,
argument remainder, opt-in environment behavior and precedence. The AST
inventory and reference archive include these behaviors.

## Dependency Feasibility

Registry metadata in observations.json proves published versions, licenses and
declared MSRVs only. It is not Cargo.lock, a native-code audit, vulnerability
check, full compatibility test or crypto review.

| Candidate | Observed Version | Decision |
| --- | --- | --- |
| tokio | 1.53.1 | Async runtime, only required features |
| bytes | 1.12.1 | Owned immutable payloads |
| thiserror | 2.0.20 | Concrete error implementation |
| aes / aes-gcm / cbc | 0.9.3 / 0.11.1 / 0.2.1 | Candidate primitives; protocol vectors required |
| hmac / sha2 | 0.13.0 / 0.11.0 | Not a complete RFC 8009 implementation |
| zeroize / secrecy | 1.9.0 / 0.10.3 | Secret lifetime/redaction |
| getrandom | 0.4.3 | OS randomness |
| serde / serde_json / base64 | 1.0.229 / 1.0.151 / 0.23.1 | Tool/test payload formats |
| tracing | 0.1.44 | Optional events, no global subscriber |
| kerberos_crypto | 0.3.7 | Not selected: AGPL-3.0; RFC 8009 coverage unverified |

Candidates other than the unselected kerberos_crypto declare MSRVs below 1.98.0
and MIT/Apache license identities. R01 must inspect complete features,
target-dependent transitive graphs, native build scripts and advisories before
adoption. No native OpenSSL/librados, Go FFI or native crypto fallback. Resolve
RFC 8009 with maintained reviewed code and compatible licensing, not handwritten
primitives or silently dropped type-2 support.

## Reference and Cluster

Use the archive in reference/go-baseline.json; a clone at original HEAD omits
captured work. Ceph source v20.2.0 and qualification v20.2.4 pins are copied
unchanged, with independent commit/image-index availability observations.

Observed Docker 29.4.0: 10 CPUs, 16819609600 bytes VM memory, approximately
96 GiB host free space. Native fixtures ran in temporary containers. This does
not validate privileged OSD/volume setup, multi-host domains, four runtime
targets or soak behavior. Prefer the later P06-P11 Docker topology over the
destructive P00 cephadm host runner unless separately provisioned/authorized.
Give Rust containers/networks/volumes/reports distinct names from Go resources.

## License and Provenance

Preserve LGPL-2.1-only and THIRD_PARTY_NOTICES. Existing Go owner approval and
P01 sidecar reviews are inherited facts, not new Rust approvals. All six P01
sidecars record redistribution approved by Oliver Tuschhoff and no secrets;
the original bytes and hashes were preserved and checked.

The private archive captures the supplied source under the owner's porting
request. Reference import is not completed Rust translation or permission to
relicense. Native/generated artifacts and Ceph documentation can have distinct
terms including LGPL and CC-BY-SA. File-level provenance review is required
before direct translation and release distribution. An accountable reviewer
must address Rust static linking, replacement/relinking and consumer duties.
R00 grants no waiver, clean-room claim, legal certification or signature.