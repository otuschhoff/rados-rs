# R01 Dependency Review

Review date: 2026-09-17. Toolchain/MSRV: Rust 1.98.0. The lockfile is version 4.

The production `rados-rs` library has no third-party dependencies. The
unpublished `rados-r01-tools` crate has four exact direct dependencies:

| Crate | Version | Enabled Features | Purpose |
| --- | --- | --- | --- |
| `base64` | 0.23.1 | `std` | Bounded JSON result bytes; default SIMD unsafe feature disabled |
| `serde` | 1.0.229 | `derive`, `std` | Strict test-only report structures |
| `serde_json` | 1.0.151 | `std` | JSON Lines and report parsing; default set disabled |
| `sha2` | 0.11.0 | none | Fixture, result and evidence SHA-256 |

`cargo metadata --locked` resolves 21 registry packages. Their declared license
expressions reduce to MIT, Apache-2.0, Unicode-3.0 and Unlicense combinations.
No package declares Cargo `links`, no C/C++ protocol or crypto dependency is
present, and all external crates are confined to the test-only tool graph.
Seven packages advertise custom-build targets (`libc`, `proc-macro2`, `quote`,
`serde`, `serde_core`, `serde_json`, `zmij`); none advertises native linkage.
`libc` is reached only through `sha2 -> cpufeatures` target detection.

The tooling crate includes the private entity-name source directly for the R01
probe. The package defines no probe feature or public probe module, and Cargo's
package allowlist excludes the tooling crate, controller, reports and schemas.

The exact feature graph is reviewed with `cargo tree --workspace -e features`.
`base64` deliberately excludes `simd-unsafe`; SHA-2 default OID/allocation
features are disabled. `deny.toml` rejects unknown registries/git sources,
wildcards, yanked crates, unapproved licenses and duplicate versions.

Observed locally with `cargo-audit 0.22.2`: no advisories in `Cargo.lock`.
CI pins `cargo-audit 0.22.2` and `cargo-deny 0.20.2`; policy remains a fresh CI
gate rather than a claim that future advisory data cannot change.

This review resolves R00-G02 for the R01 graph only. Future runtime, codec and
crypto dependencies require a new graph/feature/native-code/license review.
R00-G01 type-2 CephX crypto and R00-G03 distribution review remain open under
their owning phases; no package is publishable in R01.