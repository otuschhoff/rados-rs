# R02 Dependency Review

Review date: 2026-09-17. Toolchain/MSRV: Rust 1.98.0. Both lockfiles use
version 4 and all direct versions are exact pins.

## Production

The shipped `rados-rs` library has two dependencies:

| Crate | Version | License | Purpose |
| --- | --- | --- | --- |
| `crc32c` | 0.6.8 | Apache-2.0 OR MIT | CRC-32C with software fallback and hardware acceleration |
| `zeroize` | 1.8.2 | Apache-2.0 OR MIT | Erase owned authentication-key buffers on drop |

Its build script depends on `rustc_version 0.4.1` and `semver 1.0.28`. It
generates Rust lookup tables in `OUT_DIR` and selects an AArch64 cfg from the
compiler version; it does not invoke a C/C++ compiler and declares no Cargo
`links` value. The crate contains audited third-party `unsafe` in x86_64 and
AArch64 intrinsic implementations. Runtime feature detection selects x86_64
SSE4.2; unsupported targets use safe software code. Exact Ceph vectors,
incremental chaining, empty input and corruption tests cover the wrapper's
complemented seed/finalization convention.

`zeroize` is built with only its `alloc` feature. `SecretKey` stores a
`Zeroizing<Vec<u8>>`, so every cloned owned allocation is erased on drop. No
derive macro or platform-specific implementation is enabled.

## Tooling And Fuzzing

The unpublished R01/R02 evidence tools retain exact pins for `base64 0.23.1`,
`serde 1.0.229`, `serde_json 1.0.151` and `sha2 0.11.0`. Their feature choices
remain as reviewed in `docs/r01/dependencies.md`.

The workspace-excluded fuzz package pins `libfuzzer-sys 0.4.13` and
`crc32c 0.6.8`. `libfuzzer-sys` and its `cc` dependency compile and link LLVM
libFuzzer instrumentation, but neither is reachable from the production or
ordinary workspace graph. Fuzzing uses pinned nightly `nightly-2026-09-01` and
`cargo-fuzz 0.13.2`; no nightly feature enters shipped code.

`cargo metadata --locked` and `cargo tree --workspace -e features --locked`
show no direct production dependencies beyond `crc32c` and `zeroize`; only
`crc32c` adds the two build dependencies described above. The accepted licenses
remain Apache-2.0, MIT, Unicode-3.0 and Unlicense in the Rust graphs. `cargo
audit` and all `cargo deny` policy groups remain release gates; future advisory
data is not pre-approved.