# R06 Dependency Review

Review date: 2026-09-18. Production remains pinned to Rust 1.98.0 and adds no
new runtime dependency for placement. Exact fixed-point CRUSH logarithms use the
already-pinned `base64 0.22.1` package to decode the embedded Ceph lookup tables.
No native library, floating-point math or generic hash replacement is used.

The unpublished `rados-r06-tools` crate uses versions already in the workspace
lockfile: `base64 0.22.1`, `crc32c 0.6.8`, `serde 1.0.229`, `serde_json 1.0.151`
and `sha2 0.11.0`. It source-includes crate-private production placement/map
modules solely for deterministic qualification. The pinned Go adapter and
content-bound erasure-placement correction patch are applied to a disposable
clone and do not modify the source oracle.

Fuzz qualification uses `nightly-2026-09-01`, `cargo-fuzz 0.13.2` and
`libfuzzer-sys 0.4.13`; these are development-only and excluded from the Cargo
workspace/package. The validation matrix requires `cargo audit --deny warnings`
and `cargo deny check` against the final lockfile.

Ceph-derived P05 fixtures use the baseline image digest recorded by their
manifests. P10 fixtures use
`quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa`.
All fixture manifests retain pending human redistribution review. R06
qualification assets are excluded from published Cargo package contents.
