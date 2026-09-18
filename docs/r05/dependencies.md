# R05 Dependency Review

Review date: 2026-09-17. Rust is pinned by `rust-toolchain.toml` to 1.98.0. The
Go oracle module declares Go 1.26.8, and reproduction selects exactly that
toolchain with `GOTOOLCHAIN=go1.26.8` while disabling `GOENV`, `GOWORK`, and
ambient `GOFLAGS`.

Production monitor discovery adds exact `hickory-resolver 0.26.3` with the
`system-config` and `tokio` features for asynchronous A, AAAA, and SRV lookup.
The lockfile and `RUST_THIRD_PARTY_NOTICES` include its transitive closure.
`cargo audit` and `cargo deny check` are required by the R05 validation matrix.

The unpublished `rados-r05-tools` crate adds no dependency beyond versions
already present in the workspace lockfile: `rados-rs`, `serde 1.0.229`,
`serde_json 1.0.151`, and `sha2 0.11.0`. It imports the production map, wire,
and address modules by source path because those APIs are crate-private; config
cases call the public production `rados::Config` API. A small qualification-only
CRC32C adapter matches the already-tested production wrapper convention and
does not alter shipped behavior.

The Go adapter is copied into a temporary clone of the clean pinned oracle and
imports its public root package plus `internal/maps`; it is not added to or run
from the source checkout. The bridge binds `go.mod`, `go.sum`, configuration,
monitor, encoding, protocol, and map source sets, as well as the copied adapter
and resulting executable.

This phase makes no fixture redistribution approval claim. P04 manifests still
mark redistribution review as pending.