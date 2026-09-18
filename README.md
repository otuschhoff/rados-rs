# rados-rs

A native Rust Ceph RADOS client in phased development, ported from the pinned
pure-Go reference. R00 reference capture, the R01 workspace/evidence bridge,
R02 API contracts and bounded wire types are complete. R03 private messenger
codecs, session state and committed-tree differential verification are complete;
R04 CephX authentication and secure monitor sessions, R05 configuration/maps,
R06 exact placement, and R07 read-only object I/O are complete.

The client will use Tokio and Rust protocol/crypto implementations without a
Go runtime, native librados, FFI bridge, subprocess, gateway or proxy in the
shipped path. Go and native Ceph are isolated test oracles only.

The repository is private and has an independent main branch, CI and release
lifecycle. Ordinary Rust tests work without Go, network access or a sibling
checkout. The current library exposes locally validated ownership, error,
options and lifecycle contracts plus private bounded wire and messenger
machinery. The public client supports authenticated monitor discovery and
bounded read/stat operations against the pinned replicated profile.

License identity: LGPL-2.1-only, subject to preserved upstream notices and
file-level provenance. No Rust distribution or release approval is claimed.

## Start Here

- [Rust port spec](docs/RUST_PORT_SPEC.md)
- [R00 results, open gates and R01 handoff](docs/r00/STATUS.md)
- [R01 results and R02 handoff](docs/r01/STATUS.md)
- [R01 probe protocol](docs/r01/probe-protocol.md)
- [R01 dependency review](docs/r01/dependencies.md)
- [R02 API contract](docs/r02/api-contract.md)
- [R02 wire formats](docs/r02/wire-format.md)
- [R02 fixture matrix](docs/r02/fixture-matrix.md)
- [R02 differential probe protocol](docs/r02/probe-protocol.md)
- [R02 dependency review](docs/r02/dependencies.md)
- [R03 execution status](docs/r03/STATUS.md)
- [R04 execution status](docs/r04/STATUS.md)
- [R05 execution status](docs/r05/STATUS.md)
- [R06 execution status](docs/r06/STATUS.md)
- [R07 read-only object status](docs/r07/STATUS.md)
- [R02 execution and R03 handoff](docs/r02/STATUS.md)
- [R03 architecture](docs/r03/architecture.md)
- [R03 wire formats](docs/r03/wire-format.md)
- [R03 session contract](docs/r03/session-contract.md)
- [R03 fixture matrix](docs/r03/fixture-matrix.md)
- [R03 differential probe protocol](docs/r03/probe-protocol.md)
- [R03 dependency review](docs/r03/dependencies.md)
- [R03 execution and R04 handoff](docs/r03/STATUS.md)
- [R04 deterministic CephX core](docs/r04/cephx-core.md)
- [R04 differential probe protocol](docs/r04/probe-protocol.md)
- [R04 dependency review](docs/r04/dependencies.md)
- [R04 execution and R05 handoff](docs/r04/STATUS.md)
- [Repository decision](docs/decisions/0001-separate-repository.md)
- [Technical/dependency decisions](docs/r00/decisions.md)
- [905-row parity ledger](docs/r00/parity-ledger.csv)
- [Reference verification and import workflow](reference/README.md)

R00's offline development-evidence checks use the pinned Go reference toolchain:

```sh
GO111MODULE=off go test ./tools/r00 -count=1
GO111MODULE=off go run ./tools/r00/main.go -root . -verify
```

These development tools do not change the native-Rust production boundary.
Ordinary Rust checks require no Go, Ceph libraries, Docker or network:

```sh
cargo test --workspace --locked
```

The opt-in differential bridges and their explicit Go checkout are documented
in the R01, R02, R03 and R04 probe protocols.