# rados-rs

A planned native Rust Ceph RADOS client, ported from the pinned go-librados
reference. This repository is in R00: reference capture, evidence import and
scope definition. There is no Rust library implementation or Cargo package yet.

The client will use Tokio and Rust protocol/crypto implementations without a
Go runtime, native librados, FFI bridge, subprocess, gateway or proxy in the
shipped path. Go and native Ceph are isolated test oracles only.

The repository is private and has an independent main branch, CI and release
lifecycle. Ordinary future Rust tests must work without Go, network access or
a sibling checkout. R01 adds Cargo scaffolding; later phases implement the port.

License identity: LGPL-2.1-only, subject to preserved upstream notices and
file-level provenance. No Rust distribution or release approval is claimed.

## Start Here

- [Rust port spec](docs/RUST_PORT_SPEC.md)
- [R00 results, open gates and R01 handoff](docs/r00/STATUS.md)
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
R01 will introduce Cargo; ordinary Rust unit tests will not require Go.