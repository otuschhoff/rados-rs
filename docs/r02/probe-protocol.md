# R02 Bounded Differential Probe

R02 adds one isolated JSON Lines case,
`r02/versioned-envelope-newer-compatible`. It compares the current private Rust
wire codec with the pinned Go oracle. It does not expose a production probe API
or change the R01 schema or protocol.

The fixed nine-byte input is `03 01 03 00 00 00 01 02 ff`: `struct_v` 3,
`struct_compat` 1, and a three-byte payload. A local version 2 decoder accepts
the newer struct because compatibility permits it, reads known little-endian
`u16` value 513, retains the trailing unknown byte `ff`, and re-encodes the
complete envelope exactly. Input and output are limited to 9 bytes. Requests
and results are limited to one strict 4096-byte JSON record with unknown fields
rejected.

The Rust probe includes the exact current `src/wire/codec.rs` as a private
module. The Go adapter is copied only into a temporary clone of the pinned Go
module so it can import `internal/encoding`; the supplied checkout is never
modified. The controller verifies Go commit
`c8bb148a1379b51ef87256c27f366a05f8da4dc4`, tree
`c5039b6b50a05b942a902f70dc2fcb090463e8c7`, and Go 1.26.8. It runs adapter
negative tests before the differential case and bounds both probe captures
through FIFOs before writing more than 4097 bytes to disk.

The report schema is
[`integration/r02/report.schema.json`](../../integration/r02/report.schema.json).
The verifier bounds report reads, validates real UTC calendar seconds 00-59,
requires the exact sibling Rust probe, and replays its canonical request. It
binds the fixed input, Rust source digest and Git identity, Cargo lockfile,
Rust/Go compiler and target, Go revision/tree/lockfile, adapter, controller,
schema, commands, outputs, and timestamp. The controller requires both source
repositories to be clean committed trees before producing evidence. The source digest uses a fixed
path/length-framed manifest covering root build policy plus `src`, R02 docs,
examples, fuzz inputs, native fixtures, R02 integration files, and R02 tools.
Generated reports and build output are outside that manifest, avoiding a
self-reference cycle.

Build and run the opt-in bridge explicitly:

```sh
cargo build -p rados-r02-tools --bins --locked
GOTOOLCHAIN=go1.26.8 integration/r02/reproduce.sh \
  --go-root ../rados-go \
  --rust-probe target/debug/rados-r02-probe \
  --verifier target/debug/rados-r02-verify \
  --report target/r02/report.json
```

Ordinary workspace tests use no Go checkout or Go process.