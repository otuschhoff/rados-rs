# R01 Bounded Probe Protocol

R01 defines one additive, test-only JSON Lines case:
`p01/entity-name-client-1`. It round-trips the unchanged native
`entity_name_t` fixture through explicit `rust` and `go` runners. This is an
evidence bridge, not a production language bridge or a general protocol API.

The request is exactly one JSON object followed by a newline and is limited to
4096 bytes. Its fixed operation is `entity-name-round-trip`; fixture input and
output are each limited to 9 bytes. The fixture path and SHA-256 are allowlisted.
Unknown fields, extra JSON values, changed identities and changed bounds fail.

Results carry schema/case/operation/implementation identities, decoded entity
type, the signed 64-bit entity number as a decimal string, base64 encoded output,
output SHA-256 and canonical status. The controller captures at most 4097 bytes
from each probe through a pipe and rejects results over 4096 bytes. The report schema is
[`integration/r01/report.schema.json`](../../integration/r01/report.schema.json).
The Rust verifier additionally requires the pinned fixture, Go commit/tree,
successful and matching Rust/Go results, source/build/tool hashes, compiler and
target identities, commands and zero exit codes.

The verifier recomputes the fixture and provenance-manifest hashes, the Cargo
lockfile, controller, Go adapter directory, Rust probe executable, canonical
JSONL outputs and a path/length-framed digest of the complete R01 candidate
source set. It checks the local Rust Git revision/tree and compiler/target, the
pinned Go revision/tree/lockfile and current pinned Go compiler/target, exact
empty feature sets, the Ceph image digest and the full controller invocation.
It receives the candidate root explicitly, bounds report reads, requires the
reported probe to be the sibling artifact built with the verifier, and replays
that probe with the canonical request. Hash-shaped placeholders therefore fail
verification.

The controller requires explicit Go root, Rust probe, verifier and report paths.
It validates both Rust executables before inspecting or cloning Go, and never
falls back to Go. It checks Go commit `c8bb148a1379b51ef87256c27f366a05f8da4dc4`
and tree `c5039b6b50a05b942a902f70dc2fcb090463e8c7`, clones that checkout into a
temporary directory, and copies the Go helper under the cloned module so Go's
`internal` boundary remains intact. It runs the adapter's negative tests before
the fixture case. The supplied Go checkout is not modified.

Run the opt-in bridge after building the test-only binaries:

```sh
cargo build -p rados-r01-tools --bins --locked
GOTOOLCHAIN=go1.26.8 integration/r01/reproduce.sh \
  --go-root ../rados-go \
  --rust-probe target/debug/rados-r01-probe \
  --verifier target/debug/rados-r01-verify \
  --report target/r01/report.json
```

Ordinary `cargo test` uses repository fixtures only and needs no Go checkout,
Ceph installation, Docker or network.