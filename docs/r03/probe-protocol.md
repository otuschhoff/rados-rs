# R03 Bounded Differential Probe

R03 defines `r03/messenger-transcript-v1`, a fixed six-case JSON/JSON-Lines
comparison between private Rust messenger code and the pinned Go oracle. Cases
cover banner, four-segment CRC frame, one-record secure frame, ACK control,
message frame and the deterministic `disconnected -> ready -> stopped` session
transition.

The request is one strict JSON value limited to 16,384 bytes. It names both
implementations, all ordered case IDs, fixture paths/hashes and fixed bounds.
Each probe emits exactly six JSON Lines records, each at most 16,384 bytes.
Fixtures are at most 4,096 bytes and semantic output is at most 8,192 bytes.
Unknown, stale, extra and oversized requests fail.

The Go adapter is copied into a temporary clone because it imports Go `internal`
packages. The source checkout remains unchanged and must be clean at commit
`c8bb148a1379b51ef87256c27f366a05f8da4dc4`, tree
`c5039b6b50a05b942a902f70dc2fcb090463e8c7`, using Go 1.26.8. `GOENV`, `GOWORK`,
`GOFLAGS` and `GOTOOLCHAIN` are neutralized for every Go inspection and run.

The controller requires clean committed Rust and Go trees. It builds both Rust
tools into a fresh target with a fresh `CARGO_HOME`, neutralizing compiler,
wrapper and flag overrides, then copies only the resulting binaries to the
required `target/r03` paths. Build, adapter tests and both probes have bounded
captures and five-minute process alarms. The verifier bounds its report read,
binds source/tree/lockfile/compiler/target, fixture and sidecar hashes, adapter,
schema, controller, commands and canonical output, then replays the reported
Rust probe with a 30-second deadline and bounded concurrent stdout drain.

Verifier regressions reject stale fixture bytes, altered sidecar provenance,
substituted executables, malformed/oversized reports and partial-output hanging
probes. A child-process test proves poisoned inherited Go settings are ignored.
Offline verifier tests use hermetic report data and do not require the pinned Go
checkout.

Run the opt-in bridge only from a source repository checkout and only against
clean committed trees. The unpublished workspace tool crate is not part of the
`rados-rs` crate package:

```sh
integration/r03/reproduce.sh \
  --go-root ../rados-go \
  --rust-probe target/r03/rados-r03-probe \
  --verifier target/r03/rados-r03-verify \
  --report target/r03/report.json
```

The schema is
[`integration/r03/report.schema.json`](../../integration/r03/report.schema.json).
Absolute invocation paths are part of the anti-substitution evidence and are
verified in place. Reproduce the report in another checkout rather than moving
an existing report between paths.
The bridge proves deterministic codec/transcript parity only. It performs no
live authentication or cluster I/O.
