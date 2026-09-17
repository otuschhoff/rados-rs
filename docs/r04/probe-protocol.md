# R04 Bounded Differential Probe

R04 defines `r04/cephx-core-v1`, a fixed eleven-case JSON/JSON-Lines comparison
between the private Rust CephX core and the pinned Go oracle. The ordered cases
cover type-1 and type-2 credential parsing, keyring parsing, initial payload and
server challenge, type-1 challenge request, the exact P03 type-2 challenge
vector, type-1 and type-2 authorizers, transcript signature, the exact P03
ticket fixture, and secure-mode downgrade plus expired-ticket lifecycle
semantics.

The request is one strict JSON value limited to 16,384 bytes. It names both
implementations, all ordered case IDs, fixture paths/hashes and fixed bounds.
Each probe emits exactly eleven JSON Lines records, each at most 16,384 bytes.
Fixtures are at most 16,384 bytes and semantic output is at most 8,192 bytes.
Unknown, stale, extra and oversized requests fail.

Synthetic keys, tickets, nonces, times and the Rust type-2 confounder are fixed.
Records expose only protocol metadata, lengths, booleans and SHA-256 digests.
The pinned Go type-2 encryption API owns its random confounder, so authorizer
parity compares deterministic base bytes, nonce, key type and payload length;
exact type-2 cryptographic evidence comes from the independent P03 challenge
vector. Output hashes cover canonical semantic JSON, never raw secrets.

The Go adapter is copied into a temporary clone because it imports Go `internal`
packages. The source checkout remains unchanged and must be clean at commit
`c8bb148a1379b51ef87256c27f366a05f8da4dc4`, tree
`c5039b6b50a05b942a902f70dc2fcb090463e8c7`, using Go 1.26.8. `GOENV`, `GOWORK`,
`GOFLAGS` and `GOTOOLCHAIN` are neutralized for every Go inspection and run.

The controller requires clean committed Rust and Go trees. It builds both Rust
tools into a fresh target with a fresh `CARGO_HOME`, neutralizing compiler,
wrapper and flag overrides, then copies only the resulting binaries to the
required `target/r04` paths. Build, adapter tests and both probes have bounded
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
integration/r04/reproduce.sh \
  --go-root ../rados-go \
  --rust-probe target/r04/rados-r04-probe \
  --verifier target/r04/rados-r04-verify \
  --report target/r04/report.json
```

The schema is
[`integration/r04/report.schema.json`](../../integration/r04/report.schema.json).
Absolute invocation paths are part of the anti-substitution evidence and are
verified in place. Reproduce the report in another checkout rather than moving
an existing report between paths.
The bridge proves deterministic CephX core parity only. It is evidence tooling,
not a completion claim or live authentication/cluster gate.
