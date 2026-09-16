# Knowledge and Evidence Index

The complete path/hash index is [go-baseline.json](../../reference/go-baseline.json).
Selected copies are in [imports.json](../../reference/imports.json); exported
declarations/lines in [go-public-api.json](../../reference/go-public-api.json);
native/Go coverage in [parity-ledger.csv](parity-ledger.csv). Paths below refer
to the archived Go module, not unpublished Rust files.

| Phase | Go Knowledge | Oracle/Test Evidence |
| --- | --- | --- |
| R00-R02 | docs/p00, docs/p01, internal/encoding and protocol | Local P01 vectors/sidecars; integration/p01; tools/p01-verify |
| R03 | internal/msgr frame/secure/session/transport/control | P02 native upstream frames, fuzz and transport tests |
| R04 | internal/cephx; docs/p03 | P03 type-1/type-2 vectors and monitor runner |
| R05 | config.go, internal/mon/maps; docs/p04 | Config tests and full/incremental map fixtures |
| R06 | internal/crush, maps/placement.go | P05/P10 complete object-to-PG/primary corpora |
| R07-R08 | internal/osd/objecter, object/client/error contracts | P06 reads, P07 unknown-outcome/flush, native differential drivers |
| R09 | metadata.go, osd/objecter enumeration | P08 atomicity, namespaces and contention |
| R10 | coordination.go, osd lock/watch, objecter watch | P09 persistent mixed-client tests |
| R11 | snapshot.go, osd sparse/checksum/copy | P10 snapshots, EC and specialized operations |
| R12 | admin.go, internal/mgr, command/inconsistent | P11 admin, caps and manager failure |
| R13 | docs/p12, internal/p12*contract, tools/p12*, integration/p12 | Historical Go evidence only; fresh Rust reports required |

## Transfer Dispositions

- Copy unchanged: P01 bytes/sidecars, P00 native driver, schemas, notices and
  selected reference files, with original path/hash and destination manifest.
- Adapt later: cluster runners, resource names, controller, fixed qualification
  contracts and report binding. Preserve safety and explicit runner selection.
- Translate in owning phases: Rust probes/tests, language-specific compiler/API
  checks and production behavior after its provenance review.
- Retain in pinned Go module: working generators and helpers importing Go
  internal packages; native Ceph drivers. Opt-in differential jobs only.
- Never reuse as Rust passes: historical Go live/fuzz/qualification reports or
  review signatures. They stay labeled historical in archived evidence.

The complete compressed archive is frozen oracle source, not a second live Go
checkout committed as Rust implementation. Only 71 selected artifacts are
copied out for immediate reading/R00-R02 work. Later imports require explicit
reviewed updates, preserving fixture values and provenance.