# R06 Evidence

## Deterministic bridge

Use a clean detached Go oracle at commit
`c8bb148a1379b51ef87256c27f366a05f8da4dc4`, tree
`c5039b6b50a05b942a902f70dc2fcb090463e8c7`:

```sh
integration/r06/reproduce.sh \
  --go-root /tmp/rados-r05-go-oracle \
  --report target/r06/report.json
```

The controller requires Rust 1.98.0 and Go 1.26.8. It executes eleven fixed
cases through the production Rust and adapted pinned-Go implementations: P05
direct baseline and OSD-out; four P05 object mappings (baseline, PG-count
transition, OSD-out and upmap); P10 erasure baseline and OSD-out; and three P10
complete object mappings (baseline, OSD-out and primary affinity). These consume
1,920 native rows.

The report binds 14 fixtures and their sidecar manifests, source closures,
lockfiles, compiler/target identities, adapter and correction patch, schema,
controller, commands, stdout and executables. Verification checks the exact
reported binary hashes and replays those executables under time/output bounds.
It also clean-builds Rust and Go from the bound sources and requires both fresh
builds to reproduce the report's canonical records. This proves source-to-result
binding without claiming byte-reproducible platform linker output. The generated
report is local evidence under `target/r06` and is not committed.

The content-bound correction patch is applied only to a disposable clone of the
frozen Go oracle. It repairs known Go EC handling of sentinel slots, primary
affinity and duplicate temporary OSD slots for qualification; native Ceph 20.2.4
fixtures are authoritative for those cases.

The latest pre-commit report passed with SHA-256
`9e145cea8c5b11cb191f85861be0e01e3867b2ea1c1614518a4b9fc287bcea21`.
Regenerate it after any bound source, fixture, manifest, adapter, schema or
controller change.

## Native fixtures

P05 contributes 1,024 rows: 512 direct mappings and 512 complete
object-to-PG/acting mappings over baseline, PG-count, OSD-out and upmap
transitions. P10 contributes 512 direct erasure `CHOOSE_INDEP` mappings plus
384 complete object placements over baseline, OSD-out and primary-affinity
states. These include retained missing-shard sentinels, stable shard slots and
native duplicate acting OSD slots.

Every fixture has a schema-compatible provenance sidecar recording Ceph 20.2.4
commit `7f793731f1b39eb4f465e960113d2363c311b964`, the generating command and a
content-addressed image. Redistribution review remains pending.

## Sanitizer campaigns

Run all four source-bound campaigns with the pinned nightly:

```sh
integration/r06/fuzz-reproduce.sh docs/r06/fuzz-campaign.json
```

`r06_crush_decode`, `r06_crush_place`, `r06_object_mapping` and
`r06_osdmap_place_object` each completed 2,000 executions. The committed report
and bounded logs bind the exact source closure, seed corpus, executed binaries,
commands and observed counters. `integration/r06/verify-fuzz.rb` and
`verify-fuzz-tests.sh` reject structural, source, corpus and binary tampering.
Coverage counters are observations, not an exhaustive-coverage claim.

The current campaign report SHA-256 is
`143c78d9c4c90682ff2117f59584ca666c40183133abd145ee3e7684eac3e00b`.
