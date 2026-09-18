# R05 Evidence

## Live qualification

Run the digest-pinned live harness with Docker available:

```sh
integration/r05/live-reproduce.sh
```

It builds the Rust 1.98.0 Linux probe in the digest-pinned
`rust@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922`, starts three
Ceph v20.2.4 monitors from the fixed image digest, configures all three v2 seeds,
and drives one persistent public `Client` through initial pool discovery,
disposable pool creation/deletion, one-monitor loss with two-monitor quorum, and a
post-failover map update. A separate public-client invocation must reject a
wrong configured FSID. Every command/output and the entire harness are bounded;
the report is emitted only after explicit container/network cleanup.

`integration/r05/verify-live.rb` enforces the exact source artifact set and
hashes, image and toolchain identities, retained probe executable hash, cluster
topology, scenario key set, observed pool transitions, wrong-FSID failure, and cleanup counts.
`integration/r05/verify-live-tests.sh` checks reversed timestamps, source-set,
source-hash, probe-hash, toolchain-set, and scenario-set tampering against a
successful report.

The 2026-09-18 run passed and produced
`docs/r05/live-integration-report.json`. The report records a three-monitor
quorum, initial pool discovery, pool creation and deletion through OSDMap
  updates, one-monitor loss with quorum retained, a post-loss pool update,
wrong-FSID rejection, and zero residual containers or networks. The strict
verifier and its tamper suite pass against that report.

## Sanitizer fuzz campaigns

Run the complete campaign with the pinned nightly:

```sh
integration/r05/fuzz-reproduce.sh
```

All seven targets completed 2,000 executions without a crash, sanitizer
finding, timeout, or non-zero exit. They cover configuration parsing, MonMap,
full OSDMap, incremental OSDMap, and the corresponding monitor message
envelopes. `docs/r05/fuzz-campaign.json` binds the toolchain, complete source
closure, each retained executed binary, exact fixed-seed command, pristine seed
manifest, bounded raw log, and observed libFuzzer counters.
`integration/r05/verify-fuzz.rb` revalidates those bindings and rejects
oversized or structurally extended reports. Evolved corpus contents are
intentionally not treated as deterministic source evidence.

## Deterministic bridge

Run the bridge from the Rust checkout with a clean detached Go oracle at commit
`c8bb148a1379b51ef87256c27f366a05f8da4dc4`, whose required tree is
`c5039b6b50a05b942a902f70dc2fcb090463e8c7`:

```sh
integration/r05/reproduce.sh \
  --go-root /tmp/rados-r05-go-oracle \
  --report target/r05/report.json
```

The controller builds both probes into fixed absolute `target/r05` paths,
executes a strict single-JSON request and exactly fourteen newline-delimited
results, and then invokes the Rust verifier. Build/test/probe processes have
deadlines; logs, inputs, outputs, individual records, record counts, and report
size are bounded. The report schema is `integration/r05/report.schema.json`.

The verifier rejects unknown report fields, altered case order or membership,
stale/divergent records, fixture or manifest changes, source-set changes,
wrong Go commit/tree, adapter/schema/controller changes, substituted binaries,
and non-reproducible Rust output. It binds both compiler/target identities,
source and lockfile hashes, probe commands, executable hashes, and canonical
stdout hashes.

The generated deterministic report is local evidence under `target/r05`; it is
deliberately not committed. Reproduce it after any bound source, fixture,
schema, adapter, or controller change. Live and fuzz evidence are recorded
separately because they have different environments and reproducibility bounds.