# P00 Evidence, Scope and Oracle

Status: **P00 complete**.

P00 deliberately contains no client implementation. It freezes the evidence,
scope, reproducibility contract and independent oracle needed by later phases.

## Decisions

| Decision | Selected value |
| --- | --- |
| Go module path | `github.com/otuschhoff/go-librados` (module initialization is P01) |
| Public package | `rados` |
| Source baseline | Ceph `v20.2.0`, commit `69f84cc2651aa259a15bc192ddaabd3baba07489` |
| Qualification server | Ceph `v20.2.4`, commit `7f793731f1b39eb4f465e960113d2363c311b964` |
| Go support policy | Minimum Go 1.26.x and latest stable Go 1.27.x; CI pins patches from `evidence.json` |
| Client targets | Linux/macOS, amd64/arm64 |
| Server host | Disposable Linux host/VM, amd64 or arm64 |
| Transport | msgr2.1 secure required by default; CRC only when explicitly enabled |
| Authentication | CephX; no production no-auth mode |
| Replicated profile | size 3, min_size 2, 32 PGs, straw2 rule, OSD failure domain |
| EC profile | `k=2 m=1`, jerasure Reed-Solomon, OSD failure domain, 32 PGs, overwrite enabled |

## Artifacts

- `evidence.json`: immutable source, image and toolchain identities with hashes.
- `api-inventory.csv`: every extracted exported C function and public C++
  operation, including overloads, with Go disposition and owning phase.
- `compatibility.md`: finite initial matrix and unsupported features.
- `protocol-sources.md`: source index and unresolved questions with owners.
- `licensing.md`: provenance policy and the pre-implementation license decision.
- `threat-model.md`: trust boundaries, assets, threats and required controls.
- `task-handoff.md`: completed work, actual checks, blockers and next task.
- `tasks.md`: scoped P00 task packets, acceptance and actual status.
- `integration/p00`: destructive runner, native oracle and report schema.
- `testdata/manifest.schema.json`: provenance contract for future byte fixtures.

## Reproduction

`make verify-p00` verifies manifest hashes, exact inventory counts, complete
dispositions, fixture schema, script syntax and source pin consistency. To
regenerate the inventory, create a sparse checkout at the baseline commit:

```sh
git clone --filter=blob:none --no-checkout https://github.com/ceph/ceph.git /tmp/go-librados-ceph
git -C /tmp/go-librados-ceph sparse-checkout init --no-cone
git -C /tmp/go-librados-ceph sparse-checkout set src/include/rados/librados.h src/include/rados/librados.hpp COPYING
git -C /tmp/go-librados-ceph checkout 69f84cc2651aa259a15bc192ddaabd3baba07489
make inventory
make verify-p00
```

The live runner passed on an isolated Linux arm64 VM against Ceph 20.2.4. Its
sanitized report is
[`integration/reports/p00-aea2e269-39df-4476-9e55-b6b3de3b67c0.json`](../../integration/reports/p00-aea2e269-39df-4476-9e55-b6b3de3b67c0.json).
The native oracle has also been built successfully for both `linux/amd64` and
`linux/arm64` from the checksum-pinned `librados-devel` and
`libradospp-devel` RPMs recorded in `evidence.json`.