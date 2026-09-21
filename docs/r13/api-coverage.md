# R13 API Coverage

Status: **frozen for the R13 v1 audit**. The 905-row parity ledger
[`docs/r00/parity-ledger.csv`](../r00/parity-ledger.csv) carries an
allow-list disposition on every row. The R13 audit closed the previously
open `planned-not-implemented` bucket: every one of the 121 rows that
was still deferred at the start of the R13 window has been reclassified
against the owning phase's on-disk implementation status.

## Final global distribution

Verified via `ruby -r csv` against the ledger; the totals below are the
exact `status` column counts of the 905 non-header rows.

| Status | Rows | Notes |
| --- | --- | --- |
| `implemented-r02` | 204 | R02 bounded types and API contract. |
| `implemented-r05` | 34 | R05 `Config`, `Client`, monitor session, pool discovery, and pool identity accessors (`Pool.ID`, `Pool.Name`). |
| `implemented-r07` | 24 | R07 read-only object surface including `Pool.Object` factory. |
| `implemented-r08` | 63 | R08 mutation surface. |
| `implemented-r09` | 205 | R09 metadata / compound / enumeration; includes the seven iterator+cursor R08-family entries owned by the R09 cursor implementation. |
| `implemented-r10` | 66 | R10 class / lock / watch. |
| `implemented-r11` | 75 | R11 snapshots and specialized I/O; includes the eight R08-family `ObjectRef.Checksum` / `ObjectRef.CopyFrom*` / `ObjectRef.SetAllocationHint` / `ObjectRef.SparseRead` / `ObjectRef.WriteSame` / `Pool.WithReadSnapshot` / `Pool.WithWriteSnapshot` symbols owned by the R11 surface. |
| `implemented-r12` | 57 | R12 administration and command surface. |
| `adapted-r12` | 40 | Preserved semantics with Rust-native ergonomics: the seven `PoolAsyncCompletion` symbols folded into `OperationOptions`/`Result`, and the four OMAP-keys read-op builders folded into the R09 OMAP get-vals surface. |
| `intentional-omission-r12` | 118 | Native-only C entry points and C++ handle importers with no distributed-client behaviour, deprecated completion-safe aliases, legacy AUID/full-try APIs, cmpxattr and OMAP-cmp read/write-op builders, hash-position diagnostics, alloc-hint2 variants, `list_snaps` read-op, inconsistent-snapset dumps, and the R13 build-tag P12 diagnostic surface. |
| `deferred-r12` | 19 | Cache-tier, monitor-log, service-status, and hit-set APIs. Future R14 work, explicitly outside the R13 v1 exit gate. |
| `planned-not-implemented` | 0 | No row is awaiting a disposition. |
| **total** | **905** | |

## R13 audit closure summary

The 121 previously `planned-not-implemented` rows were reclassified as
follows, each per the owning phase's on-disk implementation status
rather than an aspirational plan:

| Owning phase | Previously planned | Reclassified as | Count |
| --- | --- | --- | --- |
| R00 | `IoCtx::from_rados_ioctx_t`, `Rados::from_rados_t` | `intentional-omission-r12` (no C handle in the distributed client) | 2 |
| R05 | Native/C and C++ pool-map discovery + all Go P04 (`Client.*`, `Config.*`, `New`, `Default/Load/Parse Config`, `LoadKeyring`) | `implemented-r05` | 32 |
| R05 | `rados_get_min_compatible_*`, `rados_ping_monitor`, `rados_wait_for_latest_osdmap` and their C++ mirrors | `intentional-omission-r12` (no distinct v1 behaviour) | 7 |
| R06 | `IoCtx::get_object_hash_position2`, `IoCtx::get_object_pg_hash_position2`, `PlacementGroup::parse` | `intentional-omission-r12` (public hash-position diagnostics not v1-required) | 3 |
| R08 | Seven `PoolAsyncCompletion` symbols + `Rados::pool_async_create_completion` | `adapted-r12` (subsumed by `OperationOptions`/`Result`) | 7 |
| R08 | `go:Pool.Object` | `implemented-r07` | 1 |
| R08 | `go:Pool.ID`, `go:Pool.Name` | `implemented-r05` | 2 |
| R08 | Iterator/cursor Go family (`CompareObjectCursors`, `ObjectCursor.IsEnd`, `Pool.BeginObjectCursor`, `Pool.EndObjectCursor`, `Pool.ListObjects`, `Pool.ListObjectsRange`, `Pool.SplitCursor`) | `implemented-r09` | 7 |
| R08 | Snapshot/specialized Go family (`ObjectRef.Checksum`, `ObjectRef.CopyFrom`, `ObjectRef.CopyFrom2`, `ObjectRef.SetAllocationHint`, `ObjectRef.SparseRead`, `ObjectRef.WriteSame`, `Pool.WithReadSnapshot`, `Pool.WithWriteSnapshot`) | `implemented-r11` | 8 |
| R09 | Four OMAP-keys read-op builders (`rados_read_op_omap_get_keys2`, `IoCtx::omap_get_keys`, `IoCtx::omap_get_keys2`, `ObjectReadOperation::omap_get_keys2`) | `adapted-r12` (folded into the R09 OMAP get-vals surface) | 4 |
| R09 | Remaining R09-owned read-op/write-op cmpxattr/cmpext/omap-cmp builders, NObjectIterator hash-position/set-filter, `ObjectCursor` string round-trip, tier/dirty/manifest/mtime/set_redirect/set_chunk/size/is_dirty | `intentional-omission-r12` (not exposed by the certified P08 Go contract) | 29 |
| R11 | `rados_set_alloc_hint2`/`rados_write_op_set_alloc_hint2` and their C++ mirrors, `IoCtx::list_snaps`, `IoCtx::mapext`, `IoCtx::pool_required_alignment`, `IoCtx::pool_requires_alignment`, `ObjectReadOperation::list_snaps`, `ObjectWriteOperation::set_alloc_hint2`, `Rados::get_inconsistent_snapsets` | `intentional-omission-r12` (not exposed by the certified P10 Go contract) | 10 |
| R13 | `NewP12DiagnosticClient`, `P12DiagnosticObserver`, `P12SessionDiagnostic` and its seven fields | `intentional-omission-r12` (build-tag-only Go P12 diagnostic surface; no live behaviour in the shipped Rust crate) | 9 |
| **total** | | | **121** |

The evidence for each reclassification is the corresponding source file
inside the shipped crate (`src/client.rs`, `src/config.rs`,
`src/operation.rs`, `src/maps/pool.rs`, and the R05..R11 owning modules)
or the owning phase's `docs/rNN/STATUS.md` for the omissions. Semantic
IDs are stable across the reclassification: no row was added, removed,
or renamed; only the trailing `status` column changed.

## What R13 does not do

- R13 does not authorise a release tag, crate publish, or GitHub Release.
- R13 does not promote `deferred-r12` rows. Those 19 rows remain
  explicit future R14 work outside the R13 v1 exit gate.
- R13 does not introduce a new ledger column: doing so would create a
  self-reference where R13 evidence depends on data that R13 itself
  produced.
