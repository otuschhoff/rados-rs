# R06 Certified Placement Scope

R06 accepts only bounded CRUSH maps using RJenkins buckets and straw2 selection.
The decoder rejects choose-args data; placement rejects missing roots/devices,
class-shadow roots, graph cycles, excessive graph depth and more than 64 result
slots.

## Certified rules

Replicated rules have exactly one of these shapes:

- `TAKE -> CHOOSE_FIRSTN -> EMIT`
- `TAKE -> CHOOSELEAF_FIRSTN(type) -> EMIT`

The choose count is supplied by pool size. `CHOOSELEAF_FIRSTN` must name an
existing bucket type.

Erasure rules have exactly this shape:

- `SET_CHOOSELEAF_TRIES(5) -> SET_CHOOSE_TRIES(100) -> TAKE -> CHOOSE_INDEP -> EMIT`

`CHOOSELEAF_INDEP`, MSR rules, nested/multi-emit programs and additional rule
steps are outside the certified surface.

## Certified tunables

Both native fixture profiles require:

- `choose_local_tries = 0`
- `choose_local_fallback_tries = 0`
- `choose_total_tries = 50`
- `chooseleaf_descend_once = 1`
- `chooseleaf_vary_r = 1`
- `chooseleaf_stable = 1`
- `msr_descents = 100`
- `msr_collision_tries = 100`

The P05 profile is `(straw_calc_version, allowed_bucket_algorithms) = (0, 22)`.
The P10 profile is `(1, 54)`. Other combinations are rejected.

## Object mapping

Pools must use RJenkins and `HASHPSPOOL`, have nonzero valid PG geometry, be
replicated or erasure-coded, and request 1 through 64 placement slots. Large
nonnegative pool IDs use their low 32 bits in the placement seed, matching Ceph
wrapping behavior. Negative IDs are rejected.

Override order is raw CRUSH, full upmap, upmap items, upmap primary, OSD-up
filtering, primary affinity, then acting `pg_temp`/`primary_temp`. Replicated
primary affinity shifts the selected primary to slot zero. Erasure placement
changes only the primary identity so shard positions remain stable. Missing
`CHOOSE_INDEP` results use the `i32::MAX` sentinel. Sharded `pg_temp` preserves
sentinel positions and native duplicate OSD slots; replicated placement sets
continue to reject duplicate OSDs.
