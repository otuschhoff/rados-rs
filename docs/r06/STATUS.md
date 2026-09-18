# R06 Execution and Handoff

R06 implements exact object-to-PG and certified CRUSH placement behind the
internal map layer. Deterministic Rust/Go/native parity and bounded sanitizer
campaigns passed on 2026-09-18.

## Delivered

- Ceph RJenkins object hashing over arbitrary object, locator and namespace
  bytes, including locator replacement, the namespace separator and StableMod.
- Wrapping CRUSH pair/triple hashes and Ceph's fixed-point `crush_ln`; no
  floating-point placement approximation is used.
- A bounded CRUSH map decoder with graph validation and explicit rejection of
  unsupported algorithms, choose arguments, class-shadow roots, cycles and
  uncertified rule/tunable profiles.
- Certified straw2 execution for replicated `CHOOSE_FIRSTN`, replicated
  `CHOOSELEAF_FIRSTN` and the P10 erasure `CHOOSE_INDEP` profile.
- Object placement through raw, up and acting sets, including OSD state/weight,
  `pg_upmap`, `pg_upmap_items`, upmap primary, `pg_temp`, `primary_temp`, primary
  affinity and erasure shard metadata. Erasure sentinel slots and shard order
  are retained.
- Native corpus parity over 1,920 rows: 512 P05 direct CRUSH mappings, 512 P05
  object transition mappings, 512 P10 erasure mappings and 384 P10 complete
  object placements.
- An eleven-case Rust/adapted-Go/native bridge. Its verifier binds all 14
  fixture and manifest pairs, clean-builds both probes from bound source, and
  replays both fresh builds as well as the exact reported executables.
- Four production-backed libFuzzer targets. Each completed 2,000 executions
  under the pinned nightly without a crash, sanitizer finding, timeout or
  non-zero exit; exact observations are in `fuzz-campaign.json`.

## Boundaries

The certified map and rule surface is listed in `certified-scope.md`. This is not
support for arbitrary CRUSH maps. Unsupported profiles fail closed.

Native differential evidence covers the P05 replicated baseline, PG-count and
OSD-out transitions, `pg_upmap_items`, and the P10 erasure baseline, OSD-out
and primary-affinity transitions. The P10 object corpus covers retained
sentinels, stable shard slots and native duplicate acting OSD slots. Other
override-ordering invariants are production-backed Rust unit tests rather than
native fixture cases. Binary identity hashing has exact pinned Go vectors,
while the native object corpus contains textual object names with empty locator
and namespace fields.

The frozen Go oracle has known erasure-placement defects for sentinel slots,
primary affinity and duplicate temporary OSD slots. Qualification applies the
content-bound `tools/r06/go-probe/placement.patch` only to a disposable clone;
the original oracle remains unchanged. Native Ceph fixtures remain the
authority for those edges.

All R06 fixture manifests retain `redistribution: pending` and name no human
reviewer. R06 fixtures, harnesses and documents are deliberately excluded from
Cargo package contents.

The parity-ledger rows for public `Pool.WithNamespace`/`Pool.WithLocator`
equivalents remain planned because R06 supplies internal placement, not the
public object-view API. That API belongs with the object client phases.

## R07 Handoff

R07 can consume `ObjectPlacement` to select an acting OSD and shard while adding
OSD authorization/session handling, request correlation and bounded read state.
R06 makes no object-I/O or OSD-session qualification claim.
