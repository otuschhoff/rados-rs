# Protocol Fixtures

P01 fixtures are under `p01/`. Every fixture has a sidecar manifest validated
against
`manifest.schema.json`. Synthetic secrets must be non-reusable and explicitly
marked. Captures containing real credentials, tickets or session secrets must
never be committed.

`generator.command` must be sufficient to reproduce the fixture in the pinned
environment. `source.paths` lists every upstream file used to interpret it.
`license.reviewed_by` must name a human reviewer before redistribution.

P04 contains `ceph-dencoder` MonMap v9, OSDMap v8, and OSDMap::Incremental v8
fixtures. The R05 deterministic bridge feeds those exact bytes to both the Rust
and pinned Go production decoders and binds the fixture and manifest hashes.
The default full and incremental files are independent decoder fixtures, not a
sequential map pair; synthetic convergence is covered separately by Rust unit
evidence. Their manifests retain `redistribution: pending` until human review.