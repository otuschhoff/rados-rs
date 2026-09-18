# R05 Monitor And Map Evidence

The bridge feeds identical bytes from `testdata/p04` to the actual Rust and Go
MonMap, OSDMap, and OSDMap::Incremental decoders. It compares stable semantics:

- MonMap FSID, epoch, monitor count, rank order, feature masks, minimum release,
  election strategy, and stretch-mode state.
- OSDMap FSID, epoch, pool count and sorted names, stored CRC, verification
  state, sort-bitwise flag, and incremental provenance flag.
- Incremental FSID, epoch, incremental CRC, and target full-map CRC.

Each semantic object has a canonical JSON SHA-256, and each raw fixture and
manifest is independently hash-bound in the report. Both implementations must
produce identical records after removing only the implementation identifier.

The default dencoder OSDMap and incremental fixtures are independent: the full
map has epoch 1 while the incremental has epoch 0. They prove decoder parity,
not sequence convergence. Rust's monitor-client unit test constructs a
synthetic next-epoch incremental, applies it to the decoded full fixture, and
checks publication against the independently applied expected snapshot while
also bounding retained history. That is intentionally recorded as Rust unit
evidence only.

The additive R05 live harness provisions three pinned Ceph v20.2.4 monitors and
requires one persistent public Rust client to observe pool creation, deletion,
and a post-monitor-loss map update. The 2026-09-17 run passed with two-monitor
quorum retained after one configured monitor was removed. A separate client
rejected a configured FSID mismatch, and cleanup left no matching containers or
network. The report does not identify which monitor held the client session, so
it proves continued operation after one-monitor loss rather than active-session
failover specifically. Manager service authorization and OSD routing remain
outside the delivered evidence.