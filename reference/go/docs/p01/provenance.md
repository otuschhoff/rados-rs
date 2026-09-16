# P01 Protocol Provenance

All Go implementation in P01 was written independently from protocol facts. No
Ceph source text or implementation structure was copied. The source baseline is
Ceph `v20.2.0` commit `69f84cc2651aa259a15bc192ddaabd3baba07489`;
fixture generation uses qualification release `v20.2.4` commit
`7f793731f1b39eb4f465e960113d2363c311b964`.

## Source Facts

| Go area | Pinned Ceph facts consulted |
| --- | --- |
| Primitive/envelope codec | `src/include/byteorder.h`, `src/include/encoding.h` |
| Feature namespaces | `src/include/ceph_features.h`, `src/include/msgr.h` |
| Entity/address layouts | `src/msg/msg_types.h`, `src/msg/msg_types.cc` |
| Oracle cases | `src/tools/ceph-dencoder/common_types.h`, `src/tools/ceph-dencoder/ceph_dencoder.cc` |

The applicable upstream licensing decision remains in `docs/p00/licensing.md`.
P01 adds no project distribution license and no third-party Go dependency.

## Fixture Oracle

Five fixtures under `testdata/p01` were emitted by `ceph-dencoder` 20.2.4 in
`quay.io/ceph/ceph@sha256:6bb1c8a42fbc0bf87938946990b65174466997bc11c31eb5a323225a779fd8f9`.
Each `.bin.json` sidecar records the exact command, source paths, commit, image,
SHA-256, secret status, and redistribution review. Oliver Tuschhoff approved
redistribution of these generated, synthetic, non-secret byte streams.

For the sixth fixture, `integration/p01/ipv6-fixture.c` creates a synthetic seed
from Linux's real `sockaddr_in6` layout with nonzero flow/scope fields and
rejects platforms whose structure is not 28 bytes. The checked-in seed and C
source are hash-bound. Pinned Ceph 20.2.4 `ceph-dencoder` imports and decodes that
candidate through `entity_addr_t`, then re-encodes the canonical fixture. Thus
the final bytes have passed both the Linux ABI oracle and Ceph's own codec.

`make reproduce-p01` executes all six pinned generator paths, rebuilds and
compares the Linux-only seed, and byte-compares every regenerated fixture.

The fixtures cover two entity names, legacy and modern IPv4, modern IPv6, and a
modern two-address vector. Tests check both exact bytes and decoded semantics;
Go encoder/decoder round trips are not treated as oracle evidence.
