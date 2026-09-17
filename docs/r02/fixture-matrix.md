# R02 Fixture Matrix

All fixtures are unchanged native Ceph 20.2.4 outputs with provenance in their
adjacent JSON sidecars.

| Fixture | Size | Required checks |
| --- | ---: | --- |
| `entity-name-client-1.bin` | 9 | type 8, signed ID 1, exact round trip |
| `entity-name-mon-new.bin` | 9 | type 1, signed ID -1, exact round trip |
| `entity-addr-ipv4-legacy.bin` | 136 | marker 0, nonce 5, Linux AF_INET, `127.0.1.2:2` |
| `entity-addr-ipv4-modern.bin` | 35 | v1 envelope, legacy address type, same endpoint |
| `entity-addr-ipv6-modern.bin` | 47 | v2 type, nonce 7, flow/scope fields, `[2001:db8::1234]:3300` |
| `entity-addrvec-modern.bin` | 99 | marker 2, two unspecified addresses |

Tests require exact decoded values and byte-for-byte re-encoding. Malformed
coverage includes truncated scalars and envelopes, incompatible versions,
oversized variable data, invalid address markers/families/lengths, impossible
vector counts, arithmetic overflow, and CRC corruption.