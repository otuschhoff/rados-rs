# R02 Bounded Wire Formats

All wire modules are private. Integers use little-endian encoding except Linux
socket ports and legacy address families, which use network byte order. Signed
values preserve their two's-complement bits.

Variable bytes use a `u32` length prefix. Every decoder receives an explicit
maximum and checks it before allocation. Every encoder has a total output limit
and retains its first error. Truncated scalars, lengths beyond remaining input,
arithmetic overflow, and limit violations fail.

Ceph versioned envelopes are:

```text
struct_v:u8 | struct_compat:u8 | payload_len:u32-le | payload
```

A decoder rejects `struct_compat` newer than its local version, bounds and
isolates the payload, skips unknown trailing payload fields, and does not consume
bytes following the envelope. A newer `struct_v` with compatible fields is
accepted. The isolated differential evidence case for this behavior is defined
in [probe-protocol.md](probe-protocol.md).

Entity names are one type byte followed by a signed `i64` identifier. Addresses
preserve Linux family numbers and exact socket bytes. Legacy addresses use the
136-byte marker/nonce/sockaddr form. Modern addresses use marker `1` and a
version `1`, compatibility `1` envelope. Modern vectors use marker `2`, a
bounded count, and nested addresses. IPv4 uses 14 socket bytes; IPv6 and
unspecified addresses use 26.

Feature values are private `u64` namespaces. Unknown bits are retained. Ceph
CRC32C uses Castagnoli update with complemented input and output seed:
`!crc32c_append(!seed, payload)`. CRC placement in messenger frames belongs to
R03.