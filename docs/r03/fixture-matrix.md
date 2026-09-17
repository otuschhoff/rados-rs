# R03 Fixture Matrix

The 12 P02 binaries are imported unchanged with adjacent JSON provenance
sidecars. Sidecars retain their recorded redistribution/review status; R03 does
not convert that metadata into release approval.

| Fixture | Bytes | SHA-256 | Coverage |
| --- | ---: | --- | --- |
| `banner-rev1.bin` | 26 | `6819c56d...98cfcca` | revision-1 banner |
| `crc-one-segment.bin` | 40 | `cc92c26d...95d37d4` | generated one-segment CRC |
| `crc-four-segment.bin` | 65 | `0fa63a78...8c42` | generated four-segment CRC |
| `secure-one-segment.bin` | 96 | `592152e2...b3926d` | generated one-record GCM |
| `secure-multi-record.bin` | 208 | `f0c51600...9d37a1` | generated multi-record GCM |
| `upstream-crc-one-segment.bin` | 40 | `cc92c26d...95d37d4` | upstream CRC parity |
| `upstream-crc-four-segment.bin` | 65 | `0fa63a78...8c42` | upstream segmented CRC parity |
| `upstream-crc-disabled-one-segment.bin` | 40 | `68cef6e7...e7569` | disabled data CRC |
| `upstream-secure-one-segment.bin` | 96 | `592152e2...b3926d` | upstream one-record GCM parity |
| `upstream-secure-multi-record.bin` | 208 | `f0c51600...9d37a1` | upstream multi-record GCM parity |
| `upstream-ack-control.bin` | 44 | `2496a22a...6ce70` | ACK control, sequence semantics |
| `upstream-message-frame.bin` | 100 | `00a22987...ff26` | 41-byte header and four segments |

Tests require exact fixture hashes, exact round trips where canonical, decoded
field/segment semantics, crossed secure directions and corruption rejection.
The differential bridge binds the five upstream/banner fixtures it consumes to
pinned binary and sidecar SHA-256 values. Its sixth input is the fixed
`start-ready\nstop\n` session transcript and has no fixture sidecar.
