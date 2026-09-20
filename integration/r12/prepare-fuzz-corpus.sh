#!/bin/sh
set -eu

destination=${1:-/tmp/rados-r12-fuzz/corpus}
rm -rf "$destination"
mkdir -p "$destination/r12_command" "$destination/r12_stats" "$destination/r12_inconsistent"
python3 - "$destination" <<'PY'
import pathlib
import struct
import sys

root = pathlib.Path(sys.argv[1])
fsid = bytes(range(16))


def mon_command_reply_front(result: int, status: bytes, arguments: list[bytes]) -> bytes:
    payload = bytearray()
    payload += struct.pack("<Q", 7)  # paxos version
    payload += struct.pack("<h", -1)  # paxos id
    payload += struct.pack("<Q", 0)  # paxos round
    payload += struct.pack("<i", result)
    payload += struct.pack("<I", len(status)) + status
    payload += struct.pack("<I", len(arguments))
    for argument in arguments:
        payload += struct.pack("<I", len(argument)) + argument
    return bytes(payload)


def prefixed(front: bytes, body: bytes) -> bytes:
    return struct.pack("<H", len(front)) + front + body


# r12_command — cover monitor, manager, and OSD command replies.
front = mon_command_reply_front(0, b"ok", [b"mon", b"status"])
(root / "r12_command" / "mon-reply.bin").write_bytes(prefixed(front, b"cluster status\n"))

manager_front = struct.pack("<i", -13) + struct.pack("<I", len(b"permission denied")) + b"permission denied"
(root / "r12_command" / "mgr-reply.bin").write_bytes(prefixed(manager_front, b"details"))

osd_front = struct.pack("<i", 0) + struct.pack("<I", len(b"ok")) + b"ok"
(root / "r12_command" / "osd-reply.bin").write_bytes(prefixed(osd_front, b"pg status"))

(root / "r12_command" / "empty.bin").write_bytes(struct.pack("<H", 0))
(root / "r12_command" / "truncated.bin").write_bytes(b"\x02\x00\x01")
(root / "r12_command" / "oversized-count.bin").write_bytes(
    struct.pack("<H", 24) + struct.pack("<Q", 0) + struct.pack("<h", -1) + struct.pack("<Q", 0)
    + struct.pack("<i", 0) + struct.pack("<I", 0) + struct.pack("<I", 0xffffffff)
)

# r12_stats — cover statfs and get-pool-stats replies.
statfs_front = fsid + struct.pack("<QQQQQ", 42, 1_000_000, 250_000, 750_000, 128)
(root / "r12_stats" / "statfs-reply.bin").write_bytes(statfs_front)

pool_stats_front = bytearray()
pool_stats_front += struct.pack("<Q", 12)
pool_stats_front += struct.pack("<h", -1)
pool_stats_front += struct.pack("<Q", 0)
pool_stats_front += fsid
pool_stats_front += struct.pack("<I", 1)
name = b"p12-data"
pool_stats_front += struct.pack("<I", len(name)) + name
pool_stats_front += struct.pack(
    "<qqqqqqqq", 4096, 2, 8, 16, 0, 0, 8192, 0
)
pool_stats_front += struct.pack("<?", True)
(root / "r12_stats" / "pool-stats-reply.bin").write_bytes(bytes(pool_stats_front))

(root / "r12_stats" / "truncated.bin").write_bytes(fsid[:8])
(root / "r12_stats" / "oversized-count.bin").write_bytes(
    struct.pack("<Q", 0) + struct.pack("<h", -1) + struct.pack("<Q", 0) + fsid + struct.pack("<I", 0xffffffff)
)

# r12_inconsistent — cover scrub-list wire buffer and inconsistent-PG JSON.
def versioned(version: int, compat: int, payload: bytes) -> bytes:
    return struct.pack("<BBI", version, compat, len(payload)) + payload


scrub_payload = struct.pack("<II", 5, 0)  # interval + zero object count
scrub_payload += struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<Q", 0) + struct.pack("<Q", 4)
scrub_bytes = versioned(1, 1, scrub_payload)
(root / "r12_inconsistent" / "scrub-empty.bin").write_bytes(scrub_bytes)

(root / "r12_inconsistent" / "inconsistent-pgs.json").write_bytes(
    b'{"pg_stats":[{"pgid":"7.1a"},{"pgid":"3.f"}]}'
)
(root / "r12_inconsistent" / "inconsistent-array.json").write_bytes(
    b'[{"pgid":"42.0"}]'
)
(root / "r12_inconsistent" / "empty.bin").write_bytes(b"")
(root / "r12_inconsistent" / "truncated.bin").write_bytes(b"\x01\x01")
(root / "r12_inconsistent" / "oversized-count.bin").write_bytes(
    versioned(1, 1, struct.pack("<II", 5, 0xffffffff))
)
PY
printf '%s\n' "R12 fuzz corpus prepared: $destination"
