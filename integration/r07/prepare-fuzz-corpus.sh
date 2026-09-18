#!/bin/sh
set -eu

destination=${1:-/tmp/rados-r07-fuzz/corpus}
rm -rf "$destination"
mkdir -p "$destination/r07_osd_reply" "$destination/r07_osd_backoff"
python3 - "$destination" <<'PY'
import pathlib
import struct
import sys

root = pathlib.Path(sys.argv[1])

def sized(value):
    return struct.pack("<I", len(value)) + value

def versioned(version, compatible, payload):
    return bytes((version, compatible)) + struct.pack("<I", len(payload)) + payload

object_name = b"object"
front = bytearray()
front += sized(object_name)
front += bytes((1,)) + struct.pack("<QI", 7, 3) + struct.pack("<i", -1)
front += struct.pack("<qi", 0, 0)
front += bytes(12)
front += struct.pack("<IIH", 9, 1, 0x1201)
front += bytes(32)
data = b"payload"
front += struct.pack("<Iii", len(data), -1, 0)
front += bytes(12)
front += struct.pack("<Q", 44)
front += bytes((0,))
front += bytes(24)
(root / "r07_osd_reply" / "valid-read.bin").write_bytes(struct.pack("<HH", len(front), 0) + front + data)
(root / "r07_osd_reply" / "truncated.bin").write_bytes(b"\x01\x00\x00")

def hobject(name):
    payload = sized(b"") + sized(name) + struct.pack("<QI", 0xfffffffffffffffe, 7)
    payload += bytes((0,)) + sized(b"") + struct.pack("<q", 1)
    return versioned(4, 3, payload)

spg = bytes((1,)) + struct.pack("<QI", 1, 7) + struct.pack("<i", -1) + struct.pack("<b", -1)
backoff = versioned(1, 1, spg) + struct.pack("<IBQ", 1, 1, 9) + hobject(b"blocked") * 2
(root / "r07_osd_backoff" / "valid-block.bin").write_bytes(struct.pack("<HH", len(backoff), 0) + backoff)
(root / "r07_osd_backoff" / "truncated.bin").write_bytes(b"\x00\x00\x00")
PY
printf '%s\n' "R07 fuzz corpus prepared: $destination"
