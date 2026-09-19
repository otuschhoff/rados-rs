#!/bin/sh
set -eu

destination=${1:-/tmp/rados-r09-fuzz/corpus}
rm -rf "$destination"
mkdir -p "$destination/r09_metadata" "$destination/r09_compound" "$destination/r09_enumeration"
python3 - "$destination" <<'PY'
import pathlib
import struct
import sys

root = pathlib.Path(sys.argv[1])

def envelope(payload):
    return bytes((1, 1)) + struct.pack("<I", len(payload)) + payload

metadata = struct.pack("<I", 2)
metadata += struct.pack("<I", 2) + b"\x00a" + struct.pack("<I", 3) + b"v\x000"
metadata += struct.pack("<I", 1) + b"\xff" + struct.pack("<I", 2) + b"vf"
(root / "r09_metadata" / "binary-map.bin").write_bytes(envelope(metadata))
(root / "r09_metadata" / "truncated.bin").write_bytes(b"\x01\x01\x08\x00")

(root / "r09_compound" / "binary-values.bin").write_bytes(bytes(range(64)))
(root / "r09_compound" / "empty.bin").write_bytes(b"")

hobject = envelope(struct.pack("<QIIq", 0, 0, 0, -(1 << 63)) + b"\x00\x00\x00")
page = struct.pack("<I", 0) + hobject + b"\x00"
(root / "r09_enumeration" / "empty-page.bin").write_bytes(page)
(root / "r09_enumeration" / "truncated-cursor.bin").write_bytes(b"\x01\x01\x10\x00\x00")
PY
printf '%s\n' "R09 fuzz corpus prepared: $destination"
