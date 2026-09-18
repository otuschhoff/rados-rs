#!/bin/sh
set -eu

destination=${1:-/tmp/rados-r08-fuzz/corpus}
rm -rf "$destination"
mkdir -p "$destination/r08_mutation_request" "$destination/r08_mutation_reply" "$destination/r08_mutation_recovery"
python3 - "$destination" <<'PY'
import pathlib
import struct
import sys

root = pathlib.Path(sys.argv[1])

payload = b"r08-mutation-payload"
request = bytes((2,)) + struct.pack("<QQ", 0, len(payload)) + payload
(root / "r08_mutation_request" / "write-full.bin").write_bytes(request)
(root / "r08_mutation_request" / "truncated.bin").write_bytes(b"\x01\x00")

front = bytearray()
front += struct.pack("<I", 4) + b"r08x"
front += bytes((1,)) + struct.pack("<QI", 1, 1) + struct.pack("<i", -1)
front += struct.pack("<qi", 5, 0)
front += bytes(12)
front += struct.pack("<IIH", 1, 1, 0x2202)
front += bytes(32)
front += struct.pack("<Iii", 0, -1, 0)
front += bytes(12)
front += struct.pack("<Q", 9)
front += bytes((0,))
front += bytes(24)
reply = struct.pack("<HH", len(front), 0) + front
(root / "r08_mutation_reply" / "durable-write.bin").write_bytes(reply)
(root / "r08_mutation_reply" / "truncated.bin").write_bytes(b"\x02\x00\x00")
(root / "r08_mutation_recovery" / "reply.bin").write_bytes(b"\x00" + reply)
(root / "r08_mutation_recovery" / "backoff-truncated.bin").write_bytes(b"\x01\x00\x00\x00")
PY
printf '%s\n' "R08 fuzz corpus prepared: $destination"