#!/bin/sh
set -eu

destination=${1:-/tmp/rados-r10-fuzz/corpus}
rm -rf "$destination"
mkdir -p "$destination/r10_class" "$destination/r10_lock" "$destination/r10_watch"
python3 - "$destination" <<'PY'
import pathlib
import struct
import sys

root = pathlib.Path(sys.argv[1])

def envelope(payload):
    return bytes((1, 1)) + struct.pack("<I", len(payload)) + payload

(root / "r10_class" / "binary-input.bin").write_bytes(bytes(range(64)))
(root / "r10_class" / "split-reply.bin").write_bytes(struct.pack("<HH", 0, 0))

empty_lock = struct.pack("<I", 0) + b"\x00" + struct.pack("<I", 0)
(root / "r10_lock" / "empty-info.bin").write_bytes(envelope(empty_lock))
(root / "r10_lock" / "truncated.bin").write_bytes(b"\x01\x01\x08\x00")

(root / "r10_watch" / "empty-notify-result.bin").write_bytes(struct.pack("<II", 0, 0))
(root / "r10_watch" / "empty-watchers.bin").write_bytes(envelope(struct.pack("<I", 0)))
notification = bytes((1, 1)) + struct.pack("<QQQ", 1, 2, 3)
notification += struct.pack("<I", 0) + struct.pack("<iQ", 0, 4)
(root / "r10_watch" / "notification.bin").write_bytes(struct.pack("<HH", len(notification), 0) + notification)
(root / "r10_watch" / "truncated.bin").write_bytes(b"\x01\x00\x00")
PY
printf '%s\n' "R10 fuzz corpus prepared: $destination"
