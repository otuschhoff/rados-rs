#!/bin/sh
set -eu

destination=${1:-/tmp/rados-r11-fuzz/corpus}
rm -rf "$destination"
mkdir -p "$destination/r11_snapshot" "$destination/r11_sparse" "$destination/r11_special"
python3 - "$destination" <<'PY'
import pathlib
import struct
import sys

root = pathlib.Path(sys.argv[1])

(root / "r11_snapshot" / "allocated-id.bin").write_bytes(struct.pack("<Q", 17))
(root / "r11_snapshot" / "truncated.bin").write_bytes(b"\x01\x01\x08\x00")
(root / "r11_snapshot" / "oversized-count.bin").write_bytes(struct.pack("<I", 0xffffffff))

sparse = struct.pack("<IQQQQI", 2, 0, 2, 5, 3, 5) + b"abcde"
(root / "r11_sparse" / "valid-sparse.bin").write_bytes(sparse)
(root / "r11_sparse" / "valid-checksum.bin").write_bytes(struct.pack("<III", 2, 0x2a86bef5, 0x2a86bef5))
(root / "r11_sparse" / "overlap.bin").write_bytes(struct.pack("<IQQQQI", 2, 0, 4, 2, 2, 6) + b"abcdef")
(root / "r11_sparse" / "truncated.bin").write_bytes(b"\x02\x00\x00")

(root / "r11_special" / "empty-reply.bin").write_bytes(struct.pack("<HH", 0, 0))
(root / "r11_special" / "pattern.bin").write_bytes(bytes(range(64)))
(root / "r11_special" / "large-pattern.bin").write_bytes(bytes(range(256)) * 16)
PY
printf '%s\n' "R11 fuzz corpus prepared: $destination"