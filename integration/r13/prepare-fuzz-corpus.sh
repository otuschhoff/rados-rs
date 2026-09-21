#!/bin/sh
# Deterministic R13 fuzz corpus preparation.
#
# Materialises one corpus directory per fuzz target under $1 (default
# fuzz/corpus in the repository, matching FUZZ_CORPUS_ROOT in
# tools/r13/src/constants.rs; the certifying producer and the verifier
# both hash the same tree). For every target we:
#
#   1) Copy any existing seed from fuzz/corpus/<target>/ if present.
#   2) Copy any pinned fixture bytes from testdata/p01/*.bin for parser
#      targets that consume raw envelopes.
#   3) Fall back to a small, deterministic byte-string seed so the target
#      is NEVER started with an empty corpus. cargo-fuzz refuses to start
#      libFuzzer with zero inputs so silently-empty corpora are impossible
#      to distinguish from a broken campaign; we therefore always emit at
#      least one file per target.
#
# The resulting layout is identical across runs (mode 0644, byte-stable
# content, sorted find order) so the tree digest recorded on the R13 fuzz
# report is deterministic.
#
# We NEVER run libFuzzer directly against this path — the certifying
# campaign creates a separate work corpus (see integration/r13/
# validate-fuzz.sh) so the fixed seed corpus stays byte-stable across
# campaigns.

set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
destination=${1:-$root/fuzz/corpus}
case "$destination" in /*) ;; *) destination="$root/$destination" ;; esac
mkdir -p "$destination"

targets='banner bounded_session_scripts cephx_auth_session_reply cephx_authorizer cephx_credentials cephx_server_challenge controls crc_frame entity_address entity_address_vector messages primitive_decoder r05_config r05_monmap r05_monmap_message r05_osdmap r05_osdmap_full_message r05_osdmap_incremental r05_osdmap_incremental_message r06_crush_decode r06_crush_place r06_object_mapping r06_osdmap_place_object r07_osd_backoff r07_osd_reply r08_mutation_recovery r08_mutation_reply r08_mutation_request r09_compound r09_enumeration r09_metadata r10_class r10_lock r10_watch r11_snapshot r11_sparse r11_special r12_command r12_inconsistent r12_stats secure_frame versioned_envelope'

count=0
for target in $targets; do
  mkdir -p "$destination/$target"
  count=$((count+1))
done
[ "$count" -eq 42 ] || { printf '%s\n' "R13 fuzz: expected 42 targets, prepared $count" >&2; exit 1; }

# 1) Import any checked-in seed corpora when the destination is not the
#    canonical seed root (so we do not attempt to self-copy files back
#    into fuzz/corpus/<target>/). This keeps the certifying corpus at
#    fuzz/corpus in-place while still supporting external work-corpus
#    materialisation for isolated libFuzzer runs.
if [ "$destination" != "$root/fuzz/corpus" ]; then
  for target in $targets; do
    source_dir="$root/fuzz/corpus/$target"
    if [ -d "$source_dir" ]; then
      find "$source_dir" -type f -print | LC_ALL=C sort | while IFS= read -r seed; do
        cp "$seed" "$destination/$target/"
      done
    fi
  done
fi

# 2) Import stable primitive fixtures where applicable.
for target in primitive_decoder versioned_envelope entity_address entity_address_vector; do
  find "$root/testdata/p01" -maxdepth 1 -name '*.bin' -type f -print | LC_ALL=C sort | while IFS= read -r fixture; do
    cp "$fixture" "$destination/$target/"
  done
done

# 3) Emit a per-target bounded seed so no corpus is empty. Each seed is a
#    small, deterministic byte string sized to exercise the target's minimal
#    length gate without producing large libFuzzer inputs.
python3 - "$destination" <<'PY'
import pathlib
import sys

root = pathlib.Path(sys.argv[1])

# 1-, 2-, 4- and 8-byte primitive seeds cover length-prefixed decoders.
BASE_SEEDS = {
    "empty.bin": b"",
    "one.bin": b"\x00",
    "two.bin": b"\x00\x01",
    "four.bin": b"\x00\x01\x02\x03",
    "eight.bin": b"\x00\x01\x02\x03\x04\x05\x06\x07",
    "sixteen.bin": bytes(range(16)),
}

for target_dir in sorted(root.iterdir()):
    if not target_dir.is_dir():
        continue
    for name, payload in BASE_SEEDS.items():
        path = target_dir / name
        if not path.exists():
            path.write_bytes(payload)
    # Guarantee at least one non-empty seed per target: libFuzzer can start
    # from empty.bin alone but coverage stays trivially bounded.
    non_empty = any(
        entry.is_file() and entry.stat().st_size > 0 for entry in target_dir.iterdir()
    )
    if not non_empty:
        (target_dir / "seed-nonempty.bin").write_bytes(bytes(range(32)))
PY

printf '%s\n' "R13 fuzz corpus prepared: $destination ($count targets)"
