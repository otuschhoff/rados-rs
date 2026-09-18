#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
report=${1:-"$root/docs/r05/fuzz-campaign.json"}
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

expect_rejected() {
  candidate=$1
  if ruby "$root/integration/r05/verify-fuzz.rb" "$root" "$candidate" >/dev/null 2>&1; then
    printf 'tampered fuzz report was accepted: %s\n' "$candidate" >&2
    exit 1
  fi
}

jq '.unexpected = true' "$report" >"$temporary/top-level-key.json"
expect_rejected "$temporary/top-level-key.json"

jq '.targets[0].unexpected = true' "$report" >"$temporary/target-key.json"
expect_rejected "$temporary/target-key.json"

jq '.targets[0].binary_sha256 = ("0" * 64)' "$report" >"$temporary/binary-hash.json"
expect_rejected "$temporary/binary-hash.json"

dd if=/dev/zero of="$temporary/oversized.json" bs=262145 count=1 2>/dev/null
expect_rejected "$temporary/oversized.json"

printf '%s\n' 'R05 fuzz verifier tamper tests passed'