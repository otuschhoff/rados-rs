#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
report=${1:-"$root/docs/r05/live-integration-report.json"}
verifier="$root/integration/r05/verify-live.rb"
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

ruby "$verifier" "$root" "$report" >/dev/null

reject() {
  name=$1
  if ruby "$verifier" "$root" "$temporary/$name.json" >"$temporary/$name.out" 2>&1; then
    printf 'tampered report passed: %s\n' "$name" >&2
    exit 1
  fi
}

jq '.finished_at = "2000-01-01T00:00:00Z"' "$report" >"$temporary/reversed-timestamp.json"
reject reversed-timestamp
jq 'del(.source.artifacts["Cargo.toml"])' "$report" >"$temporary/source-set.json"
reject source-set
jq '.source.artifacts["Cargo.toml"] = ("0" * 64)' "$report" >"$temporary/source-hash.json"
reject source-hash
jq '.toolchain.probe_binary_sha256 = ("0" * 64)' "$report" >"$temporary/probe-binary-hash.json"
reject probe-binary-hash
jq '.toolchain.extra = true' "$report" >"$temporary/toolchain-set.json"
reject toolchain-set
jq '.scenarios.extra = "passed"' "$report" >"$temporary/scenario-set.json"
reject scenario-set
printf '%s\n' 'R05 live verifier tamper tests passed: reversed-timestamp source-set source-hash probe-binary-hash toolchain-set scenario-set'