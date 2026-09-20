#!/bin/sh
set -eu

usage() { printf '%s\n' "usage: $0 --report PATH [--seconds N]" >&2; exit 2; }
report=
seconds=60
while [ "$#" -gt 0 ]; do
  case "$1" in
    --report) [ "$#" -ge 2 ] || usage; report=$2; shift 2 ;;
    --seconds) [ "$#" -ge 2 ] || usage; seconds=$2; shift 2 ;;
    *) usage ;;
  esac
done
[ -n "$report" ] || usage
case "$seconds" in ''|*[!0-9]*) usage ;; esac
[ "$seconds" -ge 60 ] || { printf '%s\n' 'R11 fuzz: budget must be at least 60 seconds' >&2; exit 2; }

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
case "$report" in /*) ;; *) report="$PWD/$report" ;; esac
nightly=nightly-2026-09-01
rustc=$(rustup which --toolchain "$nightly" rustc)
[ "$(cargo fuzz --version)" = 'cargo-fuzz 0.13.2' ] || { printf '%s\n' 'R11 fuzz: cargo-fuzz 0.13.2 is required' >&2; exit 1; }
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
corpus="$temporary/corpus"
"$root/integration/r11/prepare-fuzz-corpus.sh" "$corpus"
sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
tree_digest() { base=$1; find "$base" -type f -print | LC_ALL=C sort | while IFS= read -r file; do printf '%s  %s\n' "$(sha256_file "$file")" "${file#"$base"/}"; done | shasum -a 256 | awk '{print $1}'; }
source_digest() { git -C "$root" ls-files -co --exclude-standard -- 'src/**' 'tools/r11/**' 'integration/r11/**' 'fuzz/fuzz_targets/r11_*' Cargo.toml Cargo.lock build.rs rust-toolchain.toml | LC_ALL=C sort | while IFS= read -r file; do printf '%s  %s\n' "$(sha256_file "$root/$file")" "$file"; done | shasum -a 256 | awk '{print $1}'; }
source_sha256=$(source_digest)
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
: >"$temporary/results.jsonl"
artifacts="$(dirname "$report")/fuzz-validation-logs"
rm -rf "$artifacts"
mkdir -p "$artifacts"
for target in r11_snapshot r11_sparse r11_special; do
  output="$temporary/$target.log"
  corpus_sha256=$(tree_digest "$corpus/$target")
  RUSTC="$rustc" cargo fuzz run "$target" "$corpus/$target" -- -max_total_time="$seconds" -print_final_stats=1 -verbosity=0 >"$output" 2>&1
  cat "$output"
  executions=$(awk '/stat::number_of_executed_units:/ { value=$2 } END { print value }' "$output")
  executions_per_second=$(awk '/stat::average_exec_per_sec:/ { value=$2 } END { print value }' "$output")
  [ -n "$executions" ] && [ -n "$executions_per_second" ] || exit 1
  cp "$output" "$artifacts/$target.log"
  jq -n --arg target "$target" --argjson seconds "$seconds" --argjson executions "$executions" --argjson executions_per_second "$executions_per_second" \
    --arg corpus_sha256 "$corpus_sha256" --arg target_sha256 "$(sha256_file "$root/fuzz/fuzz_targets/$target.rs")" \
    --arg output_sha256 "$(sha256_file "$output")" --arg output_path "fuzz-validation-logs/$target.log" \
    '{target:$target,budget_seconds:$seconds,executions:$executions,executions_per_second:$executions_per_second,corpus_sha256:$corpus_sha256,target_sha256:$target_sha256,output_path:$output_path,output_sha256:$output_sha256,status:"passed"}' >>"$temporary/results.jsonl"
done
[ "$source_sha256" = "$(source_digest)" ] || { printf '%s\n' 'R11 fuzz: source changed during campaign' >&2; exit 1; }
mkdir -p "$(dirname "$report")"
jq -s --arg started_at "$started_at" --arg finished_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg source_sha256 "$source_sha256" --arg rustc "$($rustc --version)" \
  '{schema_version:1,suite_id:"r11/fuzz-task-validation-v1",status:"passed",started_at:$started_at,finished_at:$finished_at,source_sha256:$source_sha256,rustc:$rustc,cargo_fuzz:"cargo-fuzz 0.13.2",campaigns:.}' "$temporary/results.jsonl" >"$report"
cargo run --quiet -p rados-r11-tools --bin rados-r11-verify-fuzz -- "$root" "$report"
printf '%s\n' "R11 fuzz validation passed: $report"