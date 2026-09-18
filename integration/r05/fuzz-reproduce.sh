#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$root"
report=${1:-"$root/docs/r05/fuzz-campaign.json"}
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
targets='r05_config r05_monmap r05_osdmap r05_osdmap_incremental r05_monmap_message r05_osdmap_full_message r05_osdmap_incremental_message'
export RUSTUP_TOOLCHAIN=nightly-2026-09-01

for command in cargo find jq mkdir ruby rustc shasum sort wc; do
  command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 1; }
done
test "$(rustc --version)" = 'rustc 1.100.0-nightly (0dfb098f3 2026-08-31)'
test "$(cargo fuzz --version)" = 'cargo-fuzz 0.13.2'

source_paths=$(
  {
    find src -type f -name '*.rs' -print
    find fuzz/fuzz_targets -type f -name 'r05_*.rs' -print
    printf '%s\n' Cargo.lock Cargo.toml build.rs rust-toolchain.toml fuzz/Cargo.lock fuzz/Cargo.toml integration/r05/fuzz-reproduce.sh integration/r05/prepare-fuzz-corpus.sh integration/r05/verify-fuzz.rb integration/r05/verify-fuzz-tests.sh
  } | LC_ALL=C sort
)

write_artifacts() {
  output=$1
  printf '{}\n' >"$output"
  for artifact in $source_paths; do
    hash=$(shasum -a 256 "$artifact" | awk '{print $1}')
    jq --arg path "$artifact" --arg hash "$hash" '. + {($path):$hash}' "$output" >"$output.next"
    mv "$output.next" "$output"
  done
}

write_artifacts "$temporary/sources.before.json"
sh integration/r05/prepare-fuzz-corpus.sh "$temporary/pristine"
(
  cd "$temporary/pristine"
  find . -type f -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256
) >"$temporary/corpus.manifest"
corpus_manifest_sha=$(shasum -a 256 "$temporary/corpus.manifest" | awk '{print $1}')
test "$(wc -l <"$temporary/corpus.manifest" | tr -d ' ')" = 16

host=$(rustc -vV | awk '/^host: / {print $2}')
mkdir -p docs/r05/fuzz-logs
printf '[]\n' >"$temporary/targets.json"
for target in $targets; do
  cargo fuzz build "$target" >"$temporary/build-$target.log" 2>&1 || {
    cat "$temporary/build-$target.log" >&2
    exit 1
  }
  binary="fuzz/target/$host/release/$target"
  test -x "$binary"
  corpus="$temporary/work-$target"
  cp -R "$temporary/pristine/$target" "$corpus"
  mkdir -p "fuzz/artifacts/$target"
  log="docs/r05/fuzz-logs/$target.log"
  "$binary" -artifact_prefix="fuzz/artifacts/$target/" -seed=505 -runs=2000 -max_len=33554432 "$corpus" >"$log" 2>&1
  test "$(wc -c <"$log" | tr -d ' ')" -le 65536
  summary=$(grep 'DONE' "$log" | tail -1)
  printf '%s\n' "$summary" | grep -Eq '^#2000[[:space:]]+DONE'
  coverage=$(printf '%s\n' "$summary" | sed -E 's/.*cov: ([0-9]+).*/\1/')
  features=$(printf '%s\n' "$summary" | sed -E 's/.*ft: ([0-9]+).*/\1/')
  corpus_entries=$(printf '%s\n' "$summary" | sed -E 's/.*corp: ([0-9]+).*/\1/')
  binary_path="fuzz/target/$host/release/$target"
  jq \
    --arg name "$target" --arg binary_sha256 "$(shasum -a 256 "$binary" | awk '{print $1}')" \
    --arg binary_path "$binary_path" \
    --arg log_path "$log" --arg log_sha256 "$(shasum -a 256 "$log" | awk '{print $1}')" \
    --argjson coverage "$coverage" --argjson features "$features" --argjson corpus_entries "$corpus_entries" \
    '. + [{name:$name,runs:2000,coverage:$coverage,features:$features,corpus_entries:$corpus_entries,result:"passed",binary_path:$binary_path,binary_sha256:$binary_sha256,log_path:$log_path,log_sha256:$log_sha256,command:[$name,"-artifact_prefix=fuzz/artifacts/"+$name+"/","-seed=505","-runs=2000","-max_len=33554432","CORPUS/"+$name]}]' \
    "$temporary/targets.json" >"$temporary/targets.next"
  mv "$temporary/targets.next" "$temporary/targets.json"
done

write_artifacts "$temporary/sources.after.json"
cmp "$temporary/sources.before.json" "$temporary/sources.after.json" >/dev/null || {
  printf '%s\n' 'source artifacts changed during fuzz qualification' >&2
  exit 1
}

mkdir -p "$(dirname "$report")"
jq -n \
  --arg generated_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  --arg rustc "$(rustc --version)" --arg cargo_fuzz "$(cargo fuzz --version)" \
  --arg corpus_manifest_sha256 "$corpus_manifest_sha" \
  --argjson sources "$(cat "$temporary/sources.before.json")" \
  --argjson targets "$(cat "$temporary/targets.json")" \
  '{schema_version:1,status:"passed",generated_at:$generated_at,toolchain:{rustc:$rustc,cargo_fuzz:$cargo_fuzz,libfuzzer_sys:"0.4.13"},bounds:{runs_per_target:2000,max_len:33554432,random_seed:505,max_log_bytes:65536},source:{identity:"exact-content-addressed-artifacts",artifacts:$sources},initial_corpus:{file_count:16,sorted_manifest_sha256:$corpus_manifest_sha256},targets:$targets,finding:"No crash, sanitizer finding, timeout, or non-zero exit occurred. Coverage and feature counters are libFuzzer observations, not a completeness claim."}' >"$report"
ruby integration/r05/verify-fuzz.rb "$root" "$report"
integration/r05/verify-fuzz-tests.sh "$report"
printf 'R05 fuzz campaign report: %s\n' "$report"