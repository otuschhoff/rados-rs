#!/bin/sh
# R13 fuzz qualification driver.
#
# Runs one sequential libFuzzer campaign per target using the pinned
# nightly-2026-09-01 toolchain and cargo-fuzz 0.13.2. Collects
# per-target execution/exec-per-second counts, corpus/target/output
# SHA-256 hashes, and status. Emits a strict R13 fuzz report and
# validates it in-process with rados-r13-fuzz.
#
# Profiles:
#   --profile pending       do not run; emit the canonical pending report
#   --profile smoke         run every target for at least  60 s
#   --profile certifying    run every target for at least 600 s
#
# Optional flags:
#   --seconds N             override the per-target budget (>=60 for smoke,
#                           >=600 for certifying)
#   --targets t1,t2,...     restrict to a subset (unsupported for
#                           certifying; smoke may be restricted only when
#                           --allow-subset is passed)
#   --allow-subset          permit a smoke subset (still recorded on the
#                           report; the R13 verifier rejects incomplete
#                           smoke matrices)
#   --corpus-root PATH      write/read the corpus tree under PATH
#                           (default fuzz/corpus in the repository — the
#                           same path the R13 verifier hashes)
#   --report PATH           output report path (default docs/r13/fuzz-report.json)

set -eu

usage() {
  printf '%s\n' "usage: $0 --profile pending|smoke|certifying [--seconds N] [--targets t1,t2,...] [--allow-subset] [--corpus-root PATH] [--report PATH]" >&2
  exit 2
}

profile=
seconds=
targets_arg=
allow_subset=0
corpus_root=fuzz/corpus
report_path=docs/r13/fuzz-report.json
while [ "$#" -gt 0 ]; do
  case "$1" in
    --profile) [ "$#" -ge 2 ] || usage; profile=$2; shift 2 ;;
    --seconds) [ "$#" -ge 2 ] || usage; seconds=$2; shift 2 ;;
    --targets) [ "$#" -ge 2 ] || usage; targets_arg=$2; shift 2 ;;
    --allow-subset) allow_subset=1; shift ;;
    --corpus-root) [ "$#" -ge 2 ] || usage; corpus_root=$2; shift 2 ;;
    --report) [ "$#" -ge 2 ] || usage; report_path=$2; shift 2 ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done
[ -n "$profile" ] || usage

case "$profile" in
  pending|smoke|certifying) ;;
  *) printf '%s\n' "R13 fuzz: unknown profile $profile" >&2; exit 2 ;;
esac

nightly=nightly-2026-09-01
cargo_fuzz_expected='cargo-fuzz 0.13.2'
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
case "$report_path" in /*) ;; *) report_path="$root/$report_path" ;; esac
case "$corpus_root" in /*) ;; *) corpus_root="$root/$corpus_root" ;; esac

# Pending profile: emit the canonical pending shape from the checked-in
# template so smoke/certifying and pending share code paths.
if [ "$profile" = 'pending' ]; then
  mkdir -p "$(dirname "$report_path")"
  cp "$root/docs/r13/fuzz-report.pending.json" "$report_path"
  cargo run --quiet --locked -p rados-r13-tools --bin rados-r13-fuzz -- \
    --verify-shape --report "$report_path"
  printf '%s\n' "R13 fuzz pending report emitted at $report_path"
  exit 0
fi

case "$profile" in
  smoke) minimum=60 ;;
  certifying) minimum=600 ;;
esac
if [ -z "$seconds" ]; then seconds=$minimum; fi
case "$seconds" in ''|*[!0-9]*) usage ;; esac
[ "$seconds" -ge "$minimum" ] || {
  printf '%s\n' "R13 fuzz: profile $profile requires at least $minimum s per target" >&2
  exit 2
}

if [ "$profile" = 'certifying' ] && [ -n "$targets_arg" ]; then
  printf '%s\n' 'R13 fuzz: --targets is not permitted with --profile certifying' >&2
  exit 2
fi
if [ "$profile" = 'smoke' ] && [ -n "$targets_arg" ] && [ "$allow_subset" -ne 1 ]; then
  printf '%s\n' 'R13 fuzz: smoke subset requires --allow-subset (report will fail R13 verifier)' >&2
  exit 2
fi

# Verify inventory before doing any work.
cargo run --quiet --locked -p rados-r13-tools --bin rados-r13-fuzz -- \
  --check-inventory --root "$root"

# Locate rustc for the pinned nightly.
if ! command -v rustup >/dev/null 2>&1; then
  printf '%s\n' 'R13 fuzz: rustup is required to select the pinned nightly toolchain' >&2
  exit 1
fi
rustc_bin=$(rustup which --toolchain "$nightly" rustc)
rustc_version=$("$rustc_bin" --version)
observed_cargo_fuzz=$(cargo fuzz --version)
[ "$observed_cargo_fuzz" = "$cargo_fuzz_expected" ] || {
  printf '%s\n' "R13 fuzz: cargo-fuzz version mismatch (need $cargo_fuzz_expected, saw $observed_cargo_fuzz)" >&2
  exit 1
}

# Prepare the deterministic corpus for every target once.
"$root/integration/r13/prepare-fuzz-corpus.sh" "$corpus_root"

# Choose target set.
all_targets='banner bounded_session_scripts cephx_auth_session_reply cephx_authorizer cephx_credentials cephx_server_challenge controls crc_frame entity_address entity_address_vector messages primitive_decoder r05_config r05_monmap r05_monmap_message r05_osdmap r05_osdmap_full_message r05_osdmap_incremental r05_osdmap_incremental_message r06_crush_decode r06_crush_place r06_object_mapping r06_osdmap_place_object r07_osd_backoff r07_osd_reply r08_mutation_recovery r08_mutation_reply r08_mutation_request r09_compound r09_enumeration r09_metadata r10_class r10_lock r10_watch r11_snapshot r11_sparse r11_special r12_command r12_inconsistent r12_stats secure_frame versioned_envelope'
if [ -n "$targets_arg" ]; then
  IFS=',' read_targets=$(printf '%s' "$targets_arg" | tr ',' ' ')
  targets=$read_targets
else
  targets=$all_targets
fi

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) printf '%s\n' 'R13 fuzz: unsupported host OS' >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) printf '%s\n' 'R13 fuzz: unsupported host architecture' >&2; exit 1 ;;
esac

sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
tree_digest() {
  base=$1
  find "$base" -type f -print | LC_ALL=C sort | while IFS= read -r file; do
    printf '%s  %s\n' "$(sha256_file "$file")" "${file#"$base"/}"
  done | shasum -a 256 | awk '{print $1}'
}
source_digest() {
  # Reuse the tool's canonical source-artifact walk so this shell script
  # does not duplicate the git-ls-files exclusion set.
  cargo run --quiet --locked -p rados-r13-tools --bin rados-r13-qualify -- \
    --print-source-digest --root "$root"
}

schema_path="$root/integration/r13/fuzz-report.schema.json"
schema_digest=$(sha256_file "$schema_path")
source_sha256=$(source_digest)
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

artifacts_dir="$(dirname "$report_path")/fuzz-validation-logs"
rm -rf "$artifacts_dir"
mkdir -p "$artifacts_dir"

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
: >"$temporary/campaigns.jsonl"

# libFuzzer treats the FIRST corpus dir as writable — it will add new
# interesting inputs. To keep the certifying fuzz/corpus tree byte-stable
# across runs, spin up a fresh per-target work corpus and pass the seed
# corpus as a read-only secondary. The corpus_sha256 recorded on the
# report is computed against the fixed seed corpus so the verifier can
# reproduce the digest without needing the work corpus.
work_corpus_root="$temporary/work-corpus"
mkdir -p "$work_corpus_root"

report_status=passed
for target in $targets; do
  target_started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  output="$temporary/$target.log"
  corpus_sha256=$(tree_digest "$corpus_root/$target")
  target_sha256=$(sha256_file "$root/fuzz/fuzz_targets/$target.rs")
  target_workdir="$work_corpus_root/$target"
  mkdir -p "$target_workdir"
  set +e
  RUSTC="$rustc_bin" cargo +$nightly fuzz run "$target" \
    "$target_workdir" "$corpus_root/$target" -- \
    -max_total_time="$seconds" -print_final_stats=1 -verbosity=0 \
    >"$output" 2>&1
  exit_code=$?
  set -e
  target_finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  executions=$(awk '/stat::number_of_executed_units:/ { value=$2 } END { print value }' "$output")
  executions_per_second=$(awk '/stat::average_exec_per_sec:/ { value=$2 } END { print value }' "$output")
  [ -n "$executions" ] || executions=0
  [ -n "$executions_per_second" ] || executions_per_second=0
  if [ "$exit_code" -eq 0 ]; then
    campaign_status=passed
  elif [ "$exit_code" -eq 130 ] || [ "$exit_code" -eq 143 ]; then
    campaign_status=interrupted
    report_status=interrupted
  else
    campaign_status=failed
    report_status=failed
  fi
  cp "$output" "$artifacts_dir/$target.log"
  output_sha256=$(sha256_file "$artifacts_dir/$target.log")
  jq -n --arg target "$target" --argjson budget "$seconds" \
    --arg started_at "$target_started" --arg finished_at "$target_finished" \
    --argjson executions "$executions" --argjson eps "$executions_per_second" \
    --arg corpus_sha256 "$corpus_sha256" --arg target_sha256 "$target_sha256" \
    --arg output_path "fuzz-validation-logs/$target.log" --arg output_sha256 "$output_sha256" \
    --arg status "$campaign_status" \
    '{target:$target,budget_seconds:$budget,started_at:$started_at,finished_at:$finished_at,executions:$executions,executions_per_second:$eps,corpus_sha256:$corpus_sha256,target_sha256:$target_sha256,output_path:$output_path,output_sha256:$output_sha256,status:$status}' \
    >>"$temporary/campaigns.jsonl"
  if [ "$campaign_status" != 'passed' ] && [ "$profile" = 'certifying' ]; then
    printf '%s\n' "R13 fuzz: certifying campaign $target ended with status $campaign_status" >&2
    break
  fi
done

# If a subset was requested, warn — the R13 verifier will reject it.
if [ -n "$targets_arg" ]; then
  printf '%s\n' 'R13 fuzz: subset campaign recorded; report will not pass strict verifier'
fi

if [ "$source_sha256" != "$(source_digest)" ]; then
  printf '%s\n' 'R13 fuzz: source changed during campaign' >&2
  report_status=failed
fi

finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
mkdir -p "$(dirname "$report_path")"
jq -s --arg profile "$profile" --arg status "$report_status" \
  --arg started_at "$started_at" --arg finished_at "$finished_at" \
  --arg source_sha256 "$source_sha256" --arg schema_sha256 "$schema_digest" \
  --arg os "$os" --arg arch "$arch" \
  --arg nightly "$nightly" --arg rustc "$rustc_version" \
  --arg cargo_fuzz "$cargo_fuzz_expected" \
  '{schema_version:1,suite_id:"r13/fuzz-validation-v1",profile:$profile,status:$status,started_at:$started_at,finished_at:$finished_at,source_sha256:$source_sha256,schema_sha256:$schema_sha256,platform:{os:$os,arch:$arch},toolchain:{nightly:$nightly,rustc:$rustc,cargo_fuzz:$cargo_fuzz},campaigns:.}' \
  "$temporary/campaigns.jsonl" >"$report_path"

cargo run --quiet --locked -p rados-r13-tools --bin rados-r13-fuzz -- \
  --verify --root "$root" --report "$report_path" --corpus-root "$corpus_root" \
  --profile "$profile"

printf '%s\n' "R13 fuzz $profile validation: $report_path status=$report_status"
