#!/bin/sh
set -eu

usage() {
  printf '%s\n' "usage: $0 --go-root PATH --rust-probe PATH --verifier PATH --report PATH" >&2
  exit 2
}

go_root=
rust_probe=
verifier=
report=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --go-root) [ "$#" -ge 2 ] || usage; go_root=$2; shift 2 ;;
    --rust-probe) [ "$#" -ge 2 ] || usage; rust_probe=$2; shift 2 ;;
    --verifier) [ "$#" -ge 2 ] || usage; verifier=$2; shift 2 ;;
    --report) [ "$#" -ge 2 ] || usage; report=$2; shift 2 ;;
    *) usage ;;
  esac
done
[ -n "$go_root" ] && [ -n "$rust_probe" ] && [ -n "$verifier" ] && [ -n "$report" ] || usage

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
go_root=$(CDPATH= cd -- "$go_root" && pwd)
export RUSTUP_TOOLCHAIN=1.98.0
git -C "$root" diff --quiet && git -C "$root" diff --cached --quiet &&
  [ -z "$(git -C "$root" ls-files --others --exclude-standard)" ] || {
  printf '%s\n' 'R03 bridge: Rust candidate must be a clean committed tree' >&2
  exit 1
}
git -C "$go_root" diff --quiet && git -C "$go_root" diff --cached --quiet &&
  [ -z "$(git -C "$go_root" ls-files --others --exclude-standard)" ] || {
  printf '%s\n' 'R03 bridge: Go oracle must be a clean committed tree' >&2
  exit 1
}

case "$rust_probe" in /*) ;; *) rust_probe="$PWD/$rust_probe" ;; esac
case "$verifier" in /*) ;; *) verifier="$PWD/$verifier" ;; esac
case "$report" in /*) ;; *) report="$PWD/$report" ;; esac
expected_probe="$root/target/r03/rados-r03-probe"
expected_verifier="$root/target/r03/rados-r03-verify"
[ "$rust_probe" = "$expected_probe" ] && [ "$verifier" = "$expected_verifier" ] || {
  printf '%s\n' 'R03 bridge: Rust tools must use the controlled target/r03 paths' >&2
  exit 1
}
for command in awk cargo cp date env git go jq mkdir perl shasum rustc sed tr wc; do
  command -v "$command" >/dev/null 2>&1 || { printf '%s\n' "R03 bridge: required command is missing: $command" >&2; exit 1; }
done
[ "$(rustc --version | awk '{print $1, $2}')" = "rustc 1.98.0" ] || {
  printf '%s\n' 'R03 bridge: Rust compiler must be 1.98.0' >&2
  exit 1
}

expected_go_revision=c8bb148a1379b51ef87256c27f366a05f8da4dc4
expected_go_tree=c5039b6b50a05b942a902f70dc2fcb090463e8c7
[ "$(git -C "$go_root" rev-parse HEAD)" = "$expected_go_revision" ] || { printf '%s\n' 'R03 bridge: Go revision is not pinned' >&2; exit 1; }
[ "$(git -C "$go_root" rev-parse 'HEAD^{tree}')" = "$expected_go_tree" ] || { printf '%s\n' 'R03 bridge: Go tree is not pinned' >&2; exit 1; }
go_target=$(env GOENV=off GOWORK=off GOFLAGS= GOTOOLCHAIN=local go env GOOS)/$(env GOENV=off GOWORK=off GOFLAGS= GOTOOLCHAIN=local go env GOARCH)
expected_go_version="go version go1.26.8 $go_target"
[ "$(env GOENV=off GOWORK=off GOFLAGS= GOTOOLCHAIN=local go version)" = "$expected_go_version" ] || { printf '%s\n' "R03 bridge: Go compiler must be $expected_go_version" >&2; exit 1; }

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

capture() {
  output=$1
  maximum=$2
  shift 2
  blocks=$(((maximum + 511) / 512))
  (
    ulimit -f "$blocks"
    exec perl -e '$seconds = shift; alarm $seconds; exec @ARGV' 300 "$@"
  ) > "$output" 2>&1 || return $?
  bytes=$(wc -c < "$output" | tr -d ' ')
  [ "$bytes" -le "$maximum" ]
}

capture_tool_output() {
  output=$1
  maximum=$2
  shift 2
  perl -e '$seconds = shift; alarm $seconds; exec @ARGV' 300 "$@" > "$output" 2>&1 || return $?
  bytes=$(wc -c < "$output" | tr -d ' ')
  [ "$bytes" -le "$maximum" ]
}

build_output="$temporary/rust-build.txt"
mkdir -p "$temporary/cargo-home"
capture_tool_output "$build_output" 1048576 env \
  -u CARGO_BUILD_RUSTC -u CARGO_BUILD_RUSTC_WRAPPER -u CARGO_ENCODED_RUSTFLAGS \
  -u RUSTC -u RUSTC_WRAPPER -u RUSTFLAGS -u RUSTDOCFLAGS \
  RUSTUP_TOOLCHAIN="$RUSTUP_TOOLCHAIN" CARGO_HOME="$temporary/cargo-home" CARGO_TARGET_DIR="$temporary/rust-target" \
  cargo build -p rados-r03-tools --bins --locked || {
  cat "$build_output" >&2
  printf '%s\n' 'R03 bridge: controlled Rust tool build failed, timed out, or exceeded 1048576 bytes' >&2
  exit 1
}
mkdir -p "$root/target/r03"
cp "$temporary/rust-target/debug/rados-r03-probe" "$rust_probe"
cp "$temporary/rust-target/debug/rados-r03-verify" "$verifier"

git clone --quiet --no-hardlinks "$go_root" "$temporary/go"
[ "$(git -C "$temporary/go" rev-parse HEAD)" = "$expected_go_revision" ]
[ "$(git -C "$temporary/go" rev-parse 'HEAD^{tree}')" = "$expected_go_tree" ]
adapter="$temporary/go/tools/rados-rs-r03-probe"
fixture_root="$adapter/fixtures"
mkdir -p "$fixture_root/testdata/p02/upstream"
cp "$root/tools/r03/go-probe/main.go" "$root/tools/r03/go-probe/main_test.go" "$adapter/"
cp "$root/testdata/p02/banner-rev1.bin" "$fixture_root/testdata/p02/"
cp "$root/testdata/p02/upstream/upstream-crc-four-segment.bin" \
  "$root/testdata/p02/upstream/upstream-secure-one-segment.bin" \
  "$root/testdata/p02/upstream/upstream-ack-control.bin" \
  "$root/testdata/p02/upstream/upstream-message-frame.bin" \
  "$fixture_root/testdata/p02/upstream/"

session_sha=$(printf 'start-ready\nstop\n' | shasum -a 256 | awk '{print $1}')
request="$temporary/request.jsonl"
jq -nc --arg session_sha "$session_sha" '{schema_version:1,suite_id:"r03/messenger-transcript-v1",implementation_ids:["rust","go"],cases:[{case_id:"banner",path:"testdata/p02/banner-rev1.bin",sha256:"6819c56d3d3d3ccaa0545a80d55aaa8088d88e9f849113cdafa58feb298cfcca"},{case_id:"crc-frame",path:"testdata/p02/upstream/upstream-crc-four-segment.bin",sha256:"0fa63a785151214c426f128141faf3969eb0be008b9229505ab7146401dd8c42"},{case_id:"secure-frame",path:"testdata/p02/upstream/upstream-secure-one-segment.bin",sha256:"592152e22495cecb210cf5a7bfefac49f6cdd8bbbb14e223db3538bef0b3926d"},{case_id:"control-ack",path:"testdata/p02/upstream/upstream-ack-control.bin",sha256:"2496a22ad0abda5947019dcdbd5dfe482eab124a649d302cba119df923a6ce70"},{case_id:"message-frame",path:"testdata/p02/upstream/upstream-message-frame.bin",sha256:"00a22987b019e085cf811b10852000116e3c63adc33bf86729485a2ecb81ff26"},{case_id:"session-transition",path:null,sha256:$session_sha}],bounds:{max_record_bytes:16384,max_records:6,max_input_bytes:4096,max_output_bytes:8192}}' > "$request"

test_output="$temporary/go-test.txt"
capture_tool_output "$test_output" 65536 env GOENV=off GOWORK=off GOFLAGS= GOTOOLCHAIN=local sh -c 'cd "$1" && RADOS_R03_FIXTURE_ROOT=$2 exec go test ./tools/rados-rs-r03-probe -count=1' sh "$temporary/go" "$fixture_root" || {
  cat "$test_output" >&2
  printf '%s\n' 'R03 bridge: Go adapter tests failed or exceeded 65536 bytes' >&2
  exit 1
}
rust_result="$temporary/rust-result.jsonl"
capture "$rust_result" 98304 sh -c 'cd "$1" && exec "$2" < "$3"' sh "$root" "$rust_probe" "$request" || {
  printf '%s\n' 'R03 bridge: Rust probe failed or exceeded 98304 bytes' >&2
  exit 1
}
go_result="$temporary/go-result.jsonl"
capture_tool_output "$go_result" 98304 env GOENV=off GOWORK=off GOFLAGS= GOTOOLCHAIN=local sh -c 'cd "$1" && exec go run ./tools/rados-rs-r03-probe --fixture-root ./tools/rados-rs-r03-probe/fixtures < "$2"' sh "$temporary/go" "$request" || {
  printf '%s\n' 'R03 bridge: Go probe failed or exceeded 98304 bytes' >&2
  exit 1
}
[ "$(wc -l < "$rust_result" | tr -d ' ')" -eq 6 ] && [ "$(wc -l < "$go_result" | tr -d ' ')" -eq 6 ] || {
  printf '%s\n' 'R03 bridge: probes must emit exactly six records' >&2
  exit 1
}

sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
manifest_sha() { sha256_file "$root/$1.json"; }
rust_revision=$(git -C "$root" rev-parse HEAD)
rust_tree=$(git -C "$root" rev-parse 'HEAD^{tree}')
rust_target=$(rustc -vV | sed -n 's/^host: //p')
generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
controller="$root/integration/r03/reproduce.sh"
schema="$root/integration/r03/report.schema.json"
adapter_sha256=$("$verifier" path-digest "$root" tools/r03/go-probe)
mkdir -p "$(dirname "$report")"

jq -n \
  --slurpfile rust_records "$rust_result" --slurpfile go_records "$go_result" \
  --arg generated_at "$generated_at" --arg session_sha "$session_sha" \
  --arg rust_revision "$rust_revision" --arg rust_tree "$rust_tree" \
  --arg rust_source_files_sha256 "$("$verifier" rust-source-digest "$root")" \
  --arg rust_lockfile_sha256 "$(sha256_file "$root/Cargo.lock")" --arg rust_compiler "$(rustc --version)" --arg rust_target "$rust_target" \
  --arg rust_probe "$rust_probe" --arg rust_driver_sha256 "$(sha256_file "$rust_probe")" --arg rust_stdout_sha256 "$(sha256_file "$rust_result")" \
  --arg go_source_files_sha256 "$("$verifier" go-source-digest "$go_root")" --arg go_lockfile_sha256 "$(sha256_file "$go_root/go.sum")" \
  --arg go_compiler "$(env GOENV=off GOWORK=off GOFLAGS= GOTOOLCHAIN=local go version)" --arg go_target "$go_target" --arg adapter_sha256 "$adapter_sha256" --arg go_stdout_sha256 "$(sha256_file "$go_result")" \
  --arg banner_manifest "$(manifest_sha testdata/p02/banner-rev1.bin)" \
  --arg crc_manifest "$(manifest_sha testdata/p02/upstream/upstream-crc-four-segment.bin)" \
  --arg secure_manifest "$(manifest_sha testdata/p02/upstream/upstream-secure-one-segment.bin)" \
  --arg ack_manifest "$(manifest_sha testdata/p02/upstream/upstream-ack-control.bin)" \
  --arg message_manifest "$(manifest_sha testdata/p02/upstream/upstream-message-frame.bin)" \
  --arg schema_sha256 "$(sha256_file "$schema")" --arg controller_sha256 "$(sha256_file "$controller")" \
  --arg go_root "$go_root" --arg verifier "$verifier" --arg report "$report" \
  '{schema_version:1,suite_id:"r03/messenger-transcript-v1",status:"passed",generated_at:$generated_at,bounds:{max_record_bytes:16384,max_records:6,max_input_bytes:4096,max_output_bytes:8192},fixtures:[
    {case_id:"banner",path:"testdata/p02/banner-rev1.bin",sha256:"6819c56d3d3d3ccaa0545a80d55aaa8088d88e9f849113cdafa58feb298cfcca",manifest_path:"testdata/p02/banner-rev1.bin.json",manifest_sha256:$banner_manifest},
    {case_id:"crc-frame",path:"testdata/p02/upstream/upstream-crc-four-segment.bin",sha256:"0fa63a785151214c426f128141faf3969eb0be008b9229505ab7146401dd8c42",manifest_path:"testdata/p02/upstream/upstream-crc-four-segment.bin.json",manifest_sha256:$crc_manifest},
    {case_id:"secure-frame",path:"testdata/p02/upstream/upstream-secure-one-segment.bin",sha256:"592152e22495cecb210cf5a7bfefac49f6cdd8bbbb14e223db3538bef0b3926d",manifest_path:"testdata/p02/upstream/upstream-secure-one-segment.bin.json",manifest_sha256:$secure_manifest},
    {case_id:"control-ack",path:"testdata/p02/upstream/upstream-ack-control.bin",sha256:"2496a22ad0abda5947019dcdbd5dfe482eab124a649d302cba119df923a6ce70",manifest_path:"testdata/p02/upstream/upstream-ack-control.bin.json",manifest_sha256:$ack_manifest},
    {case_id:"message-frame",path:"testdata/p02/upstream/upstream-message-frame.bin",sha256:"00a22987b019e085cf811b10852000116e3c63adc33bf86729485a2ecb81ff26",manifest_path:"testdata/p02/upstream/upstream-message-frame.bin.json",manifest_sha256:$message_manifest},
    {case_id:"session-transition",path:null,sha256:$session_sha,manifest_path:null,manifest_sha256:null}],
    rust:{implementation_id:"rust",source_revision:$rust_revision,source_tree:$rust_tree,source_files_sha256:$rust_source_files_sha256,lockfile_sha256:$rust_lockfile_sha256,compiler:$rust_compiler,target:$rust_target,driver_sha256:$rust_driver_sha256,command:[$rust_probe],exit_code:0,stdout_sha256:$rust_stdout_sha256,records:$rust_records},
    go:{implementation_id:"go",source_revision:"c8bb148a1379b51ef87256c27f366a05f8da4dc4",source_tree:"c5039b6b50a05b942a902f70dc2fcb090463e8c7",source_files_sha256:$go_source_files_sha256,lockfile_sha256:$go_lockfile_sha256,compiler:$go_compiler,target:$go_target,driver_sha256:$adapter_sha256,command:["go","run","./tools/rados-rs-r03-probe","--fixture-root","./tools/rados-rs-r03-probe/fixtures"],exit_code:0,stdout_sha256:$go_stdout_sha256,records:$go_records},
    artifacts:{adapter_path:"tools/r03/go-probe",adapter_sha256:$adapter_sha256,schema_path:"integration/r03/report.schema.json",schema_sha256:$schema_sha256},
    controller:{path:"integration/r03/reproduce.sh",sha256:$controller_sha256,command:["integration/r03/reproduce.sh","--go-root",$go_root,"--rust-probe",$rust_probe,"--verifier",$verifier,"--report",$report]}}' > "$report"

env GOENV=off GOWORK=off GOFLAGS= GOTOOLCHAIN=local "$verifier" verify "$root" "$report"
printf '%s\n' "R03 Rust/Go messenger bridge passed: $report"