#!/bin/sh
set -eu

usage() {
  printf '%s\n' "usage: $0 --go-root PATH --report PATH" >&2
  exit 2
}

go_root=
report=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --go-root) [ "$#" -ge 2 ] || usage; go_root=$2; shift 2 ;;
    --report) [ "$#" -ge 2 ] || usage; report=$2; shift 2 ;;
    *) usage ;;
  esac
done
[ -n "$go_root" ] && [ -n "$report" ] || usage

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
go_root=$(CDPATH= cd -- "$go_root" && pwd)
case "$report" in /*) ;; *) report="$PWD/$report" ;; esac

for command in awk cargo cp date env git go jq mkdir mktemp perl rustc shasum tr wc; do
  command -v "$command" >/dev/null 2>&1 || { printf '%s\n' "R05 bridge: required command is missing: $command" >&2; exit 1; }
done

expected_go_revision=c8bb148a1379b51ef87256c27f366a05f8da4dc4
expected_go_tree=c5039b6b50a05b942a902f70dc2fcb090463e8c7
[ "$(git -C "$go_root" rev-parse HEAD)" = "$expected_go_revision" ] || { printf '%s\n' 'R05 bridge: Go revision is not pinned' >&2; exit 1; }
[ "$(git -C "$go_root" rev-parse 'HEAD^{tree}')" = "$expected_go_tree" ] || { printf '%s\n' 'R05 bridge: Go tree is not pinned' >&2; exit 1; }
[ -z "$(git -C "$go_root" status --porcelain=v1 --untracked-files=all)" ] || { printf '%s\n' 'R05 bridge: Go oracle must be clean' >&2; exit 1; }

export RUSTUP_TOOLCHAIN=1.98.0
[ "$(rustc --version | awk '{print $1, $2}')" = 'rustc 1.98.0' ] || { printf '%s\n' 'R05 bridge: Rust compiler must be 1.98.0' >&2; exit 1; }
go_target=$(env GOENV=off GOWORK=off GOFLAGS= GOTOOLCHAIN=go1.26.8 go env GOOS)/$(env GOENV=off GOWORK=off GOFLAGS= GOTOOLCHAIN=go1.26.8 go env GOARCH)
go_compiler=$(env GOENV=off GOWORK=off GOFLAGS= GOTOOLCHAIN=go1.26.8 go version)
[ "$go_compiler" = "go version go1.26.8 $go_target" ] || { printf '%s\n' "R05 bridge: Go compiler must be go1.26.8 for $go_target" >&2; exit 1; }

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

bounded_capture() {
  output=$1
  maximum=$2
  seconds=$3
  shift 3
  blocks=$(((maximum + 511) / 512))
  (
    ulimit -f "$blocks"
    exec perl -e '$seconds = shift; alarm $seconds; exec @ARGV' "$seconds" "$@"
  ) >"$output" 2>&1 || return $?
  [ "$(wc -c <"$output" | tr -d ' ')" -le "$maximum" ]
}

bounded_tool_output() {
  output=$1
  maximum=$2
  seconds=$3
  shift 3
  perl -e '$seconds = shift; alarm $seconds; exec @ARGV' "$seconds" "$@" >"$output" 2>&1 || return $?
  [ "$(wc -c <"$output" | tr -d ' ')" -le "$maximum" ]
}

mkdir -p "$root/target/r05/fixtures" "$temporary/cargo-home" "$temporary/rust-target"
printf '%s\n' '[client.r05]' 'key = AQB7AAAAyAEAABAAMTIzNDU2Nzg5MDEyMzQ1Ng==' >"$root/target/r05/fixtures/keyring"
cp "$root/target/r05/fixtures/keyring" "$root/target/r05/fixtures/r05.client.r05.keyring"

bounded_tool_output "$temporary/rust-build.txt" 8388608 300 env \
  -u CARGO_BUILD_RUSTC -u CARGO_BUILD_RUSTC_WRAPPER -u CARGO_ENCODED_RUSTFLAGS \
  -u RUSTC -u RUSTC_WRAPPER -u RUSTFLAGS -u RUSTDOCFLAGS \
  RUSTUP_TOOLCHAIN=1.98.0 CARGO_HOME="$temporary/cargo-home" CARGO_TARGET_DIR="$temporary/rust-target" \
  cargo build --manifest-path "$root/Cargo.toml" -p rados-r05-tools --bin rados-r05-verify --locked || {
  cat "$temporary/rust-build.txt" >&2
  printf '%s\n' 'R05 bridge: controlled Rust build failed, timed out, or exceeded output bound' >&2
  exit 1
}
cp "$temporary/rust-target/debug/rados-r05-verify" "$root/target/r05/rados-r05-verify"
verifier="$root/target/r05/rados-r05-verify"
rust_source_before=$($verifier rust-source-digest "$root")
bounded_tool_output "$temporary/rust-probe-build.txt" 8388608 300 env \
  -u CARGO_BUILD_RUSTC -u CARGO_BUILD_RUSTC_WRAPPER -u CARGO_ENCODED_RUSTFLAGS \
  -u RUSTC -u RUSTC_WRAPPER -u RUSTFLAGS -u RUSTDOCFLAGS \
  RUSTUP_TOOLCHAIN=1.98.0 CARGO_HOME="$temporary/cargo-home" CARGO_TARGET_DIR="$temporary/rust-target" \
  cargo build --manifest-path "$root/Cargo.toml" -p rados-r05-tools --bin rados-r05-probe --locked || {
  cat "$temporary/rust-probe-build.txt" >&2
  printf '%s\n' 'R05 bridge: controlled Rust probe build failed, timed out, or exceeded output bound' >&2
  exit 1
}
cp "$temporary/rust-target/debug/rados-r05-probe" "$root/target/r05/rados-r05-probe"

git clone --quiet --no-hardlinks "$go_root" "$temporary/go"
[ "$(git -C "$temporary/go" rev-parse HEAD)" = "$expected_go_revision" ]
[ "$(git -C "$temporary/go" rev-parse 'HEAD^{tree}')" = "$expected_go_tree" ]
mkdir -p "$temporary/go/tools/rados-rs-r05-probe"
cp "$root/tools/r05/go-probe/main.go" "$root/tools/r05/go-probe/main_test.go" "$temporary/go/tools/rados-rs-r05-probe/"

bounded_tool_output "$temporary/go-test.txt" 65536 120 env GOENV=off GOWORK=off GOFLAGS= GOTOOLCHAIN=go1.26.8 \
  RADOS_R05_FIXTURE_ROOT="$root" RADOS_R05_CLUSTER=env-cluster RADOS_R05_ENTITY=client.env \
  RADOS_R05_MON_HOST='v1:192.0.2.20:6789,v2:192.0.2.21:3300' RADOS_R05_OPERATION_TIMEOUT=2.5s \
  go test -C "$temporary/go" ./tools/rados-rs-r05-probe -count=1 || {
  cat "$temporary/go-test.txt" >&2
  printf '%s\n' 'R05 bridge: Go adapter tests failed, timed out, or exceeded output bound' >&2
  exit 1
}
bounded_tool_output "$temporary/go-build.txt" 1048576 300 env GOENV=off GOWORK=off GOFLAGS= GOTOOLCHAIN=go1.26.8 \
  go build -C "$temporary/go" -o "$root/target/r05/rados-r05-go-probe" ./tools/rados-rs-r05-probe || {
  cat "$temporary/go-build.txt" >&2
  printf '%s\n' 'R05 bridge: controlled Go build failed, timed out, or exceeded output bound' >&2
  exit 1
}

rust_probe="$root/target/r05/rados-r05-probe"
go_probe="$root/target/r05/rados-r05-go-probe"
test "$rust_source_before" = "$($verifier rust-source-digest "$root")" || {
  printf '%s\n' 'R05 bridge: Rust source changed during controlled build' >&2
  exit 1
}
request="$temporary/request.json"
"$verifier" default-request "$root" >"$request"

rust_result="$temporary/rust.jsonl"
go_result="$temporary/go.jsonl"
fixed_env="RADOS_R05_CLUSTER=env-cluster RADOS_R05_ENTITY=client.env RADOS_R05_MON_HOST=v1:192.0.2.20:6789,v2:192.0.2.21:3300 RADOS_R05_OPERATION_TIMEOUT=2.5s"
bounded_capture "$rust_result" 229376 30 env $fixed_env "$rust_probe" <"$request" || { printf '%s\n' 'R05 bridge: Rust probe failed, timed out, or exceeded output bound' >&2; exit 1; }
bounded_capture "$go_result" 229376 30 env $fixed_env "$go_probe" --fixture-root "$root" <"$request" || { printf '%s\n' 'R05 bridge: Go probe failed, timed out, or exceeded output bound' >&2; exit 1; }
[ "$(wc -l <"$rust_result" | tr -d ' ')" -eq 14 ] && [ "$(wc -l <"$go_result" | tr -d ' ')" -eq 14 ] || { printf '%s\n' 'R05 bridge: probes must emit exactly fourteen records' >&2; exit 1; }
test "$rust_source_before" = "$($verifier rust-source-digest "$root")" || {
  printf '%s\n' 'R05 bridge: Rust source changed during qualification' >&2
  exit 1
}

sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
rust_revision=$(git -C "$root" rev-parse HEAD)
rust_tree=$(git -C "$root" rev-parse 'HEAD^{tree}')
rust_target=$(rustc -vV | awk '/^host: / {print $2}')
schema="$root/integration/r05/report.schema.json"
controller="$root/integration/r05/reproduce.sh"
mkdir -p "$(dirname "$report")"

jq -n \
  --slurpfile request "$request" --slurpfile rust_records "$rust_result" --slurpfile go_records "$go_result" \
  --arg generated_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" --arg rust_revision "$rust_revision" --arg rust_tree "$rust_tree" \
  --arg rust_source "$rust_source_before" --arg rust_lock "$(sha256_file "$root/Cargo.lock")" \
  --arg rust_compiler "$(rustc --version)" --arg rust_target "$rust_target" --arg rust_probe "$rust_probe" \
  --arg rust_binary "$(sha256_file "$rust_probe")" --arg rust_stdout "$(sha256_file "$rust_result")" \
  --arg go_source "$($verifier go-source-digest "$go_root")" --arg go_lock "$(sha256_file "$go_root/go.sum")" \
  --arg go_compiler "$go_compiler" --arg go_target "$go_target" --arg go_probe "$go_probe" \
  --arg go_binary "$(sha256_file "$go_probe")" --arg go_stdout "$(sha256_file "$go_result")" \
  --arg adapter_sha "$($verifier path-digest "$root" tools/r05/go-probe)" --arg schema_sha "$(sha256_file "$schema")" \
  --arg controller_sha "$(sha256_file "$controller")" --arg go_root "$go_root" --arg report "$report" --arg root "$root" \
  --arg mon_manifest "$(sha256_file "$root/testdata/p04/monmap-v9.bin.manifest.json")" \
  --arg osd_manifest "$(sha256_file "$root/testdata/p04/osdmap-v8.bin.manifest.json")" \
  --arg inc_manifest "$(sha256_file "$root/testdata/p04/osdmap-incremental-v8.bin.manifest.json")" \
  '{schema_version:1,suite_id:"r05/config-maps-v1",status:"passed",generated_at:$generated_at,bounds:$request[0].bounds,
    fixtures:[$request[0].cases[] | . + {manifest_path:(if .path == null then null else (.path + ".manifest.json") end),manifest_sha256:(if .path == "testdata/p04/monmap-v9.bin" then $mon_manifest elif .path == "testdata/p04/osdmap-v8.bin" then $osd_manifest elif .path == "testdata/p04/osdmap-incremental-v8.bin" then $inc_manifest else null end)}],
    rust:{implementation_id:"rust",source_revision:$rust_revision,source_tree:$rust_tree,source_files_sha256:$rust_source,lockfile_sha256:$rust_lock,compiler:$rust_compiler,target:$rust_target,binary_path:$rust_probe,binary_sha256:$rust_binary,command:[$rust_probe],exit_code:0,stdout_sha256:$rust_stdout,records:$rust_records},
    go:{implementation_id:"go",source_revision:"c8bb148a1379b51ef87256c27f366a05f8da4dc4",source_tree:"c5039b6b50a05b942a902f70dc2fcb090463e8c7",source_files_sha256:$go_source,lockfile_sha256:$go_lock,compiler:$go_compiler,target:$go_target,binary_path:$go_probe,binary_sha256:$go_binary,command:[$go_probe,"--fixture-root",$root],exit_code:0,stdout_sha256:$go_stdout,records:$go_records},
    artifacts:{adapter_path:"tools/r05/go-probe",adapter_sha256:$adapter_sha,schema_path:"integration/r05/report.schema.json",schema_sha256:$schema_sha},
    controller:{path:"integration/r05/reproduce.sh",sha256:$controller_sha,command:["integration/r05/reproduce.sh","--go-root",$go_root,"--report",$report]}}' >"$report"

env $fixed_env "$verifier" verify "$root" "$report"
printf '%s\n' "R05 deterministic config/map bridge passed: $report"