#!/bin/sh
set -eu

usage() { printf '%s\n' "usage: $0 --go-root PATH --report PATH" >&2; exit 2; }
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
case "$report" in "$root/target/r06/"*) ;; *) printf '%s\n' 'R06 bridge: report must be under target/r06' >&2; exit 1 ;; esac

for command in awk cargo cp date env git go jq mkdir mktemp perl rustc shasum tr wc; do command -v "$command" >/dev/null 2>&1 || { printf '%s\n' "R06 bridge: missing command: $command" >&2; exit 1; }; done
expected_revision=c8bb148a1379b51ef87256c27f366a05f8da4dc4
expected_tree=c5039b6b50a05b942a902f70dc2fcb090463e8c7
check_go() { [ "$(git -C "$go_root" rev-parse HEAD)" = "$expected_revision" ] && [ "$(git -C "$go_root" rev-parse 'HEAD^{tree}')" = "$expected_tree" ] && [ -z "$(git -C "$go_root" status --porcelain=v1 --untracked-files=all)" ]; }
check_go || { printf '%s\n' 'R06 bridge: Go oracle must be the clean pinned revision and tree' >&2; exit 1; }
export RUSTUP_TOOLCHAIN=1.98.0
[ "$(rustc --version | awk '{print $1, $2}')" = 'rustc 1.98.0' ] || { printf '%s\n' 'R06 bridge: Rust compiler must be 1.98.0' >&2; exit 1; }
go_target=$(env GOENV=off GOWORK=off GOFLAGS= GOTOOLCHAIN=go1.26.8 go env GOOS)/$(env GOENV=off GOWORK=off GOFLAGS= GOTOOLCHAIN=go1.26.8 go env GOARCH)
go_compiler=$(env GOENV=off GOWORK=off GOFLAGS= GOTOOLCHAIN=go1.26.8 go version)
[ "$go_compiler" = "go version go1.26.8 $go_target" ] || { printf '%s\n' 'R06 bridge: Go compiler must be go1.26.8' >&2; exit 1; }

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
bounded() { output=$1; maximum=$2; seconds=$3; shift 3; blocks=$(((maximum + 511) / 512)); (ulimit -f "$blocks"; exec perl -e '$seconds=shift; alarm $seconds; exec @ARGV' "$seconds" "$@") >"$output" 2>&1 || return $?; [ "$(wc -c <"$output" | tr -d ' ')" -le "$maximum" ]; }
bounded_tool() { output=$1; maximum=$2; seconds=$3; shift 3; perl -e '$seconds=shift; alarm $seconds; exec @ARGV' "$seconds" "$@" >"$output" 2>&1 || return $?; [ "$(wc -c <"$output" | tr -d ' ')" -le "$maximum" ]; }
sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }

rust_target="$root/target/r06/source-build"
mkdir -p "$root/target/r06"
bounded_tool "$temporary/rust-clean.txt" 1048576 120 env -u RUSTC -u RUSTC_WRAPPER -u RUSTFLAGS -u RUSTDOCFLAGS RUSTUP_TOOLCHAIN=1.98.0 cargo clean --manifest-path "$root/Cargo.toml" -p rados-r06-tools --target-dir "$rust_target" || { cat "$temporary/rust-clean.txt" >&2; exit 1; }
bounded_tool "$temporary/rust-build.txt" 8388608 300 env -u RUSTC -u RUSTC_WRAPPER -u RUSTFLAGS -u RUSTDOCFLAGS RUSTUP_TOOLCHAIN=1.98.0 cargo build --manifest-path "$root/Cargo.toml" -p rados-r06-tools --bins --locked --target-dir "$rust_target" || { cat "$temporary/rust-build.txt" >&2; exit 1; }
cp "$rust_target/debug/rados-r06-probe" "$rust_target/debug/rados-r06-verify" "$root/target/r06/"
verifier="$root/target/r06/rados-r06-verify"
rust_before=$($verifier rust-source-digest "$root")
go_before=$($verifier go-source-digest "$go_root")

git clone --quiet --no-hardlinks "$go_root" "$temporary/go"
[ "$(git -C "$temporary/go" rev-parse HEAD)" = "$expected_revision" ] && [ "$(git -C "$temporary/go" rev-parse 'HEAD^{tree}')" = "$expected_tree" ]
git -C "$temporary/go" apply "$root/tools/r06/go-probe/placement.patch"
mkdir -p "$temporary/go/tools/rados-rs-r06-probe"
cp "$root/tools/r06/go-probe/main.go" "$root/tools/r06/go-probe/main_test.go" "$temporary/go/tools/rados-rs-r06-probe/"
cp "$root/tools/r06/go-probe/maps_adapter.go.in" "$temporary/go/internal/maps/r06_adapter.go"
bounded_tool "$temporary/go-test.txt" 1048576 120 env GOENV=off GOWORK=off GOFLAGS= GOTOOLCHAIN=go1.26.8 RADOS_R06_FIXTURE_ROOT="$root" go test -C "$temporary/go" ./tools/rados-rs-r06-probe -count=1 || { cat "$temporary/go-test.txt" >&2; exit 1; }
bounded_tool "$temporary/go-build.txt" 1048576 300 env GOENV=off GOWORK=off GOFLAGS= GOTOOLCHAIN=go1.26.8 go build -C "$temporary/go" -trimpath -o "$root/target/r06/rados-r06-go-probe" ./tools/rados-rs-r06-probe || { cat "$temporary/go-build.txt" >&2; exit 1; }

request="$temporary/request.json"; "$verifier" default-request "$root" >"$request"
rust_output="$temporary/rust.jsonl"; go_output="$temporary/go.jsonl"
bounded "$rust_output" 131072 30 "$root/target/r06/rados-r06-probe" <"$request" || { printf '%s\n' 'R06 bridge: Rust probe failed or exceeded bounds' >&2; exit 1; }
bounded "$go_output" 131072 30 "$root/target/r06/rados-r06-go-probe" --fixture-root "$root" <"$request" || { printf '%s\n' 'R06 bridge: Go probe failed or exceeded bounds' >&2; exit 1; }
[ "$(wc -l <"$rust_output" | tr -d ' ')" -eq 11 ] && [ "$(wc -l <"$go_output" | tr -d ' ')" -eq 11 ] || { printf '%s\n' 'R06 bridge: probes must emit eleven records' >&2; exit 1; }
rust_after=$($verifier rust-source-digest "$root"); go_after=$($verifier go-source-digest "$go_root")
[ "$rust_before" = "$rust_after" ] && [ "$go_before" = "$go_after" ] && check_go || { printf '%s\n' 'R06 bridge: source changed during qualification' >&2; exit 1; }

fixtures="$temporary/fixtures.jsonl"
: >"$fixtures"
fixture() { path=$1; manifest=${2-}; if [ -n "$manifest" ]; then jq -nc --arg path "$path" --arg sha "$(sha256_file "$root/$path")" --arg manifest "$manifest" --arg manifest_sha "$(sha256_file "$root/$manifest")" '{path:$path,sha256:$sha,manifest_path:$manifest,manifest_sha256:$manifest_sha}' >>"$fixtures"; else jq -nc --arg path "$path" --arg sha "$(sha256_file "$root/$path")" '{path:$path,sha256:$sha,manifest_path:null,manifest_sha256:null}' >>"$fixtures"; fi; }
fixture testdata/r06/p05/crushmap.bin testdata/r06/p05/crushmap.bin.manifest.json
fixture testdata/r06/p05/mappings.txt testdata/r06/p05/mappings.txt.manifest.json
fixture testdata/r06/p05/mappings-osd1-out.txt testdata/r06/p05/mappings-osd1-out.txt.manifest.json
fixture testdata/r06/p05/object-mappings.txt testdata/r06/p05/object-mappings.txt.manifest.json
fixture testdata/r06/p05/object-mappings-pg32.txt testdata/r06/p05/object-mappings-pg32.txt.manifest.json
fixture testdata/r06/p05/object-mappings-osd1-out.txt testdata/r06/p05/object-mappings-osd1-out.txt.manifest.json
fixture testdata/r06/p05/object-mappings-upmap.txt testdata/r06/p05/object-mappings-upmap.txt.manifest.json
fixture testdata/r06/p05/upmap-commands.txt testdata/r06/p05/upmap-commands.txt.manifest.json
fixture testdata/r06/p10/crushmap.bin testdata/r06/p10/crushmap.bin.manifest.json
fixture testdata/r06/p10/mappings.txt testdata/r06/p10/mappings.txt.manifest.json
fixture testdata/r06/p10/mappings-osd1-out.txt testdata/r06/p10/mappings-osd1-out.txt.manifest.json
fixture testdata/r06/p10/object-placements.jsonl testdata/r06/p10/object-placements.jsonl.manifest.json
fixture testdata/r06/p10/object-placements-osd1-out.jsonl testdata/r06/p10/object-placements-osd1-out.jsonl.manifest.json
fixture testdata/r06/p10/object-placements-primary-affinity.jsonl testdata/r06/p10/object-placements-primary-affinity.jsonl.manifest.json

mkdir -p "$(dirname "$report")"
rust_probe="$root/target/r06/rados-r06-probe"; go_probe="$root/target/r06/rados-r06-go-probe"
jq -n --slurpfile request "$request" --slurpfile fixtures "$fixtures" --slurpfile rust_records "$rust_output" --slurpfile go_records "$go_output" \
  --arg generated_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" --arg rust_revision "$(git -C "$root" rev-parse HEAD)" --arg rust_tree "$(git -C "$root" rev-parse 'HEAD^{tree}')" \
  --arg rust_before "$rust_before" --arg rust_after "$rust_after" --arg rust_lock "$(sha256_file "$root/Cargo.lock")" --arg rust_compiler "$(rustc --version)" --arg rust_target "$(rustc -vV | awk '/^host: / {print $2}')" --arg rust_probe "$rust_probe" --arg rust_binary "$(sha256_file "$rust_probe")" --arg rust_stdout "$(sha256_file "$rust_output")" \
  --arg go_before "$go_before" --arg go_after "$go_after" --arg go_lock "$(sha256_file "$go_root/go.sum")" --arg go_compiler "$go_compiler" --arg go_target "$go_target" --arg go_probe "$go_probe" --arg go_binary "$(sha256_file "$go_probe")" --arg go_stdout "$(sha256_file "$go_output")" \
  --arg adapter_sha "$($verifier path-digest "$root" tools/r06/go-probe)" --arg schema_sha "$(sha256_file "$root/integration/r06/report.schema.json")" --arg controller_sha "$(sha256_file "$root/integration/r06/reproduce.sh")" --arg go_root "$go_root" --arg report "$report" --arg root "$root" \
  '{schema_version:1,suite_id:"r06/placement-v1",status:"passed",generated_at:$generated_at,bounds:$request[0].bounds,fixtures:$fixtures,
    rust:{implementation_id:"rust",source_revision:$rust_revision,source_tree:$rust_tree,source_before_sha256:$rust_before,source_after_sha256:$rust_after,lockfile_sha256:$rust_lock,compiler:$rust_compiler,target:$rust_target,binary_path:$rust_probe,binary_sha256:$rust_binary,command:[$rust_probe],exit_code:0,stdout_sha256:$rust_stdout,records:$rust_records},
    go:{implementation_id:"go",source_revision:"c8bb148a1379b51ef87256c27f366a05f8da4dc4",source_tree:"c5039b6b50a05b942a902f70dc2fcb090463e8c7",source_before_sha256:$go_before,source_after_sha256:$go_after,lockfile_sha256:$go_lock,compiler:$go_compiler,target:$go_target,binary_path:$go_probe,binary_sha256:$go_binary,command:[$go_probe,"--fixture-root",$root],exit_code:0,stdout_sha256:$go_stdout,records:$go_records},
    artifacts:{adapter_path:"tools/r06/go-probe",adapter_sha256:$adapter_sha,schema_path:"integration/r06/report.schema.json",schema_sha256:$schema_sha},controller:{path:"integration/r06/reproduce.sh",sha256:$controller_sha,command:["integration/r06/reproduce.sh","--go-root",$go_root,"--report",$report]}}' >"$report"

"$verifier" verify "$root" "$report"
printf '%s\n' "R06 deterministic placement bridge passed: $report"