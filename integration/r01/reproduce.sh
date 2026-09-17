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
git -C "$root" diff --quiet && git -C "$root" diff --cached --quiet &&
  [ -z "$(git -C "$root" ls-files --others --exclude-standard)" ] || {
  printf '%s\n' 'R01 bridge: Rust candidate must be a clean committed tree' >&2
  exit 1
}
git -C "$go_root" diff --quiet && git -C "$go_root" diff --cached --quiet &&
  [ -z "$(git -C "$go_root" ls-files --others --exclude-standard)" ] || {
  printf '%s\n' 'R01 bridge: Go oracle must be a clean committed tree' >&2
  exit 1
}
case "$rust_probe" in /*) ;; *) rust_probe="$PWD/$rust_probe" ;; esac
case "$verifier" in /*) ;; *) verifier="$PWD/$verifier" ;; esac
[ -x "$rust_probe" ] || { printf '%s\n' "R01 bridge: Rust probe is missing or not executable: $rust_probe" >&2; exit 1; }
[ -x "$verifier" ] || { printf '%s\n' "R01 bridge: verifier is missing or not executable: $verifier" >&2; exit 1; }

for command in git go head jq shasum rustc date; do
  command -v "$command" >/dev/null 2>&1 || { printf '%s\n' "R01 bridge: required command is missing: $command" >&2; exit 1; }
done
go_target=$(go env GOOS)/$(go env GOARCH)
expected_go_version="go version go1.26.8 $go_target"
actual_go_version=$(go version)
[ "$actual_go_version" = "$expected_go_version" ] || { printf '%s\n' "R01 bridge: Go compiler is $actual_go_version, expected $expected_go_version" >&2; exit 1; }

expected_go_revision=c8bb148a1379b51ef87256c27f366a05f8da4dc4
expected_go_tree=c5039b6b50a05b942a902f70dc2fcb090463e8c7
actual_go_revision=$(git -C "$go_root" rev-parse HEAD)
actual_go_tree=$(git -C "$go_root" rev-parse 'HEAD^{tree}')
[ "$actual_go_revision" = "$expected_go_revision" ] || { printf '%s\n' "R01 bridge: Go HEAD is $actual_go_revision, expected $expected_go_revision" >&2; exit 1; }
[ "$actual_go_tree" = "$expected_go_tree" ] || { printf '%s\n' "R01 bridge: Go tree is $actual_go_tree, expected $expected_go_tree" >&2; exit 1; }

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
git clone --quiet --no-hardlinks "$go_root" "$temporary/go"
[ "$(git -C "$temporary/go" rev-parse HEAD)" = "$expected_go_revision" ]
mkdir -p "$temporary/go/tools/rados-rs-r01-probe"
cp "$root/tools/r01/go-probe/main.go" "$root/tools/r01/go-probe/main_test.go" "$temporary/go/tools/rados-rs-r01-probe/"

request="$temporary/request.jsonl"
printf '%s\n' '{"schema_version":1,"case_id":"p01/entity-name-client-1","operation":"entity-name-round-trip","fixture":{"path":"testdata/p01/entity-name-client-1.bin","sha256":"0ea9e19802a23c4674e289fabeaa6e600262fb9ad25ae64fd4fb927651b6abe9"},"limits":{"max_record_bytes":4096,"max_input_bytes":9,"max_output_bytes":9}}' > "$request"

rust_result="$temporary/rust-result.jsonl"
rust_pipe="$temporary/rust-result.pipe"
mkfifo "$rust_pipe"
(cd "$root" && exec "$rust_probe" < "$request") > "$rust_pipe" &
rust_pid=$!
head -c 4097 < "$rust_pipe" > "$rust_result"
wait "$rust_pid" || { printf '%s\n' 'R01 bridge: Rust probe failed' >&2; exit 1; }
[ "$(wc -c < "$rust_result" | tr -d ' ')" -le 4096 ] || { printf '%s\n' 'R01 bridge: Rust result exceeds 4096 bytes' >&2; exit 1; }

go_result="$temporary/go-result.jsonl"
(cd "$temporary/go" && go test ./tools/rados-rs-r01-probe -count=1)
go_pipe="$temporary/go-result.pipe"
mkfifo "$go_pipe"
(cd "$temporary/go" && exec go run ./tools/rados-rs-r01-probe < "$request") > "$go_pipe" &
go_pid=$!
head -c 4097 < "$go_pipe" > "$go_result"
wait "$go_pid" || { printf '%s\n' 'R01 bridge: Go probe failed' >&2; exit 1; }
[ "$(wc -c < "$go_result" | tr -d ' ')" -le 4096 ] || { printf '%s\n' 'R01 bridge: Go result exceeds 4096 bytes' >&2; exit 1; }

sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
source_files_sha256=$("$verifier" source-digest "$root")
go_source_files_sha256=$(printf '%s' "$expected_go_tree" | shasum -a 256 | awk '{print $1}')
fixture_manifest="$root/testdata/p01/entity-name-client-1.bin.json"
ceph_image=$(jq -r '.generator.image' "$fixture_manifest")
rust_revision=$(git -C "$root" rev-parse HEAD)
rust_tree=$(git -C "$root" rev-parse 'HEAD^{tree}')
rust_target=$(rustc -vV | sed -n 's/^host: //p')
generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
controller="$root/integration/r01/reproduce.sh"
go_adapter_sha256=$("$verifier" path-digest "$root" tools/r01/go-probe)
mkdir -p "$(dirname "$report")"

jq -n \
  --slurpfile rust_result "$rust_result" \
  --slurpfile go_result "$go_result" \
  --arg generated_at "$generated_at" \
  --arg ceph_image "$ceph_image" \
  --arg fixture_manifest_sha256 "$(sha256_file "$fixture_manifest")" \
  --arg rust_revision "$rust_revision" \
  --arg rust_tree "$rust_tree" \
  --arg source_files_sha256 "$source_files_sha256" \
  --arg lockfile_sha256 "$(sha256_file "$root/Cargo.lock")" \
  --arg rust_compiler "$(rustc --version)" \
  --arg rust_target "$rust_target" \
  --arg rust_probe "$rust_probe" \
  --arg verifier "$verifier" \
  --arg go_root "$go_root" \
  --arg report "$report" \
  --arg rust_probe_sha256 "$(sha256_file "$rust_probe")" \
  --arg rust_stdout_sha256 "$(sha256_file "$rust_result")" \
  --arg go_revision "$expected_go_revision" \
  --arg go_tree "$expected_go_tree" \
  --arg go_source_files_sha256 "$go_source_files_sha256" \
  --arg go_lockfile_sha256 "$(sha256_file "$temporary/go/go.sum")" \
  --arg go_compiler "$(go version)" \
  --arg go_target "$go_target" \
  --arg go_adapter_sha256 "$go_adapter_sha256" \
  --arg go_stdout_sha256 "$(sha256_file "$go_result")" \
  --arg controller_sha256 "$(sha256_file "$controller")" \
  '{
    schema_version: 1,
    case_id: "p01/entity-name-client-1",
    operation: "entity-name-round-trip",
    status: "passed",
    generated_at: $generated_at,
    fixture: {
      path: "testdata/p01/entity-name-client-1.bin",
      sha256: "0ea9e19802a23c4674e289fabeaa6e600262fb9ad25ae64fd4fb927651b6abe9",
      provenance_manifest_sha256: $fixture_manifest_sha256,
      ceph_image: $ceph_image
    },
    bounds: {max_record_bytes: 4096, max_input_bytes: 9, max_output_bytes: 9},
    rust: {
      implementation_id: "rust", source_revision: $rust_revision, source_tree: $rust_tree,
      source_files_sha256: $source_files_sha256, features: [],
      lockfile_sha256: $lockfile_sha256, compiler: $rust_compiler, target: $rust_target,
      driver_sha256: $rust_probe_sha256, command: [$rust_probe], exit_code: 0,
      stdout_sha256: $rust_stdout_sha256, result: $rust_result[0]
    },
    go: {
      implementation_id: "go", source_revision: $go_revision, source_tree: $go_tree,
      source_files_sha256: $go_source_files_sha256, features: [], lockfile_sha256: $go_lockfile_sha256,
      compiler: $go_compiler, target: $go_target, driver_sha256: $go_adapter_sha256,
      command: ["go", "run", "./tools/rados-rs-r01-probe"], exit_code: 0,
      stdout_sha256: $go_stdout_sha256, result: $go_result[0]
    },
    controller: {
      path: "integration/r01/reproduce.sh", sha256: $controller_sha256,
      command: ["integration/r01/reproduce.sh", "--go-root", $go_root, "--rust-probe", $rust_probe, "--verifier", $verifier, "--report", $report]
    }
  }' > "$report"

"$verifier" verify "$root" "$report"
printf '%s\n' "R01 Rust/Go fixture bridge passed: $report"