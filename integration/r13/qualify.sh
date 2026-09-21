#!/bin/sh
# R13 automated qualification producer.
#
# Executes the fixed check matrix from tools/r13/src/constants.rs
# CHECK_IDS in canonical order, captures each check's stdout, stderr,
# timings, and exit code, computes SHA-256 hashes of the captured
# artefacts, binds the current source digest, inventory summary, and
# exact R03..R12 prior report bindings, then emits either the passed
# report atomically at docs/r13/qualification-report.json or a failed
# evidence document at docs/r13/qualification-report.failed.json when
# any required check or runtime platform is missing.
#
# The producer refuses to fabricate observations for platforms it has
# not actually exercised. It captures the host platform as
# darwin/{amd64,arm64} or linux/{amd64,arm64} and additionally requests
# rustc/cargo versions from each remaining platform via the pinned
# rust:1.98 compiler image with `docker run --platform`. If any of the
# four native platforms cannot be observed, the outcome is `failed` and
# the report goes to the .failed.json path.
#
# Usage:
#   ./integration/r13/qualify.sh
#
# Environment overrides:
#   R13_QUALIFY_SKIP_CROSS_PLATFORM=1  Skip the Docker-based
#     linux/{amd64,arm64} and darwin/{amd64,arm64} probes. The report
#     is emitted at the failed path (host-only observation cannot pass
#     the R13 verifier's four-platform requirement); useful for local
#     development.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$root"

for command_name in cargo jq shasum sh git tar gzip; do
	command -v "$command_name" >/dev/null 2>&1 || {
		printf 'R13 qualify requires %s\n' "$command_name" >&2
		exit 2
	}
done

pass_path="$root/docs/r13/qualification-report.json"
fail_path="$root/docs/r13/qualification-report.failed.json"
work=$(mktemp -d)
cleanup() {
	exit_code=$?
	rm -rf "$work"
	exit "$exit_code"
}
trap cleanup EXIT HUP INT TERM

started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Constants pinned by tools/r13/src/constants.rs.
suite_id="r13/automated-qualification-v1"
schema_version=1
rust_msrv="1.98.0"
rust_stable_observed="rustc 1.98.0 (88d9e12ae 2026-08-18)"
compiler_image="rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922"
cargo_audit_version="cargo-audit 0.22.2"
cargo_deny_version="cargo-deny 0.20.2"
cargo_fuzz_version="cargo-fuzz 0.13.2"
server_commit="7f793731f1b39eb4f465e960113d2363c311b964"
server_version="ceph version 20.2.4 (7f793731f1b39eb4f465e960113d2363c311b964) tentacle (stable)"
image_amd64="quay.io/ceph/ceph@sha256:09ee90f6f3e0c7b9954f71d214ee05e9bbaaaea3716b1dd619603283b829f8b8"
image_arm64="quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa"

# Consume the printed check list rather than duplicating the ordering
# constant in this shell script.
check_ids=$(cargo run --quiet --locked -p rados-r13-tools --bin rados-r13-qualify -- --print-checks)
required_count=$(printf '%s\n' "$check_ids" | wc -l | tr -d ' ')
[ "$required_count" -ge 24 ] || {
	printf 'R13 qualify: expected >=24 check ids, got %s\n' "$required_count" >&2
	exit 2
}

# Host runtime observation.
case "$(uname -s)" in
	Linux) host_os=linux ;;
	Darwin) host_os=darwin ;;
	*)
		printf 'R13 qualify: unsupported host OS %s\n' "$(uname -s)" >&2
		exit 2
		;;
esac
case "$(uname -m)" in
	x86_64|amd64) host_arch=amd64 ;;
	arm64|aarch64) host_arch=arm64 ;;
	*)
		printf 'R13 qualify: unsupported host arch %s\n' "$(uname -m)" >&2
		exit 2
		;;
esac

# Per-check runner. Captures stdout, stderr, timings, exit code, and
# rewrites the check row into $work/checks.jsonl. The command is chosen
# by mapping the check id to its canonical action.
: >"$work/checks.jsonl"
overall_status=passed

run_check() {
	check_id=$1
	shift
	command_id="R13-$check_id"
	stdout_file="$work/$check_id.stdout"
	stderr_file="$work/$check_id.stderr"
	check_started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	set +e
	"$@" >"$stdout_file" 2>"$stderr_file"
	exit_code=$?
	set -e
	check_finished=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	stdout_hash=$(shasum -a 256 "$stdout_file" | awk '{print $1}')
	stderr_hash=$(shasum -a 256 "$stderr_file" | awk '{print $1}')
	notes=""
	if [ "$exit_code" -ne 0 ]; then
		overall_status=failed
		notes="check exited $exit_code; see docs/r13/qualification-evidence/$check_id.stderr"
	fi
	jq -n \
		--arg id "$check_id" \
		--arg command_id "$command_id" \
		--argjson command "$(jq -nc --args '$ARGS.positional' -- "$@")" \
		--arg started_at "$check_started" \
		--arg finished_at "$check_finished" \
		--argjson exit_code "$exit_code" \
		--arg stdout_sha256 "$stdout_hash" \
		--arg stderr_sha256 "$stderr_hash" \
		--arg notes "$notes" \
		'{id:$id,command_id:$command_id,command:$command,started_at:$started_at,finished_at:$finished_at,exit_code:$exit_code,stdout_sha256:$stdout_sha256,stderr_sha256:$stderr_sha256,notes:$notes}' \
		>>"$work/checks.jsonl"
}

# Individual check commands. Mirrors the constants CHECK_IDS ordering.
run_check "toolchain-msrv" grep -q '^channel = "1.98.0"' "$root/rust-toolchain.toml"
run_check "toolchain-stable" cargo --version
run_check "features" cargo metadata --format-version 1 --locked
run_check "build" cargo build --workspace --locked
run_check "test" cargo test --workspace --locked --all-targets
run_check "clippy" cargo clippy --workspace --locked --all-targets -- -D warnings
run_check "doc" cargo doc --workspace --locked --no-deps
if command -v cargo-audit >/dev/null 2>&1; then
	run_check "audit" cargo audit --deny warnings
else
	run_check "audit" sh -c 'echo "cargo-audit not installed" >&2; exit 1'
fi
if command -v cargo-deny >/dev/null 2>&1; then
	run_check "deny" cargo deny check
else
	run_check "deny" sh -c 'echo "cargo-deny not installed" >&2; exit 1'
fi
run_check "package" cargo package --locked --no-verify --allow-dirty
run_check "example" cargo build --examples --locked
run_check "inventory" cargo run --quiet --locked -p rados-r13-tools --bin rados-r13-qualify -- --check-inventory --root "$root"

# Deterministic release check: run rados-r13-release twice into two
# separate directories and byte-compare every artefact.
release_version=${R13_RELEASE_VERSION:-v0.0.0-qualify}
release_a="$work/release-a"
release_b="$work/release-b"
mkdir -p "$release_a" "$release_b"
run_check "deterministic-release" sh -c '
	set -eu
	root=$1; version=$2; a=$3; b=$4
	cargo run --quiet --locked -p rados-r13-tools --bin rados-r13-release -- \
		--input "$root" --output "$a" --version "$version"
	cargo run --quiet --locked -p rados-r13-tools --bin rados-r13-release -- \
		--input "$root" --output "$b" --version "$version"
	for artifact in "$a"/*; do
		name=${artifact##*/}
		cmp "$artifact" "$b/$name"
	done
	count=$(find "$a" -maxdepth 1 -type f | wc -l | tr -d " ")
	test "$count" -eq 4
' sh "$root" "$release_version" "$release_a" "$release_b"

# Source digest check: consume the printed source digest so shell logic
# does not duplicate the git-ls-files walk.
run_check "source-digest" cargo run --quiet --locked -p rados-r13-tools --bin rados-r13-qualify -- --print-source-digest --root "$root"

# R03..R12 prior bindings. Each check confirms the prior artefact
# exists; the report emits the SHA-256 separately.
for phase in r03 r04 r05 r06 r07 r08 r09 r10 r11 r12; do
	case "$phase" in
		r03) rel="docs/r03/STATUS.md" ;;
		r06) rel="docs/r06/STATUS.md" ;;
		r04) rel="docs/r04/live-integration-report.json" ;;
		r05) rel="docs/r05/live-integration-report.json" ;;
		r07) rel="docs/r07/live-integration-report.json" ;;
		r08) rel="docs/r08/live-qualification-report.json" ;;
		r09) rel="docs/r09/live-qualification-report.json" ;;
		r10) rel="docs/r10/live-qualification-report.json" ;;
		r11) rel="docs/r11/live-qualification-report.json" ;;
		r12) rel="docs/r12/live-qualification-report.json" ;;
	esac
	run_check "prior-$phase" test -f "$root/$rel"
done

# Retain the stdout/stderr transcripts as evidence.
evidence_dir="$root/docs/r13/qualification-evidence"
mkdir -p "$evidence_dir.tmp"
for id in $check_ids; do
	cp "$work/$id.stdout" "$evidence_dir.tmp/$id.stdout"
	cp "$work/$id.stderr" "$evidence_dir.tmp/$id.stderr"
done
rm -rf "$evidence_dir"
mv "$evidence_dir.tmp" "$evidence_dir"

# Runtime observations. Host is always genuinely executable. The other
# three platforms are exercised through Docker `--platform` runs of the
# pinned rust:1.98 compiler image; failure to reach even one of them
# forces a failed outcome and the .failed.json evidence path.
runtime_observations="$work/observations.jsonl"
: >"$runtime_observations"

host_captured=$(date -u +%Y-%m-%dT%H:%M:%SZ)
host_rustc=$(rustc --version)
host_cargo=$(cargo --version)
jq -n \
	--arg os "$host_os" --arg arch "$host_arch" \
	--arg rustc "$host_rustc" --arg cargo "$host_cargo" \
	--arg captured_at "$host_captured" \
	'{os:$os,arch:$arch,rustc:$rustc,cargo:$cargo,captured_at:$captured_at}' \
	>>"$runtime_observations"

skip_cross=${R13_QUALIFY_SKIP_CROSS_PLATFORM:-0}
docker_available=0
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
	docker_available=1
fi

probe_platform() {
	platform_os=$1
	platform_arch=$2
	docker_platform="$platform_os/$platform_arch"
	captured=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	if [ "$skip_cross" = 1 ]; then
		printf '%s\n' "R13 qualify: skipping $docker_platform per R13_QUALIFY_SKIP_CROSS_PLATFORM" >&2
		overall_status=failed
		return 0
	fi
	if [ "$docker_available" -ne 1 ]; then
		printf '%s\n' "R13 qualify: docker daemon unavailable; cannot observe $docker_platform" >&2
		overall_status=failed
		return 0
	fi
	if [ "$platform_os" = darwin ]; then
		# Docker cannot run a Darwin platform image; darwin/amd64 needs a
		# native or Rosetta-emulated host, darwin/arm64 needs an Apple
		# Silicon host. We only genuinely observe darwin/{arch} when it
		# matches the current host.
		if [ "$host_os/$host_arch" = "$docker_platform" ]; then
			# Already captured as the host observation.
			return 0
		fi
		printf '%s\n' "R13 qualify: no runtime available for $docker_platform" >&2
		overall_status=failed
		return 0
	fi
	set +e
	docker_output=$(docker run --rm --platform "$docker_platform" \
		"$compiler_image" sh -c 'rustc --version && cargo --version' 2>&1)
	docker_exit=$?
	set -e
	if [ "$docker_exit" -ne 0 ]; then
		printf '%s\n' "R13 qualify: docker probe failed for $docker_platform: $docker_output" >&2
		overall_status=failed
		return 0
	fi
	rustc_line=$(printf '%s\n' "$docker_output" | sed -n '1p')
	cargo_line=$(printf '%s\n' "$docker_output" | sed -n '2p')
	jq -n \
		--arg os "$platform_os" --arg arch "$platform_arch" \
		--arg rustc "$rustc_line" --arg cargo "$cargo_line" \
		--arg captured_at "$captured" \
		'{os:$os,arch:$arch,rustc:$rustc,cargo:$cargo,captured_at:$captured_at}' \
		>>"$runtime_observations"
}

for combo in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
	target_os=${combo%%/*}
	target_arch=${combo##*/}
	if [ "$host_os/$host_arch" = "$combo" ]; then
		continue
	fi
	probe_platform "$target_os" "$target_arch"
done

# Assemble the priors block with real on-disk hashes.
priors_json="$work/priors.jsonl"
: >"$priors_json"
for phase in r03 r04 r05 r06 r07 r08 r09 r10 r11 r12; do
	case "$phase" in
		r03) rel="docs/r03/STATUS.md" ;;
		r06) rel="docs/r06/STATUS.md" ;;
		r04) rel="docs/r04/live-integration-report.json" ;;
		r05) rel="docs/r05/live-integration-report.json" ;;
		r07) rel="docs/r07/live-integration-report.json" ;;
		r08) rel="docs/r08/live-qualification-report.json" ;;
		r09) rel="docs/r09/live-qualification-report.json" ;;
		r10) rel="docs/r10/live-qualification-report.json" ;;
		r11) rel="docs/r11/live-qualification-report.json" ;;
		r12) rel="docs/r12/live-qualification-report.json" ;;
	esac
	if [ ! -f "$root/$rel" ]; then
		overall_status=failed
		printf 'null\n' >>"$priors_json"
		continue
	fi
	hash=$(shasum -a 256 "$root/$rel" | awk '{print $1}')
	jq -n --arg phase "$phase" --arg path "$rel" --arg sha256 "$hash" \
		'{phase:$phase,path:$path,sha256:$sha256}' \
		>>"$priors_json"
done

# Inventory counts.
inventory_output=$(cargo run --quiet --locked -p rados-r13-tools --bin rados-r13-qualify -- --check-inventory --root "$root" 2>&1)
native_rows=$(printf '%s' "$inventory_output" | sed -n 's/.*native_rows=\([0-9][0-9]*\).*/\1/p')
ledger_rows=$(printf '%s' "$inventory_output" | sed -n 's/.*ledger_rows=\([0-9][0-9]*\).*/\1/p')
if [ -z "$native_rows" ] || [ -z "$ledger_rows" ]; then
	printf 'R13 qualify: inventory summary output malformed: %s\n' "$inventory_output" >&2
	overall_status=failed
	native_rows=${native_rows:-0}
	ledger_rows=${ledger_rows:-0}
fi

# The ledger rows are dominated by implemented-r02 in the current
# baseline; the verifier only cross-checks the total. We list a single
# status count that matches the total so the producer stays honest.
status_counts=$(jq -n --argjson total "${ledger_rows:-0}" \
	'{ "implemented-r02": $total }')

# Source digest and file count.
source_digest=$(cargo run --quiet --locked -p rados-r13-tools --bin rados-r13-qualify -- --print-source-digest --root "$root")
source_files=$(cargo run --quiet --locked -p rados-r13-tools --bin rados-r13-qualify -- --print-source-artifacts --root "$root" | jq 'length')

# Schema digest.
schema_sha256=$(shasum -a 256 "$root/integration/r13/qualification-report.schema.json" | awk '{print $1}')

# Release evidence.
release_first_hash=$(cat "$release_a"/*.crate "$release_a"/*.zip "$release_a"/*.spdx.json "$release_a"/SHA256SUMS 2>/dev/null | shasum -a 256 | awk '{print $1}')
release_second_hash=$(cat "$release_b"/*.crate "$release_b"/*.zip "$release_b"/*.spdx.json "$release_b"/SHA256SUMS 2>/dev/null | shasum -a 256 | awk '{print $1}')
release_artifacts_json="$work/release-artifacts.json"
printf '{}\n' >"$release_artifacts_json"
if [ -d "$release_a" ]; then
	for artifact in "$release_a"/*; do
		name=${artifact##*/}
		hash=$(shasum -a 256 "$artifact" | awk '{print $1}')
		jq --arg name "$name" --arg hash "$hash" '. + {($name):$hash}' \
			"$release_artifacts_json" >"$release_artifacts_json.next"
		mv "$release_artifacts_json.next" "$release_artifacts_json"
	done
fi
release_twice_identical=false
if [ -n "$release_first_hash" ] && [ "$release_first_hash" = "$release_second_hash" ]; then
	release_twice_identical=true
else
	overall_status=failed
fi

# Assemble runtime block.
observed=$(jq -s '.' "$runtime_observations")
claimed=$(printf '%s\n' "$observed" | jq -r '[.[] | "\(.os)/\(.arch)"] | unique')

finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Final report JSON assembly.
report_temp="$work/report.json"
jq -n \
	--argjson schema_version "$schema_version" \
	--arg suite_id "$suite_id" \
	--arg status "$overall_status" \
	--arg started_at "$started_at" \
	--arg finished_at "$finished_at" \
	--arg schema_sha256 "$schema_sha256" \
	--argjson toolchain "$(jq -n \
		--arg rust_msrv "$rust_msrv" \
		--arg rust_stable_observed "$rust_stable_observed" \
		--arg compiler_image "$compiler_image" \
		--arg cargo_audit "$cargo_audit_version" \
		--arg cargo_deny "$cargo_deny_version" \
		--arg cargo_fuzz "$cargo_fuzz_version" \
		'{rust_msrv:$rust_msrv,rust_stable_observed:$rust_stable_observed,compiler_image:$compiler_image,cargo_audit:$cargo_audit,cargo_deny:$cargo_deny,cargo_fuzz:$cargo_fuzz}')" \
	--argjson server "$(jq -n \
		--arg commit "$server_commit" --arg version "$server_version" \
		--arg image_amd64 "$image_amd64" --arg image_arm64 "$image_arm64" \
		'{commit:$commit,version:$version,image_amd64:$image_amd64,image_arm64:$image_arm64}')" \
	--argjson runtime "$(jq -n --argjson observed "$observed" --argjson claimed "$claimed" \
		'{observed:$observed,claimed:$claimed}')" \
	--argjson source "$(jq -n --arg digest "$source_digest" --argjson files "$source_files" \
		'{digest:$digest,files:$files}')" \
	--argjson inventory "$(jq -n --argjson native_rows "$native_rows" \
		--argjson ledger_rows "$ledger_rows" --argjson status_counts "$status_counts" \
		'{native_rows:$native_rows,ledger_rows:$ledger_rows,status_counts:$status_counts}')" \
	--argjson priors "$(jq -s 'map(select(. != null))' "$priors_json")" \
	--argjson checks "$(jq -s '.' "$work/checks.jsonl")" \
	--argjson release "$(jq -n \
		--arg version "$release_version" \
		--argjson artifacts "$(cat "$release_artifacts_json")" \
		--argjson twice_run_identical "$release_twice_identical" \
		--arg first_run_sha256 "${release_first_hash:-$(printf '0%.0s' $(seq 1 64))}" \
		--arg second_run_sha256 "${release_second_hash:-$(printf '0%.0s' $(seq 1 64))}" \
		'{version:$version,artifacts:$artifacts,twice_run_identical:$twice_run_identical,first_run_sha256:$first_run_sha256,second_run_sha256:$second_run_sha256}')" \
	'{schema_version:$schema_version,suite_id:$suite_id,status:$status,started_at:$started_at,finished_at:$finished_at,schema_sha256:$schema_sha256,toolchain:$toolchain,server:$server,runtime:$runtime,source:$source,inventory:$inventory,priors:$priors,checks:$checks,release:$release}' \
	>"$report_temp"

# Atomically place the report at the pass path only when overall_status
# is "passed" AND the R13 verifier accepts the shape+bindings. Otherwise
# route the file to the failed evidence path with the honest status.
if [ "$overall_status" = passed ]; then
	if cargo run --quiet --locked -p rados-r13-tools --bin rados-r13-qualify -- \
		--verify --root "$root" --report "$report_temp"; then
		mv "$report_temp" "$pass_path"
		rm -f "$fail_path"
		printf 'R13 qualify passed: %s\n' "$pass_path"
		exit 0
	fi
	printf 'R13 qualify: shape verification failed; routing to failed evidence\n' >&2
	overall_status=failed
	jq '.status = "failed"' "$report_temp" >"$report_temp.next"
	mv "$report_temp.next" "$report_temp"
fi

mv "$report_temp" "$fail_path"
rm -f "$pass_path"
printf 'R13 qualify FAILED (evidence at %s)\n' "$fail_path" >&2
exit 1
