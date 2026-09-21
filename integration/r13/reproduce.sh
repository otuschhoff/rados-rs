#!/bin/sh
# R13 endurance-candidate reproducer.
#
# Adapts the frozen Go P12 endurance harness architecture
# (reference/archives/go-*.tar.gz, integration/p12/reproduce.sh) to the
# Rust R13 candidate. Fresh Rust evidence only: fresh FSID
# 41111111-2222-4333-8444-131313131313, isolated 172.30.114.0/24 subnet,
# `r13-data` pool (size=2 min_size=1 pg_num=16), one monitor and three
# BlueStore OSDs (two managers when manager behavior is exercised),
# fixed 900 s auth ticket TTL, secure and CRC transports.
#
# Modes:
#
#   ./integration/r13/reproduce.sh           # certifying 24h run
#   ./integration/r13/reproduce.sh --quick   # non-certifying quick run
#
# --quick output ALWAYS carries status "non-certifying" and a command that
# is not the certifying reproduce command, so the candidate verifier
# refuses it for final gating (`rados-r13-candidate` without
# --allow-non-certifying).
#
# The certifying default REFUSES to proceed unless the current
# source-bound 42-target certifying fuzz report and the passed
# qualification report both verify. Both bindings must be freshly checked
# in and match the current tree; the harness never fabricates them.
#
# Two release builds are generated and byte-compared. Only the certifying
# run atomically retains exactly four artefacts under
# docs/r13/release-artifacts/.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$root"

quick=false
case "${1:-}" in
	"") ;;
	--quick) quick=true ;;
	*)
		printf 'usage: %s [--quick]\n' "$0" >&2
		exit 2
		;;
esac

for command_name in docker cargo jq shasum sh; do
	command -v "$command_name" >/dev/null 2>&1 || {
		printf 'R13 requires %s\n' "$command_name" >&2
		exit 2
	}
done

# Docker daemon and platform selection.
docker info >/dev/null 2>&1 || {
	printf 'R13 requires a running Docker daemon\n' >&2
	exit 2
}
docker_arch=$(docker info --format '{{.Architecture}}' 2>/dev/null || printf '')
case "$docker_arch" in
	x86_64|amd64)
		platform=linux/amd64
		image_reference=quay.io/ceph/ceph@sha256:09ee90f6f3e0c7b9954f71d214ee05e9bbaaaea3716b1dd619603283b829f8b8
		;;
	aarch64|arm64)
		platform=linux/arm64
		image_reference=quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa
		;;
	*)
		printf 'R13 supports only amd64 and arm64 Docker daemons (got %s)\n' \
			"$docker_arch" >&2
		exit 2
		;;
esac

fsid=41111111-2222-4333-8444-131313131313
subnet=172.30.114.0/24
monitor_address=v2:172.30.114.10:3300
pool_name=r13-data
ticket_ttl=900
duration=${R13_DURATION:-24h}
probe_timeout=26h
reconnect_interval=50m
sample_interval=1m
churn_interval=15m
if test "$quick" = true; then
	duration=${R13_DURATION:-3m}
	probe_timeout=10m
	reconnect_interval=2m
	sample_interval=10s
	churn_interval=30s
fi

case "$churn_interval" in
	*s) churn_interval_seconds=${churn_interval%s} ;;
	*m) churn_interval_seconds=$(( ${churn_interval%m} * 60 )) ;;
	*h) churn_interval_seconds=$(( ${churn_interval%h} * 3600 )) ;;
	*) churn_interval_seconds=$churn_interval ;;
esac

started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
temporary=$(mktemp -d)
network="rados-r13-$$"
report_temp="$root/integration/r13/.report.json.$$"
final_report="$root/integration/r13/report.json"
release_stage="$root/docs/r13/.release-artifacts.$$"

cleanup() {
	exit_code=$?
	trap - EXIT HUP INT TERM
	if test "$exit_code" -ne 0; then
		for daemon in "r13-probe-secure-$$" "r13-probe-crc-$$" \
			"r13-mon-$$" "r13-osd-0-$$" "r13-osd-1-$$" "r13-osd-2-$$" \
			"r13-mgr-a-$$" "r13-mgr-b-$$"; do
			docker logs --tail 40 "$daemon" >&2 2>/dev/null || true
		done
	fi
	for daemon in "r13-probe-secure-$$" "r13-probe-crc-$$" "r13-mon-$$" \
		"r13-osd-0-$$" "r13-osd-1-$$" "r13-osd-2-$$" \
		"r13-mgr-a-$$" "r13-mgr-b-$$"; do
		docker rm -f "$daemon" >/dev/null 2>&1 || true
	done
	for id in 0 1 2; do
		docker volume rm "rados-r13-osd-$id-$$" >/dev/null 2>&1 || true
	done
	docker network rm "$network" >/dev/null 2>&1 || true
	docker rmi "rados-r13-native:$$" >/dev/null 2>&1 || true
	docker rm -f "rados-r13-native-extract-$$" >/dev/null 2>&1 || true
	rm -rf "$temporary"
	rm -rf "$release_stage"
	rm -f "$report_temp"
	exit "$exit_code"
}
trap cleanup EXIT HUP INT TERM

# Refuse the certifying path unless the current source-bound fuzz report is
# certifying AND the qualification report passes. --quick skips these gates
# because it explicitly cannot certify.
if test "$quick" = false; then
	cargo run --quiet --locked -p rados-r13-tools --bin rados-r13-fuzz -- \
		--verify --root "$root" \
		--report "$root/docs/r13/fuzz-report.json" \
		--corpus-root "$root/fuzz/corpus" \
		--profile certifying
	cargo run --quiet --locked -p rados-r13-tools --bin rados-r13-qualify -- \
		--root "$root" \
		--report "$root/docs/r13/qualification-report.json"
fi

# Cross-compile the Rust probe/bench binaries inside the pinned
# rust:1.98-bookworm compiler image for the SAME Linux platform as the
# live Ceph cluster; the reproducer previously ran `cargo build --release`
# on the host and staged the resulting Mach-O binary into a Linux
# container, which fails when the host and Docker platform disagree
# (e.g. darwin/arm64 hosts driving linux/arm64 clusters). The compiler
# image digest is multiarch and Docker's `--platform` flag selects the
# matching platform layer, so the same digest works for both amd64 and
# arm64.
compiler_image="rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922"
case "$platform" in
	linux/amd64|linux/arm64) ;;
	*)
		printf 'R13 reproduce.sh: unsupported cross-compile platform %s\n' \
			"$platform" >&2
		exit 2
		;;
esac
cross_workdir="$temporary/cross-build"
mkdir -p "$cross_workdir/cargo-home" "$cross_workdir/target"
docker run --rm --platform "$platform" \
	-v "$root:/workspace:ro" \
	-v "$cross_workdir/cargo-home:/cargo-home" \
	-v "$cross_workdir/target:/target" \
	-e CARGO_HOME=/cargo-home \
	-e CARGO_TARGET_DIR=/target \
	"$compiler_image" sh -c '
	set -eu
	cd /workspace
	cargo build --release --locked -p rados-r13-tools \
		--bin rados-r13-probe --bin rados-r13-bench
' >&2
cp "$cross_workdir/target/release/rados-r13-probe" "$temporary/probe"
cp "$cross_workdir/target/release/rados-r13-bench" "$temporary/bench"
chmod +x "$temporary/probe" "$temporary/bench"

# Build the native librados benchmark against the same Ceph image digest
# the live cluster runs; parameterising the Dockerfile ensures we never
# ship the arm64-hardcoded image on an amd64 host.
native_image="rados-r13-native:$$"
docker build --platform "$platform" \
	--build-arg "CEPH_IMAGE=$image_reference" \
	-t "$native_image" \
	"$root/tools/r13/native-bench" >&2
native_container="rados-r13-native-extract-$$"
docker create --platform "$platform" --name "$native_container" \
	"$native_image" >/dev/null
docker cp "$native_container:/usr/local/bin/rados-r13-native" \
	"$temporary/native-bench" >/dev/null
docker rm "$native_container" >/dev/null
chmod +x "$temporary/native-bench"

# The following live-cluster orchestration mirrors the frozen Go P12
# reproducer step by step. It is intentionally sh-syntactic and requires a
# reachable Docker daemon; without one the exit above fires.
docker network create --subnet "$subnet" "$network" >/dev/null
docker run --rm --user 0 --platform "$platform" -v "$temporary:/cluster" \
	"$image_reference" sh -c '
	set -eu
	cat >/cluster/ceph.conf <<EOF
[global]
fsid = '"$fsid"'
mon host = '"$monitor_address"'
auth cluster required = cephx
auth service required = cephx
auth client required = cephx
auth service ticket ttl = '"$ticket_ttl"'
auth mon ticket ttl = '"$ticket_ttl"'
auth allow insecure global id reclaim = false
ms bind msgr1 = false
ms bind msgr2 = true
ms cluster mode = secure crc
ms service mode = secure crc
ms client mode = secure crc
osd pool default size = 2
osd pool default min size = 1
mon data avail warn = 0
EOF
	ceph-authtool /cluster/mon.keyring --create-keyring --gen-key -n mon. \
		--cap mon "allow *"
	ceph-authtool /cluster/admin.keyring --create-keyring --gen-key \
		-n client.admin --cap mon "allow *" --cap osd "allow *" \
		--cap mgr "allow *"
	ceph-authtool /cluster/mon.keyring --import-keyring /cluster/admin.keyring
	monmaptool --create --fsid '"$fsid"' --addv a "['"$monitor_address"'/0]" \
		/cluster/monmap
	mkdir -p /cluster/mondata
	ceph-mon --mkfs -i a --fsid '"$fsid"' --monmap /cluster/monmap \
		--keyring /cluster/mon.keyring --mon-data /cluster/mondata
	chown -R ceph:ceph /cluster/mondata
'

docker run -d --name "r13-mon-$$" --platform "$platform" --network "$network" \
	--ip 172.30.114.10 -v "$temporary:/cluster" "$image_reference" \
	ceph-mon -f -i a --conf /cluster/ceph.conf \
	--mon-data /cluster/mondata \
	--public-addr "$monitor_address" \
	--setuser ceph --setgroup ceph --mon-data-avail-crit 0 \
	--no-mon-cluster-log-to-stderr >/dev/null

ceph_cli() {
	docker run --rm --platform "$platform" --network "$network" \
		-v "$temporary:/cluster" "$image_reference" \
		timeout 20 ceph --conf /cluster/ceph.conf --name client.admin \
		--keyring /cluster/admin.keyring "$@"
}

for attempt in $(seq 1 60); do
	if ceph_cli status --format json 2>/dev/null | \
		jq -e '.health.status != null' >/dev/null; then
		break
	fi
	test "$attempt" -lt 60 || {
		docker logs "r13-mon-$$" >&2
		exit 1
	}
	sleep 1
done

for id in 0 1 2; do
	uuid="13000000-0000-4000-8000-00000000001$id"
	volume="rados-r13-osd-$id-$$"
	docker volume create "$volume" >/dev/null
	ceph_cli osd create "$uuid" "$id" >/dev/null
	ceph_cli auth get-or-create "osd.$id" mon 'allow profile osd' \
		mgr 'allow profile osd' osd 'allow *' \
		-o "/cluster/osd-$id.keyring"
	ceph_cli mon getmap -o "/cluster/osd-$id.monmap" >/dev/null
	docker run --rm --user 0 --privileged --platform "$platform" \
		-v "$temporary:/cluster" -v "$volume:/osd" "$image_reference" sh -c '
		set -eu
		id='"$id"'; uuid='"$uuid"'
		mkdir -p /osd/data
		truncate -s 8G /osd/block
		cp /cluster/osd-$id.keyring /osd/data/keyring
		cp /cluster/osd-$id.monmap /osd/data/activate.monmap
		chown -R ceph:ceph /osd
		ceph-osd --mkfs -i "$id" --osd-data /osd/data --osd-uuid "$uuid" \
			--osd-objectstore bluestore \
			--bluestore-block-path /osd/block \
			--monmap /osd/data/activate.monmap \
			--keyring /osd/data/keyring \
			--setuser ceph --setgroup ceph
	'
	ip="172.30.114.$((20 + id))"
	docker run -d --privileged --name "r13-osd-$id-$$" --platform "$platform" \
		--network "$network" --ip "$ip" -v "$temporary:/cluster" \
		-v "$volume:/osd" "$image_reference" \
		ceph-osd -f --conf /cluster/ceph.conf -i "$id" --osd-data /osd/data \
		--osd-objectstore bluestore \
		--public-addr "v2:$ip:6800" --cluster-addr "v2:$ip:6802" \
		--setuser ceph --setgroup ceph >/dev/null
done

for attempt in $(seq 1 120); do
	if ceph_cli osd stat --format json 2>/dev/null | \
		jq -e '.num_osds == 3 and .num_up_osds == 3 and .num_in_osds == 3' \
		>/dev/null; then
		break
	fi
	test "$attempt" -lt 120 || {
		ceph_cli osd tree >&2
		exit 1
	}
	sleep 1
done

ceph_cli osd crush rule create-replicated r13-rule default osd >/dev/null
ceph_cli osd pool create "$pool_name" 16 16 replicated r13-rule >/dev/null
ceph_cli osd pool set "$pool_name" size 2 >/dev/null
ceph_cli osd pool set "$pool_name" min_size 1 >/dev/null
ceph_cli auth get-or-create client.r13 mon 'allow r' \
	osd "allow rw pool=$pool_name" >/dev/null
ceph_cli auth get-key client.r13 >"$temporary/client.key"

managers=0
manager_behavior_exercised=false
if test "$quick" = false; then
	# Two managers are only required when manager behaviour is exercised;
	# the endurance probe/bench do not require it, so default is 0.
	managers=0
fi

# Probe run for each transport, background. The probe binary accepts
# Go-style duration strings via --duration / --reconnect-interval /
# --sample-interval, so shell converts nothing.
for transport in secure crc; do
	docker run -d --name "r13-probe-$transport-$$" --platform "$platform" \
		--network "$network" -v "$temporary:/work" "$image_reference" \
		sh -c 'exec timeout "$1" /work/probe --monitors 172.30.114.10:3300 \
			--key-file /work/client.key --fsid '"$fsid"' \
			--pool '"$pool_name"' --entity client.r13 --transport "$2" \
			--duration "$3" --reconnect-interval "$4" \
			--sample-interval "$5" --output /work/probe-$2.json' \
		sh "$probe_timeout" "$transport" "$duration" "$reconnect_interval" \
		"$sample_interval" >/dev/null
done

# Churn: monitor + every OSD restart with recovery.
monitor_restarts=0
monitor_recoveries=0
osd_restarts=0
osd_recoveries=0
osd_touched="000"
cycle=0
next_churn=$(( $(date +%s) + churn_interval_seconds ))
while :; do
	secure_running=$(docker inspect -f '{{.State.Running}}' \
		"r13-probe-secure-$$" 2>/dev/null || printf false)
	crc_running=$(docker inspect -f '{{.State.Running}}' \
		"r13-probe-crc-$$" 2>/dev/null || printf false)
	test "$secure_running" = true || break
	test "$crc_running" = true || break
	now=$(date +%s)
	if test "$now" -ge "$next_churn"; then
		if test $((cycle % 4)) -eq 0; then
			docker restart "r13-mon-$$" >/dev/null
			monitor_restarts=$((monitor_restarts + 1))
			for attempt in $(seq 1 60); do
				if ceph_cli status --format json 2>/dev/null | \
					jq -e '.health.status != null' >/dev/null; then
					monitor_recoveries=$((monitor_recoveries + 1))
					break
				fi
				test "$attempt" -lt 60 || exit 1
				sleep 1
			done
		else
			id=$(((cycle - 1) % 3))
			docker restart "r13-osd-$id-$$" >/dev/null
			osd_restarts=$((osd_restarts + 1))
			osd_touched=$(printf '%s' "$osd_touched" | \
				sed "s/./1/$((id + 1))")
			for attempt in $(seq 1 120); do
				if ceph_cli osd stat --format json 2>/dev/null | \
					jq -e '.num_up_osds == 3 and .num_in_osds == 3' \
					>/dev/null; then
					osd_recoveries=$((osd_recoveries + 1))
					break
				fi
				test "$attempt" -lt 120 || exit 1
				sleep 1
			done
		fi
		cycle=$((cycle + 1))
		next_churn=$(( $(date +%s) + churn_interval_seconds ))
	fi
	sleep 2
done

# Refuse to certify if the churn did not exercise every OSD at least once.
if test "$quick" = false; then
	case "$osd_touched" in
		111) ;;
		*)
			printf 'certifying churn must touch every OSD\n' >&2
			exit 1
			;;
	esac
fi

# Wait for probes and inspect their reports. `docker wait` prints the
# container's exit code; we check it explicitly and retain container
# logs at docs/r13/failure-diagnostics/ on any non-zero exit so
# post-mortem is possible even after the temporary directory is torn
# down.
diagnostics_dir="$root/docs/r13/failure-diagnostics"
for transport in secure crc; do
	probe_exit=$(docker wait "r13-probe-$transport-$$")
	if test "${probe_exit:-0}" -ne 0 || test ! -s "$temporary/probe-$transport.json"; then
		mkdir -p "$diagnostics_dir"
		docker logs "r13-probe-$transport-$$" \
			>"$diagnostics_dir/probe-$transport.log" 2>&1 || true
		printf 'R13 probe (%s) exited %s; diagnostics under %s\n' \
			"$transport" "${probe_exit:-unknown}" "$diagnostics_dir" >&2
		exit 1
	fi
done

# Assemble churn evidence.
jq -n --argjson mrs "$monitor_restarts" --argjson mrc "$monitor_recoveries" \
	--argjson ors "$osd_restarts" --argjson orc "$osd_recoveries" \
	'{monitor_restarts:$mrs,monitor_recoveries:$mrc,
	  osd_restarts:$ors,osd_recoveries:$orc}' \
	>"$temporary/churn.json"

# Determine certifying eligibility.
day_ns=86400000000000
if test "$quick" = false; then
	if jq -s --argjson day_ns "$day_ns" \
		'all(.[]; .requested_duration_ns >= $day_ns
		           and .elapsed_ns >= $day_ns
		           and .reconnects >= 24
		           and .longest_connection_ns > 900000000000
		           and .duplicate_mutations_detected == 0)' \
		"$temporary/probe-secure.json" "$temporary/probe-crc.json" | \
		grep -q true; then
		certifying=true
	else
		certifying=false
	fi
else
	certifying=false
fi

printf '[]\n' >"$temporary/benchmark-runs.json"
printf '{"performed":false,"version":null,"path":null,"reproducible":false,"artifacts":{}}\n' \
	>"$temporary/release.json"
printf 'null\n' >"$temporary/qualification.json"
printf 'null\n' >"$temporary/fuzz.json"

if test "$certifying" = true; then
	fuzz_report="$root/docs/r13/fuzz-report.json"
	qualification_report="$root/docs/r13/qualification-report.json"
	fuzz_hash=$(shasum -a 256 "$fuzz_report" | awk '{print $1}')
	qualification_hash=$(shasum -a 256 "$qualification_report" | \
		awk '{print $1}')
	jq -n --arg hash "$fuzz_hash" \
		'{path:"docs/r13/fuzz-report.json",status:"passed",profile:"certifying",sha256:$hash}' \
		>"$temporary/fuzz.json"
	jq -n --arg hash "$qualification_hash" \
		'{path:"docs/r13/qualification-report.json",status:"passed",sha256:$hash}' \
		>"$temporary/qualification.json"

	for transport in secure crc; do
		docker run --rm --platform "$platform" --network "$network" \
			-v "$temporary:/work" "$image_reference" \
			timeout 3600 /work/bench --monitors 172.30.114.10:3300 \
			--fsid "$fsid" --pool "$pool_name" \
			--entity client.r13 --transport "$transport" \
			--implementation rust \
			--key-file /work/client.key \
			>"$temporary/bench-rust-$transport.json"
		docker run --rm --platform "$platform" --network "$network" \
			-v "$temporary:/work" "$native_image" \
			timeout 3600 /usr/local/bin/rados-r13-native \
			--monitors 172.30.114.10:3300 --fsid "$fsid" \
			--pool "$pool_name" --entity client.r13 \
			--transport "$transport" --key-file /work/client.key \
			>"$temporary/bench-native-$transport.json"
	done
	jq -s '.' \
		"$temporary/bench-rust-secure.json" \
		"$temporary/bench-rust-crc.json" \
		"$temporary/bench-native-secure.json" \
		"$temporary/bench-native-crc.json" \
		>"$temporary/benchmark-runs.json"

	release_version=${R13_RELEASE_VERSION:?R13_RELEASE_VERSION must be supplied for certifying release}
	for run in 1 2; do
		cargo run --quiet --locked -p rados-r13-tools --bin rados-r13-release \
			-- --input "$root" --output "$temporary/release-$run" \
			--version "$release_version"
	done
	for artifact in "$temporary/release-1"/*; do
		name=${artifact##*/}
		cmp "$artifact" "$temporary/release-2/$name"
	done
	test "$(find "$temporary/release-1" -type f | wc -l | tr -d ' ')" -eq 4

	rm -rf "$release_stage"
	mkdir "$release_stage"
	for artifact in "$temporary/release-1"/*; do
		test -f "$artifact" && test ! -L "$artifact"
		cp "$artifact" "$release_stage/"
	done
	test "$(find "$release_stage" -type f | wc -l | tr -d ' ')" -eq 4
	rm -rf "$root/docs/r13/release-artifacts"
	mv "$release_stage" "$root/docs/r13/release-artifacts"

	printf '{}\n' >"$temporary/release-artifacts.json"
	for artifact in "$root/docs/r13/release-artifacts"/*; do
		name=${artifact##*/}
		hash=$(shasum -a 256 "$artifact" | awk '{print $1}')
		jq --arg name "$name" --arg hash "$hash" \
			'. + {($name):$hash}' \
			"$temporary/release-artifacts.json" \
			>"$temporary/release-artifacts.next"
		mv "$temporary/release-artifacts.next" \
			"$temporary/release-artifacts.json"
	done
	jq -n --arg version "$release_version" \
		--argjson artifacts "$(cat "$temporary/release-artifacts.json")" \
		'{performed:true,version:$version,
		  path:"docs/r13/release-artifacts",
		  reproducible:true,artifacts:$artifacts}' \
		>"$temporary/release.json"
	status=candidate
	command_recorded='./integration/r13/reproduce.sh'
else
	status=non-certifying
	if test "$quick" = true; then
		command_recorded='./integration/r13/reproduce.sh --quick'
	else
		command_recorded="R13_DURATION=$duration ./integration/r13/reproduce.sh"
	fi
fi

# Fetch server binary hashes and final cluster state.
docker run --rm --platform "$platform" -v "$temporary:/cluster" \
	"$image_reference" sh -c '
	set -eu
	ceph --version > /cluster/ceph.version
	sha256sum "$(command -v ceph-mon)" | awk "{print \$1}" \
		> /cluster/ceph-mon.sha256
	sha256sum "$(command -v ceph-osd)" | awk "{print \$1}" \
		> /cluster/ceph-osd.sha256
'
ceph_cli osd stat --format json >"$temporary/final-osd-stat.json"
ceph_cli health --format json >"$temporary/final-health.json"

# Enumerate source artefacts using the tool's canonical print mode so the
# shell script never re-implements the git-ls-files exclusion set.
cargo run --quiet --locked -p rados-r13-tools --bin rados-r13-candidate -- \
	--schema-digest --root "$root" >/dev/null

artifacts_json="$temporary/artifacts.json"
cargo run --quiet --locked -p rados-r13-tools --bin rados-r13-qualify -- \
	--print-source-artifacts --root "$root" >"$artifacts_json"

jq -n \
	--arg status "$status" \
	--arg command "$command_recorded" \
	--arg started_at "$started_at" \
	--arg finished_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
	--arg image "$image_reference" \
	--arg platform "$platform" \
	--arg version "$(cat "$temporary/ceph.version")" \
	--arg mon_sha256 "$(cat "$temporary/ceph-mon.sha256")" \
	--arg osd_sha256 "$(cat "$temporary/ceph-osd.sha256")" \
	--argjson managers "$managers" \
	--argjson manager_exercised "$manager_behavior_exercised" \
	--argjson ticket_ttl "$ticket_ttl" \
	--argjson artifacts "$(cat "$artifacts_json")" \
	--argjson secure "$(cat "$temporary/probe-secure.json")" \
	--argjson crc "$(cat "$temporary/probe-crc.json")" \
	--argjson churn "$(cat "$temporary/churn.json")" \
	--argjson final_osds "$(cat "$temporary/final-osd-stat.json")" \
	--argjson final_health "$(cat "$temporary/final-health.json")" \
	--argjson runs "$(cat "$temporary/benchmark-runs.json")" \
	--argjson release "$(cat "$temporary/release.json")" \
	--argjson qualification "$(cat "$temporary/qualification.json")" \
	--argjson fuzz "$(cat "$temporary/fuzz.json")" \
	'{
		schema_version: 2,
		status: $status,
		command: $command,
		started_at: $started_at,
		finished_at: $finished_at,
		qualification: $qualification,
		fuzz: $fuzz,
		reviews: null,
		source: {
			repository: "https://github.com/otuschhoff/rados-rs.git",
			identity: "content-addressed-artifacts",
			artifacts: $artifacts
		},
		server: {
			repository: "https://github.com/ceph/ceph.git",
			source_anchor_commit: "7f793731f1b39eb4f465e960113d2363c311b964",
			version: $version,
			image: $image,
			platform: $platform,
			binaries: {mon_sha256:$mon_sha256, osd_sha256:$osd_sha256}
		},
		cluster: {
			fsid: "41111111-2222-4333-8444-131313131313",
			network: "172.30.114.0/24",
			monitors: ["v2:172.30.114.10:3300"],
			osds: 3,
			managers: $managers,
			manager_behavior_exercised: $manager_exercised,
			pool: {name: "r13-data", size: 2, min_size: 1, pg_num: 16},
			external_defaults: false,
			service_ticket_ttl_seconds: $ticket_ttl,
			transports: ["secure", "crc"]
		},
		probe: {secure: $secure, crc: $crc},
		churn: ($churn + {final_osd_stat:$final_osds,
		                   final_health:$final_health}),
		benchmark: {performed: ($runs | length == 4), runs: $runs},
		release: $release
	}' \
	>"$report_temp"

# Reject certifying-shape reports whose command changed; refuse quick output
# masquerading as certifying.
jq -e 'if .status == "candidate" then
	.command == "./integration/r13/reproduce.sh"
	and .qualification.status == "passed"
	and .fuzz.profile == "certifying"
	and .reviews == null
	and .benchmark.performed
	and (.benchmark.runs | length) == 4
	and .release.performed
	and .release.path == "docs/r13/release-artifacts"
	and .release.reproducible
	and (.release.artifacts | length) == 4
elif .status == "non-certifying" then
	.command != "./integration/r13/reproduce.sh"
	and .qualification == null
	and .fuzz == null
	and .reviews == null
	and (.benchmark.runs | length) == 0
	and .release == {performed:false, version:null, path:null,
	                   reproducible:false, artifacts:{}}
else false end' "$report_temp" >/dev/null

# Full R13 candidate verifier: rejects anything the shape check would miss
# (schema mismatch, bad source binding, stale release artefacts, etc.).
# --allow-non-certifying is only passed for --quick output; certifying
# candidates must satisfy the strict verifier.
verify_flags="--verify --root $root --report $report_temp"
if test "$quick" = true; then
	verify_flags="$verify_flags --allow-non-certifying"
fi
# shellcheck disable=SC2086
cargo run --quiet --locked -p rados-r13-tools --bin rados-r13-candidate -- \
	$verify_flags

mv "$report_temp" "$final_report"
printf 'R13 reproduce.sh emitted %s (status=%s)\n' "$final_report" "$status"
