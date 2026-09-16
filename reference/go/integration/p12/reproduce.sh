#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$root"

quick=false
case "${1:-}" in
	"") ;;
	--quick) quick=true ;;
	*) printf 'usage: %s [--quick]\n' "$0" >&2; exit 2 ;;
esac

for command_name in docker go jq shasum; do
	command -v "$command_name" >/dev/null 2>&1 || { printf 'P12 requires %s\n' "$command_name" >&2; exit 2; }
done
docker info >/dev/null 2>&1 || { printf '%s\n' 'P12 requires a running Docker daemon' >&2; exit 2; }
case "$(docker info --format '{{.Architecture}}')" in
	x86_64|amd64) platform=linux/amd64; goarch=amd64 ;;
	aarch64|arm64) platform=linux/arm64; goarch=arm64 ;;
	*) printf '%s\n' 'P12 supports only amd64 and arm64 Docker daemons' >&2; exit 2 ;;
esac

duration=${P12_DURATION:-24h}
reconnect_interval=50m
sample_interval=1m
ticket_ttl_seconds=900
churn_interval=15m
operation_timeout=2m
probe_timeout=26h
if test "$quick" = true; then
	duration=${P12_DURATION:-3m}
	reconnect_interval=2m
	sample_interval=10s
	ticket_ttl_seconds=30
	churn_interval=30
	probe_timeout=10m
fi

if test "$quick" = false; then
	CGO_ENABLED=0 GOTOOLCHAIN=go1.27.1 go run ./tools/p12-verify -check-fuzz docs/p12/fuzz-report.json -require-certifying-fuzz
fi

started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
image_index=$(jq -er '.images.qualification.reference' docs/p00/evidence.json)
image_digest=$(jq -er --arg architecture "$goarch" '.images.qualification[$architecture]' docs/p00/evidence.json)
image="${image_index%@*}@$image_digest"
temporary=$(mktemp -d)
network="go-librados-p12-$$"
fsid=31111111-2222-4333-8444-121212121212
subnet=172.30.112.0/24
report="$root/integration/p12/.report.json.$$"
final_report="$root/integration/p12/report.json"
release_stage="$root/docs/p12/.release-artifacts.$$"

cleanup() {
	exit_code=$?
	trap - EXIT HUP INT TERM
	if test "$exit_code" -ne 0; then
		for daemon in "p12-probe-secure-$$" "p12-probe-crc-$$" "p12-mon-$$" "p12-osd-0-$$" "p12-osd-1-$$" "p12-osd-2-$$"; do
			printf 'last logs for %s\n' "$daemon" >&2
			docker logs --tail 40 "$daemon" >&2 2>/dev/null || true
		done
	fi
	for daemon in "p12-probe-secure-$$" "p12-probe-crc-$$" "p12-mon-$$" "p12-osd-0-$$" "p12-osd-1-$$" "p12-osd-2-$$"; do
		docker rm -f "$daemon" >/dev/null 2>&1 || true
	done
	for id in 0 1 2; do docker volume rm "go-librados-p12-osd-$id-$$" >/dev/null 2>&1 || true; done
	docker network rm "$network" >/dev/null 2>&1 || true
	rm -rf "$temporary"
	rm -rf "$release_stage"
	rm -f "$report"
	exit "$exit_code"
}
trap cleanup EXIT HUP INT TERM

CGO_ENABLED=0 GOTOOLCHAIN=go1.27.1 GOOS=linux GOARCH="$goarch" go build -tags p12diagnostics -trimpath -o "$temporary/probe" ./integration/p12/probe
CGO_ENABLED=0 GOTOOLCHAIN=go1.27.1 GOOS=linux GOARCH="$goarch" go build -trimpath -o "$temporary/benchmark" ./integration/p07/benchmark
cp integration/p07/native_benchmark.c "$temporary/"
docker run --rm --user 0 --platform "$platform" -v "$temporary:/cluster" "$image" sh -c '
	set -eu
	cc -std=c11 -Wall -Wextra -Werror -O2 -pthread /cluster/native_benchmark.c -ldl -o /cluster/native-benchmark
'

docker network create --subnet "$subnet" "$network" >/dev/null
docker run --rm --user 0 --platform "$platform" -v "$temporary:/cluster" "$image" sh -c '
	set -eu
	cat >/cluster/ceph.conf <<EOF
[global]
fsid = 31111111-2222-4333-8444-121212121212
mon host = v2:172.30.112.10:3300
auth cluster required = cephx
auth service required = cephx
auth client required = cephx
auth service ticket ttl = '"$ticket_ttl_seconds"'
auth mon ticket ttl = '"$ticket_ttl_seconds"'
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
	ceph-authtool /cluster/mon.keyring --create-keyring --gen-key -n mon. --cap mon "allow *"
	ceph-authtool /cluster/admin.keyring --create-keyring --gen-key -n client.admin --cap mon "allow *" --cap osd "allow *" --cap mgr "allow *"
	ceph-authtool /cluster/mon.keyring --import-keyring /cluster/admin.keyring
	monmaptool --create --fsid 31111111-2222-4333-8444-121212121212 --addv a "[v2:172.30.112.10:3300/0]" /cluster/monmap
	mkdir -p /cluster/mondata
	ceph-mon --mkfs -i a --fsid 31111111-2222-4333-8444-121212121212 --monmap /cluster/monmap --keyring /cluster/mon.keyring --mon-data /cluster/mondata
	chown -R ceph:ceph /cluster/mondata
'
docker run -d --name "p12-mon-$$" --platform "$platform" --network "$network" --ip 172.30.112.10 -v "$temporary:/cluster" "$image" \
	ceph-mon -f -i a --conf /cluster/ceph.conf --mon-data /cluster/mondata --public-addr v2:172.30.112.10:3300 --setuser ceph --setgroup ceph --mon-data-avail-crit 0 --no-mon-cluster-log-to-stderr >/dev/null

ceph_cli() {
	docker run --rm --platform "$platform" --network "$network" -v "$temporary:/cluster" "$image" \
		timeout 20 ceph --conf /cluster/ceph.conf --name client.admin --keyring /cluster/admin.keyring "$@"
}
for attempt in $(seq 1 60); do
	if ceph_cli status --format json 2>/dev/null | jq -e '.health.status != null' >/dev/null; then break; fi
	test "$attempt" -lt 60 || { docker logs "p12-mon-$$" >&2; exit 1; }
	sleep 1
done

for id in 0 1 2; do
	uuid="12000000-0000-4000-8000-00000000001$id"
	volume="go-librados-p12-osd-$id-$$"
	docker volume create "$volume" >/dev/null
	ceph_cli osd create "$uuid" "$id" >/dev/null
	ceph_cli auth get-or-create "osd.$id" mon 'allow profile osd' mgr 'allow profile osd' osd 'allow *' -o "/cluster/osd-$id.keyring"
	ceph_cli mon getmap -o "/cluster/osd-$id.monmap" >/dev/null
	docker run --rm --user 0 --privileged --platform "$platform" -v "$temporary:/cluster" -v "$volume:/osd" "$image" sh -c '
		set -eu
		id='"$id"'; uuid='"$uuid"'
		mkdir -p /osd/data
		truncate -s 8G /osd/block
		cp /cluster/osd-$id.keyring /osd/data/keyring
		cp /cluster/osd-$id.monmap /osd/data/activate.monmap
		chown -R ceph:ceph /osd
		ceph-osd --mkfs -i "$id" --osd-data /osd/data --osd-uuid "$uuid" --osd-objectstore bluestore --bluestore-block-path /osd/block --monmap /osd/data/activate.monmap --keyring /osd/data/keyring --setuser ceph --setgroup ceph
	'
	ip="172.30.112.$((20 + id))"
	docker run -d --privileged --name "p12-osd-$id-$$" --platform "$platform" --network "$network" --ip "$ip" -v "$temporary:/cluster" -v "$volume:/osd" "$image" \
		ceph-osd -f --conf /cluster/ceph.conf -i "$id" --osd-data /osd/data --osd-objectstore bluestore --public-addr "v2:$ip:6800" --cluster-addr "v2:$ip:6802" --setuser ceph --setgroup ceph >/dev/null
done
for attempt in $(seq 1 120); do
	if ceph_cli osd stat --format json 2>/dev/null | jq -e '.num_osds == 3 and .num_up_osds == 3 and .num_in_osds == 3' >/dev/null; then break; fi
	test "$attempt" -lt 120 || { ceph_cli osd tree >&2; exit 1; }
	sleep 1
done

ceph_cli osd crush rule create-replicated p12-rule default osd >/dev/null
ceph_cli osd pool create p12-data 16 16 replicated p12-rule >/dev/null
ceph_cli osd pool set p12-data size 2 >/dev/null
ceph_cli osd pool set p12-data min_size 1 >/dev/null
ceph_cli auth get-or-create client.p12 mon 'allow r' osd 'allow rw pool=p12-data' >/dev/null
ceph_cli auth get-key client.p12 >"$temporary/client.key"
# P07 benchmark programs intentionally use this fixed identity.
ceph_cli auth get-or-create client.p07 mon 'allow r' osd 'allow rw pool=p12-data' >/dev/null
ceph_cli auth get-key client.p07 >"$temporary/p07.key"
ceph_cli auth get client.p07 -o /cluster/p07.keyring >/dev/null
docker exec "p12-mon-$$" ceph --admin-daemon /run/ceph/ceph-mon.a.asok config get auth_service_ticket_ttl >"$temporary/observed-ticket-ttl.json"
jq -er '.auth_service_ticket_ttl | tonumber | floor' "$temporary/observed-ticket-ttl.json" >"$temporary/observed-ticket-ttl"
test "$(cat "$temporary/observed-ticket-ttl")" = "$ticket_ttl_seconds"

printf 'p12-ready\n' >"$temporary/ready-payload"
for attempt in $(seq 1 120); do
	if docker run --rm --platform "$platform" --network "$network" -v "$temporary:/cluster" "$image" \
		timeout 20 rados --conf /cluster/ceph.conf --name client.admin --keyring /cluster/admin.keyring --pool p12-data put p12-readiness /cluster/ready-payload >/dev/null 2>&1; then break; fi
	test "$attempt" -lt 120 || { ceph_cli health detail >&2; exit 1; }
	sleep 1
done
docker run --rm --platform "$platform" --network "$network" -v "$temporary:/cluster" "$image" \
	timeout 20 rados --conf /cluster/ceph.conf --name client.admin --keyring /cluster/admin.keyring --pool p12-data rm p12-readiness >/dev/null

for transport in secure crc; do
	docker run -d --name "p12-probe-$transport-$$" --platform "$platform" --network "$network" -v "$temporary:/work" "$image" \
		sh -c 'exec timeout "$1" /work/probe -monitors 172.30.112.10:3300 -key-file /work/client.key -fsid 31111111-2222-4333-8444-121212121212 -pool p12-data -entity client.p12 -transport "$2" -duration "$3" -reconnect-interval "$4" -sample-interval "$5" -operation-timeout "$6" -control-dir /work >"/work/probe-$2.json"' \
		sh "$probe_timeout" "$transport" "$duration" "$reconnect_interval" "$sample_interval" "$operation_timeout" >/dev/null
done

monitor_restarts=0
monitor_recoveries=0
osd_restarts=0
osd_recoveries=0
cycle=0
next_churn=$(( $(date +%s) + churn_interval ))
while :; do
	secure_running=$(docker inspect -f '{{.State.Running}}' "p12-probe-secure-$$" 2>/dev/null || printf false)
	crc_running=$(docker inspect -f '{{.State.Running}}' "p12-probe-crc-$$" 2>/dev/null || printf false)
	test "$secure_running" = true && test "$crc_running" = true || break
	now=$(date +%s)
	if test "$now" -ge "$next_churn"; then
		: >"$temporary/pause"
		for attempt in $(seq 1 180); do
			if test -f "$temporary/paused-secure" && test -f "$temporary/paused-crc"; then break; fi
			test "$attempt" -lt 180 || exit 1
			sleep 1
		done
		if test $((cycle % 2)) -eq 0; then
			docker restart "p12-mon-$$" >/dev/null
			monitor_restarts=$((monitor_restarts + 1))
			for attempt in $(seq 1 60); do
				if ceph_cli status --format json 2>/dev/null | jq -e '.health.status != null' >/dev/null; then monitor_recoveries=$((monitor_recoveries + 1)); break; fi
				test "$attempt" -lt 60 || exit 1
				sleep 1
			done
		else
			id=$((cycle / 2 % 3))
			docker restart "p12-osd-$id-$$" >/dev/null
			osd_restarts=$((osd_restarts + 1))
			for attempt in $(seq 1 120); do
				if ceph_cli osd stat --format json 2>/dev/null | jq -e '.num_up_osds == 3 and .num_in_osds == 3' >/dev/null; then osd_recoveries=$((osd_recoveries + 1)); break; fi
				test "$attempt" -lt 120 || exit 1
				sleep 1
			done
		fi
		rm -f "$temporary/pause"
		for attempt in $(seq 1 30); do
			if test ! -f "$temporary/paused-secure" && test ! -f "$temporary/paused-crc"; then break; fi
			test "$attempt" -lt 30 || exit 1
			sleep 1
		done
		cycle=$((cycle + 1))
		next_churn=$(( $(date +%s) + churn_interval ))
	fi
	sleep 2
done

for transport in secure crc; do
	exit_code=$(docker wait "p12-probe-$transport-$$")
	test "$exit_code" -eq 0 || { docker logs "p12-probe-$transport-$$" >&2; exit 1; }
	jq -e --arg transport "$transport" '.transport == $transport and .monotonic_duration_satisfied and .operations > 0 and .writes == .operations and .reads == .operations and .stats == .operations and .removes == .operations and .append_once_verifications == .operations and .duplicate_mutations_detected == 0 and any(.credential_renewals[]; .service == "monitor") and any(.credential_renewals[]; .service == "osd") and (.samples | length) >= 2 and (.samples | length) <= .maximum_configured_sample_count' "$temporary/probe-$transport.json" >/dev/null
done

jq -n --argjson monitor_restarts "$monitor_restarts" --argjson monitor_recoveries "$monitor_recoveries" --argjson osd_restarts "$osd_restarts" --argjson osd_recoveries "$osd_recoveries" \
	'{monitor_restarts:$monitor_restarts,monitor_recoveries:$monitor_recoveries,osd_restarts:$osd_restarts,osd_recoveries:$osd_recoveries}' >"$temporary/churn.json"

certifying=$(jq -s --argjson day_ns 86400000000000 --argjson mon "$monitor_recoveries" --argjson osd "$osd_recoveries" '
	($mon >= 1 and $osd >= 1) and all(.[];
		.requested_duration_ns >= $day_ns and .elapsed_ns >= $day_ns and
		.reconnects >= ((.elapsed_ns / 3600000000000) | floor) and
		any(.credential_renewals[]; .service == "monitor") and
		any(.credential_renewals[]; .service == "osd") and
		.longest_connection_ns > (900 * 1000000000) and
		.duplicate_mutations_detected == 0)
' "$temporary/probe-secure.json" "$temporary/probe-crc.json")

printf '[]\n' >"$temporary/benchmark-runs.json"
printf '{"performed":false,"version":null,"path":null,"reproducible":false,"artifacts":{}}\n' >"$temporary/release.json"
printf 'null\n' >"$temporary/qualification.json"
printf 'null\n' >"$temporary/fuzz.json"
if test "$certifying" = true; then
	fuzz_report=docs/p12/fuzz-report.json
	CGO_ENABLED=0 GOTOOLCHAIN=go1.27.1 go run ./tools/p12-verify -check-fuzz "$fuzz_report" -require-certifying-fuzz
	fuzz_hash=$(shasum -a 256 "$fuzz_report" | awk '{print $1}')
	jq -n --arg hash "$fuzz_hash" '{path:"docs/p12/fuzz-report.json",status:"passed",profile:"certifying",sha256:$hash}' >"$temporary/fuzz.json"
	qualification_report=docs/p12/qualification-report.json
	jq -e '.schema_version == 1 and .status == "passed" and .command == "./integration/p12/qualify.sh"' "$qualification_report" >/dev/null
	qualification_hash=$(shasum -a 256 "$qualification_report" | awk '{print $1}')
	jq -n --arg hash "$qualification_hash" '{path:"docs/p12/qualification-report.json",status:"passed",sha256:$hash}' >"$temporary/qualification.json"
	for transport in secure crc; do
		docker run --rm --platform "$platform" --network "$network" -v "$temporary:/work" "$image" \
			timeout 3600 /work/benchmark -monitors 172.30.112.10:3300 -key-file /work/p07.key -fsid "$fsid" -pool p12-data -transport "$transport" >"$temporary/benchmark-go-$transport.json"
		docker run --rm --platform "$platform" --network "$network" -v "$temporary:/cluster" "$image" \
			timeout 3600 /cluster/native-benchmark /cluster/ceph.conf /cluster/p07.keyring p12-data "$transport" >"$temporary/benchmark-native-$transport.json"
		jq -e --arg transport "$transport" '.implementation == "go" and .transport == $transport and (.rows | length) == 36' "$temporary/benchmark-go-$transport.json" >/dev/null
		jq -e --arg transport "$transport" '.implementation == "native" and .transport == $transport and (.rows | length) == 36' "$temporary/benchmark-native-$transport.json" >/dev/null
	done
	jq -s '.' "$temporary/benchmark-go-secure.json" "$temporary/benchmark-go-crc.json" "$temporary/benchmark-native-secure.json" "$temporary/benchmark-native-crc.json" >"$temporary/benchmark-runs.json"
	release_version=${P12_RELEASE_VERSION:?P12_RELEASE_VERSION must be supplied for a certifying release run}
	for run in 1 2; do
		CGO_ENABLED=0 GOTOOLCHAIN=go1.27.1 go run ./tools/p12-release -root . -out "$temporary/release-$run" -version "$release_version"
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
	rm -rf "$root/docs/p12/release-artifacts"
	mv "$release_stage" "$root/docs/p12/release-artifacts"
	printf '{}\n' >"$temporary/release-artifacts.json"
	for artifact in "$root/docs/p12/release-artifacts"/*; do
		name=${artifact##*/}
		hash=$(shasum -a 256 "$artifact" | awk '{print $1}')
		jq --arg name "$name" --arg hash "$hash" '. + {($name):$hash}' "$temporary/release-artifacts.json" >"$temporary/release-artifacts.next"
		mv "$temporary/release-artifacts.next" "$temporary/release-artifacts.json"
	done
	jq -n --arg version "$release_version" --argjson artifacts "$(cat "$temporary/release-artifacts.json")" \
		'{performed:true,version:$version,path:"docs/p12/release-artifacts",reproducible:true,artifacts:$artifacts}' >"$temporary/release.json"
	status=candidate
	command='./integration/p12/reproduce.sh'
else
	status=non-certifying
	if test "$quick" = true; then command='./integration/p12/reproduce.sh --quick'; else command="P12_DURATION=$duration ./integration/p12/reproduce.sh"; fi
fi

docker run --rm --platform "$platform" -v "$temporary:/cluster" "$image" sh -c '
	set -eu
	ceph --version > /cluster/ceph.version
	sha256sum "$(command -v ceph-mon)" | awk "{print \$1}" > /cluster/ceph-mon.sha256
	sha256sum "$(command -v ceph-osd)" | awk "{print \$1}" > /cluster/ceph-osd.sha256
'
ceph_cli osd stat --format json >"$temporary/final-osd-stat.json"
ceph_cli health --format json >"$temporary/final-health.json"

artifacts="$temporary/artifacts.json"
printf '{}\n' >"$artifacts"
artifact_paths=$(find . -maxdepth 1 -type f \( -name '*.go' -o -name 'go.mod' -o -name 'go.sum' -o -name 'Makefile' -o -name 'SPEC.md' -o -name 'README.md' -o -name 'LICENSE' -o -name 'THIRD_PARTY_NOTICES' -o -name 'SECURITY.md' \) -print | sed 's#^./##'; find internal examples tools -type f -name '*.go' -print; find integration/p12 -type f ! -name 'report.json' -print; find docs/p12 -path docs/p12/release-artifacts -prune -o -type f ! -path docs/p12/human-review.json ! -path docs/p12/fuzz-report.json -print; printf '%s\n' .github/workflows/p00.yml .gitignore integration/p07/benchmark/main.go integration/p07/benchmark/main_unsupported.go integration/p07/native_benchmark.c docs/p00/api-inventory.csv docs/p00/compatibility.md docs/p00/licensing.md)
for artifact in $artifact_paths; do
	test -f "$artifact"
	hash=$(shasum -a 256 "$artifact" | awk '{print $1}')
	jq --arg path "$artifact" --arg hash "$hash" '. + {($path):$hash}' "$artifacts" >"$artifacts.next"
	mv "$artifacts.next" "$artifacts"
done

jq -n \
	--arg status "$status" --arg command "$command" --arg started_at "$started_at" --arg finished_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
	--arg image "$image" --arg platform "$platform" --arg version "$(cat "$temporary/ceph.version")" \
	--arg mon_sha256 "$(cat "$temporary/ceph-mon.sha256")" --arg osd_sha256 "$(cat "$temporary/ceph-osd.sha256")" \
	--argjson ticket_ttl "$(cat "$temporary/observed-ticket-ttl")" --argjson artifacts "$(cat "$artifacts")" \
	--argjson secure "$(cat "$temporary/probe-secure.json")" --argjson crc "$(cat "$temporary/probe-crc.json")" \
	--argjson churn "$(cat "$temporary/churn.json")" --argjson final_osds "$(cat "$temporary/final-osd-stat.json")" \
	--argjson final_health "$(cat "$temporary/final-health.json")" --argjson runs "$(cat "$temporary/benchmark-runs.json")" \
	--argjson release "$(cat "$temporary/release.json")" \
	--argjson qualification "$(cat "$temporary/qualification.json")" \
	--argjson fuzz "$(cat "$temporary/fuzz.json")" \
	'{schema_version:2,status:$status,command:$command,started_at:$started_at,finished_at:$finished_at,qualification:$qualification,fuzz:$fuzz,reviews:null,source:{repository:"https://github.com/otuschhoff/go-librados.git",identity:"content-addressed-artifacts",artifacts:$artifacts},server:{repository:"https://github.com/ceph/ceph.git",source_anchor_commit:"7f793731f1b39eb4f465e960113d2363c311b964",version:$version,image:$image,platform:$platform,binaries:{mon_sha256:$mon_sha256,osd_sha256:$osd_sha256}},cluster:{fsid:"31111111-2222-4333-8444-121212121212",network:"172.30.112.0/24",monitors:["v2:172.30.112.10:3300"],osds:3,pool:{name:"p12-data",size:2,min_size:1,pg_num:16},external_defaults:false,service_ticket_ttl_seconds:$ticket_ttl,transports:["secure","crc"]},probe:{secure:$secure,crc:$crc},churn:($churn + {final_osd_stat:$final_osds,final_health:$final_health}),benchmark:{performed:($runs | length == 4),runs:$runs},release:$release}' >"$report"

jq -e 'if .status == "candidate" then .command == "./integration/p12/reproduce.sh" and .qualification.status == "passed" and .fuzz == {path:"docs/p12/fuzz-report.json",status:"passed",profile:"certifying",sha256:.fuzz.sha256} and .reviews == null and .benchmark.performed and (.benchmark.runs | length) == 4 and .release.performed and .release.path == "docs/p12/release-artifacts" and .release.reproducible and (.release.artifacts | length) == 4 else .status == "non-certifying" and .qualification == null and .fuzz == null and .reviews == null and .command != "./integration/p12/reproduce.sh" and (.benchmark.runs | length) == 0 and (.release == {performed:false,version:null,path:null,reproducible:false,artifacts:{}}) end' "$report" >/dev/null
mv "$report" "$final_report"
printf 'P12 harness completed with status %s: %s\n' "$status" "$final_report"