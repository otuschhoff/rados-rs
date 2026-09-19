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
case "$(docker info --format '{{.Architecture}}')" in
  x86_64|amd64) platform=linux/amd64 ;;
  aarch64|arm64) platform=linux/arm64 ;;
  *) printf '%s\n' 'R10 live: unsupported Docker architecture' >&2; exit 2 ;;
esac
ceph_image=quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa
rust_image=rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922
fsid=11111111-2222-4333-8444-101010101010
network="rados-rs-r10-$$"
temporary=$(mktemp -d)
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cleanup() {
  docker rm -f "r10-rust-$$" "r10-native-watch-$$" "r10-mon-$$" "r10-osd-0-$$" "r10-osd-1-$$" "r10-osd-2-$$" >/dev/null 2>&1 || true
  docker volume rm "rados-rs-r10-osd-0-$$" "rados-rs-r10-osd-1-$$" "rados-rs-r10-osd-2-$$" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker run --rm --user 0 --platform "$platform" -v "$temporary:/work" "$ceph_image" chmod -R a+rwx /work >/dev/null 2>&1 || true
  rm -rf "$temporary" || true
}
trap cleanup EXIT HUP INT TERM
fail() { dump_logs; printf '%s\n' "R10 live: $*" >&2; exit 1; }
sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
source_digest() { git -C "$root" ls-files -co --exclude-standard -- 'src/**' 'tools/r10/**' 'integration/r10/**' 'fuzz/fuzz_targets/r10_*' Cargo.toml Cargo.lock build.rs rust-toolchain.toml | LC_ALL=C sort | while IFS= read -r file; do printf '%s  %s\n' "$(sha256_file "$root/$file")" "$file"; done | shasum -a 256 | awk '{print $1}'; }
dump_logs() {
  failure_logs="/tmp/rados-r10-failure-$$"
  mkdir -p "$failure_logs"
  docker logs "r10-mon-$$" >"$failure_logs/mon.log" 2>&1 || true
  for id in 0 1 2; do docker logs "r10-osd-$id-$$" >"$failure_logs/osd-$id.log" 2>&1 || true; done
  docker logs "r10-rust-$$" >"$failure_logs/rust.log" 2>&1 || true
  printf '%s\n' "R10 live failure logs: $failure_logs" >&2
}

[ "$(git -C "$go_root" rev-parse HEAD)" = c8bb148a1379b51ef87256c27f366a05f8da4dc4 ] || fail 'unexpected Go revision'
[ "$(git -C "$go_root" rev-parse 'HEAD^{tree}')" = c5039b6b50a05b942a902f70dc2fcb090463e8c7 ] || fail 'unexpected Go tree'
[ -z "$(git -C "$go_root" status --porcelain=v1 --untracked-files=all)" ] || fail 'Go checkout is dirty'
go_version=$(GOTOOLCHAIN=go1.26.8 go version | awk '{print $3}')
[ "$go_version" = go1.26.8 ] || fail 'Go 1.26.8 is unavailable'
(cd "$go_root" && GOTOOLCHAIN=go1.26.8 CGO_ENABLED=0 go test ./internal/objecter -run '^(TestClassOperationOutcomeUnknownIsObservable|TestWatchDispatchOverflowIsObservable|TestNotifyPreservesPartialTimeoutResult|TestClientCloseSettlesPendingNotify)$' -count=1)
source_digest_before=$(source_digest)
mkdir -p "$temporary/rust-source" "$temporary/build" "$temporary/cargo-home"
git -C "$root" ls-files -co --exclude-standard -z | tar --null -T - -C "$root" -cf - | tar -C "$temporary/rust-source" -xf -
docker run --rm --platform "$platform" -v "$temporary/rust-source:/source:ro" -v "$temporary/build:/build" -v "$temporary/cargo-home:/cargo" "$rust_image" sh -c '
  set -eu; cd /source
  CARGO_HOME=/cargo CARGO_TARGET_DIR=/build cargo build --locked --release -p rados-r10-tools --bin rados-r10-live
'
cp "$temporary/build/release/rados-r10-live" "$temporary/rust-probe"
sed 's/"go-lock"/"rust-lock"/g; s/"go-cookie"/"rust-cookie"/g; s/Go lock/Rust lock/g' "$go_root/integration/p09/native_driver.c" >"$temporary/native_driver.c"
docker run --rm --user 0 --platform "$platform" -v "$temporary:/work" "$ceph_image" sh -c 'cc -std=c11 -Wall -Wextra -Werror -O2 /work/native_driver.c -ldl -o /work/native-probe'

# Bootstrap the pinned three-OSD replicated qualification cluster.
docker network create --subnet 172.30.100.0/24 "$network" >/dev/null
docker run --rm --user 0 --platform "$platform" -v "$temporary:/cluster" "$ceph_image" sh -c '
  set -eu
  cat >/cluster/ceph.conf <<EOF
[global]
fsid = 11111111-2222-4333-8444-101010101010
mon host = v2:172.30.100.10:3300
auth cluster required = cephx
auth service required = cephx
auth client required = cephx
ms bind msgr1 = false
ms bind msgr2 = true
osd pool default size = 2
osd pool default min size = 1
EOF
  ceph-authtool /cluster/mon.keyring --create-keyring --gen-key -n mon. --cap mon "allow *"
  ceph-authtool /cluster/admin.keyring --create-keyring --gen-key -n client.admin --cap mon "allow *" --cap osd "allow *" --cap mgr "allow *"
  ceph-authtool /cluster/mon.keyring --import-keyring /cluster/admin.keyring
  monmaptool --create --fsid 11111111-2222-4333-8444-101010101010 --addv a "[v2:172.30.100.10:3300/0]" /cluster/monmap
  mkdir -p /cluster/mondata
  ceph-mon --mkfs -i a --fsid 11111111-2222-4333-8444-101010101010 --monmap /cluster/monmap --keyring /cluster/mon.keyring --mon-data /cluster/mondata
  chown -R ceph:ceph /cluster/mondata
'
docker run -d --name "r10-mon-$$" --platform "$platform" --network "$network" --ip 172.30.100.10 -v "$temporary:/cluster" "$ceph_image" ceph-mon -f -i a --mon-data /cluster/mondata --public-addr v2:172.30.100.10:3300 --setuser ceph --setgroup ceph --mon-data-avail-crit 0 --no-mon-cluster-log-to-stderr >/dev/null
ceph_cli() { docker run --rm --platform "$platform" --network "$network" -v "$temporary:/cluster" "$ceph_image" timeout 20 ceph --conf /cluster/ceph.conf --name client.admin --keyring /cluster/admin.keyring "$@"; }
for attempt in $(seq 1 30); do if ceph_cli status --format json 2>/dev/null | jq -e '.health.status != null' >/dev/null; then break; fi; [ "$attempt" -lt 30 ] || { dump_logs; fail 'monitor did not become ready'; }; sleep 1; done
for id in 0 1 2; do
  uuid="00000000-0000-4000-8000-00000000010$id"; volume="rados-rs-r10-osd-$id-$$"
  docker volume create "$volume" >/dev/null
  ceph_cli osd create "$uuid" "$id" >/dev/null
  ceph_cli auth get-or-create "osd.$id" mon 'allow profile osd' mgr 'allow profile osd' osd 'allow *' -o "/cluster/osd-$id.keyring"
  ceph_cli mon getmap -o "/cluster/osd-$id.monmap" >/dev/null
  docker run --rm --user 0 --privileged --platform "$platform" -v "$temporary:/cluster" -v "$volume:/osd" "$ceph_image" sh -c '
    set -eu; id='"$id"'; uuid='"$uuid"'; mkdir -p /osd/data; truncate -s 1G /osd/block
    cp /cluster/osd-$id.keyring /osd/data/keyring; cp /cluster/osd-$id.monmap /osd/data/activate.monmap; chown -R ceph:ceph /osd
    ceph-osd --mkfs -i "$id" --osd-data /osd/data --osd-uuid "$uuid" --osd-objectstore bluestore --bluestore-block-path /osd/block --monmap /osd/data/activate.monmap --keyring /osd/data/keyring --setuser ceph --setgroup ceph
  '
  ip="172.30.100.$((20 + id))"
  docker run -d --privileged --name "r10-osd-$id-$$" --platform "$platform" --network "$network" --ip "$ip" -v "$temporary:/cluster" -v "$volume:/osd" "$ceph_image" ceph-osd -f --conf /cluster/ceph.conf -i "$id" --osd-data /osd/data --osd-objectstore bluestore --public-addr "v2:$ip:6800" --cluster-addr "v2:$ip:6802" --log-to-stderr true --err-to-stderr true --log-file '' --setuser ceph --setgroup ceph >/dev/null
done
for attempt in $(seq 1 90); do if ceph_cli osd stat --format json 2>/dev/null | jq -e '.num_osds == 3 and .num_up_osds == 3 and .num_in_osds == 3' >/dev/null; then break; fi; [ "$attempt" -lt 90 ] || { dump_logs; fail 'OSDs did not become ready'; }; sleep 1; done
ceph_cli osd crush rule create-replicated r10-rule default osd >/dev/null
ceph_cli osd pool create p10-data 16 16 replicated r10-rule >/dev/null
ceph_cli osd pool set p10-data size 2 >/dev/null
ceph_cli osd pool set p10-data min_size 1 >/dev/null
ceph_cli auth get-or-create client.p09 mon 'allow r' osd 'allow rwx pool=p10-data' -o /cluster/client.keyring >/dev/null
ceph_cli auth get-key client.p09 >"$temporary/client.key"
for attempt in $(seq 1 120); do if printf 'ready\n' | docker run --rm -i --platform "$platform" --network "$network" -v "$temporary:/cluster" "$ceph_image" timeout 20 rados --conf /cluster/ceph.conf --name client.p09 --keyring /cluster/client.keyring --pool p10-data put readiness - >/dev/null 2>&1; then break; fi; [ "$attempt" -lt 120 ] || fail 'pool I/O did not become ready'; sleep 1; done

docker run --rm --platform "$platform" --network "$network" -v "$temporary:/work" "$ceph_image" timeout 30 /work/native-probe seed /work/ceph.conf /work/client.keyring p10-data >"$temporary/native-seed.json"
docker run --rm --name "r10-native-watch-$$" --platform "$platform" --network "$network" -v "$temporary:/work" "$ceph_image" timeout 180 /work/native-probe watch /work/ceph.conf /work/client.keyring p10-data /work >"$temporary/native-watch.json" &
native_watch_pid=$!
docker run -d --name "r10-rust-$$" --platform "$platform" --network "$network" -v "$temporary:/work" "$ceph_image" /work/rust-probe --monitors 172.30.100.10:3300 --key /work/client.key --fsid "$fsid" --coordination-dir /work >/dev/null
wait_file() { file=$1; description=$2; for attempt in $(seq 1 900); do [ -f "$temporary/$file" ] && return; running=$(docker inspect -f '{{.State.Running}}' "r10-rust-$$" 2>/dev/null || true); [ "$running" = true ] || { docker logs "r10-rust-$$" >&2; fail "$description"; }; sleep 0.1; done; fail "$description"; }
wait_file native-verify-ready 'Rust lock did not become ready'
docker run --rm --platform "$platform" --network "$network" -v "$temporary:/work" "$ceph_image" timeout 30 /work/native-probe verify /work/ceph.conf /work/client.keyring p10-data >"$temporary/native-verify.json"
: >"$temporary/native-verify-complete"
wait_file go-watch-ready 'Rust watch did not become ready'
docker run --rm --platform "$platform" --network "$network" -v "$temporary:/work" "$ceph_image" timeout 30 /work/native-probe notify /work/ceph.conf /work/client.keyring p10-data >"$temporary/native-notify.json"
wait_file remap-watch-ready 'remap watch did not become ready'
old_primary=$(ceph_cli osd map p10-data coordination --format json | jq -r '.acting_primary')
docker stop "r10-osd-$old_primary-$$" >/dev/null
ceph_cli osd down "$old_primary" >/dev/null
ceph_cli osd out "$old_primary" >/dev/null
for attempt in $(seq 1 60); do new_primary=$(ceph_cli osd map p10-data coordination --format json 2>/dev/null | jq -r '.acting_primary'); if [ "$new_primary" != "$old_primary" ] && ceph_cli health --format json 2>/dev/null | jq -e '.checks.PG_AVAILABILITY == null' >/dev/null; then break; fi; [ "$attempt" -lt 60 ] || fail 'watched object did not remap'; sleep 1; done
: >"$temporary/remap-complete"
wait_file remap-verified 'post-remap delivery was not verified'
docker start "r10-osd-$old_primary-$$" >/dev/null
ceph_cli osd in "$old_primary" >/dev/null
for attempt in $(seq 1 60); do if ceph_cli osd stat --format json 2>/dev/null | jq -e '.num_up_osds == 3 and .num_in_osds == 3' >/dev/null; then break; fi; [ "$attempt" -lt 60 ] || fail 'OSD did not rejoin'; sleep 1; done
restart_primary=$(ceph_cli osd map p10-data coordination --format json | jq -r '.acting_primary')
docker stop "r10-osd-$restart_primary-$$" >/dev/null
ceph_cli osd down "$restart_primary" >/dev/null
for attempt in $(seq 1 60); do restart_failover=$(ceph_cli osd map p10-data coordination --format json 2>/dev/null | jq -r '.acting_primary'); if [ "$restart_failover" != "$restart_primary" ] && ceph_cli health --format json 2>/dev/null | jq -e '.checks.PG_AVAILABILITY == null' >/dev/null; then break; fi; [ "$attempt" -lt 60 ] || fail 'restart failover did not complete'; sleep 1; done
docker start "r10-osd-$restart_primary-$$" >/dev/null
: >"$temporary/restart-complete"
[ "$(docker wait "r10-rust-$$")" = 0 ] || { docker logs "r10-rust-$$" >&2; fail 'Rust probe failed'; }
docker logs "r10-rust-$$" >"$temporary/rust.json" 2>/dev/null
wait "$native_watch_pid" || { cat "$temporary/native-watch.json" >&2; fail 'native watch failed'; }
jq -e 'all(.[]; . == true)' "$temporary/rust.json" >/dev/null
jq -e '.native_exec and .native_lock_seed and .native_lock_renew and .native_lock_release and .native_lock_expiry' "$temporary/native-seed.json" >/dev/null
jq -e '.go_notify_native_watch and .native_watch_remap and .native_watch_restart and .native_watch_same_cookie and .native_watch_exactly_once and .native_lock_shared and .native_shared_release' "$temporary/native-watch.json" >/dev/null
jq -e '.native_notify_go_watch' "$temporary/native-notify.json" >/dev/null
jq -e '.go_lock_native_read and .native_break_go_lock' "$temporary/native-verify.json" >/dev/null

[ "$source_digest_before" = "$(source_digest)" ] || fail 'source changed during qualification'
[ -z "$(git -C "$go_root" status --porcelain=v1 --untracked-files=all)" ] || fail 'Go checkout changed during qualification'
server_version=$(docker run --rm --platform "$platform" "$ceph_image" ceph --version)
native_version=$(docker run --rm --platform "$platform" "$ceph_image" rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}' librados2)
docker run --rm --platform "$platform" "$ceph_image" sh -c 'cat "$(command -v ceph-osd)"' >"$temporary/server-binary"
server_binary_sha256=$(sha256_file "$temporary/server-binary")
mkdir -p "$(dirname "$report")"
candidate="$(dirname "$report")/.$(basename "$report").tmp.$$"
jq -n --arg started_at "$started_at" --arg finished_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg schema_sha256 "$(sha256_file "$root/integration/r10/report.schema.json")" --arg revision "$(git -C "$root" rev-parse HEAD)" --arg tree "$(git -C "$root" rev-parse 'HEAD^{tree}')" --arg source_sha256 "$source_digest_before" --arg rust_image "$rust_image" --arg platform "$platform" --arg rust_binary_sha256 "$(sha256_file "$temporary/rust-probe")" --arg native_driver_sha256 "$(sha256_file "$temporary/native_driver.c")" --arg native_binary_sha256 "$(sha256_file "$temporary/native-probe")" --arg native_version "$native_version" --arg server_version "$server_version" --arg server_binary_sha256 "$server_binary_sha256" --argjson rust_probe "$(cat "$temporary/rust.json")" --argjson native_seed "$(cat "$temporary/native-seed.json")" --argjson native_watch "$(cat "$temporary/native-watch.json")" --argjson native_notify "$(cat "$temporary/native-notify.json")" --argjson native_verify "$(cat "$temporary/native-verify.json")" '{schema_version:1,suite_id:"r10/classes-locks-watches-v1",status:"passed",started_at:$started_at,finished_at:$finished_at,schema_sha256:$schema_sha256,rust:{revision:$revision,tree:$tree,source_sha256:$source_sha256,compiler_image:$rust_image,platform:$platform,binary_sha256:$rust_binary_sha256},go:{revision:"c8bb148a1379b51ef87256c27f366a05f8da4dc4",tree:"c5039b6b50a05b942a902f70dc2fcb090463e8c7",compiler:"go1.26.8",platform:$platform,p09_driver_sha256:$native_driver_sha256,focused_tests:"passed"},native:{version:$native_version,binary_sha256:$native_binary_sha256,seed:$native_seed,watch:$native_watch,notify:$native_notify,verify:$native_verify},server:{source_anchor_commit:"7f793731f1b39eb4f465e960113d2363c311b964",version:$server_version,image:"quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa",binary_sha256:$server_binary_sha256},cluster:{fsid:"11111111-2222-4333-8444-101010101010",osds:3,pool:"p10-data",replicas:2},probe:$rust_probe,scenarios:{class_execution:"passed",lock_interoperability:"passed",lock_lease_lifecycle:"passed",watch_notify_interoperability:"passed",partial_timeout_results:"passed",remap_reregistration:"passed",osd_restart:"passed",explicit_unregister:"passed",lost_watch_observability:"passed",bounded_shutdown:"passed"},deviations:{notify_outcome_shape:"Rust returns (NotifyReply, Result<()>) so partial timeout data and the server error remain simultaneously observable; frozen Go returns (NotifyReply, error).",notification_dispatch:"Rust uses a bounded client-wide broadcast and terminates a lagging watch observably; frozen Go routes by cookie into per-watch queues."}}' >"$candidate"
jq '.deviations.ambiguous_coordination_replay = "Rust does not replay class, lock, notify, or acknowledgment operations after an ambiguous transport outcome and returns OutcomeUnknown; frozen Go may retry outcome-sensitive operations after a primary change with the same transaction identity."' "$candidate" >"$candidate.deviation"
mv "$candidate.deviation" "$candidate"
cargo run --quiet -p rados-r10-tools --bin rados-r10-verify -- "$root" "$candidate" "$temporary/rust-probe" "$go_root" "$temporary/native_driver.c" "$temporary/native-probe" "$temporary/server-binary"
mv "$candidate" "$report"
printf '%s\n' "R10 live qualification passed: $report"
