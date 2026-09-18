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
for command in awk cargo cmp cp date docker git go jq mkdir mktemp mv sed seq shasum sleep tar touch; do
  command -v "$command" >/dev/null 2>&1 || { printf '%s\n' "R08 live: missing command: $command" >&2; exit 1; }
done

case "$(docker info --format '{{.Architecture}}')" in
  x86_64|amd64) platform=linux/amd64; goarch=amd64 ;;
  aarch64|arm64) platform=linux/arm64; goarch=arm64 ;;
  *) printf '%s\n' 'R08 live: unsupported Docker architecture' >&2; exit 2 ;;
esac
ceph_image=quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa
rust_image=rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922
fsid=88888888-2222-4333-8444-666666666666
network="rados-rs-r08-$$"
native_image="rados-r08-native:$$"
fault_osd_image="rados-r08-fault-osd:$$"
temporary=$(mktemp -d)
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

cleanup() {
  docker rm -f "r08-rust-failover-$$" "r08-mon-$$" "r08-osd-0-$$" "r08-osd-1-$$" "r08-osd-2-$$" >/dev/null 2>&1 || true
  docker volume rm "rados-rs-r08-osd-0-$$" "rados-rs-r08-osd-1-$$" "rados-rs-r08-osd-2-$$" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker image rm "$native_image" >/dev/null 2>&1 || true
  docker image rm "$fault_osd_image" >/dev/null 2>&1 || true
  docker run --rm --user 0 --platform "$platform" -v "$temporary:/work" "$ceph_image" chmod -R a+rwx /work >/dev/null 2>&1 || true
  rm -rf "$temporary" || true
}
trap cleanup EXIT HUP INT TERM

fail() { printf '%s\n' "R08 live: $*" >&2; exit 1; }
sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
source_digest() {
  git -C "$root" ls-files -co --exclude-standard -- 'src/**' 'tools/r08/**' 'integration/r08/**' Cargo.toml Cargo.lock build.rs rust-toolchain.toml |
    LC_ALL=C sort | while IFS= read -r source_path; do printf '%s  %s\n' "$(sha256_file "$root/$source_path")" "$source_path"; done |
    shasum -a 256 | awk '{print $1}'
}
dump_logs() {
  docker logs "r08-mon-$$" >&2 2>/dev/null || true
  for id in 0 1 2; do docker logs "r08-osd-$id-$$" >&2 2>/dev/null || true; done
}

go_revision=$(git -C "$go_root" rev-parse HEAD)
go_tree=$(git -C "$go_root" rev-parse 'HEAD^{tree}')
[ "$go_revision" = c8bb148a1379b51ef87256c27f366a05f8da4dc4 ] || fail 'unexpected Go revision'
[ "$go_tree" = c5039b6b50a05b942a902f70dc2fcb090463e8c7 ] || fail 'unexpected Go tree'
[ -z "$(git -C "$go_root" status --porcelain=v1 --untracked-files=all)" ] || fail 'Go checkout is dirty'
source_digest_before=$(source_digest)

mkdir -p "$temporary/rust-source" "$temporary/build" "$temporary/cargo-home" "$temporary/go-source" "$temporary/go-cache" "$temporary/go-mod-cache" "$temporary/control"
git -C "$root" ls-files -co --exclude-standard -z | tar --null -T - -C "$root" -cf - | tar -C "$temporary/rust-source" -xf -
docker run --rm --platform "$platform" -v "$temporary/rust-source:/source:ro" -v "$temporary/build:/build" -v "$temporary/cargo-home:/cargo" "$rust_image" sh -c '
  set -eu
  cd /source
  CARGO_HOME=/cargo CARGO_TARGET_DIR=/build cargo build --locked --release -p rados-r08-tools --bin rados-r08-live
  CARGO_HOME=/cargo CARGO_TARGET_DIR=/build cargo test --locked --release -p rados-rs msgr::supervisor::tests
  CARGO_HOME=/cargo CARGO_TARGET_DIR=/build cargo test --locked --release -p rados-rs osd::client::tests
  CARGO_HOME=/cargo CARGO_TARGET_DIR=/build cargo test --locked --release -p rados-rs client::tests::canceled_shutdown_wait_leaves_mutation_admission_open
'
ack_vs_commit=passed
flush_watermark=passed
cancellation_drop_boundaries=passed
cp "$temporary/build/release/rados-r08-live" "$temporary/rust-probe"

git -C "$go_root" archive HEAD | tar -x -C "$temporary/go-source"
mkdir -p "$temporary/go-source/integration/r08/probe"
cp "$root/tools/r08/go-probe/main.go" "$temporary/go-source/integration/r08/probe/main.go"
(cd "$temporary/go-source" && GOTOOLCHAIN=go1.26.8 GOOS=linux GOARCH="$goarch" CGO_ENABLED=0 GOCACHE="$temporary/go-cache" GOMODCACHE="$temporary/go-mod-cache" go build -trimpath -o "$temporary/go-probe" ./integration/r08/probe)
go_version=$(GOTOOLCHAIN=go1.26.8 go version | awk '{print $3}')
[ "$go_version" = go1.26.8 ] || fail 'Go 1.26.8 is unavailable'
[ -z "$(git -C "$go_root" status --porcelain=v1 --untracked-files=all)" ] || fail 'Go checkout changed during adapter build'

docker build --platform "$platform" -t "$native_image" "$root/tools/r08/native-probe"
docker build --platform "$platform" -t "$fault_osd_image" "$root/tools/r08/fault-osd"
native_container=$(docker create --platform "$platform" "$native_image")
docker cp "$native_container:/usr/local/bin/rados-r08-native" "$temporary/native-probe"
docker rm "$native_container" >/dev/null

docker network create --subnet 172.30.98.0/24 "$network" >/dev/null
docker run --rm --user 0 --platform "$platform" -v "$temporary:/cluster" "$ceph_image" sh -c '
  set -eu
  cat >/cluster/ceph.conf <<EOF
[global]
fsid = '"$fsid"'
mon host = v2:172.30.98.10:3300
auth cluster required = cephx
auth service required = cephx
auth client required = cephx
ms bind msgr1 = false
ms bind msgr2 = true
osd pool default size = 3
osd pool default min size = 2
EOF
  ceph-authtool /cluster/mon.keyring --create-keyring --gen-key -n mon. --cap mon "allow *"
  ceph-authtool /cluster/admin.keyring --create-keyring --gen-key -n client.admin --cap mon "allow *" --cap osd "allow *" --cap mgr "allow *"
  ceph-authtool /cluster/mon.keyring --import-keyring /cluster/admin.keyring
  monmaptool --create --fsid '"$fsid"' --addv a "[v2:172.30.98.10:3300/0]" /cluster/monmap
  mkdir -p /cluster/mondata
  ceph-mon --mkfs -i a --fsid '"$fsid"' --monmap /cluster/monmap --keyring /cluster/mon.keyring --mon-data /cluster/mondata
  chown -R ceph:ceph /cluster/mondata
'
docker run -d --name "r08-mon-$$" --platform "$platform" --network "$network" --ip 172.30.98.10 -v "$temporary:/cluster" "$ceph_image" \
  ceph-mon -f -i a --mon-data /cluster/mondata --public-addr v2:172.30.98.10:3300 --setuser ceph --setgroup ceph --mon-data-avail-crit 1 --no-mon-cluster-log-to-stderr >/dev/null

ceph_cli() {
  docker run --rm --platform "$platform" --network "$network" -v "$temporary:/cluster" "$ceph_image" \
    ceph --conf /cluster/ceph.conf --name client.admin --keyring /cluster/admin.keyring "$@"
}
rados_cli() {
  docker run --rm --platform "$platform" --network "$network" -v "$temporary:/cluster" "$ceph_image" \
    rados --conf /cluster/ceph.conf --name client.admin --keyring /cluster/admin.keyring -p r08-data "$@"
}
for attempt in $(seq 1 30); do
  if ceph_cli status --format json 2>/dev/null | jq -e '.health.status != null' >/dev/null; then break; fi
  [ "$attempt" -lt 30 ] || { dump_logs; fail 'monitor did not become ready'; }
  sleep 1
done
for id in 0 1 2; do
  uuid="00000000-0000-4000-8000-00000000008$id"
  volume="rados-rs-r08-osd-$id-$$"
  docker volume create "$volume" >/dev/null
  ceph_cli osd create "$uuid" "$id" >/dev/null
  ceph_cli auth get-or-create "osd.$id" mon 'allow profile osd' mgr 'allow profile osd' osd 'allow *' -o "/cluster/osd-$id.keyring"
  ceph_cli mon getmap -o "/cluster/osd-$id.monmap" >/dev/null
  docker run --rm --user 0 --privileged --platform "$platform" -v "$temporary:/cluster" -v "$volume:/osd" "$fault_osd_image" sh -c '
    set -eu
    id='"$id"'; uuid='"$uuid"'
    mkdir -p /osd/data
    truncate -s 1G /osd/block
    cp /cluster/osd-$id.keyring /osd/data/keyring
    cp /cluster/osd-$id.monmap /osd/data/activate.monmap
    chown -R ceph:ceph /osd
    ceph-osd --mkfs -i "$id" --osd-data /osd/data --osd-uuid "$uuid" --osd-objectstore bluestore --bluestore-block-path /osd/block --monmap /osd/data/activate.monmap --keyring /osd/data/keyring --setuser ceph --setgroup ceph
  '
  ip="172.30.98.$((20 + id))"
  docker run -d --privileged --name "r08-osd-$id-$$" --platform "$platform" --network "$network" --ip "$ip" -v "$temporary:/cluster" -v "$volume:/osd" "$fault_osd_image" \
    ceph-osd -f --conf /cluster/ceph.conf -i "$id" --osd-data /osd/data --osd-objectstore bluestore --public-addr "v2:$ip:6800" --cluster-addr "v2:$ip:6802" --setuser ceph --setgroup ceph >/dev/null
done
for attempt in $(seq 1 90); do
  if ceph_cli osd stat --format json 2>/dev/null | jq -e '.num_osds == 3 and .num_up_osds == 3 and .num_in_osds == 3' >/dev/null; then break; fi
  [ "$attempt" -lt 90 ] || { dump_logs; fail 'three OSDs did not become ready'; }
  sleep 1
done
ceph_cli osd crush rule create-replicated r08-rule default host >/dev/null
ceph_cli osd pool create r08-data 16 16 replicated r08-rule >/dev/null
ceph_cli osd pool set r08-data size 3 >/dev/null
ceph_cli osd pool set r08-data min_size 2 >/dev/null
ceph_cli auth get-or-create client.r08 mon 'allow r' osd 'allow rw pool=r08-data' -o /cluster/client.r08.keyring
ceph_cli auth get-key client.r08 >"$temporary/client.key"

docker run --rm --platform "$platform" --network "$network" -v "$temporary:/work" "$ceph_image" \
  /work/rust-probe --action suite --monitors 172.30.98.10:3300 --key /work/client.key --fsid "$fsid" >"$temporary/rust.json"
docker run --rm --platform "$platform" --network "$network" -v "$temporary:/work" "$ceph_image" \
  /work/go-probe -action suite -monitors 172.30.98.10:3300 -key /work/client.key -fsid "$fsid" >"$temporary/go.json"
docker run --rm --platform "$platform" --network "$network" -v "$temporary:/work" "$native_image" \
  /usr/local/bin/rados-r08-native --action suite --monitors 172.30.98.10:3300 --key /work/client.key --fsid "$fsid" >"$temporary/native.json"
for probe in rust go native; do
  jq -e '[.create,.write,.write_full,.append,.truncate,.zero,.remove] | all' "$temporary/$probe.json" >/dev/null || fail "$probe mutation suite failed"
done
jq -s -e 'map(.performance) | (map([.workload,.payload_bytes,.concurrency,.operations]) | unique | length) == 1' "$temporary/rust.json" "$temporary/go.json" "$temporary/native.json" >/dev/null || fail 'performance workloads differ'

docker run --rm --platform "$platform" --network "$network" -v "$temporary:/work" "$ceph_image" \
  /work/rust-probe --action cross-write --value rust-created --monitors 172.30.98.10:3300 --key /work/client.key --fsid "$fsid"
docker run --rm --platform "$platform" --network "$network" -v "$temporary:/work" "$ceph_image" \
  /work/go-probe -action cross-require-write -expect rust-created -value go-updated -monitors 172.30.98.10:3300 -key /work/client.key -fsid "$fsid"
docker run --rm --platform "$platform" --network "$network" -v "$temporary:/work" "$native_image" \
  /usr/local/bin/rados-r08-native --action cross-require-write --expect go-updated --value native-updated --monitors 172.30.98.10:3300 --key /work/client.key --fsid "$fsid"
docker run --rm --platform "$platform" --network "$network" -v "$temporary:/work" "$ceph_image" \
  /work/rust-probe --action cross-require-remove --value native-updated --monitors 172.30.98.10:3300 --key /work/client.key --fsid "$fsid"

docker run -d --name "r08-rust-failover-$$" --platform "$platform" --network "$network" --ip 172.30.98.40 -v "$temporary:/work" "$ceph_image" \
  /work/rust-probe --action failover --control /work/control --monitors 172.30.98.10:3300 --key /work/client.key --fsid "$fsid" >/dev/null
for attempt in $(seq 1 120); do
  [ -e "$temporary/control/ready" ] && break
  [ "$(docker inspect -f '{{.State.Running}}' "r08-rust-failover-$$" 2>/dev/null || printf false)" = true ] || { docker logs "r08-rust-failover-$$" >&2; fail 'failover probe exited before ready'; }
  [ "$attempt" -lt 120 ] || fail 'failover probe did not become ready'
  sleep 1
done
primary=$(ceph_cli osd map r08-data append-once --format json | jq -r '.acting_primary')
docker exec "r08-osd-$primary-$$" sh -c 'command -v tc >/dev/null' || fail 'tc unavailable for isolated reply delay'
docker exec "r08-osd-$primary-$$" tc qdisc add dev eth0 root handle 1: prio
docker exec "r08-osd-$primary-$$" tc qdisc add dev eth0 parent 1:3 handle 30: netem delay 30000ms
docker exec "r08-osd-$primary-$$" tc filter add dev eth0 protocol ip parent 1:0 prio 3 u32 match ip dst 172.30.98.40/32 flowid 1:3
touch "$temporary/control/go"
for attempt in $(seq 1 120); do
  [ -e "$temporary/control/submitted" ] && break
  [ "$attempt" -lt 120 ] || fail 'append was not submitted'
  sleep 1
done
printf 'base-once' >"$temporary/expected-append"
committed=false
for attempt in $(seq 1 30); do
  if rados_cli get append-once /cluster/observed-append 2>/dev/null && cmp "$temporary/expected-append" "$temporary/observed-append"; then committed=true; break; fi
  sleep 1
done
[ "$committed" = true ] || fail 'append commit could not be observed while reply was delayed'
[ "$(docker inspect -f '{{.State.Running}}' "r08-rust-failover-$$")" = true ] || fail 'reply was not demonstrably lost'
docker kill "r08-osd-$primary-$$" >/dev/null
ceph_cli osd down "$primary" >/dev/null 2>&1 || true
for attempt in $(seq 1 60); do
  new_primary=$(ceph_cli osd map r08-data append-once --format json | jq -r '.acting_primary')
  [ "$new_primary" != "$primary" ] && break
  [ "$attempt" -lt 60 ] || fail 'acting primary did not change after fault'
  sleep 1
done
failover_exit=$(docker wait "r08-rust-failover-$$")
[ "$failover_exit" = 0 ] || { docker logs "r08-rust-failover-$$" >&2; dump_logs; fail 'append retry failed'; }
[ -e "$temporary/control/passed" ] || fail 'append-once invariant was not proved'
rados_cli get append-once /cluster/final-append
cmp "$temporary/expected-append" "$temporary/final-append" || fail 'append occurred more than once'

source_digest_after=$(source_digest)
[ "$source_digest_before" = "$source_digest_after" ] || fail 'source changed during qualification'
[ -z "$(git -C "$go_root" status --porcelain=v1 --untracked-files=all)" ] || fail 'Go checkout changed during qualification'
server_version=$(docker run --rm --platform "$platform" "$ceph_image" ceph --version)
[ "$server_version" = 'ceph version 20.2.4 (7f793731f1b39eb4f465e960113d2363c311b964) tentacle (stable)' ] || fail 'unexpected Ceph version'
native_version=$(docker run --rm --platform "$platform" "$native_image" rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}' librados2)
[ "$native_version" = 'librados2-20.2.4-0.el9' ] || fail 'native librados package does not match the pin'
server_binary_sha256=$(docker run --rm --platform "$platform" "$ceph_image" sh -c 'sha256sum "$(command -v ceph-osd)"' | awk '{print $1}')
finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
mkdir -p "$(dirname "$report")"
report_candidate="$(dirname "$report")/.$(basename "$report").tmp.$$"
trap 'rm -f "$report_candidate"; cleanup' EXIT HUP INT TERM
jq -n \
  --arg started_at "$started_at" --arg finished_at "$finished_at" --arg schema_sha256 "$(sha256_file "$root/integration/r08/report.schema.json")" \
  --arg revision "$(git -C "$root" rev-parse HEAD)" --arg tree "$(git -C "$root" rev-parse 'HEAD^{tree}')" --arg source_sha256 "$source_digest_before" \
  --arg rust_image "$rust_image" --arg platform "$platform" --arg rust_binary_sha256 "$(sha256_file "$temporary/rust-probe")" \
  --arg go_revision "$go_revision" --arg go_tree "$go_tree" --arg go_version "$go_version" --arg go_binary_sha256 "$(sha256_file "$temporary/go-probe")" \
  --arg native_version "$native_version" --arg native_binary_sha256 "$(sha256_file "$temporary/native-probe")" \
  --arg server_version "$server_version" --arg ceph_image "$ceph_image" --arg server_binary_sha256 "$server_binary_sha256" \
  --arg ack_vs_commit "$ack_vs_commit" --arg flush_watermark "$flush_watermark" --arg cancellation_drop_boundaries "$cancellation_drop_boundaries" \
  --argjson rust_performance "$(jq '.performance' "$temporary/rust.json")" --argjson go_performance "$(jq '.performance' "$temporary/go.json")" --argjson native_performance "$(jq '.performance' "$temporary/native.json")" \
  '{schema_version:1,suite_id:"r08/mutation-qualification-v1",status:"passed",started_at:$started_at,finished_at:$finished_at,schema_sha256:$schema_sha256,
    rust:{revision:$revision,tree:$tree,source_sha256:$source_sha256,compiler_image:$rust_image,platform:$platform,binary_sha256:$rust_binary_sha256},
    go:{revision:$go_revision,tree:$go_tree,compiler:$go_version,platform:$platform,binary_sha256:$go_binary_sha256},
    native:{version:$native_version,binary_sha256:$native_binary_sha256},
    server:{source_anchor_commit:"7f793731f1b39eb4f465e960113d2363c311b964",version:$server_version,image:$ceph_image,binary_sha256:$server_binary_sha256},
    scenarios:{create:"passed",write:"passed",write_full:"passed",append:"passed",truncate:"passed",zero:"passed",remove:"passed",cross_client_crud:"passed",append_once_failover_lost_reply:"passed",ack_vs_commit:$ack_vs_commit,flush_watermark:$flush_watermark,cancellation_drop_boundaries:$cancellation_drop_boundaries,performance_baseline:"passed"},
    performance:[$rust_performance,$go_performance,$native_performance]}' >"$report_candidate"
cargo run --quiet -p rados-r08-tools --bin rados-r08-verify -- "$root" "$report_candidate" "$temporary/rust-probe" "$go_root" "$temporary/go-probe" "$temporary/native-probe"
mv "$report_candidate" "$report"
printf '%s\n' "R08 live qualification passed: $report"