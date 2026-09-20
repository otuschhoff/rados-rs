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
  *) printf '%s\n' 'R12 live: unsupported Docker architecture' >&2; exit 2 ;;
esac
ceph_image=quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa
rust_image=rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922
fsid=22222222-3333-4333-8444-222222222222
network="rados-rs-r12-$$"
temporary=$(mktemp -d)
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
recovery_container="r12-recovery-$$"
cleanup() {
  docker rm -f "$recovery_container" >/dev/null 2>&1 || true
  docker rm -f "r12-mon-$$" "r12-mgr-a-$$" "r12-mgr-b-$$" "r12-osd-0-$$" >/dev/null 2>&1 || true
  docker volume rm "rados-rs-r12-osd-0-$$" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker run --rm --user 0 --platform "$platform" -v "$temporary:/work" "$ceph_image" chmod -R a+rwx /work >/dev/null 2>&1 || true
  rm -rf "$temporary" || true
}
trap cleanup EXIT HUP INT TERM
dump_logs() {
  failure_logs="/tmp/rados-r12-failure-$$"; mkdir -p "$failure_logs"
  docker logs "r12-mon-$$" >"$failure_logs/mon.log" 2>&1 || true
  for id in a b; do docker logs "r12-mgr-$id-$$" >"$failure_logs/mgr-$id.log" 2>&1 || true; done
  docker logs "r12-osd-0-$$" >"$failure_logs/osd-0.log" 2>&1 || true
  docker logs "$recovery_container" >"$failure_logs/recovery.log" 2>&1 || true
  printf '%s\n' "R12 live failure logs: $failure_logs" >&2
}
fail() { dump_logs; printf '%s\n' "R12 live: $*" >&2; exit 1; }
sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
source_digest() {
  git -C "$root" ls-files -co --exclude-standard -- 'src/**' 'tools/r12/**' 'integration/r12/**' 'fuzz/fuzz_targets/r12_*' Cargo.toml Cargo.lock build.rs rust-toolchain.toml \
    | LC_ALL=C sort \
    | while IFS= read -r file; do printf '%s  %s\n' "$(sha256_file "$root/$file")" "$file"; done \
    | shasum -a 256 | awk '{print $1}'
}

[ "$(git -C "$go_root" rev-parse HEAD)" = c8bb148a1379b51ef87256c27f366a05f8da4dc4 ] || fail 'unexpected Go revision'
[ "$(git -C "$go_root" rev-parse 'HEAD^{tree}')" = c5039b6b50a05b942a902f70dc2fcb090463e8c7 ] || fail 'unexpected Go tree'
[ -z "$(git -C "$go_root" status --porcelain=v1 --untracked-files=all)" ] || fail 'Go checkout is dirty'
go_version=$(GOTOOLCHAIN=go1.26.8 go version | awk '{print $3}')
[ "$go_version" = go1.26.8 ] || fail 'Go 1.26.8 is unavailable'
(cd "$go_root" && GOTOOLCHAIN=go1.26.8 CGO_ENABLED=0 go test . ./internal/mon ./internal/mgr ./internal/osd -run '(Command|Blocklist|ClusterStats|PoolStats|Application|Inconsistent|SessionAddresses|PoolCreate|PoolDelete)' -count=1)

source_digest_before=$(source_digest)
mkdir -p "$temporary/rust-source" "$temporary/build" "$temporary/cargo-home"
git -C "$root" ls-files -co --exclude-standard -z | tar --null -T - -C "$root" -cf - | tar -C "$temporary/rust-source" -xf -
docker run --rm --platform "$platform" -v "$temporary/rust-source:/source:ro" -v "$temporary/build:/build" -v "$temporary/cargo-home:/cargo" "$rust_image" sh -c '
  set -eu; cd /source/tools/r12
  CARGO_HOME=/cargo CARGO_TARGET_DIR=/build cargo build --locked --release --bin rados-r12-live
'
cp "$temporary/build/release/rados-r12-live" "$temporary/rust-probe"
sed 's/p11/p12/g; s/go-/rust-/g; s/go_/rust_/g; s/Go /Rust /g' "$go_root/integration/p11/native_driver.c" >"$temporary/native_driver.c"
docker run --rm --user 0 --platform "$platform" -v "$temporary:/work" "$ceph_image" sh -c 'cc -std=c11 -Wall -Wextra -Werror -O2 /work/native_driver.c -ldl -o /work/native-probe'

docker network create --subnet 172.30.113.0/24 "$network" >/dev/null
docker run --rm --user 0 --platform "$platform" -v "$temporary:/cluster" "$ceph_image" sh -c '
  set -eu
  cat >/cluster/ceph.conf <<EOF
[global]
fsid = 22222222-3333-4333-8444-222222222222
mon host = v2:172.30.113.10:3300
auth cluster required = cephx
auth service required = cephx
auth client required = cephx
ms bind msgr1 = false
ms bind msgr2 = true
osd pool default size = 1
osd pool default min size = 1
mon_allow_pool_size_one = true
mon_allow_pool_delete = true
EOF
  ceph-authtool /cluster/mon.keyring --create-keyring --gen-key -n mon. --cap mon "allow *"
  ceph-authtool /cluster/admin.keyring --create-keyring --gen-key -n client.admin --cap mon "allow *" --cap osd "allow *" --cap mgr "allow *"
  ceph-authtool /cluster/mon.keyring --import-keyring /cluster/admin.keyring
  monmaptool --create --fsid 22222222-3333-4333-8444-222222222222 --addv a "[v2:172.30.113.10:3300/0]" /cluster/monmap
  mkdir -p /cluster/mondata
  ceph-mon --mkfs -i a --fsid 22222222-3333-4333-8444-222222222222 --monmap /cluster/monmap --keyring /cluster/mon.keyring --mon-data /cluster/mondata
  chown -R ceph:ceph /cluster/mondata
'
docker run -d --name "r12-mon-$$" --platform "$platform" --network "$network" --ip 172.30.113.10 -v "$temporary:/cluster" "$ceph_image" \
  ceph-mon -f -i a --mon-data /cluster/mondata --public-addr v2:172.30.113.10:3300 --setuser ceph --setgroup ceph --mon-data-avail-crit 0 --no-mon-cluster-log-to-stderr >/dev/null
ceph_cli() {
  docker run --rm --platform "$platform" --network "$network" -v "$temporary:/cluster" "$ceph_image" \
    timeout 20 ceph --conf /cluster/ceph.conf --name client.admin --keyring /cluster/admin.keyring "$@"
}
for attempt in $(seq 1 30); do
  if ceph_cli status --format json 2>/dev/null | jq -e '.health.status != null' >/dev/null; then break; fi
  [ "$attempt" -lt 30 ] || fail 'monitor did not become ready'
  sleep 1
done

volume="rados-rs-r12-osd-0-$$"
uuid=22000000-0000-4000-8000-000000000010
docker volume create "$volume" >/dev/null
ceph_cli osd create "$uuid" 0 >/dev/null
ceph_cli auth get-or-create osd.0 mon 'allow profile osd' mgr 'allow profile osd' osd 'allow *' -o /cluster/osd-0.keyring
ceph_cli mon getmap -o /cluster/osd-0.monmap >/dev/null
docker run --rm --user 0 --privileged --platform "$platform" -v "$temporary:/cluster" -v "$volume:/osd" "$ceph_image" sh -c '
  set -eu
  mkdir -p /osd/data
  truncate -s 4G /osd/block
  cp /cluster/osd-0.keyring /osd/data/keyring
  cp /cluster/osd-0.monmap /osd/data/activate.monmap
  chown -R ceph:ceph /osd
  ceph-osd --mkfs -i 0 --osd-data /osd/data --osd-uuid 22000000-0000-4000-8000-000000000010 --osd-objectstore bluestore --bluestore-block-path /osd/block --monmap /osd/data/activate.monmap --keyring /osd/data/keyring --setuser ceph --setgroup ceph
'
docker run -d --privileged --name "r12-osd-0-$$" --platform "$platform" --network "$network" --ip 172.30.113.20 -v "$temporary:/cluster" -v "$volume:/osd" "$ceph_image" \
  ceph-osd -f --conf /cluster/ceph.conf -i 0 --osd-data /osd/data --osd-objectstore bluestore --public-addr v2:172.30.113.20:6800 --cluster-addr v2:172.30.113.20:6802 --log-to-stderr true --err-to-stderr true --log-file '' --setuser ceph --setgroup ceph >/dev/null
for attempt in $(seq 1 90); do
  if ceph_cli osd stat --format json 2>/dev/null | jq -e '.num_osds == 1 and .num_up_osds == 1 and .num_in_osds == 1' >/dev/null; then break; fi
  [ "$attempt" -lt 90 ] || fail 'OSD did not become ready'
  sleep 1
done

for id in a b; do
  ceph_cli auth get-or-create "mgr.$id" mon 'allow profile mgr' osd 'allow *' mds 'allow *' -o "/cluster/mgr-$id.keyring"
  mkdir -p "$temporary/mgr-$id"
  cp "$temporary/mgr-$id.keyring" "$temporary/mgr-$id/keyring"
  chmod 600 "$temporary/mgr-$id/keyring"
  case "$id" in a) ip=172.30.113.30 ;; b) ip=172.30.113.31 ;; esac
  docker run -d --name "r12-mgr-$id-$$" --platform "$platform" --network "$network" --ip "$ip" -v "$temporary:/cluster" "$ceph_image" \
    ceph-mgr -f -i "$id" --conf /cluster/ceph.conf --mgr-data "/cluster/mgr-$id" --keyring "/cluster/mgr-$id/keyring" --setuser ceph --setgroup ceph --log-to-stderr true --err-to-stderr true --log-file '' >/dev/null
done
for attempt in $(seq 1 90); do
  if ceph_cli mgr dump --format json 2>/dev/null | jq -e '.active_name != "" and (.standbys | length) == 1' >/dev/null; then break; fi
  [ "$attempt" -lt 90 ] || fail 'manager pair did not become ready'
  sleep 1
done

ceph_cli config set global mon_allow_pool_size_one true
ceph_cli config set mon mon_allow_pool_delete true
ceph_cli osd pool create p12-data 8 >/dev/null
ceph_cli osd pool create p12-native-app 8 >/dev/null
for pool in p12-data p12-native-app; do ceph_cli osd pool set "$pool" size 1 --yes-i-really-mean-it >/dev/null; done
printf 'p12-seed\n' >"$temporary/seed"
for attempt in $(seq 1 180); do
  if docker run --rm --platform "$platform" --network "$network" -v "$temporary:/cluster" "$ceph_image" timeout 10 rados --conf /cluster/ceph.conf --name client.admin --keyring /cluster/admin.keyring --pool p12-data put command-object /cluster/seed >/dev/null 2>&1; then break; fi
  [ "$attempt" -lt 180 ] || fail 'pool I/O did not become ready'
  sleep 1
done
pg=$(ceph_cli osd map p12-data command-object --format json | jq -r '.pgid')
pool_id=$(ceph_cli osd pool ls detail --format json | jq -r '.[] | select(.pool_name == "p12-data") | .pool_id')
[ -n "$pg" ] && [ -n "$pool_id" ] || fail 'PG or pool id not resolved'
for attempt in $(seq 1 180); do
  if ceph_cli pg dump pgs --format json 2>/dev/null | jq -e --arg pg "$pg" '.pg_stats[] | select(.pgid == $pg) | .state | contains("active+clean")' >/dev/null; then break; fi
  [ "$attempt" -lt 180 ] || fail 'PG did not become active+clean'
  sleep 1
done
last_deep_scrub=$(ceph_cli pg dump pgs --format json | jq -r --arg pg "$pg" '.pg_stats[] | select(.pgid == $pg) | .last_deep_scrub_stamp')
ceph_cli pg deep-scrub "$pg" >/dev/null
for attempt in $(seq 1 180); do
  current=$(ceph_cli pg dump pgs --format json 2>/dev/null | jq -r --arg pg "$pg" '.pg_stats[] | select(.pgid == $pg) | .last_deep_scrub_stamp')
  if [ -n "$current" ] && [ "$current" != "$last_deep_scrub" ]; then break; fi
  [ "$attempt" -lt 180 ] || fail 'deep scrub did not complete'
  sleep 1
done

ceph_cli auth get-or-create client.p12-admin mon 'allow *' mgr 'allow *' osd 'allow *' >/dev/null
ceph_cli auth get-key client.p12-admin >"$temporary/admin.key"
ceph_cli auth get client.p12-admin -o /cluster/admin-client.keyring >/dev/null
ceph_cli auth get-or-create client.p12-io mon 'allow r' osd 'allow rw pool=p12-data' >/dev/null
ceph_cli auth get-key client.p12-io >"$temporary/io.key"
ceph_cli auth get client.p12-io --format json | jq '.[0] | {entity,mon_caps:.caps.mon,mgr_caps:(.caps.mgr // ""),osd_caps:.caps.osd}' >"$temporary/io-auth.json"
ceph_cli auth get client.p12-admin --format json | jq '.[0] | {entity,mon_caps:.caps.mon,mgr_caps:.caps.mgr,osd_caps:.caps.osd}' >"$temporary/admin-auth.json"

docker run --rm --platform "$platform" --network "$network" -v "$temporary:/work" "$ceph_image" \
  timeout 60 /work/native-probe /work/ceph.conf /work/admin-client.keyring "$pg" "$pool_id" >"$temporary/native.json"

docker run --rm --platform "$platform" --network "$network" -v "$temporary:/work" "$ceph_image" \
  timeout 180 /work/rust-probe --mode admin --monitors 172.30.113.10:3300 --key /work/admin.key --fsid "$fsid" --pg "$pg" --osd 0 >"$temporary/admin.json"

rm -f "$temporary/ready" "$temporary/continue" "$temporary/failover-done" "$temporary/managerless"
docker run -d --name "$recovery_container" --platform "$platform" --network "$network" -v "$temporary:/work" "$ceph_image" sh -c \
  "timeout 200 /work/rust-probe --mode recovery --monitors 172.30.113.10:3300 --key /work/admin.key --fsid $fsid --coordination-dir /work >/work/recovery.json" >/dev/null
for attempt in $(seq 1 120); do [ -f "$temporary/ready" ] && break; [ "$attempt" -lt 120 ] || fail 'recovery probe did not signal ready'; sleep 1; done
active=$(ceph_cli mgr dump --format json | jq -r '.active_name')
[ "$active" = a ] || [ "$active" = b ] || fail 'no active manager before failover'
docker rm -f "r12-mgr-$active-$$" >/dev/null
for attempt in $(seq 1 90); do
  new_active=$(ceph_cli mgr dump --format json 2>/dev/null | jq -r '.active_name // empty')
  if [ -n "$new_active" ] && [ "$new_active" != "$active" ]; then break; fi
  [ "$attempt" -lt 90 ] || fail 'manager failover did not complete'
  sleep 1
done
: >"$temporary/continue"
for attempt in $(seq 1 120); do [ -f "$temporary/failover-done" ] && break; [ "$attempt" -lt 120 ] || fail 'recovery probe did not confirm failover'; sleep 1; done
docker rm -f "r12-mgr-$new_active-$$" >/dev/null
: >"$temporary/managerless"
[ "$(docker wait "$recovery_container")" = 0 ] || fail 'recovery probe failed'

docker run --rm --platform "$platform" --network "$network" -v "$temporary:/work" "$ceph_image" \
  timeout 90 /work/rust-probe --mode least --entity client.p12-io --monitors 172.30.113.10:3300 --key /work/io.key --fsid "$fsid" >"$temporary/least.json"

jq -e '([del(.session_addresses)[]] | all(. == true)) and (.session_addresses | length > 0)' "$temporary/admin.json" >/dev/null
jq -e 'all(.[]; . == true)' "$temporary/native.json" >/dev/null
jq -e 'all(.[]; . == true)' "$temporary/recovery.json" >/dev/null
jq -e '.write_read_without_manager' "$temporary/least.json" >/dev/null

[ "$source_digest_before" = "$(source_digest)" ] || fail 'source changed during qualification'
[ -z "$(git -C "$go_root" status --porcelain=v1 --untracked-files=all)" ] || fail 'Go checkout changed during qualification'
server_version=$(docker run --rm --platform "$platform" "$ceph_image" ceph --version)
native_version=$(docker run --rm --platform "$platform" "$ceph_image" rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' librados2)
docker run --rm --platform "$platform" "$ceph_image" sh -c 'cat "$(command -v ceph-osd)"' >"$temporary/server-binary"
mkdir -p "$(dirname "$report")"
candidate="$(dirname "$report")/.$(basename "$report").tmp.$$"
jq -n --arg started_at "$started_at" --arg finished_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg schema_sha256 "$(sha256_file "$root/integration/r12/report.schema.json")" \
  --arg revision "$(git -C "$root" rev-parse HEAD)" --arg tree "$(git -C "$root" rev-parse 'HEAD^{tree}')" \
  --arg source_sha256 "$source_digest_before" --arg rust_image "$rust_image" --arg platform "$platform" \
  --arg rust_binary_sha256 "$(sha256_file "$temporary/rust-probe")" \
  --arg native_driver_sha256 "$(sha256_file "$temporary/native_driver.c")" \
  --arg native_binary_sha256 "$(sha256_file "$temporary/native-probe")" \
  --arg native_version "$native_version" \
  --arg server_version "$server_version" --arg server_binary_sha256 "$(sha256_file "$temporary/server-binary")" \
  --argjson admin "$(cat "$temporary/admin.json")" \
  --argjson recovery "$(cat "$temporary/recovery.json")" \
  --argjson least "$(cat "$temporary/least.json")" \
  --argjson native_admin "$(cat "$temporary/native.json")" \
  --argjson admin_client "$(cat "$temporary/admin-auth.json")" \
  --argjson io_client "$(cat "$temporary/io-auth.json")" \
  '{
    schema_version: 1,
    suite_id: "r12/administration-and-manager-v1",
    status: "passed",
    started_at: $started_at,
    finished_at: $finished_at,
    schema_sha256: $schema_sha256,
    rust: {
      revision: $revision,
      tree: $tree,
      source_sha256: $source_sha256,
      compiler_image: $rust_image,
      platform: $platform,
      binary_sha256: $rust_binary_sha256
    },
    go: {
      revision: "c8bb148a1379b51ef87256c27f366a05f8da4dc4",
      tree: "c5039b6b50a05b942a902f70dc2fcb090463e8c7",
      compiler: "go1.26.8",
      platform: $platform,
      p11_driver_sha256: $native_driver_sha256,
      focused_tests: "passed"
    },
    native: {
      version: $native_version,
      binary_sha256: $native_binary_sha256,
      admin: $native_admin
    },
    server: {
      source_anchor_commit: "7f793731f1b39eb4f465e960113d2363c311b964",
      version: $server_version,
      image: "quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa",
      binary_sha256: $server_binary_sha256
    },
    cluster: {
      fsid: "22222222-3333-4333-8444-222222222222",
      network: "172.30.113.0/24",
      osds: 1,
      objectstore: "bluestore",
      manager_daemons: 2,
      data_pool: {name: "p12-data", size: 1, min_size: 1, pg_num: 8},
      native_app_pool: {name: "p12-native-app", size: 1, min_size: 1, pg_num: 8},
      admin_client: $admin_client,
      io_client: $io_client
    },
    probe: {
      admin: $admin,
      recovery: $recovery,
      least_privilege: $least
    },
    scenarios: {
      administration: "passed",
      native_conformance: "passed",
      manager_failover: "passed",
      manager_loss_io: "passed",
      least_privilege: "passed",
      destructive_resource_validation: "passed"
    },
    deviations: {
      command_partial_status: "Manager, monitor, OSD, and PG command wire errors preserve the last CommandResult status and output on the returned tuple.",
      destructive_scope: "Pool create, delete, blocklist, and application metadata operations are constrained to disposable p12-rust-created, p12-native-created, and p12-native-app resources plus the fresh p12-data snapshot."
    }
  }' >"$candidate"
(cd "$root/tools/r12" && cargo run --quiet --release --bin rados-r12-verify -- "$root" "$candidate" "$temporary/rust-probe" "$go_root" "$temporary/native_driver.c" "$temporary/native-probe" "$temporary/server-binary")
mv "$candidate" "$report"
printf '%s\n' "R12 live qualification passed: $report"
