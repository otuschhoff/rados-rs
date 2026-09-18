#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$root"
image='quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa'
build_image='rust@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922'
fsid='51111111-2222-4333-8444-555555555555'
foreign_fsid='aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
temporary=$(mktemp -d)
run_id=$$
prefix="rados-rs-r05-$run_id"
network="$prefix-net"
build_container="$prefix-build"
probe_container="$prefix-probe"
wrong_container="$prefix-wrong-fsid"
report="$root/docs/r05/live-integration-report.json"
started_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
max_output_bytes=65536
harness_pid=$$
(sleep 600; kill -TERM "$harness_pid" 2>/dev/null || true) &
watchdog_pid=$!

case "$(docker info --format '{{.Architecture}}')" in
  x86_64|amd64) platform=linux/amd64 ;;
  aarch64|arm64) platform=linux/arm64 ;;
  *) printf '%s\n' 'unsupported Docker architecture' >&2; exit 2 ;;
esac

remove_resources() {
  for container in "$build_container" "$probe_container" "$wrong_container" "$prefix-mon-a" "$prefix-mon-b" "$prefix-mon-c"; do
    docker rm -f "$container" >/dev/null 2>&1 || true
  done
  docker network rm "$network" >/dev/null 2>&1 || true
}

cleanup() {
  exit_code=$?
  trap - EXIT HUP INT TERM
  kill "$watchdog_pid" >/dev/null 2>&1 || true
  if test "$exit_code" -ne 0; then
    for monitor in a b c; do docker logs --tail 40 "$prefix-mon-$monitor" 2>&1 >&2 || true; done
    docker logs --tail 80 "$probe_container" 2>&1 >&2 || true
    docker logs --tail 80 "$wrong_container" 2>&1 >&2 || true
  fi
  remove_resources
  rm -rf "$temporary"
  exit "$exit_code"
}
trap cleanup EXIT HUP INT TERM
remove_resources

wait_container() {
  container=$1
  seconds=$2
  attempt=0
  while test "$attempt" -lt "$seconds"; do
    state=$(docker inspect --format '{{.State.Status}}' "$container" 2>/dev/null || true)
    if test "$state" = exited; then
      docker inspect --format '{{.State.ExitCode}}' "$container"
      return 0
    fi
    test "$state" = running || { printf 'container %s entered state %s\n' "$container" "$state" >&2; return 1; }
    sleep 1
    attempt=$((attempt + 1))
  done
  docker rm -f "$container" >/dev/null 2>&1 || true
  printf 'container %s exceeded %s seconds\n' "$container" "$seconds" >&2
  return 1
}

wait_file() {
  path=$1
  seconds=$2
  attempt=0
  while test "$attempt" -lt "$seconds"; do
    test -f "$path" && return 0
    state=$(docker inspect --format '{{.State.Status}}' "$probe_container" 2>/dev/null || true)
    test "$state" = running || { docker logs "$probe_container" 2>&1 >&2 || true; return 1; }
    sleep 1
    attempt=$((attempt + 1))
  done
  printf 'timed out waiting for %s\n' "$path" >&2
  return 1
}

bounded_file() {
  path=$1
  size=$(wc -c <"$path" | tr -d ' ')
  test "$size" -le "$max_output_bytes" || { printf '%s exceeds output bound\n' "$path" >&2; return 1; }
}

artifact_paths=$(
  {
    find src -type f -name '*.rs' -print
    printf '%s\n' Cargo.lock Cargo.toml build.rs rust-toolchain.toml integration/r05/live-report.schema.json integration/r05/live-reproduce.sh integration/r05/verify-live.rb integration/r05/verify-live-tests.sh
  } | LC_ALL=C sort
)

write_artifacts() {
  output=$1
  printf '{}\n' >"$output"
  for artifact in $artifact_paths; do
    test -f "$artifact"
    hash=$(shasum -a 256 "$artifact" | awk '{print $1}')
    jq --arg path "$artifact" --arg hash "$hash" '. + {($path):$hash}' "$output" >"$output.next"
    mv "$output.next" "$output"
  done
}

write_artifacts "$temporary/artifacts.before.json"

ceph_cli() {
  docker run --rm --platform "$platform" --network "$network" -v "$temporary:/cluster" "$image" \
    timeout 20 ceph --conf /cluster/ceph.conf --name client.admin --keyring /cluster/admin.keyring "$@"
}

docker pull "$image" >/dev/null
docker pull "$build_image" >/dev/null
image_id=$(docker image inspect --format '{{.Id}}' "$image")
build_image_id=$(docker image inspect --format '{{.Id}}' "$build_image")
docker create --name "$build_container" -v "$root:/src:ro" -v "$temporary:/out" -w /src "$build_image" \
  sh -c 'cargo build --locked --release --features r05-integration --bin rados-r05-live --target-dir /out' >/dev/null
docker start "$build_container" >/dev/null
test "$(wait_container "$build_container" 300)" = 0 || { docker logs "$build_container" >&2; exit 1; }
docker logs "$build_container" >"$temporary/build.stdout" 2>"$temporary/build.stderr"
bounded_file "$temporary/build.stdout"
bounded_file "$temporary/build.stderr"
rustc_version=$(docker run --rm "$build_image" rustc --version)
cargo_version=$(docker run --rm "$build_image" cargo --version)
ceph_version=$(docker run --rm --platform "$platform" "$image" ceph --version)
probe_binary_sha=$(shasum -a 256 "$temporary/release/rados-r05-live" | awk '{print $1}')
mkdir -p "$root/target/r05"
cp "$temporary/release/rados-r05-live" "$root/target/r05/rados-r05-live"

docker network create --subnet 172.30.105.0/24 "$network" >/dev/null
docker run --rm --user 0 --platform "$platform" -v "$temporary:/cluster" "$image" timeout 60 sh -c '
  set -eu
  cat >/cluster/ceph.conf <<EOF
[global]
fsid = 51111111-2222-4333-8444-555555555555
mon host = v2:172.30.105.10:3300,v2:172.30.105.11:3300,v2:172.30.105.12:3300
auth cluster required = cephx
auth service required = cephx
auth client required = cephx
auth allow insecure global id reclaim = false
ms bind msgr1 = false
ms bind msgr2 = true
ms cluster mode = secure
ms service mode = secure
ms client mode = secure
mon data avail warn = 0
mon allow pool delete = true
EOF
  ceph-authtool /cluster/mon.keyring --create-keyring --gen-key -n mon. --cap mon "allow *"
  ceph-authtool /cluster/admin.keyring --create-keyring --gen-key -n client.admin --cap mon "allow *" --cap osd "allow *" --cap mgr "allow *"
  ceph-authtool /cluster/client.keyring --create-keyring --gen-key -n client.r05 --cap mon "allow r"
  ceph-authtool /cluster/mon.keyring --import-keyring /cluster/admin.keyring
  ceph-authtool /cluster/mon.keyring --import-keyring /cluster/client.keyring
  monmaptool --create --fsid 51111111-2222-4333-8444-555555555555 --addv a "[v2:172.30.105.10:3300/0]" --addv b "[v2:172.30.105.11:3300/0]" --addv c "[v2:172.30.105.12:3300/0]" /cluster/monmap
  for id in a b c; do
    mkdir -p "/cluster/mondata-$id"
    ceph-mon --mkfs -i "$id" --fsid 51111111-2222-4333-8444-555555555555 --monmap /cluster/monmap --keyring /cluster/mon.keyring --mon-data "/cluster/mondata-$id"
  done
  cat >/cluster/client.conf <<EOF
[global]
fsid = 51111111-2222-4333-8444-555555555555
mon_host = v2:172.30.105.10:3300,v2:172.30.105.11:3300,v2:172.30.105.12:3300
name = client.r05
keyring = /work/client.keyring
dial_timeout = 10s
handshake_timeout = 15s
operation_timeout = 8s
EOF
  cat >/cluster/wrong.conf <<EOF
[global]
fsid = aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee
mon_host = v2:172.30.105.11:3300,v2:172.30.105.12:3300
name = client.r05
keyring = /work/client.keyring
dial_timeout = 5s
handshake_timeout = 5s
operation_timeout = 10s
EOF
  chown -R ceph:ceph /cluster/mondata-a /cluster/mondata-b /cluster/mondata-c
'

start_mon() {
  id=$1
  ip=$2
  docker run -d --name "$prefix-mon-$id" --platform "$platform" --network "$network" --ip "$ip" -v "$temporary:/cluster" "$image" \
    ceph-mon -f -i "$id" --conf /cluster/ceph.conf --mon-data "/cluster/mondata-$id" --public-addr "v2:$ip:3300" --setuser ceph --setgroup ceph --mon-data-avail-crit 0 --no-mon-cluster-log-to-stderr >/dev/null
}
start_mon a 172.30.105.10
start_mon b 172.30.105.11
start_mon c 172.30.105.12
attempt=0
while test "$attempt" -lt 60; do
  quorum=$(ceph_cli quorum_status --format json 2>/dev/null | jq -r '.quorum | length' || true)
  test "$quorum" = 3 && break
  sleep 1
  attempt=$((attempt + 1))
done
test "${quorum:-0}" = 3
ceph_cli osd pool create r05-initial 8 8 replicated >/dev/null

docker run -d --name "$probe_container" --platform "$platform" --network "$network" --ip 172.30.105.20 -v "$temporary:/work" "$image" \
  /work/release/rados-r05-live --config /work/client.conf --expect-pool r05-initial --absent-pool r05-disposable --absent-pool r05-failover \
  --control-dir /work --disposable-pool r05-disposable --failover-pool r05-failover --timeout-seconds 120 >/dev/null
wait_file "$temporary/ready" 40
ceph_cli osd pool create r05-disposable 8 8 replicated >/dev/null
wait_file "$temporary/created" 40
ceph_cli osd pool delete r05-disposable r05-disposable --yes-i-really-really-mean-it >/dev/null
wait_file "$temporary/deleted" 40
docker rm -f "$prefix-mon-a" >/dev/null
attempt=0
while test "$attempt" -lt 40; do
  quorum=$(ceph_cli quorum_status --format json 2>/dev/null | jq -r '.quorum | length' || true)
  test "$quorum" = 2 && break
  sleep 1
  attempt=$((attempt + 1))
done
test "${quorum:-0}" = 2
ceph_cli osd pool create r05-failover 8 8 replicated >/dev/null
test "$(wait_container "$probe_container" 60)" = 0 || { docker logs "$probe_container" >&2; exit 1; }
docker logs "$probe_container" >"$temporary/probe.json" 2>"$temporary/probe.stderr"
bounded_file "$temporary/probe.json"
bounded_file "$temporary/probe.stderr"
jq -e . "$temporary/probe.json" >/dev/null

docker create --name "$wrong_container" --platform "$platform" --network "$network" -v "$temporary:/work" "$image" \
  /work/release/rados-r05-live --config /work/wrong.conf --expect-pool r05-initial --timeout-seconds 20 >/dev/null
docker start "$wrong_container" >/dev/null
wrong_exit=$(wait_container "$wrong_container" 35)
test "$wrong_exit" -ne 0
docker logs "$wrong_container" >"$temporary/wrong.stdout" 2>"$temporary/wrong.stderr"
bounded_file "$temporary/wrong.stdout"
bounded_file "$temporary/wrong.stderr"
grep -Fq 'Client::connect failed: Conflict' "$temporary/wrong.stderr"
wrong_stderr_sha=$(shasum -a 256 "$temporary/wrong.stderr" | awk '{print $1}')

write_artifacts "$temporary/artifacts.after.json"
cmp "$temporary/artifacts.before.json" "$temporary/artifacts.after.json" >/dev/null || {
  printf '%s\n' 'source artifacts changed during live qualification' >&2
  exit 1
}

remove_resources
orphan_containers=$(docker ps -a --filter "name=^/$prefix" --format '{{.Names}}' | wc -l | tr -d ' ')
if docker network inspect "$network" >/dev/null 2>&1; then orphan_networks=1; else orphan_networks=0; fi
test "$orphan_containers" = 0
test "$orphan_networks" = 0

mkdir -p "$(dirname "$report")"
jq -n \
  --arg started_at "$started_at" --arg finished_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  --arg image "$image" --arg image_id "$image_id" --arg ceph_version "$ceph_version" --arg platform "$platform" \
  --arg rustc "$rustc_version" --arg cargo "$cargo_version" --arg build_image "$build_image" --arg build_image_id "$build_image_id" --arg probe_binary_path "target/r05/rados-r05-live" --arg probe_binary_sha "$probe_binary_sha" \
  --arg fsid "$fsid" --arg wrong_stderr_sha "$wrong_stderr_sha" --argjson wrong_exit "$wrong_exit" \
  --argjson artifacts "$(cat "$temporary/artifacts.before.json")" --argjson probe "$(cat "$temporary/probe.json")" \
  '{schema_version:1,status:"passed",command:"integration/r05/live-reproduce.sh",started_at:$started_at,finished_at:$finished_at,
    source:{identity:"exact-content-addressed-artifacts",artifacts:$artifacts},
    server:{image:$image,image_id:$image_id,ceph_version:$ceph_version,platform:$platform},
    toolchain:{rustc:$rustc,cargo:$cargo,build_image:$build_image,build_image_id:$build_image_id,probe_binary_path:$probe_binary_path,probe_binary_sha256:$probe_binary_sha},
    cluster:{fsid:$fsid,monitors:["v2:172.30.105.10:3300","v2:172.30.105.11:3300","v2:172.30.105.12:3300"],seeds_used:["v2:172.30.105.10:3300","v2:172.30.105.11:3300","v2:172.30.105.12:3300"],initial_pool:"r05-initial",disposable_pool:"r05-disposable",failover_pool:"r05-failover",quorum_before:3,quorum_after_loss:2},
    bounds:{harness_seconds:600,probe_seconds:120,command_seconds:20,max_output_bytes:65536,max_report_bytes:262144},
    scenarios:{secure_default_v2:"passed",expected_pools:"passed",pool_map_updates:"passed",monitor_failover:"passed",wrong_fsid:"passed",bounded_cleanup:"passed"},
    observations:{probe:$probe,wrong_fsid:{exit_code:$wrong_exit,stderr_sha256:$wrong_stderr_sha,fsid_mismatch_observed:true},cleanup:{orphan_containers:0,orphan_networks:0}}}' >"$report"
bounded_file "$report"
ruby integration/r05/verify-live.rb "$root" "$report"
integration/r05/verify-live-tests.sh "$report"
printf 'R05 live integration report: %s\n' "$report"