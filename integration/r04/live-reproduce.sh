#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$root"
started_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
report=${R04_LIVE_REPORT:-"$root/docs/r04/live-integration-report.json"}
image='quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa'
platform=linux/arm64
network="rados-rs-r04-$$"
monitor="rados-rs-r04-mon-$$"
subnet=172.30.94.0/24
monitor_ip=172.30.94.10
client_ip=172.30.94.20
wrong_client_ip=172.30.94.21
fsid=41111111-2222-4333-8444-555555555555
temporary=$(mktemp -d)

for command_name in cargo docker git jq perl rustup shasum zig; do
  command -v "$command_name" >/dev/null 2>&1 || { printf 'R04 live gate requires %s\n' "$command_name" >&2; exit 2; }
done
docker info >/dev/null 2>&1 || { printf '%s\n' 'R04 live gate requires a running Docker daemon' >&2; exit 2; }
test "$(docker info --format '{{.Architecture}}')" = aarch64 || { printf '%s\n' 'R04 live gate requires native linux/arm64 Docker' >&2; exit 2; }
test "$(shasum -a 256 integration/r04/legacy-crush.txt | awk '{print $1}')" = 5b07d221477e01a50ad37ab113cb8511ada2895bd3e848504518d0ef634f13ea

cleanup() {
  exit_code=$?
  trap - EXIT HUP INT TERM
  if test "$exit_code" -ne 0; then
    test ! -f "$temporary/success.json" || { printf '%s\n' 'R04 captured probe output:' >&2; cat "$temporary/success.json" >&2; }
    docker inspect --format 'R04 monitor state: running={{.State.Running}} exit={{.State.ExitCode}} error={{.State.Error}}' "$monitor" >&2 2>/dev/null || true
    docker logs --tail 80 "$monitor" >&2 2>/dev/null || true
  fi
  docker rm -f "$monitor" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker run --rm --user 0 --platform "$platform" -v "$temporary:/cluster" "$image" find /cluster -mindepth 1 -delete >/dev/null 2>&1 || true
  rm -rf "$temporary"
  exit "$exit_code"
}
trap cleanup EXIT HUP INT TERM

bounded() {
  seconds=$1
  shift
  perl -e '$seconds = shift; alarm $seconds; exec @ARGV' "$seconds" "$@"
}

test -z "$(find src -type l -print -quit)" || {
  printf '%s\n' 'R04 live gate rejects symlinks beneath src' >&2
  exit 2
}
artifact_paths=$(find src -type f -print | LC_ALL=C sort)
artifact_paths="Cargo.toml Cargo.lock rust-toolchain.toml integration/r04/live-reproduce.sh integration/r04/verify-live-report.sh integration/r04/live-report.schema.json integration/r04/legacy-crush.txt integration/r04/legacy-crush.provenance.json $artifact_paths"
hash_artifacts() {
  for artifact in $artifact_paths; do
    printf '%s\t%s\n' "$artifact" "$(shasum -a 256 "$artifact" | awk '{print $1}')"
  done | jq -Rn '[inputs | split("\t") | {(.[0]):.[1]}] | add'
}
artifacts=$(hash_artifacts)
repository_commit=$(git rev-parse HEAD)
repository_dirty=false
test -z "$(git status --porcelain --untracked-files=all)" || repository_dirty=true

rustup target list --installed --toolchain 1.98.0 | grep -qx aarch64-unknown-linux-gnu || bounded 180 rustup target add --toolchain 1.98.0 aarch64-unknown-linux-gnu
rustc_path=$(rustup which --toolchain 1.98.0 rustc)
bounded 600 env RUSTUP_TOOLCHAIN=1.98.0 RUSTC="$rustc_path" CARGO_TARGET_DIR="$temporary/target" cargo zigbuild --locked --release --target aarch64-unknown-linux-gnu --features r04-integration --bin rados-r04-live
cp "$temporary/target/aarch64-unknown-linux-gnu/release/rados-r04-live" "$temporary/probe"

bounded 300 docker pull --platform "$platform" "$image" >/dev/null
docker network create --subnet "$subnet" "$network" >/dev/null
bounded 120 docker run --rm --user 0 --platform "$platform" -v "$temporary:/cluster" "$image" sh -c '
  set -eu
  cat >/cluster/ceph.conf <<EOF
[global]
fsid = 41111111-2222-4333-8444-555555555555
mon host = v2:172.30.94.10:3300
auth cluster required = cephx
auth service required = cephx
auth client required = cephx
auth allow insecure global id reclaim = false
ms bind msgr1 = false
ms bind msgr2 = true
[mon.a]
public addr = v2:172.30.94.10:3300
EOF
  ceph-authtool /cluster/mon.keyring --create-keyring --gen-key -n mon. --cap mon "allow *"
  ceph-authtool /cluster/admin.keyring --create-keyring --gen-key -n client.admin --cap mon "allow *" --cap osd "allow *" --cap mgr "allow *"
  ceph-authtool /cluster/client.keyring --create-keyring --gen-key -n client.r04 --cap mon "allow r"
  ceph-authtool /cluster/bad.keyring --create-keyring --gen-key -n client.r04
  ceph-authtool /cluster/mon.keyring --import-keyring /cluster/admin.keyring
  ceph-authtool /cluster/mon.keyring --import-keyring /cluster/client.keyring
  monmaptool --create --fsid 41111111-2222-4333-8444-555555555555 --addv a "[v2:172.30.94.10:3300/0]" /cluster/monmap
  mkdir -p /cluster/mondata
  ceph-mon --conf /cluster/ceph.conf --mkfs -i a --fsid 41111111-2222-4333-8444-555555555555 --monmap /cluster/monmap --keyring /cluster/mon.keyring --mon-data /cluster/mondata
  chown -R ceph:ceph /cluster/mondata /cluster/*.keyring /cluster/monmap
  chmod 755 /cluster /cluster/probe
'

start_monitor() {
  mode=$1
  docker run -d --name "$monitor" --platform "$platform" --network "$network" --ip "$monitor_ip" -v "$temporary:/cluster" "$image" \
    ceph-mon -f --conf /cluster/ceph.conf -i a --mon-data /cluster/mondata --public-addr "v2:$monitor_ip:3300" --setuser ceph --setgroup ceph \
    --mon-data-avail-crit 1 --ms-mon-service-mode "$mode" --auth-mon-ticket-ttl 4 --auth-service-ticket-ttl 4 \
    --no-mon-cluster-log-to-stderr >/dev/null
  attempt=1
  while test "$attempt" -le 20; do
    if bounded 10 docker run --rm --platform "$platform" --network "$network" "$image" bash -c "</dev/tcp/$monitor_ip/3300"; then return 0; fi
    attempt=$((attempt + 1))
    sleep 1
  done
  docker logs "$monitor" >&2 || true
  return 1
}

run_probe() {
  address=$1
  keyring=$2
  shift 2
  bounded 30 docker run --rm --platform "$platform" --network "$network" --ip "$address" \
    -v "$temporary/probe:/probe:ro" -v "$temporary/$keyring:/client.keyring:ro" "$image" \
    /probe --monitor "$monitor_ip:3300" --client-address "$address:0" --entity client.r04 \
    --keyring /client.keyring --timeout-seconds 20 "$@"
}

start_monitor 'secure crc'
printf '%s\n' 'R04 monitor ready in secure/crc mode'
bounded 30 docker run --rm --platform "$platform" --network "$network" -v "$temporary/admin.keyring:/admin.keyring:ro" \
  -v "$temporary:/cluster" -v "$root/integration/r04:/input:ro" "$image" sh -c '
    set -eu
    crushtool -c /input/legacy-crush.txt -o /cluster/legacy-crush.bin
    timeout 20 ceph --conf /cluster/ceph.conf --mon-host v2:172.30.94.10:3300 --name client.admin --keyring /admin.keyring osd setcrushmap -i /cluster/legacy-crush.bin >/dev/null
  '
printf '%s\n' 'R04 legacy CRUSH map installed'

run_probe "$client_ip" client.keyring --exercise-lifecycle >"$temporary/success.json"
printf '%s\n' 'R04 lifecycle probe completed'
jq -e '.authenticated_mode == "secure" and .global_id > 0 and .reconnected and .ticket_renewed and .expiry_rejected and .expired_reconnect and .renewed_global_id == .global_id and .post_expiry_global_id != .global_id and (.server_addresses | index("172.30.94.10:3300") != null)' "$temporary/success.json" >/dev/null

set +e
wrong_output=$(run_probe "$wrong_client_ip" bad.keyring 2>&1)
wrong_status=$?
set -e
test "$wrong_status" -ne 0 || { printf '%s\n' 'R04 wrong-key probe unexpectedly succeeded' >&2; exit 1; }
case "$wrong_output" in *'cephx authentication rejected'*) ;; *) printf '%s\n' "$wrong_output" >&2; exit 1 ;; esac
printf '%s\n' 'R04 wrong-key rejection passed'

docker rm -f "$monitor" >/dev/null
start_monitor crc
printf '%s\n' 'R04 monitor ready in CRC-only mode'
set +e
downgrade_output=$(run_probe "$client_ip" client.keyring 2>&1)
downgrade_status=$?
set -e
test "$downgrade_status" -ne 0 || { printf '%s\n' 'R04 downgrade probe unexpectedly succeeded' >&2; exit 1; }
case "$downgrade_output" in *'cephx auth downgrade rejected'*) ;; *) printf '%s\n' "$downgrade_output" >&2; exit 1 ;; esac
printf '%s\n' 'R04 secure-default downgrade rejection passed'

runtime_package=$(docker exec "$monitor" rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}' ceph-mon)
monitor_binary_sha256=$(docker exec "$monitor" sh -c 'sha256sum "$(command -v ceph-mon)"' | awk '{print $1}')
server_version=$(docker exec "$monitor" ceph-mon --version)
test "$(hash_artifacts)" = "$artifacts"
mkdir -p "$(dirname "$report")"
jq -n --arg started_at "$started_at" --arg finished_at "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
  --arg revision "$repository_commit" --argjson dirty "$repository_dirty" --argjson artifacts "$artifacts" \
  --arg version "$server_version" --arg runtime_package "$runtime_package" --arg monitor_sha "$monitor_binary_sha256" \
  --slurpfile probe "$temporary/success.json" '{
    schema_version:1,suite_id:"r04/live-monitor-v1",status:"passed",command:"integration/r04/live-reproduce.sh",started_at:$started_at,finished_at:$finished_at,
    source:{repository:"https://github.com/otuschhoff/rados-rs",revision:$revision,dirty:$dirty,identity:"content-addressed-artifacts",artifacts:$artifacts},
    server:{repository:"https://github.com/ceph/ceph.git",source_anchor_commit:"7f793731f1b39eb4f465e960113d2363c311b964",version:$version,image:"quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa",platform:"linux/arm64",host_platform:"linux/arm64",runtime_package:$runtime_package,monitor_binary_sha256:$monitor_sha},
    cluster:{fsid:"41111111-2222-4333-8444-555555555555",network:"172.30.94.0/24",monitor:"v2:172.30.94.10:3300",client:"172.30.94.20",monitor_name:"a",client_entity:"client.r04",external_config:false,ticket_ttl_seconds:4},
    scenarios:{secure_authentication:"passed",client_server_ident:"passed",same_session_renewal:"passed",global_id_reuse:"passed",ticket_rotation:"passed",expired_ticket_rejection:"passed",post_expiry_fresh_global_id:"passed",valid_wrong_key_rejection:"passed",secure_default_downgrade_rejection:"passed"},
    negative_observations:{wrong_key:"cephx authentication rejected",downgrade:"cephx auth downgrade rejected"},probe:$probe[0]
  }' >"$report"

integration/r04/verify-live-report.sh "$root" "$report"
printf 'R04 live monitor gate passed: %s\n' "$report"