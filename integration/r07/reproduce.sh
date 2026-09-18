#!/bin/sh
set -eu

usage() {
  printf '%s\n' "usage: $0 --go-root PATH --report PATH" >&2
  exit 2
}
report=
go_root=
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
for command in cargo cmp cp date docker git go jq mkdir mktemp mv shasum tar; do
  command -v "$command" >/dev/null 2>&1 || { printf '%s\n' "R07 live: missing command: $command" >&2; exit 1; }
done

case "$(docker info --format '{{.Architecture}}')" in
  x86_64|amd64) platform=linux/amd64; goarch=amd64 ;;
  aarch64|arm64) platform=linux/arm64; goarch=arm64 ;;
  *) printf '%s\n' 'R07 live: unsupported Docker architecture' >&2; exit 2 ;;
esac
ceph_image=quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa
rust_image=rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922
fsid=11111111-2222-4333-8444-666666666666
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
temporary=$(mktemp -d)
network="rados-rs-r07-$$"
cleanup() {
  docker rm -f "r07-rust-$$" "r07-go-$$" "r07-mon-$$" "r07-osd-0-$$" "r07-osd-1-$$" "r07-osd-2-$$" >/dev/null 2>&1 || true
  docker volume rm "rados-rs-r07-osd-0-$$" "rados-rs-r07-osd-1-$$" "rados-rs-r07-osd-2-$$" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker run --rm --user 0 --platform "$platform" -v "$temporary:/work" "$ceph_image" chmod -R a+rwx /work >/dev/null 2>&1 || true
  rm -rf "$temporary" || true
}
trap cleanup EXIT HUP INT TERM
dump_osd_logs() {
  for id in 0 1 2; do
    printf '%s\n' "--- osd.$id log ---" >&2
    docker logs "r07-osd-$id-$$" >&2 2>/dev/null || true
  done
}

sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
source_digest() {
  git -C "$root" ls-files -co --exclude-standard 'src/**' 'tools/r07/**' 'integration/r07/**' Cargo.toml Cargo.lock build.rs rust-toolchain.toml | LC_ALL=C sort | while IFS= read -r path; do printf '%s  %s\n' "$(sha256_file "$root/$path")" "$path"; done | shasum -a 256 | awk '{print $1}'
}
source_digest_before=$(source_digest)
mkdir -p "$temporary/rust-source" "$temporary/build" "$temporary/cargo-home"
git -C "$root" ls-files -co --exclude-standard -z | tar --null -T - -C "$root" -cf - | tar -C "$temporary/rust-source" -xf -
docker run --rm --platform "$platform" -v "$temporary/rust-source:/source:ro" -v "$temporary/build:/build" -v "$temporary/cargo-home:/cargo" "$rust_image" sh -c '
  set -eu
  cd /source
  CARGO_HOME=/cargo CARGO_TARGET_DIR=/build cargo build --locked --release -p rados-r07-tools --bin rados-r07-live
'
cp "$temporary/build/release/rados-r07-live" "$temporary/probe"
go_revision=$(git -C "$go_root" rev-parse HEAD)
go_tree=$(git -C "$go_root" rev-parse 'HEAD^{tree}')
[ "$go_revision" = c8bb148a1379b51ef87256c27f366a05f8da4dc4 ] || { printf '%s\n' 'R07 live: unexpected Go revision' >&2; exit 1; }
[ "$go_tree" = c5039b6b50a05b942a902f70dc2fcb090463e8c7 ] || { printf '%s\n' 'R07 live: unexpected Go tree' >&2; exit 1; }
[ -z "$(git -C "$go_root" status --porcelain)" ] || { printf '%s\n' 'R07 live: Go oracle checkout is dirty' >&2; exit 1; }
mkdir -p "$temporary/go-source" "$temporary/go-cache" "$temporary/go-mod-cache"
git -C "$go_root" archive HEAD | tar -x -C "$temporary/go-source"
mkdir -p "$temporary/go-source/integration/r07/probe"
cp "$temporary/rust-source/tools/r07/go-probe/main.go" "$temporary/go-source/integration/r07/probe/main.go"
(cd "$temporary/go-source" && GOTOOLCHAIN=go1.26.8 GOOS=linux GOARCH="$goarch" CGO_ENABLED=0 GOCACHE="$temporary/go-cache" GOMODCACHE="$temporary/go-mod-cache" go build -trimpath -o "$temporary/go-probe" ./integration/r07/probe)
go_version=$(GOTOOLCHAIN=go1.26.8 go version | awk '{print $3}')
[ "$go_version" = go1.26.8 ] || { printf '%s\n' 'R07 live: Go 1.26.8 is unavailable' >&2; exit 1; }
python3 -c 'import sys; sys.stdout.buffer.write(bytes(range(256))*16)' >"$temporary/data.bin"
: >"$temporary/empty"
printf namespace-value >"$temporary/namespace"
printf locator-value >"$temporary/locator"
mkdir -p "$temporary/rust-control" "$temporary/go-control"

docker network create --subnet 172.30.97.0/24 "$network" >/dev/null
docker run --rm --user 0 --platform "$platform" -v "$temporary:/cluster" "$ceph_image" sh -c '
  set -eu
  cat >/cluster/ceph.conf <<EOF
[global]
fsid = '"$fsid"'
mon host = v2:172.30.97.10:3300
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
  monmaptool --create --fsid '"$fsid"' --addv a "[v2:172.30.97.10:3300/0]" /cluster/monmap
  mkdir -p /cluster/mondata
  ceph-mon --mkfs -i a --fsid '"$fsid"' --monmap /cluster/monmap --keyring /cluster/mon.keyring --mon-data /cluster/mondata
  chown -R ceph:ceph /cluster/mondata
'
docker run -d --rm --name "r07-mon-$$" --platform "$platform" --network "$network" --ip 172.30.97.10 -v "$temporary:/cluster" "$ceph_image" \
  ceph-mon -f -i a --mon-data /cluster/mondata --public-addr v2:172.30.97.10:3300 --setuser ceph --setgroup ceph --mon-data-avail-crit 1 --no-mon-cluster-log-to-stderr >/dev/null

ceph_cli() {
  docker run --rm --platform "$platform" --network "$network" -v "$temporary:/cluster" "$ceph_image" \
    ceph --conf /cluster/ceph.conf --name client.admin --keyring /cluster/admin.keyring "$@"
}
for attempt in $(seq 1 30); do
  if ceph_cli status --format json 2>/dev/null | jq -e '.health.status != null' >/dev/null; then break; fi
  [ "$attempt" -lt 30 ] || { docker logs "r07-mon-$$" >&2; exit 1; }
  sleep 1
done
for id in 0 1 2; do
  uuid="00000000-0000-4000-8000-00000000000$id"
  volume="rados-rs-r07-osd-$id-$$"
  docker volume create "$volume" >/dev/null
  ceph_cli osd create "$uuid" "$id" >/dev/null
  ceph_cli auth get-or-create "osd.$id" mon 'allow profile osd' mgr 'allow profile osd' osd 'allow *' -o "/cluster/osd-$id.keyring"
  ceph_cli mon getmap -o "/cluster/osd-$id.monmap" >/dev/null
  docker run --rm --user 0 --privileged --platform "$platform" -v "$temporary:/cluster" -v "$volume:/osd" "$ceph_image" sh -c '
    set -eu
    id='"$id"'; uuid='"$uuid"'
    mkdir -p /osd/data
    truncate -s 1G /osd/block
    cp /cluster/osd-$id.keyring /osd/data/keyring
    cp /cluster/osd-$id.monmap /osd/data/activate.monmap
    chown -R ceph:ceph /osd
    ceph-osd --mkfs -i "$id" --osd-data /osd/data --osd-uuid "$uuid" --osd-objectstore bluestore --bluestore-block-path /osd/block --monmap /osd/data/activate.monmap --keyring /osd/data/keyring --setuser ceph --setgroup ceph
  '
  ip="172.30.97.$((20 + id))"
  docker run -d --privileged --name "r07-osd-$id-$$" --platform "$platform" --network "$network" --ip "$ip" -v "$temporary:/cluster" -v "$volume:/osd" "$ceph_image" \
    ceph-osd -f --conf /cluster/ceph.conf -i "$id" --osd-data /osd/data --osd-objectstore bluestore --public-addr "v2:$ip:6800" --cluster-addr "v2:$ip:6802" --setuser ceph --setgroup ceph >/dev/null
done
for attempt in $(seq 1 60); do
  if ceph_cli osd stat --format json 2>/dev/null | jq -e '.num_osds == 3 and .num_up_osds == 3 and .num_in_osds == 3' >/dev/null; then break; fi
  [ "$attempt" -lt 60 ] || { ceph_cli osd tree >&2; exit 1; }
  sleep 1
done
ceph_cli osd crush rule create-replicated r07-rule default host >/dev/null
ceph_cli osd pool create p06-data 16 16 replicated r07-rule >/dev/null
ceph_cli osd pool set p06-data size 2 >/dev/null
ceph_cli osd pool set p06-data min_size 1 >/dev/null
ceph_cli auth get-or-create client.p06 mon 'allow r' osd 'allow r pool=p06-data' >/dev/null
ceph_cli auth get-key client.p06 >"$temporary/client.key"
rados_cli() {
  docker run --rm --platform "$platform" --network "$network" -v "$temporary:/cluster" "$ceph_image" \
    rados --conf /cluster/ceph.conf --name client.admin --keyring /cluster/admin.keyring -p p06-data "$@"
}
rados_cli put binary /cluster/data.bin
rados_cli put empty /cluster/empty
rados_cli -N space put namespaced /cluster/namespace
rados_cli --object-locator routing-key put located /cluster/locator

docker run -d --name "r07-rust-$$" --platform "$platform" --network "$network" --ip 172.30.97.40 -v "$temporary:/work" "$ceph_image" \
  /work/probe --monitors 172.30.97.10:3300 --key /work/client.key --fsid "$fsid" --data /work/data.bin --control /work/rust-control >/dev/null
docker run -d --name "r07-go-$$" --platform "$platform" --network "$network" --ip 172.30.97.41 -v "$temporary:/work" "$ceph_image" \
  /work/go-probe --monitors 172.30.97.10:3300 --key /work/client.key --fsid "$fsid" --data /work/data.bin --control /work/go-control >/dev/null
for attempt in $(seq 1 180); do
  if [ -e "$temporary/rust-control/ready" ] && [ -e "$temporary/go-control/ready" ]; then break; fi
  rust_running=$(docker inspect -f '{{.State.Running}}' "r07-rust-$$" 2>/dev/null || printf false)
  go_running=$(docker inspect -f '{{.State.Running}}' "r07-go-$$" 2>/dev/null || printf false)
  [ "$rust_running" = true ] && [ "$go_running" = true ] || { docker logs "r07-rust-$$" >&2; docker logs "r07-go-$$" >&2; dump_osd_logs; exit 1; }
  [ "$attempt" -lt 180 ] || { docker logs "r07-rust-$$" >&2; docker logs "r07-go-$$" >&2; dump_osd_logs; exit 1; }
  sleep 1
done
primary=$(ceph_cli osd map p06-data binary --format json | jq -r '.acting_primary')
docker rm -f "r07-osd-$primary-$$" >/dev/null
ceph_cli osd down "$primary" >/dev/null
for attempt in $(seq 1 60); do
  new_primary=$(ceph_cli osd map p06-data binary --format json | jq -r '.acting_primary')
  [ "$new_primary" != "$primary" ] && break
  [ "$attempt" -lt 60 ] || exit 1
  sleep 1
done
touch "$temporary/rust-control/remapped" "$temporary/go-control/remapped"
rust_exit=$(docker wait "r07-rust-$$")
go_exit=$(docker wait "r07-go-$$")
[ "$rust_exit" = 0 ] && [ "$go_exit" = 0 ] || { docker logs "r07-rust-$$" >&2; docker logs "r07-go-$$" >&2; dump_osd_logs; exit 1; }
docker logs "r07-rust-$$" >"$temporary/rust-probe.json"
docker logs "r07-go-$$" >"$temporary/go-probe.json"
jq -e '.ranged_read and .full_read and .empty_read and .namespace_read and .locator_read and .stat and .missing and .primary_change and .version > 0' "$temporary/rust-probe.json" >/dev/null
jq -S . "$temporary/rust-probe.json" >"$temporary/rust-probe.canonical.json"
jq -S . "$temporary/go-probe.json" >"$temporary/go-probe.canonical.json"
cmp "$temporary/rust-probe.canonical.json" "$temporary/go-probe.canonical.json"

source_digest_after=$(source_digest)
[ "$source_digest_before" = "$source_digest_after" ] || { printf '%s\n' 'R07 live: source changed during qualification' >&2; exit 1; }
server_version=$(docker run --rm --platform "$platform" "$ceph_image" ceph --version)
server_binary_sha256=$(docker run --rm --platform "$platform" "$ceph_image" sh -c 'sha256sum "$(command -v ceph-osd)"' | awk '{print $1}')
finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
mkdir -p "$(dirname "$report")"
report_candidate="$(dirname "$report")/.$(basename "$report").tmp.$$"
trap 'rm -f "$report_candidate"; cleanup' EXIT HUP INT TERM
jq -n \
  --arg started_at "$started_at" --arg finished_at "$finished_at" --arg platform "$platform" \
  --arg revision "$(git -C "$root" rev-parse HEAD)" --arg tree "$(git -C "$root" rev-parse 'HEAD^{tree}')" \
  --arg source_sha256 "$source_digest_before" --arg binary_sha256 "$(sha256_file "$temporary/probe")" \
  --arg rust_stdout_sha256 "$(sha256_file "$temporary/rust-probe.json")" \
  --arg go_revision "$go_revision" --arg go_tree "$go_tree" --arg go_version "$go_version" --arg go_binary_sha256 "$(sha256_file "$temporary/go-probe")" --arg go_adapter_sha256 "$(sha256_file "$temporary/rust-source/tools/r07/go-probe/main.go")" \
  --arg go_stdout_sha256 "$(sha256_file "$temporary/go-probe.json")" \
  --arg rust_image "$rust_image" --arg ceph_image "$ceph_image" --arg server_version "$server_version" \
  --arg controller_sha256 "$(sha256_file "$temporary/rust-source/integration/r07/reproduce.sh")" --arg fixture_sha256 "$(sha256_file "$temporary/data.bin")" \
  --arg server_binary_sha256 "$server_binary_sha256" --argjson probe "$(cat "$temporary/rust-probe.json")" --argjson go_probe "$(cat "$temporary/go-probe.json")" \
  '{schema_version:1,suite_id:"r07/read-only-live-v1",status:"passed",started_at:$started_at,finished_at:$finished_at,controller_sha256:$controller_sha256,fixture_sha256:$fixture_sha256,
    rust:{revision:$revision,tree:$tree,source_sha256:$source_sha256,compiler_image:$rust_image,platform:$platform,binary_sha256:$binary_sha256,features:[],build_command:"cargo build --locked --release -p rados-r07-tools --bin rados-r07-live",build_exit_code:0,probe_exit_code:0,stdout_sha256:$rust_stdout_sha256},
    go:{revision:$go_revision,tree:$go_tree,compiler:$go_version,platform:$platform,binary_sha256:$go_binary_sha256,adapter_sha256:$go_adapter_sha256,build_command:"go build -trimpath ./integration/r07/probe",build_exit_code:0,probe_exit_code:0,stdout_sha256:$go_stdout_sha256},
    server:{source_anchor_commit:"7f793731f1b39eb4f465e960113d2363c311b964",version:$server_version,image:$ceph_image,binary_sha256:$server_binary_sha256},
    cluster:{fsid:"11111111-2222-4333-8444-666666666666",osds:3,pool:"p06-data",replicas:2},
    scenarios:{native_contents:"passed",go_differential:"passed",ranged_read:"passed",full_read:"passed",empty_read:"passed",namespace_read:"passed",locator_read:"passed",stat_metadata:"passed",missing_object:"passed",operation_version:"passed",primary_change:"passed"},probe:$probe,go_probe:$go_probe}' >"$report_candidate"
  jq -e '.schema_version == 1 and .suite_id == "r07/read-only-live-v1" and .status == "passed" and .probe == .go_probe and .probe.primary_change and .probe.version > 0' "$report_candidate" >/dev/null
  cargo run --quiet -p rados-r07-tools --bin rados-r07-verify -- "$root" "$report_candidate" "$temporary/probe" "$go_root" "$temporary/go-probe"
  mv "$report_candidate" "$report"
printf '%s\n' "R07 live qualification passed: $report"
