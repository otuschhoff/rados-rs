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
  x86_64|amd64) platform=linux/amd64; goarch=amd64 ;;
  aarch64|arm64) platform=linux/arm64; goarch=arm64 ;;
  *) printf '%s\n' 'R09 live: unsupported Docker architecture' >&2; exit 2 ;;
esac
ceph_image=quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa
rust_image=rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922
fsid=11111111-2222-4333-8444-888888888888
network="rados-rs-r09-$$"
temporary=$(mktemp -d)
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cleanup() {
  docker rm -f "r09-rust-$$" "r09-go-$$" "r09-mon-$$" "r09-osd-0-$$" "r09-osd-1-$$" "r09-osd-2-$$" >/dev/null 2>&1 || true
  docker volume rm "rados-rs-r09-osd-0-$$" "rados-rs-r09-osd-1-$$" "rados-rs-r09-osd-2-$$" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker run --rm --user 0 --platform "$platform" -v "$temporary:/work" "$ceph_image" chmod -R a+rwx /work >/dev/null 2>&1 || true
  rm -rf "$temporary" || true
}
trap cleanup EXIT HUP INT TERM
fail() { printf '%s\n' "R09 live: $*" >&2; exit 1; }
sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
source_digest() { git -C "$root" ls-files -co --exclude-standard -- 'src/**' 'tools/r09/**' 'integration/r09/**' 'fuzz/fuzz_targets/r09_*' Cargo.toml Cargo.lock build.rs rust-toolchain.toml | LC_ALL=C sort | while IFS= read -r file; do printf '%s  %s\n' "$(sha256_file "$root/$file")" "$file"; done | shasum -a 256 | awk '{print $1}'; }
dump_logs() { docker logs "r09-mon-$$" >&2 2>/dev/null || true; for id in 0 1 2; do docker logs "r09-osd-$id-$$" >&2 2>/dev/null || true; done; }

[ "$(git -C "$go_root" rev-parse HEAD)" = c8bb148a1379b51ef87256c27f366a05f8da4dc4 ] || fail 'unexpected Go revision'
[ "$(git -C "$go_root" rev-parse 'HEAD^{tree}')" = c5039b6b50a05b942a902f70dc2fcb090463e8c7 ] || fail 'unexpected Go tree'
[ -z "$(git -C "$go_root" status --porcelain=v1 --untracked-files=all)" ] || fail 'Go checkout is dirty'
source_digest_before=$(source_digest)
mkdir -p "$temporary/rust-source" "$temporary/build" "$temporary/cargo-home" "$temporary/go-source" "$temporary/go-cache" "$temporary/go-mod-cache" "$temporary/rust-control" "$temporary/go-control"
git -C "$root" ls-files -co --exclude-standard -z | tar --null -T - -C "$root" -cf - | tar -C "$temporary/rust-source" -xf -
docker run --rm --platform "$platform" -v "$temporary/rust-source:/source:ro" -v "$temporary/build:/build" -v "$temporary/cargo-home:/cargo" "$rust_image" sh -c '
  set -eu; cd /source
  CARGO_HOME=/cargo CARGO_TARGET_DIR=/build cargo build --locked --release -p rados-r09-tools --bin rados-r09-live
'
cp "$temporary/build/release/rados-r09-live" "$temporary/rust-probe"
git -C "$go_root" archive HEAD | tar -x -C "$temporary/go-source"
(cd "$temporary/go-source" && GOTOOLCHAIN=go1.26.8 GOOS=linux GOARCH="$goarch" CGO_ENABLED=0 GOCACHE="$temporary/go-cache" GOMODCACHE="$temporary/go-mod-cache" go build -trimpath -o "$temporary/go-probe" ./integration/p08/probe)
go_version=$(GOTOOLCHAIN=go1.26.8 go version | awk '{print $3}')
[ "$go_version" = go1.26.8 ] || fail 'Go 1.26.8 is unavailable'
cp "$go_root/integration/p08/native_driver.c" "$temporary/native_driver.c"
docker run --rm --user 0 --platform "$platform" -v "$temporary:/work" "$ceph_image" sh -c 'cc -std=c11 -Wall -Wextra -Werror -O2 /work/native_driver.c -ldl -o /work/native-probe'

# Bootstrap an isolated three-OSD replicated cluster.
docker network create --subnet 172.30.98.0/24 "$network" >/dev/null
docker run --rm --user 0 --platform "$platform" -v "$temporary:/cluster" "$ceph_image" sh -c '
  set -eu
  cat >/cluster/ceph.conf <<EOF
[global]
fsid = 11111111-2222-4333-8444-888888888888
mon host = v2:172.30.98.10:3300
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
  monmaptool --create --fsid 11111111-2222-4333-8444-888888888888 --addv a "[v2:172.30.98.10:3300/0]" /cluster/monmap
  mkdir -p /cluster/mondata
  ceph-mon --mkfs -i a --fsid 11111111-2222-4333-8444-888888888888 --monmap /cluster/monmap --keyring /cluster/mon.keyring --mon-data /cluster/mondata
  chown -R ceph:ceph /cluster/mondata
'
docker run -d --name "r09-mon-$$" --platform "$platform" --network "$network" --ip 172.30.98.10 -v "$temporary:/cluster" "$ceph_image" ceph-mon -f -i a --mon-data /cluster/mondata --public-addr v2:172.30.98.10:3300 --setuser ceph --setgroup ceph --mon-data-avail-crit 0 --no-mon-cluster-log-to-stderr >/dev/null
ceph_cli() { docker run --rm --platform "$platform" --network "$network" -v "$temporary:/cluster" "$ceph_image" timeout 20 ceph --conf /cluster/ceph.conf --name client.admin --keyring /cluster/admin.keyring "$@"; }
rados_cli() { docker run --rm -i --platform "$platform" --network "$network" -v "$temporary:/cluster" "$ceph_image" timeout 20 rados --conf /cluster/ceph.conf --name client.admin --keyring /cluster/admin.keyring "$@"; }
for attempt in $(seq 1 30); do if ceph_cli status --format json 2>/dev/null | jq -e '.health.status != null' >/dev/null; then break; fi; [ "$attempt" -lt 30 ] || { dump_logs; fail 'monitor did not become ready'; }; sleep 1; done
for id in 0 1 2; do
  uuid="00000000-0000-4000-8000-00000000009$id"; volume="rados-rs-r09-osd-$id-$$"
  docker volume create "$volume" >/dev/null
  ceph_cli osd create "$uuid" "$id" >/dev/null
  ceph_cli auth get-or-create "osd.$id" mon 'allow profile osd' mgr 'allow profile osd' osd 'allow *' -o "/cluster/osd-$id.keyring"
  ceph_cli mon getmap -o "/cluster/osd-$id.monmap" >/dev/null
  docker run --rm --user 0 --privileged --platform "$platform" -v "$temporary:/cluster" -v "$volume:/osd" "$ceph_image" sh -c '
    set -eu; id='"$id"'; uuid='"$uuid"'; mkdir -p /osd/data; truncate -s 1G /osd/block
    cp /cluster/osd-$id.keyring /osd/data/keyring; cp /cluster/osd-$id.monmap /osd/data/activate.monmap; chown -R ceph:ceph /osd
    ceph-osd --mkfs -i "$id" --osd-data /osd/data --osd-uuid "$uuid" --osd-objectstore bluestore --bluestore-block-path /osd/block --monmap /osd/data/activate.monmap --keyring /osd/data/keyring --setuser ceph --setgroup ceph
  '
  ip="172.30.98.$((20 + id))"
  docker run -d --privileged --name "r09-osd-$id-$$" --platform "$platform" --network "$network" --ip "$ip" -v "$temporary:/cluster" -v "$volume:/osd" "$ceph_image" ceph-osd -f --conf /cluster/ceph.conf -i "$id" --osd-data /osd/data --osd-objectstore bluestore --public-addr "v2:$ip:6800" --cluster-addr "v2:$ip:6802" --log-file '' --setuser ceph --setgroup ceph >/dev/null
done
for attempt in $(seq 1 90); do if ceph_cli osd stat --format json 2>/dev/null | jq -e '.num_osds == 3 and .num_up_osds == 3 and .num_in_osds == 3' >/dev/null; then break; fi; [ "$attempt" -lt 90 ] || { dump_logs; fail 'OSDs did not become ready'; }; sleep 1; done
ceph_cli osd crush rule create-replicated r09-rule default osd >/dev/null
for pool in p09-rust p08-data; do ceph_cli osd pool create "$pool" 16 16 replicated r09-rule >/dev/null; ceph_cli osd pool set "$pool" size 2 >/dev/null; ceph_cli osd pool set "$pool" min_size 1 >/dev/null; done
ceph_cli auth get-or-create client.p08 mon 'allow r' osd 'allow rw pool=p09-rust, allow rw pool=p08-data' -o /cluster/client.keyring >/dev/null
ceph_cli auth get-key client.p08 >"$temporary/client.key"
for attempt in $(seq 1 120); do
  ready=true
  for pool in p09-rust p08-data; do
    if ! printf 'r09-ready\n' | rados_cli --pool "$pool" put r09-readiness - >/dev/null 2>&1 ||
       [ "$(rados_cli --pool "$pool" get r09-readiness - 2>/dev/null)" != 'r09-ready' ] ||
       ! rados_cli --pool "$pool" rm r09-readiness >/dev/null 2>&1; then
      ready=false
      break
    fi
  done
  if "$ready"; then break; fi
  [ "$attempt" -lt 120 ] || { dump_logs; fail 'initial pool I/O did not become ready'; }
  sleep 1
done
for pool in p09-rust p08-data; do docker run --rm --platform "$platform" --network "$network" -v "$temporary:/work" "$ceph_image" timeout 60 /work/native-probe seed /work/ceph.conf /work/client.keyring "$pool" >"$temporary/$pool-seed.json"; done

# Both clients cross the same map epoch boundary without sharing object state.
docker run -d --name "r09-rust-$$" --platform "$platform" --network "$network" -v "$temporary:/work" "$ceph_image" /work/rust-probe --monitors 172.30.98.10:3300 --key /work/client.key --fsid "$fsid" --pool p09-rust --coordination-dir /work/rust-control >/dev/null
docker run -d --name "r09-go-$$" --platform "$platform" --network "$network" -v "$temporary:/work" "$ceph_image" /work/go-probe -monitors 172.30.98.10:3300 -key /work/client.key -fsid "$fsid" -coordination-dir /work/go-control >/dev/null
for attempt in $(seq 1 120); do
  if [ -f "$temporary/rust-control/enumeration-ready" ] && [ -f "$temporary/go-control/enumeration-ready" ]; then break; fi
  [ "$attempt" -lt 120 ] || { docker logs "r09-rust-$$" >&2; docker logs "r09-go-$$" >&2; fail 'probes did not reach map-change point'; }
  sleep 1
done
for pool in p09-rust p08-data; do ceph_cli osd pool set "$pool" pg_num 32 >/dev/null; done
touch "$temporary/rust-control/map-changed" "$temporary/go-control/map-changed"
[ "$(docker wait "r09-rust-$$")" = 0 ] || { docker logs "r09-rust-$$" >&2; fail 'Rust probe failed'; }
[ "$(docker wait "r09-go-$$")" = 0 ] || { docker logs "r09-go-$$" >&2; fail 'Go probe failed'; }
docker logs "r09-rust-$$" >"$temporary/rust.json" 2>/dev/null
docker logs "r09-go-$$" >"$temporary/go.json" 2>/dev/null
jq -e 'all(.[]; . == true)' "$temporary/rust.json" >/dev/null
jq -e 'all(.[]; . == true)' "$temporary/go.json" >/dev/null
for pool in p09-rust p08-data; do docker run --rm --platform "$platform" --network "$network" -v "$temporary:/work" "$ceph_image" timeout 60 /work/native-probe verify /work/ceph.conf /work/client.keyring "$pool" >"$temporary/$pool-verify.json"; done

[ "$source_digest_before" = "$(source_digest)" ] || fail 'source changed during qualification'
[ -z "$(git -C "$go_root" status --porcelain=v1 --untracked-files=all)" ] || fail 'Go checkout changed during qualification'
server_version=$(docker run --rm --platform "$platform" "$ceph_image" ceph --version)
native_version=$(docker run --rm --platform "$platform" "$ceph_image" rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}' librados2)
server_binary_sha256=$(docker run --rm --platform "$platform" "$ceph_image" sh -c 'sha256sum "$(command -v ceph-osd)"' | awk '{print $1}')
mkdir -p "$(dirname "$report")"
candidate="$(dirname "$report")/.$(basename "$report").tmp.$$"
jq -n --arg started_at "$started_at" --arg finished_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg schema_sha256 "$(sha256_file "$root/integration/r09/report.schema.json")" \
  --arg revision "$(git -C "$root" rev-parse HEAD)" --arg tree "$(git -C "$root" rev-parse 'HEAD^{tree}')" --arg source_sha256 "$source_digest_before" --arg rust_image "$rust_image" --arg platform "$platform" --arg rust_binary_sha256 "$(sha256_file "$temporary/rust-probe")" \
  --arg go_version "$go_version" --arg go_binary_sha256 "$(sha256_file "$temporary/go-probe")" --arg native_version "$native_version" --arg native_binary_sha256 "$(sha256_file "$temporary/native-probe")" --arg server_version "$server_version" --arg server_binary_sha256 "$server_binary_sha256" \
  --argjson rust_probe "$(cat "$temporary/rust.json")" --argjson go_probe "$(cat "$temporary/go.json")" --argjson rust_seed "$(cat "$temporary/p09-rust-seed.json")" --argjson rust_verify "$(cat "$temporary/p09-rust-verify.json")" --argjson go_seed "$(cat "$temporary/p08-data-seed.json")" --argjson go_verify "$(cat "$temporary/p08-data-verify.json")" \
  '{schema_version:1,suite_id:"r09/metadata-compound-enumeration-v1",status:"passed",started_at:$started_at,finished_at:$finished_at,schema_sha256:$schema_sha256,
    rust:{revision:$revision,tree:$tree,source_sha256:$source_sha256,compiler_image:$rust_image,platform:$platform,binary_sha256:$rust_binary_sha256},
    go:{revision:"c8bb148a1379b51ef87256c27f366a05f8da4dc4",tree:"c5039b6b50a05b942a902f70dc2fcb090463e8c7",compiler:$go_version,platform:$platform,binary_sha256:$go_binary_sha256},
    native:{version:$native_version,binary_sha256:$native_binary_sha256,rust_seed:$rust_seed,rust_verify:$rust_verify,go_seed:$go_seed,go_verify:$go_verify},
    server:{source_anchor_commit:"7f793731f1b39eb4f465e960113d2363c311b964",version:$server_version,image:"quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa",binary_sha256:$server_binary_sha256},
    cluster:{fsid:"11111111-2222-4333-8444-888888888888",osds:3,pool:"p08-data",replicas:2,initial_pgs:16,final_pgs:32},probes:{rust:$rust_probe,go:$go_probe},
    scenarios:{native_metadata:"passed",binary_metadata:"passed",omap_pagination:"passed",compound_read:"passed",compound_atomicity:"passed",cross_client_contention:"passed",enumeration:"passed",namespaces:"passed",cursor_continuation:"passed",cursor_partitioning:"passed"}}' >"$candidate"
cargo run --quiet -p rados-r09-tools --bin rados-r09-verify -- "$root" "$candidate" "$temporary/rust-probe" "$go_root" "$temporary/go-probe" "$temporary/native-probe"
mv "$candidate" "$report"
printf '%s\n' "R09 live qualification passed: $report"
