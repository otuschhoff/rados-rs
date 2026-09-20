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
  *) printf '%s\n' 'R11 live: unsupported Docker architecture' >&2; exit 2 ;;
esac
ceph_image=quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa
rust_image=rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922
fsid=21111111-2222-4333-8444-111111111111
network="rados-rs-r11-$$"
temporary=$(mktemp -d)
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cleanup() {
  docker rm -f "r11-mon-$$" "r11-osd-0-$$" "r11-osd-1-$$" "r11-osd-2-$$" >/dev/null 2>&1 || true
  docker volume rm "rados-rs-r11-osd-0-$$" "rados-rs-r11-osd-1-$$" "rados-rs-r11-osd-2-$$" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker run --rm --user 0 --platform "$platform" -v "$temporary:/work" "$ceph_image" chmod -R a+rwx /work >/dev/null 2>&1 || true
  rm -rf "$temporary" || true
}
trap cleanup EXIT HUP INT TERM
dump_logs() {
  failure_logs="/tmp/rados-r11-failure-$$"; mkdir -p "$failure_logs"
  docker logs "r11-mon-$$" >"$failure_logs/mon.log" 2>&1 || true
  for id in 0 1 2; do docker logs "r11-osd-$id-$$" >"$failure_logs/osd-$id.log" 2>&1 || true; done
  printf '%s\n' "R11 live failure logs: $failure_logs" >&2
}
fail() { dump_logs; printf '%s\n' "R11 live: $*" >&2; exit 1; }
sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
source_digest() { git -C "$root" ls-files -co --exclude-standard -- 'src/**' 'tools/r11/**' 'integration/r11/**' 'fuzz/fuzz_targets/r11_*' Cargo.toml Cargo.lock build.rs rust-toolchain.toml | LC_ALL=C sort | while IFS= read -r file; do printf '%s  %s\n' "$(sha256_file "$root/$file")" "$file"; done | shasum -a 256 | awk '{print $1}'; }

[ "$(git -C "$go_root" rev-parse HEAD)" = c8bb148a1379b51ef87256c27f366a05f8da4dc4 ] || fail 'unexpected Go revision'
[ "$(git -C "$go_root" rev-parse 'HEAD^{tree}')" = c5039b6b50a05b942a902f70dc2fcb090463e8c7 ] || fail 'unexpected Go tree'
[ -z "$(git -C "$go_root" status --porcelain=v1 --untracked-files=all)" ] || fail 'Go checkout is dirty'
go_version=$(GOTOOLCHAIN=go1.26.8 go version | awk '{print $3}')
[ "$go_version" = go1.26.8 ] || fail 'Go 1.26.8 is unavailable'
(cd "$go_root" && GOTOOLCHAIN=go1.26.8 CGO_ENABLED=0 go test . ./internal/mon ./internal/osd ./internal/objecter -run '(Snapshot|Sparse|Checksum|WriteSame|Copy|Erasure|Alignment)' -count=1)

source_digest_before=$(source_digest)
mkdir -p "$temporary/rust-source" "$temporary/build" "$temporary/cargo-home"
git -C "$root" ls-files -co --exclude-standard -z | tar --null -T - -C "$root" -cf - | tar -C "$temporary/rust-source" -xf -
docker run --rm --platform "$platform" -v "$temporary/rust-source:/source:ro" -v "$temporary/build:/build" -v "$temporary/cargo-home:/cargo" "$rust_image" sh -c '
  set -eu; cd /source
  CARGO_HOME=/cargo CARGO_TARGET_DIR=/build cargo build --locked --release -p rados-r11-tools --bin rados-r11-live
'
cp "$temporary/build/release/rados-r11-live" "$temporary/rust-probe"
sed 's/p10/p11/g; s/go-/rust-/g; s/go_/rust_/g; s/Go /Rust /g' "$go_root/integration/p10/native_driver.c" >"$temporary/native_driver.c"
docker run --rm --user 0 --platform "$platform" -v "$temporary:/work" "$ceph_image" sh -c 'cc -std=c11 -Wall -Wextra -Werror -O2 /work/native_driver.c -ldl -o /work/native-probe'

docker network create --subnet 172.30.111.0/24 "$network" >/dev/null
docker run --rm --user 0 --platform "$platform" -v "$temporary:/cluster" "$ceph_image" sh -c '
  set -eu
  cat >/cluster/ceph.conf <<EOF
[global]
fsid = 21111111-2222-4333-8444-111111111111
mon host = v2:172.30.111.10:3300
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
  monmaptool --create --fsid 21111111-2222-4333-8444-111111111111 --addv a "[v2:172.30.111.10:3300/0]" /cluster/monmap
  mkdir -p /cluster/mondata
  ceph-mon --mkfs -i a --fsid 21111111-2222-4333-8444-111111111111 --monmap /cluster/monmap --keyring /cluster/mon.keyring --mon-data /cluster/mondata
  chown -R ceph:ceph /cluster/mondata
'
docker run -d --name "r11-mon-$$" --platform "$platform" --network "$network" --ip 172.30.111.10 -v "$temporary:/cluster" "$ceph_image" ceph-mon -f -i a --mon-data /cluster/mondata --public-addr v2:172.30.111.10:3300 --setuser ceph --setgroup ceph --mon-data-avail-crit 0 --no-mon-cluster-log-to-stderr >/dev/null
ceph_cli() { docker run --rm --platform "$platform" --network "$network" -v "$temporary:/cluster" "$ceph_image" timeout 20 ceph --conf /cluster/ceph.conf --name client.admin --keyring /cluster/admin.keyring "$@"; }
for attempt in $(seq 1 30); do if ceph_cli status --format json 2>/dev/null | jq -e '.health.status != null' >/dev/null; then break; fi; [ "$attempt" -lt 30 ] || fail 'monitor did not become ready'; sleep 1; done
for id in 0 1 2; do
  uuid="11000000-0000-4000-8000-00000000001$id"; volume="rados-rs-r11-osd-$id-$$"
  docker volume create "$volume" >/dev/null
  ceph_cli osd create "$uuid" "$id" >/dev/null
  ceph_cli auth get-or-create "osd.$id" mon 'allow profile osd' mgr 'allow profile osd' osd 'allow *' -o "/cluster/osd-$id.keyring"
  ceph_cli mon getmap -o "/cluster/osd-$id.monmap" >/dev/null
  docker run --rm --user 0 --privileged --platform "$platform" -v "$temporary:/cluster" -v "$volume:/osd" "$ceph_image" sh -c '
    set -eu; id='"$id"'; uuid='"$uuid"'; mkdir -p /osd/data; truncate -s 2G /osd/block
    cp /cluster/osd-$id.keyring /osd/data/keyring; cp /cluster/osd-$id.monmap /osd/data/activate.monmap; chown -R ceph:ceph /osd
    ceph-osd --mkfs -i "$id" --osd-data /osd/data --osd-uuid "$uuid" --osd-objectstore bluestore --bluestore-block-path /osd/block --monmap /osd/data/activate.monmap --keyring /osd/data/keyring --setuser ceph --setgroup ceph
  '
  ip="172.30.111.$((20 + id))"
  docker run -d --privileged --name "r11-osd-$id-$$" --platform "$platform" --network "$network" --ip "$ip" -v "$temporary:/cluster" -v "$volume:/osd" "$ceph_image" ceph-osd -f --conf /cluster/ceph.conf -i "$id" --osd-data /osd/data --osd-objectstore bluestore --public-addr "v2:$ip:6800" --cluster-addr "v2:$ip:6802" --log-to-stderr true --err-to-stderr true --log-file '' --setuser ceph --setgroup ceph >/dev/null
done
for attempt in $(seq 1 90); do if ceph_cli osd stat --format json 2>/dev/null | jq -e '.num_osds == 3 and .num_up_osds == 3 and .num_in_osds == 3' >/dev/null; then break; fi; [ "$attempt" -lt 90 ] || fail 'OSDs did not become ready'; sleep 1; done

ceph_cli osd crush rule create-replicated r11-replicated-rule default osd >/dev/null
ceph_cli osd erasure-code-profile set r11-ec-profile plugin=jerasure k=2 m=1 crush-failure-domain=osd stripe_unit=4096 >/dev/null
ceph_cli osd crush rule create-erasure r11-ec-rule r11-ec-profile >/dev/null
ceph_cli osd pool create p11-named 16 16 replicated r11-replicated-rule >/dev/null
ceph_cli osd pool create p11-self 16 16 replicated r11-replicated-rule >/dev/null
ceph_cli osd pool create p11-ec 16 16 erasure r11-ec-profile r11-ec-rule >/dev/null
for pool in p11-named p11-self; do ceph_cli osd pool set "$pool" size 2 >/dev/null; ceph_cli osd pool set "$pool" min_size 1 >/dev/null; done
[ "$(ceph_cli osd pool get p11-ec size --format json | jq -r '.size')" -eq 3 ] || fail 'EC size mismatch'
[ "$(ceph_cli osd pool get p11-ec min_size --format json | jq -r '.min_size')" -eq 2 ] || fail 'EC min_size mismatch'
[ "$(ceph_cli osd pool get p11-ec allow_ec_overwrites --format json | jq -r '.allow_ec_overwrites')" = false ] || fail 'EC overwrite profile mismatch'
ceph_cli auth get-or-create client.p11 mon 'allow rw' osd 'allow rwx pool=p11-named, allow rwx pool=p11-self, allow rwx pool=p11-ec' -o /cluster/client.keyring >/dev/null
ceph_cli auth get-key client.p11 >"$temporary/client.key"
printf 'ready\n' >"$temporary/readiness"
for attempt in $(seq 1 180); do
  ready=true
  for pool_object in p11-named:readiness p11-self:readiness p11-ec:readiness; do
    pool=${pool_object%%:*}; object=${pool_object#*:}
    if ! docker run --rm --platform "$platform" --network "$network" -v "$temporary:/cluster" "$ceph_image" timeout 15 rados --conf /cluster/ceph.conf --name client.p11 --keyring /cluster/client.keyring --pool "$pool" put "$object" /cluster/readiness >/dev/null 2>&1; then ready=false; break; fi
  done
  "$ready" && break
  [ "$attempt" -lt 180 ] || fail 'pool I/O did not become ready'; sleep 1
done
for pool in p11-named p11-self p11-ec; do docker run --rm --platform "$platform" --network "$network" -v "$temporary:/cluster" "$ceph_image" timeout 15 rados --conf /cluster/ceph.conf --name client.p11 --keyring /cluster/client.keyring --pool "$pool" rm readiness >/dev/null; done

docker run --rm --platform "$platform" --network "$network" -v "$temporary:/work" "$ceph_image" timeout 45 /work/native-probe seed /work/ceph.conf /work/client.keyring >"$temporary/native-seed.json"
docker run --rm --platform "$platform" --network "$network" -v "$temporary:/work" "$ceph_image" timeout 180 /work/rust-probe --monitors 172.30.111.10:3300 --key /work/client.key --fsid "$fsid" --coordination-dir /work >"$temporary/rust.json"
docker run --rm --platform "$platform" --network "$network" -v "$temporary:/work" "$ceph_image" timeout 45 /work/native-probe verify /work/ceph.conf /work/client.keyring >"$temporary/native-verify.json"
jq -e 'all(.[]; if type == "boolean" then . else true end) and .checksum_hex == "02000000f5be862af5be862a" and .required_alignment == 8192' "$temporary/rust.json" >/dev/null
jq -e 'all(.[]; . == true)' "$temporary/native-seed.json" >/dev/null
jq -e 'all(.[]; if type == "boolean" then . else true end) and .rust_checksum_hex == "02000000f5be862af5be862a"' "$temporary/native-verify.json" >/dev/null

[ "$source_digest_before" = "$(source_digest)" ] || fail 'source changed during qualification'
[ -z "$(git -C "$go_root" status --porcelain=v1 --untracked-files=all)" ] || fail 'Go checkout changed during qualification'
server_version=$(docker run --rm --platform "$platform" "$ceph_image" ceph --version)
native_version=$(docker run --rm --platform "$platform" "$ceph_image" rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}' librados2)
docker run --rm --platform "$platform" "$ceph_image" sh -c 'cat "$(command -v ceph-osd)"' >"$temporary/server-binary"
mkdir -p "$(dirname "$report")"
candidate="$(dirname "$report")/.$(basename "$report").tmp.$$"
jq -n --arg started_at "$started_at" --arg finished_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg schema_sha256 "$(sha256_file "$root/integration/r11/report.schema.json")" --arg revision "$(git -C "$root" rev-parse HEAD)" --arg tree "$(git -C "$root" rev-parse 'HEAD^{tree}')" \
  --arg source_sha256 "$source_digest_before" --arg rust_image "$rust_image" --arg platform "$platform" --arg rust_binary_sha256 "$(sha256_file "$temporary/rust-probe")" \
  --arg native_driver_sha256 "$(sha256_file "$temporary/native_driver.c")" --arg native_binary_sha256 "$(sha256_file "$temporary/native-probe")" --arg native_version "$native_version" \
  --arg server_version "$server_version" --arg server_binary_sha256 "$(sha256_file "$temporary/server-binary")" --argjson probe "$(cat "$temporary/rust.json")" \
  --argjson native_seed "$(cat "$temporary/native-seed.json")" --argjson native_verify "$(cat "$temporary/native-verify.json")" \
  '{schema_version:1,suite_id:"r11/snapshots-specialized-ec-v1",status:"passed",started_at:$started_at,finished_at:$finished_at,schema_sha256:$schema_sha256,rust:{revision:$revision,tree:$tree,source_sha256:$source_sha256,compiler_image:$rust_image,platform:$platform,binary_sha256:$rust_binary_sha256},go:{revision:"c8bb148a1379b51ef87256c27f366a05f8da4dc4",tree:"c5039b6b50a05b942a902f70dc2fcb090463e8c7",compiler:"go1.26.8",platform:$platform,p10_driver_sha256:$native_driver_sha256,focused_tests:"passed"},native:{version:$native_version,binary_sha256:$native_binary_sha256,seed:$native_seed,verify:$native_verify},server:{source_anchor_commit:"7f793731f1b39eb4f465e960113d2363c311b964",version:$server_version,image:"quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa",binary_sha256:$server_binary_sha256},cluster:{fsid:"21111111-2222-4333-8444-111111111111",osds:3,objectstore:"bluestore",named_pool:{name:"p11-named",size:2,min_size:1,pg_num:16},self_managed_pool:{name:"p11-self",size:2,min_size:1,pg_num:16},ec_pool:{name:"p11-ec",size:3,min_size:2,pg_num:16,plugin:"jerasure",k:2,m:1,failure_domain:"osd",allow_ec_overwrites:false,stripe_unit:4096,stripe_width:$probe.required_alignment}},probe:$probe,scenarios:{named_snapshots:"passed",self_managed_snapshots:"passed",snapshot_context_validation:"passed",specialized_io:"passed",erasure_coded_io:"passed",native_interoperability:"passed"},deviations:{snapshot_views:"Rust represents mutable ioctx snapshot state as owned immutable Pool views.",uncertain_monitor_mutations:"Cancellation or deadline after a monitor snapshot mutation is dispatched returns OutcomeUnknown and resets the monitor session.",non_frozen_variants:["rados_set_alloc_hint2","rados_write_op_set_alloc_hint2","IoCtx::list_snaps","IoCtx::mapext","IoCtx::pool_required_alignment","IoCtx::pool_requires_alignment","IoCtx::set_alloc_hint2","ObjectReadOperation::list_snaps","ObjectWriteOperation::set_alloc_hint2","Rados::get_inconsistent_snapsets"]}}' >"$candidate"
cargo run --quiet -p rados-r11-tools --bin rados-r11-verify -- "$root" "$candidate" "$temporary/rust-probe" "$go_root" "$temporary/native_driver.c" "$temporary/native-probe" "$temporary/server-binary"
mv "$candidate" "$report"
printf '%s\n' "R11 live qualification passed: $report"