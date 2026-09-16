#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$root"
image=$(jq -r '.images.qualification.reference' docs/p00/evidence.json)
features=720575940647714820
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

compare_dencoder() {
  fixture=$1
  shift
  docker run --rm "$image" ceph-dencoder "$@" export /dev/stdout > "$temporary/$fixture"
  cmp "testdata/p01/$fixture" "$temporary/$fixture"
}

compare_dencoder entity-name-mon-new.bin type entity_name_t select_test 1 encode
compare_dencoder entity-name-client-1.bin type entity_name_t select_test 4 encode
compare_dencoder entity-addr-ipv4-legacy.bin type entity_addr_t select_test 3 set_features 0 encode
compare_dencoder entity-addr-ipv4-modern.bin type entity_addr_t select_test 3 set_features "$features" encode
compare_dencoder entity-addrvec-modern.bin type entity_addrvec_t select_test 3 set_features "$features" encode

docker run --rm -v "$root:/src:ro" -w /tmp "$image" sh -c \
  'cc -std=c11 -Wall -Wextra -Werror -O2 /src/integration/p01/ipv6-fixture.c -o ipv6-fixture && ./ipv6-fixture' \
  > "$temporary/entity-addr-ipv6-seed.bin"
cmp integration/p01/entity-addr-ipv6-seed.bin "$temporary/entity-addr-ipv6-seed.bin"

docker run --rm -v "$root:/src:ro" "$image" ceph-dencoder \
  type entity_addr_t import /src/integration/p01/entity-addr-ipv6-seed.bin \
  decode encode export /dev/stdout > "$temporary/entity-addr-ipv6-modern.bin"
cmp testdata/p01/entity-addr-ipv6-modern.bin "$temporary/entity-addr-ipv6-modern.bin"

printf '%s\n' 'P01 fixture reproduction passed'
