#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
destination=${1:-/tmp/rados-r05-fuzz/corpus}

verify_sha256() {
  expected=$1
  source=$2
  actual=$(shasum -a 256 "$source" | awk '{print $1}')
  [ "$actual" = "$expected" ] || {
    printf '%s\n' "R05 fuzz corpus: unexpected SHA-256 for $source" >&2
    exit 1
  }
}

monmap="$root/testdata/p04/monmap-v9.bin"
osdmap="$root/testdata/p04/osdmap-v8.bin"
incremental="$root/testdata/p04/osdmap-incremental-v8.bin"

verify_sha256 d575f2f1267aaad35803d0c7fbd61bd0d1ab00ac7837bb6210a835a0d4c3e3da "$monmap"
verify_sha256 7131ba24e481dd198a90b6121d6fc2a16b32dc61928dfcd9f5df9efc730acda8 "$osdmap"
verify_sha256 57ee8c961bac016deb512b6f741b66231a9c337bc1bdfce0b54ef9697c0b9763 "$incremental"

rm -rf "$destination"
mkdir -p \
  "$destination/r05_config" \
  "$destination/r05_monmap" \
  "$destination/r05_osdmap" \
  "$destination/r05_osdmap_incremental" \
  "$destination/r05_monmap_message" \
  "$destination/r05_osdmap_full_message" \
  "$destination/r05_osdmap_incremental_message"

printf '%s\n' \
  '[global]' \
  'name = client.fuzz' \
  'mon_host = [v2:192.0.2.1:3300,192.0.2.2:3300]' \
  'ms_mode = secure' \
  'operation_timeout = 250ms' \
  > "$destination/r05_config/representative.conf"
printf '%s\n' '[global' 'mon_host = [v2:192.0.2.1:3300' \
  > "$destination/r05_config/malformed-section.conf"
printf '\377\376\000[global]\nname = client.fuzz\n' \
  > "$destination/r05_config/malformed-utf8.bin"
printf '%s\n' '[global]' 'include = /bounded/rejected.conf' \
  > "$destination/r05_config/rejected-include.conf"

cp "$monmap" "$destination/r05_monmap/p04-monmap-v9.bin"
cp "$osdmap" "$destination/r05_osdmap/p04-osdmap-v8.bin"
cp "$incremental" "$destination/r05_osdmap_incremental/p04-osdmap-incremental-v8.bin"
printf '\011\001\377\000\000\000' > "$destination/r05_monmap/malformed-versioned.bin"
printf '\010\007\004\000\000\000\012\011' > "$destination/r05_osdmap/malformed-versioned.bin"
printf '\010\007\004\000\000\000\011\010' \
  > "$destination/r05_osdmap_incremental/malformed-versioned.bin"

perl -e '
  use strict; use warnings;
  my ($source, $output) = @ARGV;
  open my $input, "<:raw", $source or die "$source: $!";
  local $/; my $map = <$input>;
  open my $front, ">:raw", $output or die "$output: $!";
  print {$front} pack("V", length($map)), $map;
' "$monmap" "$destination/r05_monmap_message/p04-monmap-message-front.bin"
printf '\000\000\000\200' \
  > "$destination/r05_monmap_message/malformed-length.bin"

perl -e '
  use strict; use warnings;
  my ($kind, $source, $output) = @ARGV;
  open my $input, "<:raw", $source or die "$source: $!";
  local $/; my $map = <$input>;
  die "short versioned OSD map" if length($map) < 32;
  my $fsid = substr($map, 12, 16);
  my $epoch = unpack("V", substr($map, 28, 4));
  my $entry = pack("V V", $epoch, length($map)) . $map;
  my ($incrementals, $full) = $kind eq "incremental"
    ? (pack("V", 1) . $entry, pack("V", 0))
    : (pack("V", 0), pack("V", 1) . $entry);
  open my $front, ">:raw", $output or die "$output: $!";
  print {$front} $fsid, $incrementals, $full, pack("V V V", $epoch, $epoch, 0);
' full "$osdmap" "$destination/r05_osdmap_full_message/p04-osdmap-full-message-front.bin"
perl -e '
  use strict; use warnings;
  my ($kind, $source, $output) = @ARGV;
  open my $input, "<:raw", $source or die "$source: $!";
  local $/; my $map = <$input>;
  die "short versioned OSD map" if length($map) < 32;
  my $fsid = substr($map, 12, 16);
  my $epoch = unpack("V", substr($map, 28, 4));
  my $entry = pack("V V", $epoch, length($map)) . $map;
  my ($incrementals, $full) = $kind eq "incremental"
    ? (pack("V", 1) . $entry, pack("V", 0))
    : (pack("V", 0), pack("V", 1) . $entry);
  open my $front, ">:raw", $output or die "$output: $!";
  print {$front} $fsid, $incrementals, $full, pack("V V V", $epoch, $epoch, 0);
' incremental "$incremental" "$destination/r05_osdmap_incremental_message/p04-osdmap-incremental-message-front.bin"
printf '\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\101\000\000\000' \
  > "$destination/r05_osdmap_full_message/malformed-count.bin"
cp "$destination/r05_osdmap_full_message/malformed-count.bin" \
  "$destination/r05_osdmap_incremental_message/malformed-count.bin"