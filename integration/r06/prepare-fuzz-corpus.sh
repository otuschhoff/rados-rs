#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
destination=${1:-/tmp/rados-r06-fuzz/corpus}

verify_sha256() {
  expected=$1
  source=$2
  actual=$(shasum -a 256 "$source" | awk '{print $1}')
  [ "$actual" = "$expected" ] || { printf '%s\n' "R06 fuzz corpus: unexpected SHA-256 for $source" >&2; exit 1; }
}

p05="$root/testdata/r06/p05/crushmap.bin"
p10="$root/testdata/r06/p10/crushmap.bin"
verify_sha256 9679682ba0a62113d699006a09f96142536de2ae699dc92e9ffd39999792157f "$p05"
verify_sha256 d2fcae471a000699a3ddd30ccb48b38a0f99a303e92332e52e134e71ea6b4a12 "$p10"

rm -rf "$destination"
mkdir -p "$destination/r06_crush_decode" "$destination/r06_crush_place" \
  "$destination/r06_object_mapping" "$destination/r06_osdmap_place_object"
cp "$p05" "$destination/r06_crush_decode/p05-crushmap.bin"
cp "$p10" "$destination/r06_crush_decode/p10-crushmap.bin"
printf '\000\000\001\000\377\377\377' >"$destination/r06_crush_decode/malformed.bin"

perl -e '
  use strict; use warnings;
  my ($rule, $weights, $source, $output) = @ARGV;
  open my $input, "<:raw", $source or die "$source: $!"; local $/; my $map = <$input>;
  my @weight = (0x8000) x $weights;
  open my $out, ">:raw", $output or die "$output: $!";
  print {$out} pack("V V C C v*", $rule, 0, 2, $weights - 1, @weight), $map;
' 0 4 "$p05" "$destination/r06_crush_place/p05-rule0.bin"
perl -e '
  use strict; use warnings;
  my ($rule, $weights, $source, $output) = @ARGV;
  open my $input, "<:raw", $source or die "$source: $!"; local $/; my $map = <$input>;
  my @weight = (0x8000) x $weights;
  open my $out, ">:raw", $output or die "$output: $!";
  print {$out} pack("V V C C v*", $rule, 0, 2, $weights - 1, @weight), $map;
' 2 3 "$p10" "$destination/r06_crush_place/p10-rule2.bin"
printf '\000\000\000' >"$destination/r06_crush_place/truncated.bin"

perl -e '
  use strict; use warnings;
  my ($output, $object, $namespace, $locator, $pgs) = @ARGV;
  open my $out, ">:raw", $output or die "$output: $!";
  print {$out} pack("v v v V", length($object), length($namespace), length($locator), $pgs), $object, $namespace, $locator;
' "$destination/r06_object_mapping/namespaced.bin" 'object' 'namespace' 'locator' 32
printf '\000\000\000\000\000\000\000\000\000\000\377\376\000\037' >"$destination/r06_object_mapping/binary.bin"
printf '\001\002\003' >"$destination/r06_object_mapping/truncated.bin"

perl -e '
  use strict; use warnings;
  my ($source, $output, $rule) = @ARGV;
  open my $input, "<:raw", $source or die "$source: $!"; local $/; my $map = <$input>;
  my $control = "\0" x 32;
  substr($control, 0, 4, pack("V", 256));
  substr($control, 4, 8, pack("v4", (0x8000) x 4));
  my $object = "p05-object-0";
  substr($control, 12, 3, pack("C3", length($object), 0, 0));
  substr($control, 15, length($object), $object);
  substr($control, 29, 3, pack("C3", $rule, 0, 2));
  open my $out, ">:raw", $output or die "$output: $!";
  print {$out} $control, $map;
' "$p05" "$destination/r06_osdmap_place_object/p05-object.bin" 0
perl -e '
  use strict; use warnings;
  my ($source, $output, $rule) = @ARGV;
  open my $input, "<:raw", $source or die "$source: $!"; local $/; my $map = <$input>;
  my $control = "\0" x 32;
  substr($control, 0, 4, pack("V", 32));
  substr($control, 4, 8, pack("v4", (0x8000) x 4));
  substr($control, 12, 3, pack("C3", 6, 2, 2));
  substr($control, 15, 10, "objectnslo");
  substr($control, 29, 3, pack("C3", $rule, 1, 3));
  open my $out, ">:raw", $output or die "$output: $!";
  print {$out} $control, $map;
' "$p05" "$destination/r06_osdmap_place_object/p05-override.bin" 0
printf '\000\000\000\000' >"$destination/r06_osdmap_place_object/truncated.bin"
