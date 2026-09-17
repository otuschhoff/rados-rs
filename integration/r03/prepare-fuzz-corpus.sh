#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
destination=${1:-/tmp/rados-r03-fuzz/corpus}

rm -rf "$destination"
mkdir -p \
  "$destination/banner" \
  "$destination/crc_frame" \
  "$destination/secure_frame" \
  "$destination/controls" \
  "$destination/messages" \
  "$destination/bounded_session_scripts"

cp "$root/testdata/p02/banner-rev1.bin" \
  "$destination/banner/banner-rev1.bin"
{ printf '\001'; cat "$root/testdata/p02/upstream/upstream-crc-four-segment.bin"; } \
  > "$destination/crc_frame/crc-four-segment-with-data-crc.bin"
cp "$root/testdata/p02/upstream/upstream-secure-one-segment.bin" \
  "$destination/secure_frame/secure-one-segment.bin"
{ printf '\000'; cat "$root/testdata/p02/upstream/upstream-crc-four-segment.bin"; } \
  > "$destination/secure_frame/crc-four-segment-generation.bin"
{ printf '\024'; dd if="$root/testdata/p02/upstream/upstream-ack-control.bin" \
    bs=1 skip=32 count=8 status=none; } \
  > "$destination/controls/ack-sequence.bin"
cp "$root/testdata/p02/upstream/upstream-message-frame.bin" \
  "$destination/messages/message-frame.bin"
cp "$root/fuzz/corpus/bounded_session_scripts/go-session-938f779fb2101a93.raw" \
  "$destination/bounded_session_scripts/go-session-938f779fb2101a93.raw"
