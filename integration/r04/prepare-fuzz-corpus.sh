#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
destination=${1:-/tmp/rados-r04-fuzz/corpus}
encoding_vectors="$root/testdata/p03/cephx-encoding-vectors.json"
crypto_vectors="$root/testdata/p03/crypto-vectors.json"
aes_key='AQB7AAAAyAEAABAAMTIzNDU2Nzg5MDEyMzQ1Ng=='
aes256_key='AgBm8qdqnvU7HiAAg6prN8XJ47FG9AprWpB72EwKyLfFC7UgnMYvcnFI29M='

rm -rf "$destination"
mkdir -p \
  "$destination/cephx_credentials" \
  "$destination/cephx_server_challenge" \
  "$destination/cephx_auth_session_reply" \
  "$destination/cephx_authorizer"

printf '\000%s' "$aes_key" \
  > "$destination/cephx_credentials/parse-key-aes.bin"
printf '\000%s' "$aes256_key" \
  > "$destination/cephx_credentials/parse-key-aes256.bin"
printf '\001[client.fuzz]\nkey = %s\n' "$aes_key" \
  > "$destination/cephx_credentials/parse-keyring-aes.bin"
printf '\001[client.fuzz]\nkey = %s\n' "$aes256_key" \
  > "$destination/cephx_credentials/parse-keyring-aes256.bin"

sed -n 's/.*"type": "CephXServerChallenge".*"hex": "\([0-9a-f]*\)".*/\1/p' \
  "$encoding_vectors" | xxd -r -p \
  > "$destination/cephx_server_challenge/p03-server-challenge.bin"
printf '\377\001\002' \
  > "$destination/cephx_server_challenge/malformed.bin"

printf '\000\000\000' > "$destination/cephx_auth_session_reply/aes-crc-ticket.bin"
printf '\000\001\001' > "$destination/cephx_auth_session_reply/aes-secure-connection.bin"
printf '\001\000\000' > "$destination/cephx_auth_session_reply/aes256-crc-ticket.bin"
printf '\001\001\001' > "$destination/cephx_auth_session_reply/aes256-secure-connection.bin"
printf '\001\001\000\000' \
  > "$destination/cephx_auth_session_reply/aes256-authenticated-malformed.bin"
sed -n 's/.*"plaintext_hex": "\([0-9a-f]*\)".*/\1/p' "$crypto_vectors" \
  | tail -1 | xxd -r -p \
  >> "$destination/cephx_auth_session_reply/aes256-authenticated-malformed.bin"

printf '\000\000' > "$destination/cephx_authorizer/aes-reply.bin"
printf '\000\001' > "$destination/cephx_authorizer/aes-challenge.bin"
printf '\001\000' > "$destination/cephx_authorizer/aes256-reply.bin"
printf '\001\001' > "$destination/cephx_authorizer/aes256-challenge.bin"
printf '\001\001\000' \
  > "$destination/cephx_authorizer/aes256-authenticated-malformed.bin"
sed -n 's/.*"plaintext_hex": "\([0-9a-f]*\)".*/\1/p' "$crypto_vectors" \
  | tail -1 | xxd -r -p \
  >> "$destination/cephx_authorizer/aes256-authenticated-malformed.bin"