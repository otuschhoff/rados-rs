#!/bin/sh
set -eu

test "$#" -eq 2 || { printf 'usage: %s ROOT REPORT\n' "$0" >&2; exit 2; }
root=$(CDPATH= cd -- "$1" && pwd)
report=$2
test -f "$report" && test "$(wc -c <"$report" | tr -d ' ')" -le 262144
test -z "$(find "$root/src" -type l -print -quit)" || {
  printf '%s\n' 'R04 live verifier: symlinks beneath src are forbidden' >&2
  exit 1
}

artifact_paths=$(find "$root/src" -type f -print | sed "s|^$root/||" | LC_ALL=C sort)
artifact_paths="Cargo.toml Cargo.lock rust-toolchain.toml integration/r04/live-reproduce.sh integration/r04/verify-live-report.sh integration/r04/live-report.schema.json integration/r04/legacy-crush.txt integration/r04/legacy-crush.provenance.json $artifact_paths"
expected_artifact_keys=$(
  for artifact in $artifact_paths; do printf '%s\n' "$artifact"; done |
    jq -Rn '[inputs] | sort'
)

jq -e '
  (keys | sort) == ["cluster","command","finished_at","negative_observations","probe","scenarios","schema_version","server","source","started_at","status","suite_id"] and
  .schema_version == 1 and .suite_id == "r04/live-monitor-v1" and .status == "passed" and
  .command == "integration/r04/live-reproduce.sh" and
  (.started_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")) and
  (.finished_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")) and
  (.source | keys | sort) == ["artifacts","dirty","identity","repository","revision"] and
  .source.repository == "https://github.com/otuschhoff/rados-rs" and .source.identity == "content-addressed-artifacts" and
  (.server | keys | sort) == ["host_platform","image","monitor_binary_sha256","platform","repository","runtime_package","source_anchor_commit","version"] and
  .server.image == "quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa" and
  .server.platform == "linux/arm64" and .server.host_platform == "linux/arm64" and
  .server.source_anchor_commit == "7f793731f1b39eb4f465e960113d2363c311b964" and
  .server.version == "ceph version 20.2.4 (7f793731f1b39eb4f465e960113d2363c311b964) tentacle (stable - RelWithDebInfo)" and
  .cluster == {fsid:"41111111-2222-4333-8444-555555555555",network:"172.30.94.0/24",monitor:"v2:172.30.94.10:3300",client:"172.30.94.20",monitor_name:"a",client_entity:"client.r04",external_config:false,ticket_ttl_seconds:4} and
  (.scenarios | keys | sort) == ["client_server_ident","expired_ticket_rejection","global_id_reuse","post_expiry_fresh_global_id","same_session_renewal","secure_authentication","secure_default_downgrade_rejection","ticket_rotation","valid_wrong_key_rejection"] and
  all(.scenarios[]; . == "passed") and
  .negative_observations == {wrong_key:"cephx authentication rejected",downgrade:"cephx auth downgrade rejected"} and
  .probe.authenticated_mode == "secure" and .probe.global_id > 0 and .probe.reconnected and .probe.ticket_renewed and
  .probe.expiry_rejected and .probe.expired_reconnect and .probe.renewed_global_id == .probe.global_id and
  .probe.post_expiry_global_id > 0 and .probe.post_expiry_global_id != .probe.global_id and
  (.probe.initial_ticket_sha256 | test("^[0-9a-f]{64}$")) and (.probe.renewed_ticket_sha256 | test("^[0-9a-f]{64}$")) and
  .probe.initial_ticket_sha256 != .probe.renewed_ticket_sha256 and (.probe.server_addresses | index("172.30.94.10:3300") != null)
' "$report" >/dev/null

jq -e --argjson expected "$expected_artifact_keys" \
  '(.source.artifacts | keys | sort) == $expected' "$report" >/dev/null || {
    printf '%s\n' 'R04 live verifier: artifact set does not match the required live source closure' >&2
    exit 1
  }

jq -r '.source.artifacts | to_entries[] | [.key,.value] | @tsv' "$report" |
while IFS="	" read -r artifact expected; do
  test -f "$root/$artifact"
  actual=$(shasum -a 256 "$root/$artifact" | awk '{print $1}')
  test "$actual" = "$expected" || { printf 'R04 live verifier: changed artifact %s\n' "$artifact" >&2; exit 1; }
done

printf 'R04 live report verified: %s\n' "$report"