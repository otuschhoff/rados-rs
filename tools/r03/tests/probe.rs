use std::path::Path;

use rados_r03_tools::{MAX_RECORD_BYTES, MAX_RECORDS, default_request_json, run_rust_probe};

#[test]
fn rust_probe_emits_all_canonical_cases() {
    let root = Path::new("../..");
    let mut output = Vec::new();
    run_rust_probe(root, default_request_json().as_bytes(), &mut output).expect("probe passes");
    let records = output
        .split(|byte| *byte == b'\n')
        .filter(|record| !record.is_empty())
        .map(|record| serde_json::from_slice::<serde_json::Value>(record).expect("valid result"))
        .collect::<Vec<_>>();
    assert_eq!(records.len(), MAX_RECORDS);
    assert_eq!(records[0]["case_id"], "banner");
    assert_eq!(records[5]["case_id"], "session-transition");
}

#[test]
fn rust_probe_rejects_oversized_unknown_and_stale_requests() {
    let root = Path::new("../..");
    let oversized = usize::try_from(MAX_RECORD_BYTES).expect("record bound") + 1;
    assert!(run_rust_probe(root, vec![b' '; oversized].as_slice(), Vec::new()).is_err());
    let unknown = default_request_json().replace(
        "\"schema_version\":1",
        "\"unknown\":true,\"schema_version\":1",
    );
    assert!(run_rust_probe(root, unknown.as_bytes(), Vec::new()).is_err());
    let stale = default_request_json().replace(
        "6819c56d3d3d3ccaa0545a80d55aaa8088d88e9f849113cdafa58feb298cfcca",
        &"0".repeat(64),
    );
    assert!(run_rust_probe(root, stale.as_bytes(), Vec::new()).is_err());
}
