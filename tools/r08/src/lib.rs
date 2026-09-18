#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_REPORT_BYTES: u64 = 262_144;
const SUITE_ID: &str = "r08/mutation-qualification-v1";
const COMPILER_IMAGE: &str =
    "rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922";
const SERVER_COMMIT: &str = "7f793731f1b39eb4f465e960113d2363c311b964";
const SERVER_VERSION: &str =
    "ceph version 20.2.4 (7f793731f1b39eb4f465e960113d2363c311b964) tentacle (stable)";
const SERVER_IMAGE: &str =
    "quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa";
const NATIVE_VERSION: &str = "librados2-20.2.4-0.el9";
const GO_REVISION: &str = "c8bb148a1379b51ef87256c27f366a05f8da4dc4";
const GO_TREE: &str = "c5039b6b50a05b942a902f70dc2fcb090463e8c7";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Report {
    schema_version: u32,
    suite_id: String,
    status: String,
    started_at: String,
    finished_at: String,
    schema_sha256: String,
    rust: RustEvidence,
    go: GoEvidence,
    native: NativeEvidence,
    server: ServerEvidence,
    scenarios: Scenarios,
    performance: Vec<Performance>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RustEvidence {
    revision: String,
    tree: String,
    source_sha256: String,
    compiler_image: String,
    platform: String,
    binary_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GoEvidence {
    revision: String,
    tree: String,
    compiler: String,
    platform: String,
    binary_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeEvidence {
    version: String,
    binary_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ServerEvidence {
    source_anchor_commit: String,
    version: String,
    image: String,
    binary_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Scenarios {
    create: String,
    write: String,
    write_full: String,
    append: String,
    truncate: String,
    zero: String,
    remove: String,
    cross_client_crud: String,
    append_once_failover_lost_reply: String,
    ack_vs_commit: String,
    flush_watermark: String,
    cancellation_drop_boundaries: String,
    performance_baseline: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Performance {
    implementation: String,
    workload: String,
    payload_bytes: u64,
    concurrency: u32,
    operations: u64,
    elapsed_seconds: f64,
    operations_per_second: f64,
    latency_p50_microseconds: f64,
    latency_p95_microseconds: f64,
    latency_p99_microseconds: f64,
    cpu_user_seconds: f64,
    cpu_system_seconds: f64,
    allocation_metric: AllocationMetric,
    retained_bytes: u64,
    peak_rss_bytes: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AllocationMetric {
    name: String,
    value: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FuzzReport {
    schema_version: u32,
    suite_id: String,
    status: String,
    started_at: String,
    finished_at: String,
    source_sha256: String,
    rustc: String,
    cargo_fuzz: String,
    campaigns: Vec<FuzzCampaign>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FuzzCampaign {
    target: String,
    budget_seconds: u64,
    executions: u64,
    executions_per_second: u64,
    corpus_sha256: String,
    target_sha256: String,
    output_path: String,
    output_sha256: String,
    status: String,
}

/// Verifies a stored R08 report against its strict typed contract and current source.
///
/// # Errors
/// Returns an error when the report is malformed, stale, incomplete, or implausible.
pub fn verify_report_file(root: &Path, report_path: &Path) -> Result<(), String> {
    let mut data = Vec::new();
    fs::File::open(report_path)
        .map_err(|error| format!("open report: {error}"))?
        .take(MAX_REPORT_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|error| format!("read report: {error}"))?;
    if data.len() as u64 > MAX_REPORT_BYTES {
        return Err("report exceeds byte limit".to_owned());
    }
    verify_report_bytes(root, &data)
}

/// Verifies a report and the exact Rust, frozen-Go, and native executables used.
///
/// # Errors
/// Returns an error when executable hashes or the frozen Go checkout do not match.
pub fn verify_report_artifacts(
    root: &Path,
    report_path: &Path,
    rust_binary: &Path,
    go_root: &Path,
    go_binary: &Path,
    native_binary: &Path,
) -> Result<(), String> {
    let data = fs::read(report_path).map_err(|error| format!("read report: {error}"))?;
    verify_report_bytes(root, &data)?;
    let report: Report =
        serde_json::from_slice(&data).map_err(|error| format!("decode report: {error}"))?;
    if report.rust.binary_sha256 != file_digest(rust_binary)?
        || report.go.binary_sha256 != file_digest(go_binary)?
        || report.native.binary_sha256 != file_digest(native_binary)?
    {
        return Err("reported executable digest does not match".to_owned());
    }
    if git_output(go_root, &["rev-parse", "HEAD"])? != GO_REVISION
        || git_output(go_root, &["rev-parse", "HEAD^{tree}"])? != GO_TREE
        || !git_output(
            go_root,
            &["status", "--porcelain=v1", "--untracked-files=all"],
        )?
        .is_empty()
    {
        return Err("Go oracle is not clean and pinned".to_owned());
    }
    Ok(())
}

/// Verifies a stored R08 fuzz task-validation report and retained logs.
///
/// # Errors
/// Returns an error when the report is stale, incomplete, malformed, or its
/// target and output artifacts do not match their recorded hashes.
pub fn verify_fuzz_report_file(root: &Path, report_path: &Path) -> Result<(), String> {
    let data = fs::read(report_path).map_err(|error| format!("read fuzz report: {error}"))?;
    if data.len() as u64 > MAX_REPORT_BYTES {
        return Err("fuzz report exceeds byte limit".to_owned());
    }
    let report: FuzzReport =
        serde_json::from_slice(&data).map_err(|error| format!("decode fuzz report: {error}"))?;
    if report.schema_version != 1
        || report.suite_id != "r08/fuzz-task-validation-v1"
        || report.status != "passed"
        || report.rustc != "rustc 1.100.0-nightly (0dfb098f3 2026-08-31)"
        || report.cargo_fuzz != "cargo-fuzz 0.13.2"
        || !valid_timestamp(&report.started_at)
        || !valid_timestamp(&report.finished_at)
        || report.started_at > report.finished_at
        || report.source_sha256 != rust_source_digest(root)?
    {
        return Err("fuzz report identity, provenance, or timestamps are invalid".to_owned());
    }
    let expected = BTreeMap::from([
        (
            "r08_mutation_request",
            "49f7a35cae6ecfc43a46e0833539585d23c44069b5d980074307e6867fd1d689",
        ),
        (
            "r08_mutation_reply",
            "0a34d0f6c1703d0455d5236b45d3474b8e98ac38f4171419ed810d1b6a4fd70b",
        ),
        (
            "r08_mutation_recovery",
            "4b24904bbcbf89601a22dfb3b7d84b2e7832673375815844ad4b7a020303de59",
        ),
    ]);
    if report.campaigns.len() != expected.len() {
        return Err("fuzz campaign matrix is incomplete".to_owned());
    }
    let report_directory = report_path
        .parent()
        .ok_or_else(|| "fuzz report has no parent directory".to_owned())?;
    let mut observed = BTreeSet::new();
    for campaign in &report.campaigns {
        let Some(expected_corpus) = expected.get(campaign.target.as_str()) else {
            return Err("unexpected fuzz target".to_owned());
        };
        let expected_output = format!("fuzz-validation-logs/{}.log", campaign.target);
        let target_path = root.join(format!("fuzz/fuzz_targets/{}.rs", campaign.target));
        if !observed.insert(campaign.target.as_str())
            || campaign.status != "passed"
            || campaign.budget_seconds < 60
            || campaign.executions == 0
            || campaign.executions_per_second == 0
            || campaign.corpus_sha256 != *expected_corpus
            || campaign.output_path != expected_output
            || !is_hex(&campaign.target_sha256, 64)
            || campaign.target_sha256 != file_digest(&target_path)?
            || !is_hex(&campaign.output_sha256, 64)
            || campaign.output_sha256 != file_digest(&report_directory.join(&campaign.output_path))?
        {
            return Err("fuzz campaign evidence is invalid".to_owned());
        }
    }
    Ok(())
}

fn verify_report_bytes(root: &Path, data: &[u8]) -> Result<(), String> {
    let report: Report =
        serde_json::from_slice(data).map_err(|error| format!("decode report: {error}"))?;
    verify_shape(&report)?;
    verify_git_identity(root, &report.rust)?;
    if report.schema_sha256 != file_digest(&root.join("integration/r08/report.schema.json"))?
        || report.rust.source_sha256 != rust_source_digest(root)?
    {
        return Err("schema or Rust source digest does not match checkout".to_owned());
    }
    Ok(())
}

fn verify_shape(report: &Report) -> Result<(), String> {
    if report.schema_version != 1 || report.suite_id != SUITE_ID || report.status != "passed" {
        return Err("report identity or status is invalid".to_owned());
    }
    if !valid_timestamp(&report.started_at)
        || !valid_timestamp(&report.finished_at)
        || report.started_at > report.finished_at
    {
        return Err("report timestamps are invalid".to_owned());
    }
    if report.rust.compiler_image != COMPILER_IMAGE
        || !matches!(report.rust.platform.as_str(), "linux/amd64" | "linux/arm64")
        || report.go.revision != GO_REVISION
        || report.go.tree != GO_TREE
        || report.go.compiler != "go1.26.8"
        || report.go.platform != report.rust.platform
    {
        return Err("client provenance is invalid".to_owned());
    }
    if report.server.source_anchor_commit != SERVER_COMMIT
        || report.server.version != SERVER_VERSION
        || report.server.image != SERVER_IMAGE
        || report.native.version != NATIVE_VERSION
    {
        return Err("Ceph provenance is invalid".to_owned());
    }
    let statuses = [
        &report.scenarios.create,
        &report.scenarios.write,
        &report.scenarios.write_full,
        &report.scenarios.append,
        &report.scenarios.truncate,
        &report.scenarios.zero,
        &report.scenarios.remove,
        &report.scenarios.cross_client_crud,
        &report.scenarios.append_once_failover_lost_reply,
        &report.scenarios.ack_vs_commit,
        &report.scenarios.flush_watermark,
        &report.scenarios.cancellation_drop_boundaries,
        &report.scenarios.performance_baseline,
    ];
    if statuses.iter().any(|status| status.as_str() != "passed") {
        return Err("scenario evidence is incomplete".to_owned());
    }
    for digest in [
        &report.schema_sha256,
        &report.rust.source_sha256,
        &report.rust.binary_sha256,
        &report.go.binary_sha256,
        &report.native.binary_sha256,
        &report.server.binary_sha256,
    ] {
        if !is_hex(digest, 64) {
            return Err("invalid digest".to_owned());
        }
    }
    if !is_hex(&report.rust.revision, 40) || !is_hex(&report.rust.tree, 40) {
        return Err("invalid Rust revision".to_owned());
    }
    verify_performance(&report.performance)
}

fn verify_performance(records: &[Performance]) -> Result<(), String> {
    if records.len() != 3 {
        return Err("performance baseline must contain exactly three records".to_owned());
    }
    let mut matrix = BTreeMap::<&str, BTreeSet<&str>>::new();
    for record in records {
        let operations = u32::try_from(record.operations).map_or(f64::NAN, f64::from);
        if !matches!(record.implementation.as_str(), "rust" | "go" | "native")
            || record.workload != "write-full-baseline-v1"
            || record.payload_bytes != 4096
            || record.concurrency != 1
            || record.operations != 128
            || !positive(record.elapsed_seconds)
            || !positive(record.operations_per_second)
            || ((record.operations_per_second - operations / record.elapsed_seconds)
                / record.operations_per_second)
                .abs()
                > 0.001
            || !positive(record.latency_p50_microseconds)
            || record.latency_p50_microseconds > record.latency_p95_microseconds
            || record.latency_p95_microseconds > record.latency_p99_microseconds
            || !nonnegative(record.cpu_user_seconds)
            || !nonnegative(record.cpu_system_seconds)
            || !positive(record.cpu_user_seconds + record.cpu_system_seconds)
            || record.allocation_metric.name.is_empty()
            || record.allocation_metric.value == 0
            || record.retained_bytes < record.payload_bytes
            || record.peak_rss_bytes == 0
        {
            return Err("performance record is incomplete or implausible".to_owned());
        }
        if !matrix
            .entry(&record.workload)
            .or_default()
            .insert(&record.implementation)
        {
            return Err("duplicate implementation/workload performance record".to_owned());
        }
    }
    let implementations = BTreeSet::from(["go", "native", "rust"]);
    if matrix.is_empty() || matrix.values().any(|actual| actual != &implementations) {
        return Err("performance matrix is incomplete".to_owned());
    }
    Ok(())
}

fn positive(value: f64) -> bool {
    value.is_finite() && value > 0.0
}

fn nonnegative(value: f64) -> bool {
    value.is_finite() && value >= 0.0
}

/// Hashes the complete Rust source and R08 qualification closure.
///
/// # Errors
/// Returns an error when the source set cannot be listed or read.
pub fn rust_source_digest(root: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .args([
            "ls-files",
            "-co",
            "--exclude-standard",
            "--",
            "src/**",
            "tools/r08/**",
            "integration/r08/**",
            "Cargo.toml",
            "Cargo.lock",
            "build.rs",
            "rust-toolchain.toml",
        ])
        .current_dir(root)
        .output()
        .map_err(|error| format!("list Rust source files: {error}"))?;
    if !output.status.success() {
        return Err("git ls-files failed".to_owned());
    }
    let listing =
        String::from_utf8(output.stdout).map_err(|_| "source path is not UTF-8".to_owned())?;
    let mut paths = listing.lines().collect::<Vec<_>>();
    paths.sort_unstable();
    paths.dedup();
    if paths.is_empty() {
        return Err("Rust source set is empty".to_owned());
    }
    let mut aggregate = Sha256::new();
    for path in paths {
        let digest = file_digest(&root.join(path))?;
        aggregate.update(format!("{digest}  {path}\n").as_bytes());
    }
    Ok(lower_hex(&aggregate.finalize()))
}

fn verify_git_identity(root: &Path, evidence: &RustEvidence) -> Result<(), String> {
    let status = Command::new("git")
        .args(["merge-base", "--is-ancestor", &evidence.revision, "HEAD"])
        .current_dir(root)
        .status()
        .map_err(|error| error.to_string())?;
    if !status.success()
        || git_output(
            root,
            &["rev-parse", &format!("{}^{{tree}}", evidence.revision)],
        )? != evidence.tree
    {
        return Err("reported Rust revision identity is invalid".to_owned());
    }
    Ok(())
}

fn file_digest(path: &Path) -> Result<String, String> {
    fs::read(path)
        .map(|bytes| hex_digest(&bytes))
        .map_err(|error| format!("read {}: {error}", path.display()))
}

fn git_output(root: &Path, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(root)
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("git command failed".to_owned());
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| "git output is not UTF-8".to_owned())
}

fn hex_digest(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(result, "{byte:02x}").expect("String write");
    }
    result
}

fn is_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_timestamp(value: &str) -> bool {
    value.len() == 20
        && value.ends_with('Z')
        && value.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7) && byte == b'-'
                || index == 10 && byte == b'T'
                || matches!(index, 13 | 16) && byte == b':'
                || index == 19 && byte == b'Z'
                || !matches!(index, 4 | 7 | 10 | 13 | 16 | 19) && byte.is_ascii_digit()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn valid_report(root: &Path) -> Value {
        let revision = git_output(root, &["rev-parse", "HEAD"]).expect("revision");
        let tree = git_output(root, &["rev-parse", "HEAD^{tree}"]).expect("tree");
        let performance = ["rust", "go", "native"].map(|implementation| {
            serde_json::json!({
                "implementation":implementation,"workload":"write-full-baseline-v1",
                "payload_bytes":4096,"concurrency":1,"operations":128,
                "elapsed_seconds":1.0,"operations_per_second":128.0,
                "latency_p50_microseconds":10.0,"latency_p95_microseconds":20.0,
                "latency_p99_microseconds":30.0,"cpu_user_seconds":0.1,
                "cpu_system_seconds":0.01,
                "allocation_metric":{"name":"allocated_objects","value":1},
                "retained_bytes":4096,"peak_rss_bytes":8192
            })
        });
        serde_json::json!({
            "schema_version":1,"suite_id":SUITE_ID,"status":"passed",
            "started_at":"2026-09-18T00:00:00Z","finished_at":"2026-09-18T00:01:00Z",
            "schema_sha256":file_digest(&root.join("integration/r08/report.schema.json")).expect("schema"),
            "rust":{"revision":revision,"tree":tree,"source_sha256":rust_source_digest(root).expect("source"),"compiler_image":COMPILER_IMAGE,"platform":"linux/arm64","binary_sha256":"a".repeat(64)},
            "go":{"revision":GO_REVISION,"tree":GO_TREE,"compiler":"go1.26.8","platform":"linux/arm64","binary_sha256":"b".repeat(64)},
            "native":{"version":NATIVE_VERSION,"binary_sha256":"c".repeat(64)},
            "server":{"source_anchor_commit":SERVER_COMMIT,"version":SERVER_VERSION,"image":SERVER_IMAGE,"binary_sha256":"d".repeat(64)},
            "scenarios":{"create":"passed","write":"passed","write_full":"passed","append":"passed","truncate":"passed","zero":"passed","remove":"passed","cross_client_crud":"passed","append_once_failover_lost_reply":"passed","ack_vs_commit":"passed","flush_watermark":"passed","cancellation_drop_boundaries":"passed","performance_baseline":"passed"},
            "performance":performance
        })
    }

    fn rejects(root: &Path, report: &Value) {
        assert!(verify_report_bytes(root, &serde_json::to_vec(report).expect("encode")).is_err());
    }

    #[test]
    fn accepts_complete_source_bound_report() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        verify_report_bytes(
            &root,
            &serde_json::to_vec(&valid_report(&root)).expect("encode"),
        )
        .expect("valid report");
    }

    #[test]
    fn rejects_unknown_field_and_failed_scenario() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut unknown = valid_report(&root);
        unknown["unexpected"] = Value::Bool(true);
        rejects(&root, &unknown);
        let mut failed = valid_report(&root);
        failed["scenarios"]["flush_watermark"] = Value::String("failed".to_owned());
        rejects(&root, &failed);
    }

    #[test]
    fn rejects_source_and_pin_tampering() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut source = valid_report(&root);
        source["rust"]["source_sha256"] = Value::String("0".repeat(64));
        rejects(&root, &source);
        let mut go = valid_report(&root);
        go["go"]["tree"] = Value::String("0".repeat(40));
        rejects(&root, &go);
    }

    #[test]
    fn rejects_incomplete_or_implausible_performance() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut incomplete = valid_report(&root);
        incomplete["performance"]
            .as_array_mut()
            .expect("array")
            .pop();
        rejects(&root, &incomplete);
        let mut implausible = valid_report(&root);
        implausible["performance"][0]["latency_p95_microseconds"] = Value::from(1.0);
        rejects(&root, &implausible);
        let mut allocation = valid_report(&root);
        allocation["performance"][0]["allocation_metric"]["value"] = Value::from(0);
        rejects(&root, &allocation);
    }

    #[test]
    fn rejects_inconsistent_throughput_arithmetic() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut report = valid_report(&root);
        report["performance"][0]["operations_per_second"] = Value::from(64.0);
        rejects(&root, &report);
    }
}
