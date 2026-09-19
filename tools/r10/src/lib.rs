#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::Command;

use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const MAX_REPORT_BYTES: u64 = 262_144;
const SUITE_ID: &str = "r10/classes-locks-watches-v1";
const COMPILER_IMAGE: &str =
    "rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922";
const SERVER_COMMIT: &str = "7f793731f1b39eb4f465e960113d2363c311b964";
const SERVER_VERSION: &str =
    "ceph version 20.2.4 (7f793731f1b39eb4f465e960113d2363c311b964) tentacle (stable)";
const SERVER_IMAGE: &str =
    "quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa";
const GO_REVISION: &str = "c8bb148a1379b51ef87256c27f366a05f8da4dc4";
const GO_TREE: &str = "c5039b6b50a05b942a902f70dc2fcb090463e8c7";

#[derive(Deserialize)]
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
    cluster: ClusterEvidence,
    probe: Probe,
    scenarios: Scenarios,
    deviations: Deviations,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RustEvidence {
    revision: String,
    tree: String,
    source_sha256: String,
    compiler_image: String,
    platform: String,
    binary_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GoEvidence {
    revision: String,
    tree: String,
    compiler: String,
    platform: String,
    p09_driver_sha256: String,
    focused_tests: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeEvidence {
    version: String,
    binary_sha256: String,
    seed: NativeSeed,
    watch: NativeWatch,
    notify: NativeNotify,
    verify: NativeVerify,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools, clippy::struct_field_names)]
struct NativeSeed {
    native_exec: bool,
    native_exec_result: usize,
    native_exec_output: String,
    native_lock_seed: bool,
    native_lock_renew: bool,
    native_lock_release: bool,
    native_lock_expiry: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools, clippy::struct_field_names)]
struct NativeWatch {
    go_notify_native_watch: bool,
    native_watch_remap: bool,
    native_watch_restart: bool,
    native_watch_same_cookie: bool,
    native_watch_exactly_once: bool,
    native_lock_shared: bool,
    native_shared_release: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeNotify {
    native_notify_go_watch: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeVerify {
    go_lock_native_read: bool,
    native_break_go_lock: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerEvidence {
    source_anchor_commit: String,
    version: String,
    image: String,
    binary_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClusterEvidence {
    fsid: String,
    osds: u32,
    pool: String,
    replicas: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct Probe {
    class_execution: bool,
    lock_contention: bool,
    lock_renew: bool,
    lock_break: bool,
    lock_shared: bool,
    lock_expiry: bool,
    watch_ack: bool,
    notify_timeout: bool,
    native_locks: bool,
    native_watch: bool,
    native_notify: bool,
    watch_remap: bool,
    osd_restart: bool,
    explicit_unregister: bool,
    watch_shutdown: bool,
    client_shutdown: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenarios {
    class_execution: String,
    lock_interoperability: String,
    lock_lease_lifecycle: String,
    watch_notify_interoperability: String,
    partial_timeout_results: String,
    remap_reregistration: String,
    osd_restart: String,
    explicit_unregister: String,
    lost_watch_observability: String,
    bounded_shutdown: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Deviations {
    notify_outcome_shape: String,
    notification_dispatch: String,
    ambiguous_coordination_replay: String,
}

#[derive(Deserialize)]
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

#[derive(Deserialize)]
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

/// Verifies a retained R10 live qualification report and its local provenance.
///
/// # Errors
///
/// Returns an explanation if the report cannot be read or any evidence is invalid.
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
    let report: Report = serde_json::from_slice(&data).map_err(|error| error.to_string())?;
    if report.schema_version != 1
        || report.suite_id != SUITE_ID
        || report.status != "passed"
        || !valid_timestamp(&report.started_at)
        || !valid_timestamp(&report.finished_at)
        || report.started_at > report.finished_at
    {
        return Err("report identity or timestamps are invalid".to_owned());
    }
    if report.rust.compiler_image != COMPILER_IMAGE
        || !matches!(report.rust.platform.as_str(), "linux/amd64" | "linux/arm64")
        || report.go.revision != GO_REVISION
        || report.go.tree != GO_TREE
        || report.go.compiler != "go1.26.8"
        || report.go.platform != report.rust.platform
        || report.go.focused_tests != "passed"
        || report.server.source_anchor_commit != SERVER_COMMIT
        || report.server.version != SERVER_VERSION
        || report.server.image != SERVER_IMAGE
        || report.native.version != "librados2-20.2.4-0.el9"
    {
        return Err("client or server provenance is invalid".to_owned());
    }
    if report.cluster.fsid != "11111111-2222-4333-8444-101010101010"
        || report.cluster.osds != 3
        || report.cluster.pool != "p10-data"
        || report.cluster.replicas != 2
    {
        return Err("cluster profile is invalid".to_owned());
    }
    let scenarios = [
        &report.scenarios.class_execution,
        &report.scenarios.lock_interoperability,
        &report.scenarios.lock_lease_lifecycle,
        &report.scenarios.watch_notify_interoperability,
        &report.scenarios.partial_timeout_results,
        &report.scenarios.remap_reregistration,
        &report.scenarios.osd_restart,
        &report.scenarios.explicit_unregister,
        &report.scenarios.lost_watch_observability,
        &report.scenarios.bounded_shutdown,
    ];
    if scenarios.iter().any(|status| status.as_str() != "passed")
        || !probe_passed(&report.probe)
        || !native_passed(&report.native)
        || report.deviations.notify_outcome_shape.is_empty()
        || report.deviations.notification_dispatch.is_empty()
        || report.deviations.ambiguous_coordination_replay.is_empty()
    {
        return Err("scenario evidence is incomplete".to_owned());
    }
    for digest in [
        &report.schema_sha256,
        &report.rust.source_sha256,
        &report.rust.binary_sha256,
        &report.go.p09_driver_sha256,
        &report.native.binary_sha256,
        &report.server.binary_sha256,
    ] {
        if !is_hex(digest, 64) {
            return Err("invalid digest".to_owned());
        }
    }
    if !is_hex(&report.rust.revision, 40)
        || !is_hex(&report.rust.tree, 40)
        || report.schema_sha256 != file_digest(&root.join("integration/r10/report.schema.json"))?
        || report.rust.source_sha256 != rust_source_digest(root)?
    {
        return Err("Rust identity, schema, or source digest is invalid".to_owned());
    }
    verify_git_identity(root, &report.rust)
}

/// Verifies a live report plus every locally reproducible artifact used to create it.
///
/// # Errors
///
/// Returns an explanation if an artifact hash or frozen checkout identity differs.
pub fn verify_report_artifacts(
    root: &Path,
    report_path: &Path,
    rust_binary: &Path,
    go_root: &Path,
    native_driver: &Path,
    native_binary: &Path,
    server_binary: &Path,
) -> Result<(), String> {
    verify_report_file(root, report_path)?;
    let data = fs::read(report_path).map_err(|error| format!("read report: {error}"))?;
    let report: Report = serde_json::from_slice(&data).map_err(|error| error.to_string())?;
    if report.rust.binary_sha256 != file_digest(rust_binary)?
        || report.go.p09_driver_sha256 != file_digest(native_driver)?
        || report.native.binary_sha256 != file_digest(native_binary)?
        || report.server.binary_sha256 != file_digest(server_binary)?
    {
        return Err("reported artifact digest does not match".to_owned());
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
    let source = fs::read_to_string(go_root.join("integration/p09/native_driver.c"))
        .map_err(|error| format!("read native driver source: {error}"))?;
    let expected = source
        .replace("\"go-lock\"", "\"rust-lock\"")
        .replace("\"go-cookie\"", "\"rust-cookie\"")
        .replace("Go lock", "Rust lock");
    if fs::read(native_driver).map_err(|error| format!("read native driver: {error}"))?
        != expected.as_bytes()
    {
        return Err("native driver is not the canonical frozen-Go transformation".to_owned());
    }
    Ok(())
}

/// Verifies a retained R10 fuzz report, source closure, targets, and logs.
///
/// # Errors
///
/// Returns an explanation if the report cannot be read or any evidence is invalid.
pub fn verify_fuzz_report_file(root: &Path, report_path: &Path) -> Result<(), String> {
    let data = fs::read(report_path).map_err(|error| format!("read fuzz report: {error}"))?;
    let report: FuzzReport = serde_json::from_slice(&data).map_err(|error| error.to_string())?;
    if data.len() as u64 > MAX_REPORT_BYTES
        || report.schema_version != 1
        || report.suite_id != "r10/fuzz-task-validation-v1"
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
    let expected = std::collections::BTreeMap::from([
        (
            "r10_class",
            "b4e985bbbcdfde9b1bd1c3a731f469d0b88e9b3019e44402cc4e1efbc9443105",
        ),
        (
            "r10_lock",
            "0cbab3cdc73010fd492d870f346a6ca64b967f5e7847556de0f80668d623e8e9",
        ),
        (
            "r10_watch",
            "3e848a7d59fbd1d73d46042c87f7b9171e3715822003883239684896eadf300e",
        ),
    ]);
    let directory = report_path.parent().ok_or("fuzz report has no parent")?;
    let mut observed = BTreeSet::new();
    for campaign in &report.campaigns {
        let Some(corpus_digest) = expected.get(campaign.target.as_str()) else {
            return Err("unexpected fuzz target".to_owned());
        };
        let output_path = format!("fuzz-validation-logs/{}.log", campaign.target);
        if !observed.insert(campaign.target.as_str())
            || campaign.status != "passed"
            || campaign.budget_seconds < 60
            || campaign.executions == 0
            || campaign.executions_per_second == 0
            || campaign.corpus_sha256 != *corpus_digest
            || campaign.output_path != output_path
            || campaign.target_sha256
                != file_digest(&root.join(format!("fuzz/fuzz_targets/{}.rs", campaign.target)))?
            || campaign.output_sha256 != file_digest(&directory.join(&campaign.output_path))?
        {
            return Err("fuzz campaign evidence is invalid".to_owned());
        }
    }
    if observed != expected.keys().copied().collect() {
        return Err("fuzz campaign matrix is incomplete".to_owned());
    }
    Ok(())
}

fn probe_passed(probe: &Probe) -> bool {
    probe.class_execution
        && probe.lock_contention
        && probe.lock_renew
        && probe.lock_break
        && probe.lock_shared
        && probe.lock_expiry
        && probe.watch_ack
        && probe.notify_timeout
        && probe.native_locks
        && probe.native_watch
        && probe.native_notify
        && probe.watch_remap
        && probe.osd_restart
        && probe.explicit_unregister
        && probe.watch_shutdown
        && probe.client_shutdown
}

fn native_passed(native: &NativeEvidence) -> bool {
    native.seed.native_exec
        && native.seed.native_exec_result > 0
        && !native.seed.native_exec_output.is_empty()
        && native.seed.native_lock_seed
        && native.seed.native_lock_renew
        && native.seed.native_lock_release
        && native.seed.native_lock_expiry
        && native.watch.go_notify_native_watch
        && native.watch.native_watch_remap
        && native.watch.native_watch_restart
        && native.watch.native_watch_same_cookie
        && native.watch.native_watch_exactly_once
        && native.watch.native_lock_shared
        && native.watch.native_shared_release
        && native.notify.native_notify_go_watch
        && native.verify.go_lock_native_read
        && native.verify.native_break_go_lock
}

/// Computes the deterministic digest of the complete R10 Rust source closure.
///
/// # Errors
///
/// Returns an explanation if Git cannot enumerate the source or a file cannot be read.
pub fn rust_source_digest(root: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .args([
            "ls-files",
            "-co",
            "--exclude-standard",
            "--",
            "src/**",
            "tools/r10/**",
            "integration/r10/**",
            "fuzz/fuzz_targets/r10_*",
            "Cargo.toml",
            "Cargo.lock",
            "build.rs",
            "rust-toolchain.toml",
        ])
        .current_dir(root)
        .output()
        .map_err(|error| error.to_string())?;
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
        aggregate.update(format!("{}  {path}\n", file_digest(&root.join(path))?).as_bytes());
    }
    Ok(lower_hex(&aggregate.finalize()))
}

fn verify_git_identity(root: &Path, evidence: &RustEvidence) -> Result<(), String> {
    if !Command::new("git")
        .args(["merge-base", "--is-ancestor", &evidence.revision, "HEAD"])
        .current_dir(root)
        .status()
        .map_err(|error| error.to_string())?
        .success()
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
        .map(|bytes| lower_hex(&Sha256::digest(bytes)))
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
