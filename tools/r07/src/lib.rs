#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_REPORT_BYTES: u64 = 65_536;
const SUITE_ID: &str = "r07/read-only-live-v1";
const COMPILER_IMAGE: &str =
    "rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922";
const SERVER_COMMIT: &str = "7f793731f1b39eb4f465e960113d2363c311b964";
const SERVER_VERSION: &str =
    "ceph version 20.2.4 (7f793731f1b39eb4f465e960113d2363c311b964) tentacle (stable)";
const SERVER_IMAGE: &str =
    "quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa";
const FSID: &str = "11111111-2222-4333-8444-666666666666";
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
    controller_sha256: String,
    fixture_sha256: String,
    rust: RustEvidence,
    go: GoEvidence,
    server: ServerEvidence,
    cluster: ClusterEvidence,
    scenarios: Scenarios,
    probe: Probe,
    go_probe: Probe,
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
    features: Vec<String>,
    build_command: String,
    build_exit_code: i32,
    probe_exit_code: i32,
    stdout_sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GoEvidence {
    revision: String,
    tree: String,
    compiler: String,
    platform: String,
    binary_sha256: String,
    adapter_sha256: String,
    build_command: String,
    build_exit_code: i32,
    probe_exit_code: i32,
    stdout_sha256: String,
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
struct ClusterEvidence {
    fsid: String,
    osds: u32,
    pool: String,
    replicas: u8,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Scenarios {
    native_contents: String,
    go_differential: String,
    ranged_read: String,
    full_read: String,
    empty_read: String,
    namespace_read: String,
    locator_read: String,
    stat_metadata: String,
    missing_object: String,
    operation_version: String,
    primary_change: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct Probe {
    ranged_read: bool,
    full_read: bool,
    empty_read: bool,
    namespace_read: bool,
    locator_read: bool,
    stat: bool,
    missing: bool,
    primary_change: bool,
    stat_size: u64,
    stat_mtime_seconds: i64,
    stat_mtime_nanosecond: u32,
    version: u64,
}

/// Verifies a stored R07 report against its schema and the current Rust source.
///
/// # Errors
/// Returns an error when the report is malformed, stale, or has invalid provenance.
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

/// Verifies a report and the exact Rust and Go executables used by a live run.
///
/// # Errors
/// Returns an error when report, executable, or frozen-Go provenance is invalid.
pub fn verify_report_artifacts(
    root: &Path,
    report_path: &Path,
    rust_binary: &Path,
    go_root: &Path,
    go_binary: &Path,
) -> Result<(), String> {
    let data = fs::read(report_path).map_err(|error| format!("read report: {error}"))?;
    verify_report_bytes(root, &data)?;
    let report: Report =
        serde_json::from_slice(&data).map_err(|error| format!("decode report: {error}"))?;
    if report.rust.binary_sha256 != file_digest(rust_binary)?
        || report.go.binary_sha256 != file_digest(go_binary)?
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

fn verify_report_bytes(root: &Path, data: &[u8]) -> Result<(), String> {
    let report: Report =
        serde_json::from_slice(data).map_err(|error| format!("decode report: {error}"))?;
    verify_shape(&report)?;
    verify_git_identity(root, &report.rust)?;
    let source_digest = rust_source_digest(root)?;
    if report.rust.source_sha256 != source_digest {
        return Err("Rust source digest does not match checkout".to_owned());
    }
    if report.go.adapter_sha256 != file_digest(&root.join("tools/r07/go-probe/main.go"))? {
        return Err("Go adapter digest does not match checkout".to_owned());
    }
    if report.controller_sha256 != file_digest(&root.join("integration/r07/reproduce.sh"))?
        || report.fixture_sha256 != hex_digest(&(0_u8..=255).cycle().take(4096).collect::<Vec<_>>())
    {
        return Err("controller or fixture digest does not match".to_owned());
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
        || !is_hex(&report.rust.revision, 40)
        || !is_hex(&report.rust.tree, 40)
        || !is_hex(&report.rust.source_sha256, 64)
        || !is_hex(&report.rust.binary_sha256, 64)
        || !report.rust.features.is_empty()
        || report.rust.build_command
            != "cargo build --locked --release -p rados-r07-tools --bin rados-r07-live"
        || report.rust.build_exit_code != 0
        || report.rust.probe_exit_code != 0
        || !is_hex(&report.rust.stdout_sha256, 64)
    {
        return Err("Rust provenance is invalid".to_owned());
    }
    if report.server.source_anchor_commit != SERVER_COMMIT
        || report.server.version != SERVER_VERSION
        || report.server.image != SERVER_IMAGE
        || !is_hex(&report.server.binary_sha256, 64)
    {
        return Err("server provenance is invalid".to_owned());
    }
    if report.go.revision != GO_REVISION
        || report.go.tree != GO_TREE
        || report.go.compiler != "go1.26.8"
        || report.go.platform != report.rust.platform
        || !is_hex(&report.go.binary_sha256, 64)
        || !is_hex(&report.go.adapter_sha256, 64)
        || report.go.build_command != "go build -trimpath ./integration/r07/probe"
        || report.go.build_exit_code != 0
        || report.go.probe_exit_code != 0
        || !is_hex(&report.go.stdout_sha256, 64)
    {
        return Err("Go provenance is invalid".to_owned());
    }
    if report.cluster.fsid != FSID
        || report.cluster.osds != 3
        || report.cluster.pool != "p06-data"
        || report.cluster.replicas != 2
    {
        return Err("cluster topology is invalid".to_owned());
    }
    let scenarios = [
        &report.scenarios.native_contents,
        &report.scenarios.go_differential,
        &report.scenarios.ranged_read,
        &report.scenarios.full_read,
        &report.scenarios.empty_read,
        &report.scenarios.namespace_read,
        &report.scenarios.locator_read,
        &report.scenarios.stat_metadata,
        &report.scenarios.missing_object,
        &report.scenarios.operation_version,
        &report.scenarios.primary_change,
    ];
    if scenarios.iter().any(|status| status.as_str() != "passed")
        || !report.probe.ranged_read
        || !report.probe.full_read
        || !report.probe.empty_read
        || !report.probe.namespace_read
        || !report.probe.locator_read
        || !report.probe.stat
        || !report.probe.missing
        || !report.probe.primary_change
        || report.probe.stat_size != 4096
        || report.probe.stat_mtime_seconds <= 0
        || report.probe.stat_mtime_nanosecond >= 1_000_000_000
        || report.probe.version == 0
        || report.probe.ranged_read != report.go_probe.ranged_read
        || report.probe.full_read != report.go_probe.full_read
        || report.probe.empty_read != report.go_probe.empty_read
        || report.probe.namespace_read != report.go_probe.namespace_read
        || report.probe.locator_read != report.go_probe.locator_read
        || report.probe.stat != report.go_probe.stat
        || report.probe.missing != report.go_probe.missing
        || report.probe.primary_change != report.go_probe.primary_change
        || report.probe.stat_size != report.go_probe.stat_size
        || report.probe.stat_mtime_seconds != report.go_probe.stat_mtime_seconds
        || report.probe.stat_mtime_nanosecond != report.go_probe.stat_mtime_nanosecond
        || report.probe.version != report.go_probe.version
    {
        return Err("scenario evidence is incomplete".to_owned());
    }
    verify_probe_output(&report.probe, &report.rust.stdout_sha256)?;
    verify_probe_output(&report.go_probe, &report.go.stdout_sha256)?;
    Ok(())
}

fn verify_probe_output(probe: &Probe, expected_digest: &str) -> Result<(), String> {
    let mut output = serde_json::to_vec(probe).map_err(|error| error.to_string())?;
    output.push(b'\n');
    if expected_digest != hex_digest(&output) {
        return Err("probe output digest does not match result".to_owned());
    }
    Ok(())
}

fn verify_git_identity(root: &Path, evidence: &RustEvidence) -> Result<(), String> {
    let ancestor = Command::new("git")
        .args(["merge-base", "--is-ancestor", &evidence.revision, "HEAD"])
        .current_dir(root)
        .status()
        .map_err(|error| format!("run git merge-base: {error}"))?;
    if !ancestor.success() {
        return Err("reported revision is not an ancestor of HEAD".to_owned());
    }
    let tree = git_output(
        root,
        &["rev-parse", &format!("{}^{{tree}}", evidence.revision)],
    )?;
    if tree != evidence.tree {
        return Err("reported revision tree does not match".to_owned());
    }
    Ok(())
}

/// Hashes the complete Rust source, build, and R07 evidence-controller closure.
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
            "tools/r07/**",
            "integration/r07/**",
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
        if path.contains('\n') || Path::new(path).is_absolute() {
            return Err("invalid Rust source path".to_owned());
        }
        let bytes = fs::read(root.join(path)).map_err(|error| format!("read {path}: {error}"))?;
        let digest = hex_digest(&bytes);
        aggregate.update(format!("{digest}  {path}\n").as_bytes());
    }
    Ok(lower_hex(&aggregate.finalize()))
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
        .map_err(|error| format!("run git: {error}"))?;
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
        write!(result, "{byte:02x}").expect("writing to String cannot fail");
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
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value.as_bytes()[10] == b'T'
        && value.as_bytes()[13] == b':'
        && value.as_bytes()[16] == b':'
        && value.ends_with('Z')
        && value.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn valid_report(root: &Path) -> Value {
        let revision = git_output(root, &["rev-parse", "HEAD"]).expect("revision");
        let tree = git_output(root, &["rev-parse", "HEAD^{tree}"]).expect("tree");
        let mut report = serde_json::json!({
            "schema_version": 1, "suite_id": SUITE_ID, "status": "passed",
            "started_at": "2026-09-18T00:00:00Z", "finished_at": "2026-09-18T00:01:00Z",
            "controller_sha256": file_digest(&root.join("integration/r07/reproduce.sh")).expect("controller digest"),
            "fixture_sha256": hex_digest(&(0_u8..=255).cycle().take(4096).collect::<Vec<_>>()),
            "rust": {"revision": revision, "tree": tree, "source_sha256": rust_source_digest(root).expect("digest"),
                "compiler_image": COMPILER_IMAGE, "platform": "linux/arm64", "binary_sha256": "0".repeat(64),
                "features":[], "build_command":"cargo build --locked --release -p rados-r07-tools --bin rados-r07-live",
                "build_exit_code":0, "probe_exit_code":0, "stdout_sha256":"0".repeat(64)},
            "go": {"revision": GO_REVISION, "tree": GO_TREE, "compiler": "go1.26.8",
                "platform": "linux/arm64", "binary_sha256": "2".repeat(64),
                "adapter_sha256": file_digest(&root.join("tools/r07/go-probe/main.go")).expect("adapter digest"),
                "build_command":"go build -trimpath ./integration/r07/probe", "build_exit_code":0,
                "probe_exit_code":0, "stdout_sha256":"0".repeat(64)},
            "server": {"source_anchor_commit": SERVER_COMMIT, "version": SERVER_VERSION,
                "image": SERVER_IMAGE, "binary_sha256": "1".repeat(64)},
            "cluster": {"fsid": FSID, "osds": 3, "pool": "p06-data", "replicas": 2},
            "scenarios": {"native_contents":"passed", "go_differential":"passed", "ranged_read":"passed", "full_read":"passed",
                "empty_read":"passed", "namespace_read":"passed", "locator_read":"passed",
                "stat_metadata":"passed", "missing_object":"passed", "operation_version":"passed", "primary_change":"passed"},
            "probe": {"ranged_read":true, "full_read":true, "empty_read":true, "namespace_read":true,
                "locator_read":true, "stat":true, "missing":true, "primary_change":true,
                "stat_size":4096, "stat_mtime_seconds":1, "stat_mtime_nanosecond":2, "version":1},
            "go_probe": {"ranged_read":true, "full_read":true, "empty_read":true, "namespace_read":true,
                "locator_read":true, "stat":true, "missing":true, "primary_change":true,
                "stat_size":4096, "stat_mtime_seconds":1, "stat_mtime_nanosecond":2, "version":1}
        });
        let probe = serde_json::from_value::<Probe>(report["probe"].clone()).expect("probe");
        let mut output = serde_json::to_vec(&probe).expect("output");
        output.push(b'\n');
        let digest = hex_digest(&output);
        report["rust"]["stdout_sha256"] = Value::String(digest.clone());
        report["go"]["stdout_sha256"] = Value::String(digest);
        report
    }

    #[test]
    fn accepts_current_source_and_rejects_tampering() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let report = valid_report(&root);
        let bytes = serde_json::to_vec(&report).expect("encode report");
        verify_report_bytes(&root, &bytes).expect("verify valid report");

        let mut status_tamper = report.clone();
        status_tamper["scenarios"]["locator_read"] = Value::String("failed".to_owned());
        assert!(
            verify_report_bytes(&root, &serde_json::to_vec(&status_tamper).expect("encode"))
                .is_err()
        );

        let mut source_tamper = report;
        source_tamper["rust"]["source_sha256"] = Value::String("f".repeat(64));
        assert!(
            verify_report_bytes(&root, &serde_json::to_vec(&source_tamper).expect("encode"))
                .is_err()
        );
    }
}
