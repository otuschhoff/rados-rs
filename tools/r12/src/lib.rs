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
pub const SUITE_ID: &str = "r12/administration-and-manager-v1";
pub const FUZZ_SUITE_ID: &str = "r12/fuzz-task-validation-v1";
pub const FUZZ_RUSTC: &str = "rustc 1.100.0-nightly (0dfb098f3 2026-08-31)";
pub const FUZZ_CARGO_FUZZ: &str = "cargo-fuzz 0.13.2";
pub const FUZZ_TARGETS: [&str; 3] = ["r12_command", "r12_stats", "r12_inconsistent"];
pub const COMPILER_IMAGE: &str =
    "rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922";
pub const SERVER_COMMIT: &str = "7f793731f1b39eb4f465e960113d2363c311b964";
pub const SERVER_VERSION: &str =
    "ceph version 20.2.4 (7f793731f1b39eb4f465e960113d2363c311b964) tentacle (stable)";
pub const SERVER_IMAGE: &str =
    "quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa";
pub const GO_REVISION: &str = "c8bb148a1379b51ef87256c27f366a05f8da4dc4";
pub const GO_TREE: &str = "c5039b6b50a05b942a902f70dc2fcb090463e8c7";
pub const GO_COMPILER: &str = "go1.26.8";
pub const NATIVE_VERSION_LINUX_AMD64: &str = "librados2-20.2.4-0.el9.x86_64";
pub const NATIVE_VERSION_LINUX_ARM64: &str = "librados2-20.2.4-0.el9.aarch64";
pub const FSID: &str = "22222222-3333-4333-8444-222222222222";
pub const NETWORK: &str = "172.30.113.0/24";
pub const DATA_POOL: &str = "p12-data";
pub const NATIVE_APP_POOL: &str = "p12-native-app";
pub const ADMIN_ENTITY: &str = "client.p12-admin";
pub const IO_ENTITY: &str = "client.p12-io";
pub const COMMAND_PARTIAL_STATUS: &str = "Manager, monitor, OSD, and PG command wire errors preserve the last CommandResult status and output on the returned tuple.";

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
    p11_driver_sha256: String,
    focused_tests: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeEvidence {
    version: String,
    binary_sha256: String,
    admin: NativeAdmin,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct NativeAdmin {
    cluster_stats: bool,
    pool_stats: bool,
    monitor_command: bool,
    manager_command: bool,
    osd_command: bool,
    pg_command: bool,
    pool_create_delete: bool,
    application_metadata: bool,
    session_addresses: bool,
    blocklist: bool,
    inconsistent_pgs: bool,
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
    network: String,
    osds: u32,
    objectstore: String,
    manager_daemons: u32,
    data_pool: PoolEvidence,
    native_app_pool: PoolEvidence,
    admin_client: ClientEvidence,
    io_client: ClientEvidence,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolEvidence {
    name: String,
    size: u32,
    min_size: u32,
    pg_num: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientEvidence {
    entity: String,
    mon_caps: String,
    mgr_caps: String,
    osd_caps: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Probe {
    admin: AdminProbe,
    recovery: RecoveryProbe,
    least_privilege: LeastPrivilegeProbe,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct AdminProbe {
    cluster_stats: bool,
    pool_stats: bool,
    monitor_command: bool,
    manager_command: bool,
    osd_command: bool,
    pg_command: bool,
    pool_create_delete: bool,
    application_enable_list: bool,
    application_metadata_set_get_list_remove: bool,
    session_addresses: Vec<String>,
    blocklist: bool,
    inconsistent_pgs: bool,
    inconsistent_objects: bool,
    command_error_output_preserved: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct RecoveryProbe {
    manager_before_failover: bool,
    manager_after_failover: bool,
    io_after_manager_loss: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeastPrivilegeProbe {
    write_read_without_manager: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenarios {
    administration: String,
    native_conformance: String,
    manager_failover: String,
    manager_loss_io: String,
    least_privilege: String,
    destructive_resource_validation: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Deviations {
    command_partial_status: String,
    destructive_scope: String,
}

/// Verifies a retained R12 live report and its repository-bound provenance.
///
/// # Errors
///
/// Returns an explanation if the report cannot be read or any evidence is invalid.
pub fn verify_report_file(root: &Path, report_path: &Path) -> Result<(), String> {
    let bytes = read_report_bytes(report_path)?;
    let report = parse_and_validate(&bytes)?;
    if report.schema_sha256 != file_digest(&root.join("integration/r12/report.schema.json"))?
        || report.rust.source_sha256 != rust_source_digest(root)?
    {
        return Err("schema or source digest is invalid".into());
    }
    verify_git_identity(root, &report.rust)
}

/// Verifies the shape of a report from raw JSON bytes, without touching git or the filesystem.
///
/// # Errors
///
/// Returns an explanation if the report bytes are invalid, tampered, or oversized.
pub fn verify_report_bytes(bytes: &[u8]) -> Result<(), String> {
    parse_and_validate(bytes).map(drop)
}

fn parse_and_validate(bytes: &[u8]) -> Result<Report, String> {
    if bytes.len() as u64 > MAX_REPORT_BYTES {
        return Err("report exceeds byte limit".into());
    }
    let report: Report = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    verify_report_shape(&report)?;
    Ok(report)
}

fn verify_report_shape(report: &Report) -> Result<(), String> {
    if report.schema_version != 1
        || report.suite_id != SUITE_ID
        || report.status != "passed"
        || !valid_timestamps(&report.started_at, &report.finished_at)
    {
        return Err("report identity or timestamps are invalid".into());
    }
    if report.rust.compiler_image != COMPILER_IMAGE
        || !platform(&report.rust.platform)
        || report.go.revision != GO_REVISION
        || report.go.tree != GO_TREE
        || report.go.compiler != GO_COMPILER
        || report.go.platform != report.rust.platform
        || report.go.focused_tests != "passed"
        || report.server.source_anchor_commit != SERVER_COMMIT
        || report.server.version != SERVER_VERSION
        || report.server.image != SERVER_IMAGE
        || native_version_for(&report.rust.platform)
            .is_none_or(|expected| report.native.version != expected)
    {
        return Err("client, server, or native provenance is invalid".into());
    }
    if !cluster_passed(&report.cluster)
        || !admin_passed(&report.probe.admin)
        || !recovery_passed(&report.probe.recovery)
        || !least_passed(&report.probe.least_privilege)
        || !native_admin_passed(&report.native.admin)
        || !scenarios_passed(&report.scenarios)
        || report.deviations.command_partial_status != COMMAND_PARTIAL_STATUS
        || report.deviations.destructive_scope.is_empty()
    {
        return Err("scenario, probe, or deviation evidence is incomplete".into());
    }
    for digest in [
        &report.schema_sha256,
        &report.rust.source_sha256,
        &report.rust.binary_sha256,
        &report.go.p11_driver_sha256,
        &report.native.binary_sha256,
        &report.server.binary_sha256,
    ] {
        if !is_hex(digest, 64) {
            return Err("invalid digest".into());
        }
    }
    if !is_hex(&report.rust.revision, 40) || !is_hex(&report.rust.tree, 40) {
        return Err("invalid Rust identity".into());
    }
    Ok(())
}

/// Verifies a live report plus every local binary and frozen source artifact.
///
/// # Errors
///
/// Returns an explanation if any artifact hash or the frozen driver transformation differs.
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
    let bytes = read_report_bytes(report_path)?;
    let report = parse_and_validate(&bytes)?;
    if report.rust.binary_sha256 != file_digest(rust_binary)?
        || report.go.p11_driver_sha256 != file_digest(native_driver)?
        || report.native.binary_sha256 != file_digest(native_binary)?
        || report.server.binary_sha256 != file_digest(server_binary)?
    {
        return Err("reported artifact digest does not match".into());
    }
    if git_output(go_root, &["rev-parse", "HEAD"])? != GO_REVISION
        || git_output(go_root, &["rev-parse", "HEAD^{tree}"])? != GO_TREE
        || !git_output(
            go_root,
            &["status", "--porcelain=v1", "--untracked-files=all"],
        )?
        .is_empty()
    {
        return Err("Go oracle is not clean and pinned".into());
    }
    let source = fs::read_to_string(go_root.join("integration/p11/native_driver.c"))
        .map_err(|error| error.to_string())?;
    let expected = source
        .replace("p11", "p12")
        .replace("go-", "rust-")
        .replace("go_", "rust_")
        .replace("Go ", "Rust ");
    if fs::read(native_driver).map_err(|error| error.to_string())? != expected.as_bytes() {
        return Err("native driver is not the canonical frozen-Go transformation".into());
    }
    Ok(())
}

/// Computes the digest of the complete R12 Rust source and qualification closure.
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
            "tools/r12/**",
            "integration/r12/**",
            "fuzz/fuzz_targets/r12_*",
            "Cargo.toml",
            "Cargo.lock",
            "build.rs",
            "rust-toolchain.toml",
        ])
        .current_dir(root)
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("git ls-files failed".into());
    }
    let listing =
        String::from_utf8(output.stdout).map_err(|_| "source path is not UTF-8".to_owned())?;
    let mut paths = listing.lines().collect::<Vec<_>>();
    paths.sort_unstable();
    paths.dedup();
    if paths.is_empty() {
        return Err("Rust source set is empty".into());
    }
    let mut aggregate = Sha256::new();
    for path in paths {
        aggregate.update(format!("{}  {path}\n", file_digest(&root.join(path))?).as_bytes());
    }
    Ok(lower_hex(&aggregate.finalize()))
}

fn read_report_bytes(path: &Path) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    fs::File::open(path)
        .map_err(|error| error.to_string())?
        .take(MAX_REPORT_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|error| error.to_string())?;
    if data.len() as u64 > MAX_REPORT_BYTES {
        return Err("report exceeds byte limit".into());
    }
    Ok(data)
}

fn cluster_passed(value: &ClusterEvidence) -> bool {
    let data = |pool: &PoolEvidence, name: &str| {
        pool.name == name && pool.size == 1 && pool.min_size == 1 && pool.pg_num == 8
    };
    value.fsid == FSID
        && value.network == NETWORK
        && value.osds == 1
        && value.objectstore == "bluestore"
        && value.manager_daemons == 2
        && data(&value.data_pool, DATA_POOL)
        && data(&value.native_app_pool, NATIVE_APP_POOL)
        && value.admin_client.entity == ADMIN_ENTITY
        && !value.admin_client.mon_caps.is_empty()
        && !value.admin_client.mgr_caps.is_empty()
        && !value.admin_client.osd_caps.is_empty()
        && value.io_client.entity == IO_ENTITY
        && !value.io_client.mon_caps.is_empty()
        && value.io_client.mgr_caps.is_empty()
        && !value.io_client.osd_caps.is_empty()
}

fn admin_passed(value: &AdminProbe) -> bool {
    value.cluster_stats
        && value.pool_stats
        && value.monitor_command
        && value.manager_command
        && value.osd_command
        && value.pg_command
        && value.pool_create_delete
        && value.application_enable_list
        && value.application_metadata_set_get_list_remove
        && !value.session_addresses.is_empty()
        && value
            .session_addresses
            .iter()
            .all(|address| valid_session_address(address))
        && value.blocklist
        && value.inconsistent_pgs
        && value.inconsistent_objects
        && value.command_error_output_preserved
}

fn recovery_passed(value: &RecoveryProbe) -> bool {
    value.manager_before_failover && value.manager_after_failover && value.io_after_manager_loss
}

fn least_passed(value: &LeastPrivilegeProbe) -> bool {
    value.write_read_without_manager
}

fn native_admin_passed(value: &NativeAdmin) -> bool {
    value.cluster_stats
        && value.pool_stats
        && value.monitor_command
        && value.manager_command
        && value.osd_command
        && value.pg_command
        && value.pool_create_delete
        && value.application_metadata
        && value.session_addresses
        && value.blocklist
        && value.inconsistent_pgs
}

fn scenarios_passed(value: &Scenarios) -> bool {
    [
        &value.administration,
        &value.native_conformance,
        &value.manager_failover,
        &value.manager_loss_io,
        &value.least_privilege,
        &value.destructive_resource_validation,
    ]
    .iter()
    .all(|status| status.as_str() == "passed")
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
        return Err("reported Rust revision identity is invalid".into());
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
        return Err("git command failed".into());
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| "git output is not UTF-8".into())
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

fn platform(value: &str) -> bool {
    matches!(value, "linux/amd64" | "linux/arm64")
}

fn native_version_for(platform: &str) -> Option<&'static str> {
    match platform {
        "linux/amd64" => Some(NATIVE_VERSION_LINUX_AMD64),
        "linux/arm64" => Some(NATIVE_VERSION_LINUX_ARM64),
        _ => None,
    }
}

fn valid_session_address(value: &str) -> bool {
    let Some(rest) = value
        .strip_prefix("v2:")
        .or_else(|| value.strip_prefix("v1:"))
    else {
        return false;
    };
    let Some((address, nonce)) = rest.rsplit_once('/') else {
        return false;
    };
    !address.is_empty() && !nonce.is_empty() && nonce.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_timestamps(start: &str, finish: &str) -> bool {
    valid_timestamp(start) && valid_timestamp(finish) && start <= finish
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

/// Verifies a retained R12 fuzz report against its repository-bound provenance and logs.
///
/// # Errors
///
/// Returns an explanation if the report cannot be read or any campaign evidence is invalid.
pub fn verify_fuzz_report_file(root: &Path, report_path: &Path) -> Result<(), String> {
    let bytes = read_report_bytes(report_path)?;
    let report: FuzzReport = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    verify_fuzz_report_shape(&report)?;
    if report.source_sha256 != rust_source_digest(root)? {
        return Err("fuzz source digest is invalid".into());
    }
    let directory = report_path.parent().ok_or("fuzz report has no parent")?;
    let mut observed = BTreeSet::new();
    for campaign in &report.campaigns {
        if !FUZZ_TARGETS.contains(&campaign.target.as_str()) {
            return Err("unexpected fuzz target".into());
        }
        let output_path = format!("fuzz-validation-logs/{}.log", campaign.target);
        if !observed.insert(campaign.target.clone())
            || campaign.status != "passed"
            || campaign.budget_seconds < 60
            || campaign.executions == 0
            || campaign.executions_per_second == 0
            || !is_hex(&campaign.corpus_sha256, 64)
            || campaign.output_path != output_path
            || campaign.target_sha256
                != file_digest(&root.join(format!("fuzz/fuzz_targets/{}.rs", campaign.target)))?
            || campaign.output_sha256 != file_digest(&directory.join(output_path))?
        {
            return Err("fuzz campaign evidence is invalid".into());
        }
    }
    if observed.len() != FUZZ_TARGETS.len() {
        return Err("fuzz campaign matrix is incomplete".into());
    }
    Ok(())
}

/// Verifies the shape of a fuzz report from raw JSON bytes without touching git or the filesystem.
///
/// # Errors
///
/// Returns an explanation if the bytes are invalid, tampered, or oversized.
pub fn verify_fuzz_report_bytes(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() as u64 > MAX_REPORT_BYTES {
        return Err("fuzz report exceeds byte limit".into());
    }
    let report: FuzzReport = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    verify_fuzz_report_shape(&report)
}

fn verify_fuzz_report_shape(report: &FuzzReport) -> Result<(), String> {
    if report.schema_version != 1
        || report.suite_id != FUZZ_SUITE_ID
        || report.status != "passed"
        || report.rustc != FUZZ_RUSTC
        || report.cargo_fuzz != FUZZ_CARGO_FUZZ
        || !valid_timestamps(&report.started_at, &report.finished_at)
        || !is_hex(&report.source_sha256, 64)
    {
        return Err("fuzz report identity, provenance, or timestamps are invalid".into());
    }
    let mut observed = BTreeSet::new();
    for campaign in &report.campaigns {
        if !FUZZ_TARGETS.contains(&campaign.target.as_str())
            || !observed.insert(campaign.target.as_str())
            || campaign.status != "passed"
            || campaign.budget_seconds < 60
            || campaign.executions == 0
            || campaign.executions_per_second == 0
            || !is_hex(&campaign.corpus_sha256, 64)
            || !is_hex(&campaign.target_sha256, 64)
            || !is_hex(&campaign.output_sha256, 64)
            || campaign.output_path != format!("fuzz-validation-logs/{}.log", campaign.target)
        {
            return Err("fuzz campaign evidence is invalid".into());
        }
    }
    if observed.len() != FUZZ_TARGETS.len() {
        return Err("fuzz campaign matrix is incomplete".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn valid_report_value() -> Value {
        json!({
            "schema_version": 1,
            "suite_id": SUITE_ID,
            "status": "passed",
            "started_at": "2026-09-20T00:00:00Z",
            "finished_at": "2026-09-20T00:10:00Z",
            "schema_sha256": "a".repeat(64),
            "rust": {
                "revision": "1".repeat(40),
                "tree": "2".repeat(40),
                "source_sha256": "b".repeat(64),
                "compiler_image": COMPILER_IMAGE,
                "platform": "linux/amd64",
                "binary_sha256": "c".repeat(64),
            },
            "go": {
                "revision": GO_REVISION,
                "tree": GO_TREE,
                "compiler": GO_COMPILER,
                "platform": "linux/amd64",
                "p11_driver_sha256": "d".repeat(64),
                "focused_tests": "passed",
            },
            "native": {
                "version": NATIVE_VERSION_LINUX_AMD64,
                "binary_sha256": "e".repeat(64),
                "admin": {
                    "cluster_stats": true, "pool_stats": true, "monitor_command": true,
                    "manager_command": true, "osd_command": true, "pg_command": true,
                    "pool_create_delete": true, "application_metadata": true,
                    "session_addresses": true, "blocklist": true, "inconsistent_pgs": true,
                },
            },
            "server": {
                "source_anchor_commit": SERVER_COMMIT,
                "version": SERVER_VERSION,
                "image": SERVER_IMAGE,
                "binary_sha256": "f".repeat(64),
            },
            "cluster": {
                "fsid": FSID,
                "network": NETWORK,
                "osds": 1,
                "objectstore": "bluestore",
                "manager_daemons": 2,
                "data_pool": {"name": DATA_POOL, "size": 1, "min_size": 1, "pg_num": 8},
                "native_app_pool": {"name": NATIVE_APP_POOL, "size": 1, "min_size": 1, "pg_num": 8},
                "admin_client": {
                    "entity": ADMIN_ENTITY, "mon_caps": "allow *", "mgr_caps": "allow *",
                    "osd_caps": "allow *",
                },
                "io_client": {
                    "entity": IO_ENTITY, "mon_caps": "allow r", "mgr_caps": "",
                    "osd_caps": "allow rw pool=p12-data",
                },
            },
            "probe": {
                "admin": {
                    "cluster_stats": true, "pool_stats": true, "monitor_command": true,
                    "manager_command": true, "osd_command": true, "pg_command": true,
                    "pool_create_delete": true, "application_enable_list": true,
                    "application_metadata_set_get_list_remove": true,
                    "session_addresses": ["v2:172.30.113.10:3300/0"],
                    "blocklist": true, "inconsistent_pgs": true, "inconsistent_objects": true,
                    "command_error_output_preserved": true,
                },
                "recovery": {
                    "manager_before_failover": true, "manager_after_failover": true,
                    "io_after_manager_loss": true,
                },
                "least_privilege": {"write_read_without_manager": true},
            },
            "scenarios": {
                "administration": "passed", "native_conformance": "passed",
                "manager_failover": "passed", "manager_loss_io": "passed",
                "least_privilege": "passed", "destructive_resource_validation": "passed",
            },
            "deviations": {
                "command_partial_status": COMMAND_PARTIAL_STATUS,
                "destructive_scope": "Pool create, delete, blocklist, and application metadata operations run only against disposable p12 resources.",
            },
        })
    }

    fn encode(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).expect("valid JSON")
    }

    #[test]
    fn valid_report_passes_shape_verification() {
        let bytes = encode(&valid_report_value());
        verify_report_bytes(&bytes).expect("baseline shape must pass");
    }

    #[test]
    fn rejects_wrong_suite_id() {
        let mut value = valid_report_value();
        value["suite_id"] = json!("r11/snapshots-specialized-ec-v1");
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_non_passed_status() {
        let mut value = valid_report_value();
        value["status"] = json!("failed");
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_wrong_schema_version() {
        let mut value = valid_report_value();
        value["schema_version"] = json!(2);
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_reordered_timestamps() {
        let mut value = valid_report_value();
        value["started_at"] = json!("2026-09-20T00:10:00Z");
        value["finished_at"] = json!("2026-09-20T00:00:00Z");
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_malformed_timestamp() {
        let mut value = valid_report_value();
        value["started_at"] = json!("2026-09-20 00:00:00");
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_unknown_platform() {
        let mut value = valid_report_value();
        value["rust"]["platform"] = json!("linux/riscv64");
        value["go"]["platform"] = json!("linux/riscv64");
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_platform_mismatch_between_rust_and_go() {
        let mut value = valid_report_value();
        value["go"]["platform"] = json!("linux/arm64");
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_tampered_compiler_image() {
        let mut value = valid_report_value();
        value["rust"]["compiler_image"] = json!("rust:1.99.0-bookworm");
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_wrong_go_revision() {
        let mut value = valid_report_value();
        value["go"]["revision"] = json!("0".repeat(40));
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_wrong_server_commit() {
        let mut value = valid_report_value();
        value["server"]["source_anchor_commit"] = json!("0".repeat(40));
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_wrong_server_image() {
        let mut value = valid_report_value();
        value["server"]["image"] = json!("quay.io/ceph/ceph:latest");
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_mismatched_native_version_for_platform() {
        let mut value = valid_report_value();
        value["native"]["version"] = json!(NATIVE_VERSION_LINUX_ARM64);
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_wrong_fsid() {
        let mut value = valid_report_value();
        value["cluster"]["fsid"] = json!("21111111-2222-4333-8444-111111111111");
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_wrong_network() {
        let mut value = valid_report_value();
        value["cluster"]["network"] = json!("172.30.111.0/24");
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_single_manager_daemon() {
        let mut value = valid_report_value();
        value["cluster"]["manager_daemons"] = json!(1);
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_missing_admin_caps() {
        let mut value = valid_report_value();
        value["cluster"]["admin_client"]["mgr_caps"] = json!("");
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_io_client_with_manager_cap() {
        let mut value = valid_report_value();
        value["cluster"]["io_client"]["mgr_caps"] = json!("allow r");
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_admin_probe_false_flag() {
        for flag in [
            "cluster_stats",
            "pool_stats",
            "monitor_command",
            "manager_command",
            "osd_command",
            "pg_command",
            "pool_create_delete",
            "application_enable_list",
            "application_metadata_set_get_list_remove",
            "blocklist",
            "inconsistent_pgs",
            "inconsistent_objects",
            "command_error_output_preserved",
        ] {
            let mut value = valid_report_value();
            value["probe"]["admin"][flag] = json!(false);
            assert!(
                verify_report_bytes(&encode(&value)).is_err(),
                "flipped admin.{flag} was accepted"
            );
        }
    }

    #[test]
    fn rejects_empty_session_addresses() {
        let mut value = valid_report_value();
        value["probe"]["admin"]["session_addresses"] = json!([]);
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_malformed_session_address() {
        let mut value = valid_report_value();
        value["probe"]["admin"]["session_addresses"] = json!(["v3:172.30.113.10:3300/0"]);
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_recovery_regression() {
        for flag in [
            "manager_before_failover",
            "manager_after_failover",
            "io_after_manager_loss",
        ] {
            let mut value = valid_report_value();
            value["probe"]["recovery"][flag] = json!(false);
            assert!(
                verify_report_bytes(&encode(&value)).is_err(),
                "flipped recovery.{flag} was accepted"
            );
        }
    }

    #[test]
    fn rejects_least_privilege_regression() {
        let mut value = valid_report_value();
        value["probe"]["least_privilege"]["write_read_without_manager"] = json!(false);
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_native_admin_regression() {
        for flag in [
            "cluster_stats",
            "pool_stats",
            "monitor_command",
            "manager_command",
            "osd_command",
            "pg_command",
            "pool_create_delete",
            "application_metadata",
            "session_addresses",
            "blocklist",
            "inconsistent_pgs",
        ] {
            let mut value = valid_report_value();
            value["native"]["admin"][flag] = json!(false);
            assert!(
                verify_report_bytes(&encode(&value)).is_err(),
                "flipped native.admin.{flag} was accepted"
            );
        }
    }

    #[test]
    fn rejects_scenario_not_passed() {
        for scenario in [
            "administration",
            "native_conformance",
            "manager_failover",
            "manager_loss_io",
            "least_privilege",
            "destructive_resource_validation",
        ] {
            let mut value = valid_report_value();
            value["scenarios"][scenario] = json!("skipped");
            assert!(
                verify_report_bytes(&encode(&value)).is_err(),
                "flipped scenario.{scenario} was accepted"
            );
        }
    }

    #[test]
    fn rejects_missing_command_partial_status_deviation() {
        let mut value = valid_report_value();
        value["deviations"]["command_partial_status"] = json!("");
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_empty_destructive_scope_deviation() {
        let mut value = valid_report_value();
        value["deviations"]["destructive_scope"] = json!("");
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_unknown_field() {
        let mut value = valid_report_value();
        value["extra"] = json!("nope");
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_non_hex_digest() {
        let mut value = valid_report_value();
        value["schema_sha256"] = json!("Z".repeat(64));
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_uppercase_hex_digest() {
        let mut value = valid_report_value();
        value["schema_sha256"] = json!("A".repeat(64));
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_short_git_identity() {
        let mut value = valid_report_value();
        value["rust"]["revision"] = json!("1".repeat(39));
        assert!(verify_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_oversized_report() {
        let padding = " ".repeat(usize::try_from(MAX_REPORT_BYTES).expect("limit fits usize") + 1);
        let bytes = padding.into_bytes();
        assert!(verify_report_bytes(&bytes).is_err());
    }

    #[test]
    fn read_report_bytes_rejects_oversized_file() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("report.json");
        fs::write(
            &path,
            vec![b' '; usize::try_from(MAX_REPORT_BYTES).expect("limit fits usize") + 1],
        )
        .expect("write oversize");
        assert!(read_report_bytes(&path).is_err());
    }

    #[test]
    fn verify_report_file_rejects_missing_file() {
        let directory = tempfile::tempdir().expect("temp dir");
        let missing = directory.path().join("missing.json");
        assert!(verify_report_file(directory.path(), &missing).is_err());
    }

    #[test]
    fn verify_report_file_rejects_tampered_bytes_before_git() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("report.json");
        let mut value = valid_report_value();
        value["status"] = json!("failed");
        fs::write(&path, encode(&value)).expect("write report");
        assert!(verify_report_file(directory.path(), &path).is_err());
    }

    #[test]
    fn accepts_arm64_native_version() {
        let mut value = valid_report_value();
        value["rust"]["platform"] = json!("linux/arm64");
        value["go"]["platform"] = json!("linux/arm64");
        value["native"]["version"] = json!(NATIVE_VERSION_LINUX_ARM64);
        verify_report_bytes(&encode(&value)).expect("arm64 baseline must pass");
    }

    #[test]
    fn accepts_v1_session_address() {
        let mut value = valid_report_value();
        value["probe"]["admin"]["session_addresses"] = json!(["v1:172.30.113.10:6789/0"]);
        verify_report_bytes(&encode(&value)).expect("v1 messenger address is accepted");
    }

    #[test]
    fn valid_session_address_helper() {
        assert!(valid_session_address("v2:172.30.113.10:3300/0"));
        assert!(valid_session_address("v1:10.0.0.1:6789/42"));
        assert!(!valid_session_address("172.30.113.10:3300/0"));
        assert!(!valid_session_address("v2:172.30.113.10:3300"));
        assert!(!valid_session_address("v2:172.30.113.10:3300/"));
        assert!(!valid_session_address("v2:172.30.113.10:3300/abc"));
        assert!(!valid_session_address(""));
    }

    fn valid_fuzz_campaign(target: &str) -> Value {
        json!({
            "target": target,
            "budget_seconds": 60,
            "executions": 12_345,
            "executions_per_second": 200,
            "corpus_sha256": "a".repeat(64),
            "target_sha256": "b".repeat(64),
            "output_path": format!("fuzz-validation-logs/{target}.log"),
            "output_sha256": "c".repeat(64),
            "status": "passed",
        })
    }

    fn valid_fuzz_report_value() -> Value {
        json!({
            "schema_version": 1,
            "suite_id": FUZZ_SUITE_ID,
            "status": "passed",
            "started_at": "2026-09-20T00:00:00Z",
            "finished_at": "2026-09-20T00:10:00Z",
            "source_sha256": "d".repeat(64),
            "rustc": FUZZ_RUSTC,
            "cargo_fuzz": FUZZ_CARGO_FUZZ,
            "campaigns": [
                valid_fuzz_campaign("r12_command"),
                valid_fuzz_campaign("r12_stats"),
                valid_fuzz_campaign("r12_inconsistent"),
            ],
        })
    }

    #[test]
    fn valid_fuzz_report_passes_shape_verification() {
        let bytes = encode(&valid_fuzz_report_value());
        verify_fuzz_report_bytes(&bytes).expect("baseline fuzz shape must pass");
    }

    #[test]
    fn fuzz_rejects_wrong_suite_id() {
        let mut value = valid_fuzz_report_value();
        value["suite_id"] = json!("r11/fuzz-task-validation-v1");
        assert!(verify_fuzz_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn fuzz_rejects_non_passed_status() {
        let mut value = valid_fuzz_report_value();
        value["status"] = json!("failed");
        assert!(verify_fuzz_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn fuzz_rejects_wrong_schema_version() {
        let mut value = valid_fuzz_report_value();
        value["schema_version"] = json!(2);
        assert!(verify_fuzz_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn fuzz_rejects_short_budget() {
        let mut value = valid_fuzz_report_value();
        value["campaigns"][0]["budget_seconds"] = json!(30);
        assert!(verify_fuzz_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn fuzz_rejects_zero_executions() {
        let mut value = valid_fuzz_report_value();
        value["campaigns"][1]["executions"] = json!(0);
        assert!(verify_fuzz_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn fuzz_rejects_unknown_target() {
        let mut value = valid_fuzz_report_value();
        value["campaigns"][2]["target"] = json!("r12_unknown");
        value["campaigns"][2]["output_path"] = json!("fuzz-validation-logs/r12_unknown.log");
        assert!(verify_fuzz_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn fuzz_rejects_duplicate_targets() {
        let mut value = valid_fuzz_report_value();
        value["campaigns"][2] = valid_fuzz_campaign("r12_command");
        assert!(verify_fuzz_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn fuzz_rejects_incomplete_matrix() {
        let mut value = valid_fuzz_report_value();
        value["campaigns"] = json!([valid_fuzz_campaign("r12_command")]);
        assert!(verify_fuzz_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn fuzz_rejects_mismatched_output_path() {
        let mut value = valid_fuzz_report_value();
        value["campaigns"][0]["output_path"] = json!("fuzz-validation-logs/r12_stats.log");
        assert!(verify_fuzz_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn fuzz_rejects_wrong_rustc() {
        let mut value = valid_fuzz_report_value();
        value["rustc"] = json!("rustc 1.99.0-nightly (deadbeef 2020-01-01)");
        assert!(verify_fuzz_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn fuzz_rejects_wrong_cargo_fuzz() {
        let mut value = valid_fuzz_report_value();
        value["cargo_fuzz"] = json!("cargo-fuzz 0.12.0");
        assert!(verify_fuzz_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn fuzz_rejects_reordered_timestamps() {
        let mut value = valid_fuzz_report_value();
        value["started_at"] = json!("2026-09-20T00:10:00Z");
        value["finished_at"] = json!("2026-09-20T00:00:00Z");
        assert!(verify_fuzz_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn fuzz_rejects_non_hex_corpus_digest() {
        let mut value = valid_fuzz_report_value();
        value["campaigns"][0]["corpus_sha256"] = json!("Z".repeat(64));
        assert!(verify_fuzz_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn fuzz_rejects_unknown_field() {
        let mut value = valid_fuzz_report_value();
        value["extra"] = json!("nope");
        assert!(verify_fuzz_report_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn fuzz_rejects_oversized_report() {
        let padding = " ".repeat(usize::try_from(MAX_REPORT_BYTES).expect("limit fits usize") + 1);
        let bytes = padding.into_bytes();
        assert!(verify_fuzz_report_bytes(&bytes).is_err());
    }

    #[test]
    fn verify_fuzz_report_file_rejects_missing_file() {
        let directory = tempfile::tempdir().expect("temp dir");
        let missing = directory.path().join("missing.json");
        assert!(verify_fuzz_report_file(directory.path(), &missing).is_err());
    }

    #[test]
    fn verify_fuzz_report_file_rejects_tampered_bytes_before_git() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("report.json");
        let mut value = valid_fuzz_report_value();
        value["status"] = json!("failed");
        fs::write(&path, encode(&value)).expect("write report");
        assert!(verify_fuzz_report_file(directory.path(), &path).is_err());
    }
}
