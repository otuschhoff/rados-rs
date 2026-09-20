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
const SUITE_ID: &str = "r11/snapshots-specialized-ec-v1";
const COMPILER_IMAGE: &str =
    "rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922";
const SERVER_COMMIT: &str = "7f793731f1b39eb4f465e960113d2363c311b964";
const SERVER_VERSION: &str =
    "ceph version 20.2.4 (7f793731f1b39eb4f465e960113d2363c311b964) tentacle (stable)";
const SERVER_IMAGE: &str =
    "quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa";
const GO_REVISION: &str = "c8bb148a1379b51ef87256c27f366a05f8da4dc4";
const GO_TREE: &str = "c5039b6b50a05b942a902f70dc2fcb090463e8c7";
const OMITTED_VARIANTS: [&str; 10] = [
    "rados_set_alloc_hint2",
    "rados_write_op_set_alloc_hint2",
    "IoCtx::list_snaps",
    "IoCtx::mapext",
    "IoCtx::pool_required_alignment",
    "IoCtx::pool_requires_alignment",
    "IoCtx::set_alloc_hint2",
    "ObjectReadOperation::list_snaps",
    "ObjectWriteOperation::set_alloc_hint2",
    "Rados::get_inconsistent_snapsets",
];

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
    p10_driver_sha256: String,
    focused_tests: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeEvidence {
    version: String,
    binary_sha256: String,
    seed: NativeSeed,
    verify: NativeVerify,
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
    objectstore: String,
    named_pool: ReplicatedPool,
    self_managed_pool: ReplicatedPool,
    ec_pool: EcPool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplicatedPool {
    name: String,
    size: u32,
    min_size: u32,
    pg_num: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EcPool {
    name: String,
    size: u32,
    min_size: u32,
    pg_num: u32,
    plugin: String,
    k: u32,
    m: u32,
    failure_domain: String,
    allow_ec_overwrites: bool,
    stripe_unit: u64,
    stripe_width: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct Probe {
    named_create_list_lookup: bool,
    named_read_snapshot: bool,
    named_rollback: bool,
    named_remove: bool,
    self_managed_create: bool,
    self_managed_write_context: bool,
    self_managed_read: bool,
    self_managed_rollback: bool,
    self_managed_remove: bool,
    snapshot_context_validation: bool,
    write_same: bool,
    checksum: bool,
    checksum_hex: String,
    allocation_hint: bool,
    sparse_read: bool,
    copy_from: bool,
    copy_from2: bool,
    replicated_capabilities: bool,
    ec_capabilities: bool,
    ec_write_read: bool,
    ec_overwrite_rejected: bool,
    ec_write_same_rejected: bool,
    ec_checksum: bool,
    ec_allocation_hint: bool,
    ec_sparse_read: bool,
    ec_copy_from: bool,
    ec_omap_rejected: bool,
    ec_alignment_evidence: bool,
    native_seed_read: bool,
    required_alignment: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenarios {
    named_snapshots: String,
    self_managed_snapshots: String,
    snapshot_context_validation: String,
    specialized_io: String,
    erasure_coded_io: String,
    native_interoperability: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Deviations {
    snapshot_views: String,
    uncertain_monitor_mutations: String,
    non_frozen_variants: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeSeed {
    named_create_list_lookup_name_stamp: bool,
    named_read_rollback_remove: bool,
    self_managed_create_write_read_rollback_remove: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools, clippy::struct_field_names)]
struct NativeVerify {
    rust_named_snapshot: bool,
    rust_named_head: bool,
    rust_copy: bool,
    rust_copy_from2: bool,
    rust_ec_copy: bool,
    rust_checksum_hex: String,
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

/// Verifies a retained R11 live report and its repository-bound provenance.
///
/// # Errors
///
/// Returns an explanation if the report cannot be read or any evidence is invalid.
pub fn verify_report_file(root: &Path, report_path: &Path) -> Result<(), String> {
    let report = read_report(report_path)?;
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
        || report.go.compiler != "go1.26.8"
        || report.go.platform != report.rust.platform
        || report.go.focused_tests != "passed"
        || report.server.source_anchor_commit != SERVER_COMMIT
        || report.server.version != SERVER_VERSION
        || report.server.image != SERVER_IMAGE
        || report.native.version != "librados2-20.2.4-0.el9"
    {
        return Err("client or server provenance is invalid".into());
    }
    if !cluster_passed(&report.cluster)
        || !probe_passed(&report.probe)
        || !native_passed(&report.native)
        || !scenarios_passed(&report.scenarios)
        || report.deviations.snapshot_views.is_empty()
        || report.deviations.uncertain_monitor_mutations.is_empty()
        || report.deviations.non_frozen_variants != OMITTED_VARIANTS
    {
        return Err("scenario evidence or deviations are incomplete".into());
    }
    for digest in [
        &report.schema_sha256,
        &report.rust.source_sha256,
        &report.rust.binary_sha256,
        &report.go.p10_driver_sha256,
        &report.native.binary_sha256,
        &report.server.binary_sha256,
    ] {
        if !is_hex(digest, 64) {
            return Err("invalid digest".into());
        }
    }
    if !is_hex(&report.rust.revision, 40)
        || !is_hex(&report.rust.tree, 40)
        || report.schema_sha256 != file_digest(&root.join("integration/r11/report.schema.json"))?
        || report.rust.source_sha256 != rust_source_digest(root)?
    {
        return Err("Rust identity, schema, or source digest is invalid".into());
    }
    verify_git_identity(root, &report.rust)
}

/// Verifies a live report plus every local binary and frozen source artifact.
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
    let report = read_report(report_path)?;
    if report.rust.binary_sha256 != file_digest(rust_binary)?
        || report.go.p10_driver_sha256 != file_digest(native_driver)?
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
    let source = fs::read_to_string(go_root.join("integration/p10/native_driver.c"))
        .map_err(|error| error.to_string())?;
    let expected = source
        .replace("p10", "p11")
        .replace("go-", "rust-")
        .replace("go_", "rust_")
        .replace("Go ", "Rust ");
    if fs::read(native_driver).map_err(|error| error.to_string())? != expected.as_bytes() {
        return Err("native driver is not the canonical frozen-Go transformation".into());
    }
    Ok(())
}

/// Verifies retained R11 fuzz campaigns and their exact logs and targets.
///
/// # Errors
///
/// Returns an explanation if the report cannot be read or any campaign evidence is invalid.
pub fn verify_fuzz_report_file(root: &Path, report_path: &Path) -> Result<(), String> {
    let data = fs::read(report_path).map_err(|error| error.to_string())?;
    if data.len() as u64 > MAX_REPORT_BYTES {
        return Err("fuzz report exceeds byte limit".into());
    }
    let report: FuzzReport = serde_json::from_slice(&data).map_err(|error| error.to_string())?;
    if report.schema_version != 1
        || report.suite_id != "r11/fuzz-task-validation-v1"
        || report.status != "passed"
        || report.rustc != "rustc 1.100.0-nightly (0dfb098f3 2026-08-31)"
        || report.cargo_fuzz != "cargo-fuzz 0.13.2"
        || !valid_timestamps(&report.started_at, &report.finished_at)
        || report.source_sha256 != rust_source_digest(root)?
    {
        return Err("fuzz report identity, provenance, or timestamps are invalid".into());
    }
    let expected = std::collections::BTreeMap::from([
        (
            "r11_snapshot",
            "54fdd7c0058f31207d11ba8a4751fb47e25904cc0f57b135dc54580d4e32c408",
        ),
        (
            "r11_sparse",
            "d29625484e4e9d943950b42dfb726a0399d1351252992761cc389734963d724e",
        ),
        (
            "r11_special",
            "9d3ce88cc7af175852051420d71bd509d2b752783b62c846148d879fb4db0266",
        ),
    ]);
    let directory = report_path.parent().ok_or("fuzz report has no parent")?;
    let mut observed = BTreeSet::new();
    for campaign in &report.campaigns {
        let Some(corpus_digest) = expected.get(campaign.target.as_str()) else {
            return Err("unexpected fuzz target".into());
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
            || campaign.output_sha256 != file_digest(&directory.join(output_path))?
        {
            return Err("fuzz campaign evidence is invalid".into());
        }
    }
    if observed != expected.keys().copied().collect() {
        return Err("fuzz campaign matrix is incomplete".into());
    }
    Ok(())
}

/// Computes the digest of the complete R11 Rust source and qualification closure.
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
            "tools/r11/**",
            "integration/r11/**",
            "fuzz/fuzz_targets/r11_*",
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

fn read_report(path: &Path) -> Result<Report, String> {
    let mut data = Vec::new();
    fs::File::open(path)
        .map_err(|error| error.to_string())?
        .take(MAX_REPORT_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|error| error.to_string())?;
    if data.len() as u64 > MAX_REPORT_BYTES {
        return Err("report exceeds byte limit".into());
    }
    serde_json::from_slice(&data).map_err(|error| error.to_string())
}

fn cluster_passed(value: &ClusterEvidence) -> bool {
    let replicated = |pool: &ReplicatedPool, name| {
        pool.name == name && pool.size == 2 && pool.min_size == 1 && pool.pg_num == 16
    };
    value.fsid == "21111111-2222-4333-8444-111111111111"
        && value.osds == 3
        && value.objectstore == "bluestore"
        && replicated(&value.named_pool, "p11-named")
        && replicated(&value.self_managed_pool, "p11-self")
        && value.ec_pool.name == "p11-ec"
        && value.ec_pool.size == 3
        && value.ec_pool.min_size == 2
        && value.ec_pool.pg_num == 16
        && value.ec_pool.plugin == "jerasure"
        && value.ec_pool.k == 2
        && value.ec_pool.m == 1
        && value.ec_pool.failure_domain == "osd"
        && !value.ec_pool.allow_ec_overwrites
        && value.ec_pool.stripe_unit == 4096
        && value.ec_pool.stripe_width == 8192
}
fn probe_passed(value: &Probe) -> bool {
    value.named_create_list_lookup
        && value.named_read_snapshot
        && value.named_rollback
        && value.named_remove
        && value.self_managed_create
        && value.self_managed_write_context
        && value.self_managed_read
        && value.self_managed_rollback
        && value.self_managed_remove
        && value.snapshot_context_validation
        && value.write_same
        && value.checksum
        && value.checksum_hex == "02000000f5be862af5be862a"
        && value.allocation_hint
        && value.sparse_read
        && value.copy_from
        && value.copy_from2
        && value.replicated_capabilities
        && value.ec_capabilities
        && value.ec_write_read
        && value.ec_overwrite_rejected
        && value.ec_write_same_rejected
        && value.ec_checksum
        && value.ec_allocation_hint
        && value.ec_sparse_read
        && value.ec_copy_from
        && value.ec_omap_rejected
        && value.ec_alignment_evidence
        && value.native_seed_read
        && value.required_alignment == 8192
}
fn native_passed(value: &NativeEvidence) -> bool {
    value.seed.named_create_list_lookup_name_stamp
        && value.seed.named_read_rollback_remove
        && value.seed.self_managed_create_write_read_rollback_remove
        && value.verify.rust_named_snapshot
        && value.verify.rust_named_head
        && value.verify.rust_copy
        && value.verify.rust_copy_from2
        && value.verify.rust_ec_copy
        && value.verify.rust_checksum_hex == "02000000f5be862af5be862a"
}
fn scenarios_passed(value: &Scenarios) -> bool {
    [
        &value.named_snapshots,
        &value.self_managed_snapshots,
        &value.snapshot_context_validation,
        &value.specialized_io,
        &value.erasure_coded_io,
        &value.native_interoperability,
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
