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
const SUITE_ID: &str = "r09/metadata-compound-enumeration-v1";
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
    cluster: ClusterEvidence,
    probes: ProbeEvidence,
    scenarios: Scenarios,
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
    rust_seed: NativeSeed,
    rust_verify: NativeVerify,
    go_seed: NativeSeed,
    go_verify: NativeVerify,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeSeed {
    native_binary_metadata: bool,
    native_compound_seed: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct NativeVerify {
    go_binary_metadata: bool,
    go_omap_native_read: bool,
    go_enumeration_native_read: bool,
    namespace_filtering: bool,
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
    replicas: u32,
    initial_pgs: u32,
    final_pgs: u32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProbeEvidence {
    rust: Probe,
    go: Probe,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct Probe {
    native_metadata: bool,
    binary_metadata: bool,
    omap_pagination: bool,
    compound_read: bool,
    compound_atomicity: bool,
    cross_client_contention: bool,
    enumeration: bool,
    namespaces: bool,
    cursor_continuation: bool,
    cursor_partitioning: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Scenarios {
    native_metadata: String,
    binary_metadata: String,
    omap_pagination: String,
    compound_read: String,
    compound_atomicity: String,
    cross_client_contention: String,
    enumeration: String,
    namespaces: String,
    cursor_continuation: String,
    cursor_partitioning: String,
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

/// Verifies a stored R09 report against its strict typed contract and current source.
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

/// Verifies the report plus the exact executables and frozen Go checkout used.
///
/// # Errors
/// Returns an error when an executable hash or frozen checkout identity differs.
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
    let report: Report = serde_json::from_slice(&data).map_err(|error| error.to_string())?;
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

/// Verifies a retained R09 fuzz task-validation report and its logs.
///
/// # Errors
/// Returns an error when the report or any retained artifact is invalid.
pub fn verify_fuzz_report_file(root: &Path, report_path: &Path) -> Result<(), String> {
    let data = fs::read(report_path).map_err(|error| format!("read fuzz report: {error}"))?;
    if data.len() as u64 > MAX_REPORT_BYTES {
        return Err("fuzz report exceeds byte limit".to_owned());
    }
    let report: FuzzReport = serde_json::from_slice(&data).map_err(|error| error.to_string())?;
    if report.schema_version != 1
        || report.suite_id != "r09/fuzz-task-validation-v1"
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
            "r09_metadata",
            "fe801b8c692373a6a6015bd1eef07930a4c5e8e9cbc6472571977fb5113156dc",
        ),
        (
            "r09_compound",
            "a9903e204c3ce19f4199601a384d6d24366d2e602742c9747b9ddbed11ad79a2",
        ),
        (
            "r09_enumeration",
            "f6b2361eefb4e5de47ff012d6795ccbc5e768f96467956406e8f4021b3a495e3",
        ),
    ]);
    if report.campaigns.len() != expected.len() {
        return Err("fuzz campaign matrix is incomplete".to_owned());
    }
    let directory = report_path
        .parent()
        .ok_or_else(|| "fuzz report has no parent".to_owned())?;
    let mut observed = BTreeSet::new();
    for campaign in &report.campaigns {
        let Some(corpus) = expected.get(campaign.target.as_str()) else {
            return Err("unexpected fuzz target".to_owned());
        };
        let output_path = format!("fuzz-validation-logs/{}.log", campaign.target);
        if !observed.insert(campaign.target.as_str())
            || campaign.status != "passed"
            || campaign.budget_seconds < 60
            || campaign.executions == 0
            || campaign.executions_per_second == 0
            || campaign.corpus_sha256 != *corpus
            || campaign.output_path != output_path
            || campaign.target_sha256
                != file_digest(&root.join(format!("fuzz/fuzz_targets/{}.rs", campaign.target)))?
            || campaign.output_sha256 != file_digest(&directory.join(&campaign.output_path))?
        {
            return Err("fuzz campaign evidence is invalid".to_owned());
        }
    }
    Ok(())
}

fn verify_report_bytes(root: &Path, data: &[u8]) -> Result<(), String> {
    let report: Report = serde_json::from_slice(data).map_err(|error| error.to_string())?;
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
        || report.server.source_anchor_commit != SERVER_COMMIT
        || report.server.version != SERVER_VERSION
        || report.server.image != SERVER_IMAGE
        || report.native.version != NATIVE_VERSION
    {
        return Err("client or server provenance is invalid".to_owned());
    }
    if report.cluster.fsid != "11111111-2222-4333-8444-888888888888"
        || report.cluster.osds != 3
        || report.cluster.pool != "p08-data"
        || report.cluster.replicas != 2
        || report.cluster.initial_pgs != 16
        || report.cluster.final_pgs != 32
    {
        return Err("cluster profile is invalid".to_owned());
    }
    let statuses = [
        &report.scenarios.native_metadata,
        &report.scenarios.binary_metadata,
        &report.scenarios.omap_pagination,
        &report.scenarios.compound_read,
        &report.scenarios.compound_atomicity,
        &report.scenarios.cross_client_contention,
        &report.scenarios.enumeration,
        &report.scenarios.namespaces,
        &report.scenarios.cursor_continuation,
        &report.scenarios.cursor_partitioning,
    ];
    if statuses.iter().any(|status| status.as_str() != "passed")
        || !probe_passed(&report.probes.rust)
        || !probe_passed(&report.probes.go)
        || !report.native.rust_seed.native_binary_metadata
        || !report.native.rust_seed.native_compound_seed
        || !native_verified(&report.native.rust_verify)
        || !report.native.go_seed.native_binary_metadata
        || !report.native.go_seed.native_compound_seed
        || !native_verified(&report.native.go_verify)
    {
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
    if !is_hex(&report.rust.revision, 40)
        || !is_hex(&report.rust.tree, 40)
        || report.schema_sha256 != file_digest(&root.join("integration/r09/report.schema.json"))?
        || report.rust.source_sha256 != rust_source_digest(root)?
    {
        return Err("Rust identity, schema, or source digest is invalid".to_owned());
    }
    verify_git_identity(root, &report.rust)
}

fn probe_passed(probe: &Probe) -> bool {
    probe.native_metadata
        && probe.binary_metadata
        && probe.omap_pagination
        && probe.compound_read
        && probe.compound_atomicity
        && probe.cross_client_contention
        && probe.enumeration
        && probe.namespaces
        && probe.cursor_continuation
        && probe.cursor_partitioning
}

fn native_verified(verify: &NativeVerify) -> bool {
    verify.go_binary_metadata
        && verify.go_omap_native_read
        && verify.go_enumeration_native_read
        && verify.namespace_filtering
}

/// Hashes the complete Rust source and R09 qualification closure.
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
            "tools/r09/**",
            "integration/r09/**",
            "fuzz/fuzz_targets/r09_*",
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn valid_report(root: &Path) -> Value {
        serde_json::json!({
            "schema_version":1,"suite_id":SUITE_ID,"status":"passed","started_at":"2026-09-19T00:00:00Z","finished_at":"2026-09-19T00:01:00Z",
            "schema_sha256":file_digest(&root.join("integration/r09/report.schema.json")).expect("schema"),
            "rust":{"revision":git_output(root,&["rev-parse","HEAD"]).expect("revision"),"tree":git_output(root,&["rev-parse","HEAD^{tree}"]).expect("tree"),"source_sha256":rust_source_digest(root).expect("source"),"compiler_image":COMPILER_IMAGE,"platform":"linux/arm64","binary_sha256":"a".repeat(64)},
            "go":{"revision":GO_REVISION,"tree":GO_TREE,"compiler":"go1.26.8","platform":"linux/arm64","binary_sha256":"b".repeat(64)},
            "native":{"version":NATIVE_VERSION,"binary_sha256":"c".repeat(64),"rust_seed":{"native_binary_metadata":true,"native_compound_seed":true},"rust_verify":{"go_binary_metadata":true,"go_omap_native_read":true,"go_enumeration_native_read":true,"namespace_filtering":true},"go_seed":{"native_binary_metadata":true,"native_compound_seed":true},"go_verify":{"go_binary_metadata":true,"go_omap_native_read":true,"go_enumeration_native_read":true,"namespace_filtering":true}},
            "server":{"source_anchor_commit":SERVER_COMMIT,"version":SERVER_VERSION,"image":SERVER_IMAGE,"binary_sha256":"d".repeat(64)},
            "cluster":{"fsid":"11111111-2222-4333-8444-888888888888","osds":3,"pool":"p08-data","replicas":2,"initial_pgs":16,"final_pgs":32},
            "probes":{"rust":{"native_metadata":true,"binary_metadata":true,"omap_pagination":true,"compound_read":true,"compound_atomicity":true,"cross_client_contention":true,"enumeration":true,"namespaces":true,"cursor_continuation":true,"cursor_partitioning":true},"go":{"native_metadata":true,"binary_metadata":true,"omap_pagination":true,"compound_read":true,"compound_atomicity":true,"cross_client_contention":true,"enumeration":true,"namespaces":true,"cursor_continuation":true,"cursor_partitioning":true}},
            "scenarios":{"native_metadata":"passed","binary_metadata":"passed","omap_pagination":"passed","compound_read":"passed","compound_atomicity":"passed","cross_client_contention":"passed","enumeration":"passed","namespaces":"passed","cursor_continuation":"passed","cursor_partitioning":"passed"}
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
    fn rejects_unknown_failed_and_stale_reports() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut unknown = valid_report(&root);
        unknown["unexpected"] = Value::Bool(true);
        rejects(&root, &unknown);
        let mut failed = valid_report(&root);
        failed["scenarios"]["compound_atomicity"] = Value::String("failed".to_owned());
        rejects(&root, &failed);
        let mut stale = valid_report(&root);
        stale["rust"]["source_sha256"] = Value::String("0".repeat(64));
        rejects(&root, &stale);
    }

    #[test]
    fn rejects_pin_cluster_and_native_tampering() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut go = valid_report(&root);
        go["go"]["tree"] = Value::String("0".repeat(40));
        rejects(&root, &go);
        let mut cluster = valid_report(&root);
        cluster["cluster"]["final_pgs"] = Value::from(16);
        rejects(&root, &cluster);
        let mut native = valid_report(&root);
        native["native"]["rust_verify"]["namespace_filtering"] = Value::Bool(false);
        rejects(&root, &native);
        let mut probe = valid_report(&root);
        probe["probes"]["rust"]["cursor_continuation"] = Value::Bool(false);
        rejects(&root, &probe);
    }
}
