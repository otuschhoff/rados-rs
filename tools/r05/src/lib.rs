#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[allow(dead_code, unused_imports)]
#[path = "../../../src/maps/mod.rs"]
mod maps;
#[allow(dead_code)]
#[path = "../../../src/protocol/address.rs"]
mod protocol_address;
#[allow(dead_code)]
#[path = "../../../src/protocol/features.rs"]
mod protocol_features;
#[allow(dead_code)]
#[path = "../../../src/wire/mod.rs"]
mod wire;

mod protocol {
    pub(crate) mod address {
        pub(crate) use crate::protocol_address::*;
    }
    pub(crate) mod features {
        pub(crate) use crate::protocol_features::*;
    }
}

extern crate self as crc32c;

pub(crate) fn crc32c_append(seed: u32, payload: &[u8]) -> u32 {
    let mut crc = !seed;
    for byte in payload {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0x82f6_3b78 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

pub const SUITE_ID: &str = "r05/config-maps-v1";
pub const GO_REVISION: &str = "c8bb148a1379b51ef87256c27f366a05f8da4dc4";
pub const GO_TREE: &str = "c5039b6b50a05b942a902f70dc2fcb090463e8c7";
pub const MAX_RECORD_BYTES: u64 = 16_384;
pub const MAX_RECORDS: usize = 14;
pub const MAX_INPUT_BYTES: u64 = 32 << 20;
pub const MAX_OUTPUT_BYTES: u64 = 8_192;
pub const MAX_REPORT_BYTES: u64 = 262_144;

const MONMAP: &str = "testdata/p04/monmap-v9.bin";
const OSDMAP: &str = "testdata/p04/osdmap-v8.bin";
const INCREMENTAL: &str = "testdata/p04/osdmap-incremental-v8.bin";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct Bounds {
    max_record_bytes: u64,
    max_records: usize,
    max_input_bytes: u64,
    max_output_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseInput {
    case_id: String,
    path: Option<String>,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeRequest {
    schema_version: u32,
    suite_id: String,
    implementation_ids: Vec<String>,
    cases: Vec<CaseInput>,
    bounds: Bounds,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeResult {
    schema_version: u32,
    suite_id: String,
    implementation_id: String,
    case_id: String,
    input_sha256: String,
    output_sha256: String,
    semantic: Value,
    status: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FixtureEvidence {
    case_id: String,
    path: Option<String>,
    sha256: String,
    manifest_path: Option<String>,
    manifest_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ImplementationEvidence {
    implementation_id: String,
    source_revision: String,
    source_tree: String,
    source_files_sha256: String,
    lockfile_sha256: String,
    compiler: String,
    target: String,
    binary_path: String,
    binary_sha256: String,
    command: Vec<String>,
    exit_code: i32,
    stdout_sha256: String,
    records: Vec<ProbeResult>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactEvidence {
    adapter_path: String,
    adapter_sha256: String,
    schema_path: String,
    schema_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ControllerEvidence {
    path: String,
    sha256: String,
    command: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BridgeReport {
    schema_version: u32,
    suite_id: String,
    status: String,
    generated_at: String,
    bounds: Bounds,
    fixtures: Vec<FixtureEvidence>,
    rust: ImplementationEvidence,
    go: ImplementationEvidence,
    artifacts: ArtifactEvidence,
    controller: ControllerEvidence,
}

struct Case {
    id: &'static str,
    path: Option<&'static str>,
    input: &'static [u8],
}

const CASES: &[Case] = &[
    Case {
        id: "defaults",
        path: None,
        input: b"Config::default",
    },
    Case {
        id: "global-entity-precedence",
        path: None,
        input: b"global then exact entity; unknown file option excluded; v1 monitor excluded",
    },
    Case {
        id: "explicit-env",
        path: None,
        input: b"RADOS_R05 explicit environment prefix",
    },
    Case {
        id: "args-remainder",
        path: None,
        input: b"recognized args plus unchanged remainder",
    },
    Case {
        id: "key-over-keyring",
        path: None,
        input: b"direct key wins when both args are present",
    },
    Case {
        id: "keyring-expansion",
        path: None,
        input: b"$cluster and $name keyring expansion",
    },
    Case {
        id: "duration-syntax",
        path: None,
        input: b"Go duration units, compound and decimal",
    },
    Case {
        id: "unknown-retained",
        path: None,
        input: b"unknown programmatic option retained",
    },
    Case {
        id: "reject-include",
        path: None,
        input: b"file include exclusion",
    },
    Case {
        id: "reject-duration",
        path: None,
        input: b"non-positive duration rejection",
    },
    Case {
        id: "reject-monitor-bound",
        path: None,
        input: b"65 monitor seeds exceed bound 64",
    },
    Case {
        id: "monmap-p04",
        path: Some(MONMAP),
        input: b"",
    },
    Case {
        id: "osdmap-p04",
        path: Some(OSDMAP),
        input: b"",
    },
    Case {
        id: "incremental-p04",
        path: Some(INCREMENTAL),
        input: b"",
    },
];

fn bounds() -> Bounds {
    Bounds {
        max_record_bytes: MAX_RECORD_BYTES,
        max_records: MAX_RECORDS,
        max_input_bytes: MAX_INPUT_BYTES,
        max_output_bytes: MAX_OUTPUT_BYTES,
    }
}

fn case_data(root: &Path, case: &Case) -> Result<Vec<u8>, String> {
    let data = match case.path {
        Some(path) => fs::read(root.join(path)).map_err(|error| format!("read {path}: {error}"))?,
        None => case.input.to_vec(),
    };
    if data.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!("case input exceeds bound: {}", case.id));
    }
    Ok(data)
}

fn expected_request(root: &Path) -> Result<ProbeRequest, String> {
    let cases = CASES
        .iter()
        .map(|case| {
            Ok(CaseInput {
                case_id: case.id.to_owned(),
                path: case.path.map(str::to_owned),
                sha256: hex_digest(&case_data(root, case)?),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(ProbeRequest {
        schema_version: 1,
        suite_id: SUITE_ID.to_owned(),
        implementation_ids: vec!["rust".to_owned(), "go".to_owned()],
        cases,
        bounds: bounds(),
    })
}

/// Returns the one canonical request accepted by both R05 probes.
///
/// # Errors
///
/// Returns an error when a fixed fixture cannot be read.
pub fn default_request_json(root: &Path) -> Result<String, String> {
    let mut encoded =
        serde_json::to_string(&expected_request(root)?).map_err(|error| error.to_string())?;
    encoded.push('\n');
    Ok(encoded)
}

/// Runs the strict bounded Rust R05 probe.
///
/// # Errors
///
/// Returns an error if the request, fixtures, implementation, or output violates the contract.
pub fn run_rust_probe(root: &Path, input: impl Read, mut output: impl Write) -> Result<(), String> {
    let mut data = Vec::new();
    input
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|error| format!("read request: {error}"))?;
    if data.len() as u64 > MAX_RECORD_BYTES {
        return Err("request exceeds record bound".to_owned());
    }
    let request: ProbeRequest =
        serde_json::from_slice(&data).map_err(|error| format!("decode request: {error}"))?;
    if request != expected_request(root)? {
        return Err("request does not match the fixed R05 suite".to_owned());
    }
    for result in rust_results(root)? {
        let mut encoded = serde_json::to_vec(&result).map_err(|error| error.to_string())?;
        encoded.push(b'\n');
        if encoded.len() as u64 > MAX_RECORD_BYTES {
            return Err("result exceeds record bound".to_owned());
        }
        output
            .write_all(&encoded)
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn rust_results(root: &Path) -> Result<Vec<ProbeResult>, String> {
    CASES
        .iter()
        .map(|case| {
            let input = case_data(root, case)?;
            let semantic = match case.id {
                "monmap-p04" => map_summary("monmap", &input)?,
                "osdmap-p04" => map_summary("osdmap", &input)?,
                "incremental-p04" => map_summary("incremental", &input)?,
                id => config_case(id, &root.join("target/r05/fixtures")),
            };
            let canonical = serde_json::to_vec(&semantic).map_err(|error| error.to_string())?;
            if canonical.len() as u64 > MAX_OUTPUT_BYTES {
                return Err(format!("semantic output exceeds bound: {}", case.id));
            }
            Ok(ProbeResult {
                schema_version: 1,
                suite_id: SUITE_ID.to_owned(),
                implementation_id: "rust".to_owned(),
                case_id: case.id.to_owned(),
                input_sha256: hex_digest(&input),
                output_sha256: hex_digest(&canonical),
                semantic,
                status: "passed".to_owned(),
            })
        })
        .collect()
}

const MAP_LIMITS: maps::Limits = maps::Limits {
    max_bytes: 32 << 20,
    max_monitors: 64,
    max_addresses: 64,
    max_locations: 64,
    max_pools: 4096,
    max_osds: 65_536,
    max_pg_mappings: 1 << 20,
    max_collection_entries: 1 << 20,
};

fn config_case(case_id: &str, fixture_root: &Path) -> Value {
    use rados::Config;
    let result = match case_id {
		"defaults" => Ok((Config::default(), Vec::new())),
		"global-entity-precedence" => Config::parse(
			b"[global]\nname = client.r05\nmon host = v1:192.0.2.1:6789, v2:192.0.2.2:3300\noperation timeout = 4s\nfuture option = ignored\n[client.r05]\nmon_host = [v2:192.0.2.3:3300,192.0.2.4:3300]\nms_mode = crc\n",
		).map(|value| (value, Vec::new())),
		"explicit-env" => Config::default().parse_env("RADOS_R05").map(|value| (value, Vec::new())),
		"args-remainder" => Config::default().parse_args([
			"input", "--unknown", "value", "--id=test", "--mon-host",
			"v1:192.0.2.9:6789,v2:192.0.2.10:3300", "--operation-timeout=1h2m3.004005006s",
			"--", "--cluster=ignored",
		]),
		"key-over-keyring" => Config::default().parse_args([
			"--keyring".to_owned(), fixture_root.join("keyring").display().to_string(),
			"--key".to_owned(), "AQB7AAAAyAEAABAAMTIzNDU2Nzg5MDEyMzQ1Ng==".to_owned(),
		]),
		"keyring-expansion" => Config::default()
			.with_option("cluster", "r05")
			.and_then(|value| value.with_option("name", "client.r05"))
			.and_then(|value| value.with_option("keyring", &fixture_root.join("$cluster.$name.keyring").display().to_string()))
			.map(|value| (value, Vec::new())),
		"duration-syntax" => Config::default()
			.with_option("dial_timeout", "1h2m3.004005006s")
			.and_then(|value| value.with_option("handshake_timeout", "250ms"))
			.and_then(|value| value.with_option("operation_timeout", "1us"))
			.map(|value| (value, Vec::new())),
		"unknown-retained" => Config::default().with_option("future-option", " enabled ").map(|value| (value, Vec::new())),
		"reject-include" => Config::parse(b"[global]\ninclude = /tmp/ceph.conf\n").map(|value| (value, Vec::new())),
		"reject-duration" => Config::default().with_option("operation_timeout", "0s").map(|value| (value, Vec::new())),
		"reject-monitor-bound" => Config::default().with_option("mon_host", &vec!["v2:192.0.2.1:3300"; 65].join(",")).map(|value| (value, Vec::new())),
		_ => return serde_json::json!({"status":"unknown-case"}),
	};
    match result {
        Ok((value, remainder)) => summarize_config(&value, &remainder, fixture_root),
        Err(_) => serde_json::json!({"status":"error","kind":"invalid_argument"}),
    }
}

fn summarize_config(value: &rados::Config, remainder: &[String], fixture_root: &Path) -> Value {
    let keyring = value.option("keyring").map(|path| {
        path.strip_prefix(&fixture_root.display().to_string())
            .map_or(path.clone(), |suffix| format!("$fixture{suffix}"))
    });
    serde_json::json!({
        "status":"ok", "cluster":value.cluster(), "entity":value.entity(), "monitors":value.monitors(),
        "fsid":value.cluster_fsid(), "key_sha256":value.key().map(|key| hex_digest(key.expose())),
        "keyring":keyring,
        "mode":match value.security_mode() { rados::SecurityMode::Secure => "secure", rados::SecurityMode::Crc => "crc" },
        "dial_timeout":value.option("dial_timeout"), "handshake_timeout":value.option("handshake_timeout"),
        "operation_timeout":value.option("operation_timeout"), "future_option":value.option("future_option"),
        "remainder":remainder,
    })
}

fn map_summary(kind: &str, data: &[u8]) -> Result<Value, String> {
    match kind {
        "monmap" => {
            let value = maps::decode_monmap(data, MAP_LIMITS).map_err(|error| error.to_string())?;
            Ok(serde_json::json!({
                "kind":"monmap", "fsid":value.fsid().to_string(), "epoch":value.epoch(),
                "monitor_count":value.monitors().len(), "ranks":value.ranks(),
                "persistent_features":value.persistent_features(), "optional_features":value.optional_features(),
                "minimum_monitor_release":value.minimum_monitor_release(), "election_strategy":value.election_strategy(),
                "stretch_mode":value.stretch_mode_enabled(),
            }))
        }
        "osdmap" => {
            let value = maps::decode_osdmap(data, MAP_LIMITS).map_err(|error| error.to_string())?;
            let mut pools = value.pool_names().map(str::to_owned).collect::<Vec<_>>();
            pools.sort();
            Ok(serde_json::json!({
                "kind":"osdmap", "fsid":value.fsid().to_string(), "epoch":value.epoch(),
                "pool_count":value.pools().len(), "pools":pools, "crc":value.crc(),
                "crc_verified":value.crc_verified(), "sort_bitwise":value.sort_bitwise(),
                "applied_incremental":value.applied_incremental(),
            }))
        }
        "incremental" => {
            let value = maps::decode_osdmap_incremental(data, MAP_LIMITS)
                .map_err(|error| error.to_string())?;
            Ok(serde_json::json!({
                "kind":"incremental", "fsid":value.fsid().to_string(), "epoch":value.epoch(),
                "incremental_crc":value.incremental_crc(), "full_crc":value.full_crc(),
            }))
        }
        _ => Err("unknown map kind".to_owned()),
    }
}

fn hex_digest(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .fold(String::new(), |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to a String cannot fail");
            output
        })
}

const RUST_SOURCE_FILES: &[&str] = &[
    "Cargo.lock",
    "Cargo.toml",
    "build.rs",
    "rust-toolchain.toml",
    "src/config.rs",
    "src/error.rs",
];
const RUST_SOURCE_DIRECTORIES: &[&str] = &[
    "src/maps",
    "src/protocol",
    "src/wire",
    "tools/r05",
    "integration/r05",
];
const GO_SOURCE_FILES: &[&str] = &["go.mod", "go.sum", "client.go", "config.go"];
const GO_SOURCE_DIRECTORIES: &[&str] = &[
    "internal/encoding",
    "internal/maps",
    "internal/mon",
    "internal/protocol",
];

/// Verifies a strict bounded R05 report against the current Rust checkout and pinned Go oracle.
///
/// # Errors
///
/// Returns an error for stale, substituted, malformed, oversized, or divergent evidence.
pub fn verify_report_file(root: &Path, report_path: &Path) -> std::result::Result<(), String> {
    let mut data = Vec::new();
    fs::File::open(report_path)
        .map_err(|error| format!("open report: {error}"))?
        .take(MAX_REPORT_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|error| error.to_string())?;
    if data.len() as u64 > MAX_REPORT_BYTES || !data.ends_with(b"\n") || data.ends_with(b"\n\n") {
        return Err("report size or newline framing is invalid".to_owned());
    }
    let report: BridgeReport =
        serde_json::from_slice(&data).map_err(|error| format!("decode report: {error}"))?;
    let verifier = std::env::current_exe().map_err(|error| error.to_string())?;
    let rust_probe = verifier.with_file_name("rados-r05-probe");
    let go_probe = verifier.with_file_name("rados-r05-go-probe");
    verify_report(root, report_path, &rust_probe, &go_probe, &report)?;
    replay_probe(
        root,
        &rust_probe,
        &report.rust.records,
        Duration::from_secs(20),
    )
}

fn verify_report(
    root: &Path,
    report_path: &Path,
    rust_probe: &Path,
    go_probe: &Path,
    report: &BridgeReport,
) -> std::result::Result<(), String> {
    verify_report_shape(report)?;
    for (fixture, case) in report.fixtures.iter().zip(CASES) {
        if let Some(path) = case.path {
            let manifest = format!("{path}.manifest.json");
            if fixture.manifest_path.as_deref() != Some(&manifest)
                || fixture.manifest_sha256.as_deref() != Some(&file_digest(&root.join(&manifest))?)
                || fixture.sha256 != file_digest(&root.join(path))?
            {
                return Err(format!("fixture provenance is invalid: {path}"));
            }
        } else if fixture.manifest_path.is_some() || fixture.manifest_sha256.is_some() {
            return Err("synthetic case must not claim fixture provenance".to_owned());
        }
    }
    let go_root = controller_go_root(&report.controller.command)?;
    if git_value(go_root, &["rev-parse", "HEAD"])? != GO_REVISION
        || git_value(go_root, &["rev-parse", "HEAD^{tree}"])? != GO_TREE
        || !git_value(
            go_root,
            &["status", "--porcelain=v1", "--untracked-files=all"],
        )?
        .is_empty()
    {
        return Err("Go oracle is not the clean pinned commit and tree".to_owned());
    }
    if report.rust.source_revision != git_value(root, &["rev-parse", "HEAD"])?
        || report.rust.source_tree != git_value(root, &["rev-parse", "HEAD^{tree}"])?
        || report.rust.source_files_sha256 != rust_source_digest(root)?
        || report.rust.lockfile_sha256 != file_digest(&root.join("Cargo.lock"))?
        || !report.rust.compiler.starts_with("rustc 1.98.0 ")
        || Path::new(&report.rust.binary_path) != rust_probe
        || report.rust.binary_sha256 != file_digest(rust_probe)?
        || report.rust.command != [rust_probe.to_string_lossy().as_ref()]
    {
        return Err(
            "Rust source, tree, lockfile, command, or binary evidence is invalid".to_owned(),
        );
    }
    if report.go.source_revision != GO_REVISION
        || report.go.source_tree != GO_TREE
        || report.go.source_files_sha256 != go_source_digest(go_root)?
        || report.go.lockfile_sha256 != file_digest(&go_root.join("go.sum"))?
        || report.go.compiler != format!("go version go1.26.8 {}", report.go.target)
        || Path::new(&report.go.binary_path) != go_probe
        || report.go.binary_sha256 != file_digest(go_probe)?
        || report.go.command
            != [
                go_probe.to_string_lossy().as_ref(),
                "--fixture-root",
                root.to_string_lossy().as_ref(),
            ]
    {
        return Err("Go source, tree, lockfile, command, or binary evidence is invalid".to_owned());
    }
    if report.artifacts.adapter_path != "tools/r05/go-probe"
        || report.artifacts.adapter_sha256 != path_digest(root, Path::new("tools/r05/go-probe"))?
        || report.artifacts.schema_path != "integration/r05/report.schema.json"
        || report.artifacts.schema_sha256
            != file_digest(&root.join("integration/r05/report.schema.json"))?
        || report.controller.path != "integration/r05/reproduce.sh"
        || report.controller.sha256 != file_digest(&root.join("integration/r05/reproduce.sh"))?
        || report.controller.command
            != [
                "integration/r05/reproduce.sh",
                "--go-root",
                go_root.to_string_lossy().as_ref(),
                "--report",
                report_path.to_string_lossy().as_ref(),
            ]
    {
        return Err("adapter, schema, or controller evidence is invalid".to_owned());
    }
    Ok(())
}

fn verify_report_shape(report: &BridgeReport) -> std::result::Result<(), String> {
    if report.schema_version != 1
        || report.suite_id != SUITE_ID
        || report.status != "passed"
        || report.bounds != bounds()
        || !valid_utc_timestamp(&report.generated_at)
        || report.fixtures.len() != CASES.len()
    {
        return Err("report identity, timestamp, bounds, or case set is invalid".to_owned());
    }
    for ((fixture, case), index) in report.fixtures.iter().zip(CASES).zip(0..) {
        if fixture.case_id != case.id
            || fixture.path.as_deref() != case.path
            || fixture.sha256
                != report
                    .rust
                    .records
                    .get(index)
                    .map_or("", |record| &record.input_sha256)
        {
            return Err("fixture identity, ordering, or case set is invalid".to_owned());
        }
    }
    verify_implementation(&report.rust, "rust")?;
    verify_implementation(&report.go, "go")?;
    if report.rust.stdout_sha256 != records_digest(&report.rust.records)?
        || report.go.stdout_sha256 != records_digest(&report.go.records)?
        || normalized_records(&report.rust.records, "rust")?
            != normalized_records(&report.go.records, "go")?
    {
        return Err("probe records are stale, tampered, or divergent".to_owned());
    }
    Ok(())
}

fn verify_implementation(
    value: &ImplementationEvidence,
    id: &str,
) -> std::result::Result<(), String> {
    if value.implementation_id != id
        || value.exit_code != 0
        || value.records.len() != MAX_RECORDS
        || value.source_revision.is_empty()
        || value.source_tree.is_empty()
        || value.compiler.is_empty()
        || value.target.is_empty()
        || value.command.is_empty()
        || !is_sha256(&value.source_files_sha256)
        || !is_sha256(&value.lockfile_sha256)
        || !is_sha256(&value.binary_sha256)
        || !is_sha256(&value.stdout_sha256)
        || value
            .records
            .iter()
            .any(|record| record.implementation_id != id || record.status != "passed")
    {
        return Err(format!("{id} implementation evidence is invalid"));
    }
    Ok(())
}

fn normalized_records(
    records: &[ProbeResult],
    id: &str,
) -> std::result::Result<Vec<Value>, String> {
    records
        .iter()
        .map(|record| {
            if record.implementation_id != id {
                return Err("record implementation identity is invalid".to_owned());
            }
            let mut value = serde_json::to_value(record).map_err(|error| error.to_string())?;
            value
                .as_object_mut()
                .ok_or("record is not an object")?
                .remove("implementation_id");
            Ok(value)
        })
        .collect()
}

fn records_digest(records: &[ProbeResult]) -> std::result::Result<String, String> {
    let mut data = Vec::new();
    for record in records {
        serde_json::to_writer(&mut data, record).map_err(|error| error.to_string())?;
        data.push(b'\n');
    }
    Ok(hex_digest(&data))
}

fn replay_probe(
    root: &Path,
    probe: &Path,
    records: &[ProbeResult],
    timeout: Duration,
) -> std::result::Result<(), String> {
    let mut child = Command::new(probe)
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| error.to_string())?;
    child
        .stdin
        .take()
        .ok_or("probe stdin unavailable")?
        .write_all(default_request_json(root)?.as_bytes())
        .map_err(|error| error.to_string())?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            let output = child
                .wait_with_output()
                .map_err(|error| error.to_string())?;
            if !status.success()
                || output.stdout.len() as u64 > MAX_RECORD_BYTES * MAX_RECORDS as u64
                || hex_digest(&output.stdout) != records_digest(records)?
            {
                return Err(
                    "reported Rust probe does not reproduce bounded canonical output".to_owned(),
                );
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("reported Rust probe timed out".to_owned());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Computes the digest of the fixed Rust evidence source set.
///
/// # Errors
///
/// Returns an error when a source path cannot be inspected or read.
pub fn rust_source_digest(root: &Path) -> std::result::Result<String, String> {
    source_digest(root, RUST_SOURCE_FILES, RUST_SOURCE_DIRECTORIES)
}
/// Computes the digest of the fixed pinned-Go evidence source set.
///
/// # Errors
///
/// Returns an error when a source path cannot be inspected or read.
pub fn go_source_digest(root: &Path) -> std::result::Result<String, String> {
    source_digest(root, GO_SOURCE_FILES, GO_SOURCE_DIRECTORIES)
}
/// Computes a deterministic digest of a file or directory tree.
///
/// # Errors
///
/// Returns an error for missing, unreadable, symlinked, or non-UTF-8 paths.
pub fn path_digest(root: &Path, relative: &Path) -> std::result::Result<String, String> {
    let mut paths = Vec::new();
    collect_files(root, relative, &mut paths)?;
    digest_relative_paths(root, &mut paths)
}
/// Computes a SHA-256 digest for one file.
///
/// # Errors
///
/// Returns an error when the file cannot be read.
pub fn file_digest(path: &Path) -> std::result::Result<String, String> {
    fs::read(path)
        .map(|data| hex_digest(&data))
        .map_err(|error| error.to_string())
}

fn source_digest(
    root: &Path,
    files: &[&str],
    directories: &[&str],
) -> std::result::Result<String, String> {
    let mut paths = files.iter().map(PathBuf::from).collect::<Vec<_>>();
    for directory in directories {
        collect_files(root, Path::new(directory), &mut paths)?;
    }
    digest_relative_paths(root, &mut paths)
}
fn collect_files(
    root: &Path,
    relative: &Path,
    paths: &mut Vec<PathBuf>,
) -> std::result::Result<(), String> {
    let metadata = fs::symlink_metadata(root.join(relative))
        .map_err(|error| format!("inspect {}: {error}", relative.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "evidence path is a symlink: {}",
            relative.display()
        ));
    }
    if metadata.is_file() {
        paths.push(relative.to_owned());
        return Ok(());
    }
    for entry in fs::read_dir(root.join(relative)).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        collect_files(root, &relative.join(entry.file_name()), paths)?;
    }
    Ok(())
}
fn digest_relative_paths(
    root: &Path,
    paths: &mut Vec<PathBuf>,
) -> std::result::Result<String, String> {
    paths.sort();
    paths.dedup();
    let mut digest = Sha256::new();
    for relative in paths {
        let name = relative.to_str().ok_or("non-UTF-8 evidence path")?;
        let data = fs::read(root.join(&*relative)).map_err(|error| error.to_string())?;
        digest.update((name.len() as u64).to_le_bytes());
        digest.update(name.as_bytes());
        digest.update((data.len() as u64).to_le_bytes());
        digest.update(data);
    }
    Ok(hex_digest(&digest.finalize()))
}
fn git_value(root: &Path, arguments: &[&str]) -> std::result::Result<String, String> {
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
        .map_err(|error| error.to_string())
}
fn controller_go_root(command: &[String]) -> std::result::Result<&Path, String> {
    if command.len() == 5 && command[1] == "--go-root" {
        Ok(Path::new(&command[2]))
    } else {
        Err("controller command is malformed".to_owned())
    }
}
fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn valid_utc_timestamp(value: &str) -> bool {
    value.len() == 20
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(7) == Some(&b'-')
        && value.as_bytes().get(10) == Some(&b'T')
        && value.ends_with('Z')
}

/// Runs the probe rooted at the current directory.
///
/// # Errors
///
/// Returns an error when the current directory or probe execution fails.
pub fn run_from_current_directory() -> Result<(), String> {
    let root = std::env::current_dir().map_err(|error| error.to_string())?;
    run_rust_probe(&root, std::io::stdin().lock(), std::io::stdout().lock())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape_report(root: &Path) -> BridgeReport {
        let rust_records = rust_results(root).expect("Rust records");
        let mut go_records = rust_records.clone();
        for record in &mut go_records {
            record.implementation_id = "go".to_owned();
        }
        let fixtures = CASES
            .iter()
            .zip(&rust_records)
            .map(|(case, record)| FixtureEvidence {
                case_id: case.id.to_owned(),
                path: case.path.map(str::to_owned),
                sha256: record.input_sha256.clone(),
                manifest_path: case.path.map(|path| format!("{path}.manifest.json")),
                manifest_sha256: case.path.map(|_| "0".repeat(64)),
            })
            .collect();
        let implementation = |id: &str, records: Vec<ProbeResult>| ImplementationEvidence {
            implementation_id: id.to_owned(),
            source_revision: "revision".to_owned(),
            source_tree: "tree".to_owned(),
            source_files_sha256: "0".repeat(64),
            lockfile_sha256: "1".repeat(64),
            compiler: "compiler".to_owned(),
            target: "target".to_owned(),
            binary_path: "/probe".to_owned(),
            binary_sha256: "2".repeat(64),
            command: vec!["/probe".to_owned()],
            exit_code: 0,
            stdout_sha256: records_digest(&records).expect("digest"),
            records,
        };
        BridgeReport {
            schema_version: 1,
            suite_id: SUITE_ID.to_owned(),
            status: "passed".to_owned(),
            generated_at: "2026-09-17T00:00:00Z".to_owned(),
            bounds: bounds(),
            fixtures,
            rust: implementation("rust", rust_records),
            go: implementation("go", go_records),
            artifacts: ArtifactEvidence {
                adapter_path: "tools/r05/go-probe".to_owned(),
                adapter_sha256: "3".repeat(64),
                schema_path: "integration/r05/report.schema.json".to_owned(),
                schema_sha256: "4".repeat(64),
            },
            controller: ControllerEvidence {
                path: "integration/r05/reproduce.sh".to_owned(),
                sha256: "5".repeat(64),
                command: vec![],
            },
        }
    }

    #[test]
    fn request_is_strict_single_newline_json() {
        let root = Path::new("../..");
        let request = default_request_json(root).expect("request");
        assert_eq!(request.matches('\n').count(), 1);
        assert_eq!(
            serde_json::from_str::<ProbeRequest>(&request)
                .expect("JSON")
                .cases
                .len(),
            MAX_RECORDS
        );
    }

    #[test]
    fn rejects_stale_unknown_and_oversized_requests() {
        let root = Path::new("../..");
        for input in [b"{}".as_slice(), br#"{"schema_version":1,"unknown":true}"#] {
            assert!(run_rust_probe(root, input, Vec::new()).is_err());
        }
        assert!(
            run_rust_probe(
                root,
                vec![b' '; usize::try_from(MAX_RECORD_BYTES).expect("record bound fits usize") + 1]
                    .as_slice(),
                Vec::new()
            )
            .is_err()
        );
    }

    #[test]
    fn map_fixtures_use_actual_production_decoders() {
        let root = Path::new("../..");
        let results = rust_results(root).expect("results");
        assert_eq!(results.len(), MAX_RECORDS);
        assert_eq!(results[11].semantic["kind"], "monmap");
        assert_eq!(results[12].semantic["kind"], "osdmap");
        assert_eq!(results[13].semantic["kind"], "incremental");
    }

    #[test]
    fn verifier_rejects_stale_record_tampering() {
        let mut report = shape_report(Path::new("../.."));
        report.go.records[0].semantic["cluster"] = Value::String("stale".to_owned());
        assert!(verify_report_shape(&report).is_err());
    }

    #[test]
    fn verifier_rejects_source_hash_tampering() {
        let mut report = shape_report(Path::new("../.."));
        report.rust.source_files_sha256 = "not-a-hash".to_owned();
        assert!(verify_report_shape(&report).is_err());
    }

    #[test]
    fn verifier_rejects_binary_hash_tampering() {
        let mut report = shape_report(Path::new("../.."));
        report.go.binary_sha256 = "f".repeat(63);
        assert!(verify_report_shape(&report).is_err());
    }

    #[test]
    fn verifier_rejects_case_set_tampering() {
        let mut report = shape_report(Path::new("../.."));
        report.fixtures.pop();
        assert!(verify_report_shape(&report).is_err());
    }
}
