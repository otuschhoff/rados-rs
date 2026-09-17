#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

#[allow(dead_code)]
#[path = "../../../src/cephx/mod.rs"]
mod cephx;
#[allow(dead_code, unused_imports)]
#[path = "../../../src/wire/mod.rs"]
mod wire;

use cephx::core::{
    CONNECTION_MODE_CRC, SERVICE_AUTH, SERVICE_MONITOR, ServiceTicket, TicketBlob,
    build_authorizer, build_challenge_request, build_initial_payload, parse_server_challenge,
};
use cephx::crypto::{
    Limits, calculate_challenge, transcript_signature, verify_transcript_signature,
};
use cephx::{Error as CephxError, parse_key, parse_keyring};
use command_group::CommandGroup as _;
use wire::Decoder;

pub const SUITE_ID: &str = "r04/cephx-core-v1";
pub const GO_REVISION: &str = "c8bb148a1379b51ef87256c27f366a05f8da4dc4";
pub const GO_TREE: &str = "c5039b6b50a05b942a902f70dc2fcb090463e8c7";
const RUST_VERSION_PREFIX: &str = "rustc 1.98.0 ";
pub const MAX_RECORD_BYTES: u64 = 16_384;
pub const MAX_RECORDS: usize = 11;
pub const MAX_INPUT_BYTES: u64 = 16_384;
pub const MAX_OUTPUT_BYTES: u64 = 8_192;
pub const MAX_REPORT_BYTES: u64 = 262_144;

const RUST_SOURCE_FILES: &[&str] = &[
    "Cargo.lock",
    "Cargo.toml",
    "rust-toolchain.toml",
    "src/wire/mod.rs",
    "src/wire/codec.rs",
    "src/cephx/mod.rs",
    "src/cephx/core.rs",
    "src/cephx/crypto.rs",
    "testdata/p03/cephx-encoding-vectors.json",
    "testdata/p03/cephx-encoding-vectors.json.manifest.json",
    "testdata/p03/crypto-vectors.json",
    "testdata/p03/crypto-vectors.json.manifest.json",
];
const RUST_SOURCE_DIRECTORIES: &[&str] = &["tools/r04", "integration/r04"];
const GO_SOURCE_FILES: &[&str] = &["go.mod", "go.sum"];
const GO_SOURCE_DIRECTORIES: &[&str] =
    &["internal/cephx", "internal/encoding", "internal/protocol"];

const TYPE1_KEY: &str = "AQB7AAAAyAEAABAAMTIzNDU2Nzg5MDEyMzQ1Ng==";
const TYPE2_KEY: &str = "AgBm8qdqnvU7HiAAg6prN8XJ47FG9AprWpB72EwKyLfFC7UgnMYvcnFI29M=";
const ENCODING_FIXTURE: &str = "testdata/p03/cephx-encoding-vectors.json";
const CRYPTO_FIXTURE: &str = "testdata/p03/crypto-vectors.json";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
struct Bounds {
    max_record_bytes: u64,
    max_records: usize,
    max_input_bytes: u64,
    max_output_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CaseInput {
    case_id: String,
    path: Option<String>,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProbeRequest {
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
    semantic: serde_json::Value,
    status: String,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureEvidence {
    case_id: String,
    path: Option<String>,
    sha256: String,
    manifest_path: Option<String>,
    manifest_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImplementationEvidence {
    implementation_id: String,
    source_revision: String,
    source_tree: String,
    source_files_sha256: String,
    lockfile_sha256: String,
    compiler: String,
    target: String,
    driver_sha256: String,
    command: Vec<String>,
    exit_code: i32,
    stdout_sha256: String,
    records: Vec<ProbeResult>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactEvidence {
    adapter_path: String,
    adapter_sha256: String,
    schema_path: String,
    schema_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControllerEvidence {
    path: String,
    sha256: String,
    command: Vec<String>,
}

struct Case {
    id: &'static str,
    path: Option<&'static str>,
    input: &'static [u8],
    manifest_sha256: Option<&'static str>,
}

const CASES: &[Case] = &[
    Case {
        id: "credential-type1",
        path: Some(ENCODING_FIXTURE),
        input: b"",
        manifest_sha256: Some("3bc88c5d4d0b08a805a45ab1c6d415a6ebb92023a48dc8863eef04011596bb9d"),
    },
    Case {
        id: "credential-type2",
        path: None,
        input: b"client.p03/type2/AES256-KRB5",
        manifest_sha256: None,
    },
    Case {
        id: "keyring",
        path: None,
        input: b"[client.p03]\nkey = AQB7AAAAyAEAABAAMTIzNDU2Nzg5MDEyMzQ1Ng==\n",
        manifest_sha256: None,
    },
    Case {
        id: "initial-server-challenge",
        path: Some(ENCODING_FIXTURE),
        input: b"",
        manifest_sha256: Some("3bc88c5d4d0b08a805a45ab1c6d415a6ebb92023a48dc8863eef04011596bb9d"),
    },
    Case {
        id: "challenge-type1",
        path: None,
        input: b"server=1122334455667788/client=0102030405060708/type=1",
        manifest_sha256: None,
    },
    Case {
        id: "challenge-type2-vector",
        path: Some(CRYPTO_FIXTURE),
        input: b"",
        manifest_sha256: Some("4439090b0f0041a48ea5275bfa1580014d68d4e22528e341208f526051283dbe"),
    },
    Case {
        id: "authorizer-type1",
        path: None,
        input: b"service=1/global=77/now=100/expiry=200/nonce=0807060504030201/type=1",
        manifest_sha256: None,
    },
    Case {
        id: "authorizer-type2",
        path: None,
        input:
            b"service=1/global=77/now=100/expiry=200/nonce=0807060504030201/confounder=10x16/type=2",
        manifest_sha256: None,
    },
    Case {
        id: "transcript-signature",
        path: None,
        input: b"rados-r04-fixed-transcript-v1",
        manifest_sha256: None,
    },
    Case {
        id: "ticket-fixture",
        path: Some(ENCODING_FIXTURE),
        input: b"",
        manifest_sha256: Some("3bc88c5d4d0b08a805a45ab1c6d415a6ebb92023a48dc8863eef04011596bb9d"),
    },
    Case {
        id: "downgrade-lifecycle",
        path: None,
        input: b"secure-required/crc-offered/expired-ticket-at-now",
        manifest_sha256: None,
    },
];

fn case_input(case: &Case, root: &Path) -> Result<Vec<u8>, String> {
    if let Some(path) = case.path {
        fs::read(root.join(path)).map_err(|error| format!("read {path}: {error}"))
    } else {
        Ok(case.input.to_vec())
    }
}

fn case_sha(case: &Case) -> &'static str {
    match case.path {
        Some(ENCODING_FIXTURE) => {
            "6b7c66e654f2f11a2effa2c51119b4cdcf19eba642952d8eaa292de3182f1cc4"
        }
        Some(CRYPTO_FIXTURE) => "9baad25768d0d32c238cb1c98bc2d6c08f66f84dde724b92b5d518dce50b4591",
        _ => "",
    }
}

fn expected_request() -> ProbeRequest {
    ProbeRequest {
        schema_version: 1,
        suite_id: SUITE_ID.to_owned(),
        implementation_ids: vec!["rust".to_owned(), "go".to_owned()],
        cases: CASES
            .iter()
            .map(|case| CaseInput {
                case_id: case.id.to_owned(),
                path: case.path.map(str::to_owned),
                sha256: if case.path.is_some() {
                    case_sha(case).to_owned()
                } else {
                    hex_digest(case.input)
                },
            })
            .collect(),
        bounds: Bounds {
            max_record_bytes: MAX_RECORD_BYTES,
            max_records: MAX_RECORDS,
            max_input_bytes: MAX_INPUT_BYTES,
            max_output_bytes: MAX_OUTPUT_BYTES,
        },
    }
}

/// Returns the one canonical request accepted by both R04 probes.
///
/// # Panics
///
/// Panics only if the statically defined request cannot be represented as JSON.
#[must_use]
pub fn default_request_json() -> String {
    let mut encoded = serde_json::to_string(&expected_request()).expect("request is serializable");
    encoded.push('\n');
    encoded
}

/// Runs the strict bounded Rust R04 probe.
///
/// # Errors
///
/// Returns an error if the request, fixtures, codecs, or output violate the contract.
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
    if request != expected_request() {
        return Err("request does not match the fixed R04 suite".to_owned());
    }
    for result in rust_results(root)? {
        let mut encoded =
            serde_json::to_vec(&result).map_err(|error| format!("encode result: {error}"))?;
        encoded.push(b'\n');
        if encoded.len() as u64 > MAX_RECORD_BYTES {
            return Err("result exceeds record bound".to_owned());
        }
        output
            .write_all(&encoded)
            .map_err(|error| format!("write result: {error}"))?;
    }
    Ok(())
}

fn rust_results(root: &Path) -> Result<Vec<ProbeResult>, String> {
    let mut results = Vec::with_capacity(MAX_RECORDS);
    for case in CASES {
        let input = case_input(case, root)?;
        let input_sha = if case.path.is_some() {
            case_sha(case).to_owned()
        } else {
            hex_digest(&input)
        };
        if input.len() as u64 > MAX_INPUT_BYTES || hex_digest(&input) != input_sha {
            return Err(format!("case input identity is invalid: {}", case.id));
        }
        let semantic = cephx_semantic(case.id, &input)?;
        results.push(result("rust", case.id, &input_sha, semantic)?);
    }
    Ok(results)
}

/// Verifies a bounded R04 report against clean committed Rust and Go trees.
///
/// # Errors
///
/// Returns an error if any identity, bound, artifact, source, or result is invalid.
pub fn verify_report_file(root: &Path, report_path: &Path) -> Result<(), String> {
    require_clean_tree(root, "Rust candidate")?;
    let mut data = Vec::new();
    fs::File::open(report_path)
        .map_err(|error| format!("open report: {error}"))?
        .take(MAX_REPORT_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|error| format!("read report: {error}"))?;
    if data.len() as u64 > MAX_REPORT_BYTES {
        return Err("report exceeds bound".to_owned());
    }
    let verifier = std::env::current_exe().map_err(|error| format!("locate verifier: {error}"))?;
    let probe = verifier.with_file_name("rados-r04-probe");
    verify_report(
        root,
        report_path,
        &verifier,
        &probe,
        &data,
        None,
        Duration::from_secs(30),
    )
}

#[doc(hidden)]
pub fn verify_report_bytes_for_tests(
    root: &Path,
    report_path: &Path,
    verifier: &Path,
    probe: &Path,
    data: &[u8],
) -> Result<(), String> {
    verify_report_bytes_with_timeout_for_tests(
        root,
        report_path,
        verifier,
        probe,
        data,
        Duration::from_secs(30),
    )
}

#[doc(hidden)]
pub fn verify_report_bytes_with_timeout_for_tests(
    root: &Path,
    report_path: &Path,
    verifier: &Path,
    probe: &Path,
    data: &[u8],
    replay_timeout: Duration,
) -> Result<(), String> {
    let report: BridgeReport =
        serde_json::from_slice(data).map_err(|error| format!("decode report: {error}"))?;
    let go_environment = (report.go.compiler.clone(), report.go.target.clone());
    verify_report(
        root,
        report_path,
        verifier,
        probe,
        data,
        Some(go_environment),
        replay_timeout,
    )
}

fn verify_report(
    root: &Path,
    report_path: &Path,
    verifier: &Path,
    probe: &Path,
    data: &[u8],
    test_go_environment: Option<(String, String)>,
    replay_timeout: Duration,
) -> Result<(), String> {
    if data.len() as u64 > MAX_REPORT_BYTES {
        return Err("report exceeds bound".to_owned());
    }
    let report: BridgeReport =
        serde_json::from_slice(data).map_err(|error| format!("decode report: {error}"))?;
    if report.schema_version != 1
        || report.suite_id != SUITE_ID
        || report.status != "passed"
        || !valid_utc_timestamp(&report.generated_at)
        || report.bounds != expected_request().bounds
    {
        return Err("report identity, status, timestamp, or bounds are invalid".to_owned());
    }
    verify_fixtures(root, &report.fixtures)?;
    verify_implementation(&report.rust, "rust")?;
    verify_implementation(&report.go, "go")?;
    if report.rust.command != [probe.to_string_lossy().as_ref()]
        || report.rust.source_revision != git_value(root, &["rev-parse", "HEAD"])?
        || report.rust.source_tree != git_value(root, &["rev-parse", "HEAD^{tree}"])?
        || report.rust.source_files_sha256 != rust_source_digest(root)?
        || report.rust.lockfile_sha256 != file_digest(&root.join("Cargo.lock"))?
        || !report.rust.compiler.starts_with(RUST_VERSION_PREFIX)
        || report.rust.compiler != command_value("rustc", &["--version"])?
        || report.rust.target != rust_target()?
        || report.rust.driver_sha256 != file_digest(probe)?
        || report.rust.stdout_sha256 != records_digest(&report.rust.records)?
    {
        return Err("Rust evidence does not match the current R04 candidate".to_owned());
    }
    let go_root = controller_go_root(&report.controller.command)?;
    if test_go_environment.is_none() {
        require_clean_tree(go_root, "Go oracle")?;
    }
    if report.go.source_revision != GO_REVISION || report.go.source_tree != GO_TREE {
        return Err("Go revision or tree is not pinned".to_owned());
    }
    if test_go_environment.is_none()
        && (git_value(go_root, &["rev-parse", "HEAD"])? != GO_REVISION
            || git_value(go_root, &["rev-parse", "HEAD^{tree}"])? != GO_TREE
            || report.go.source_files_sha256 != go_source_digest(go_root)?
            || report.go.lockfile_sha256 != file_digest(&go_root.join("go.sum"))?)
    {
        return Err("Go checkout source or lockfile evidence is invalid".to_owned());
    }
    let (go_compiler, go_target) = if let Some(environment) = test_go_environment {
        environment
    } else {
        (go_command_value(&["version"])?, go_target()?)
    };
    if report.go.compiler != go_compiler
        || report.go.target != go_target
        || !valid_go_environment(&report.go.compiler, &report.go.target)
    {
        return Err("Go compiler or target evidence is invalid".to_owned());
    }
    if report.go.driver_sha256 != report.artifacts.adapter_sha256
        || report.go.command
            != [
                "go",
                "run",
                "./tools/rados-rs-r04-probe",
                "--fixture-root",
                "./tools/rados-rs-r04-probe/fixtures",
            ]
    {
        return Err("Go adapter or invocation evidence is invalid".to_owned());
    }
    if report.go.stdout_sha256 != records_digest(&report.go.records)? {
        return Err("Go canonical stdout evidence is invalid".to_owned());
    }
    let expected = rust_results(root)?;
    if report.rust.records != expected
        || normalized_records(&report.rust.records, "rust")?
            != normalized_records(&report.go.records, "go")?
    {
        return Err("probe records are stale, noncanonical, or differ".to_owned());
    }
    if report.artifacts.adapter_path != "tools/r04/go-probe"
        || report.artifacts.adapter_sha256 != path_digest(root, Path::new("tools/r04/go-probe"))?
        || report.artifacts.schema_path != "integration/r04/report.schema.json"
        || report.artifacts.schema_sha256
            != file_digest(&root.join("integration/r04/report.schema.json"))?
    {
        return Err("adapter or schema evidence is invalid".to_owned());
    }
    if report.controller.path != "integration/r04/reproduce.sh"
        || report.controller.sha256 != file_digest(&root.join("integration/r04/reproduce.sh"))?
        || !valid_controller_command(
            &report.controller.command,
            go_root,
            probe,
            verifier,
            report_path,
        )
    {
        return Err("controller evidence is invalid".to_owned());
    }
    verify_probe_execution(root, probe, &report.rust.records, replay_timeout)
}

fn verify_fixtures(root: &Path, evidence: &[FixtureEvidence]) -> Result<(), String> {
    if evidence.len() != CASES.len() {
        return Err("fixture evidence count is invalid".to_owned());
    }
    for (actual, expected) in evidence.iter().zip(CASES) {
        let expected_sha = if expected.path.is_some() {
            case_sha(expected).to_owned()
        } else {
            hex_digest(expected.input)
        };
        if actual.case_id != expected.id
            || actual.path.as_deref() != expected.path
            || actual.sha256 != expected_sha
        {
            return Err("fixture identity or ordering is invalid".to_owned());
        }
        if let Some(path) = expected.path {
            let manifest = format!("{path}.manifest.json");
            if actual.manifest_path.as_deref() != Some(&manifest)
                || actual.manifest_sha256.as_deref() != expected.manifest_sha256
                || file_digest(&root.join(&manifest))?
                    != expected.manifest_sha256.unwrap_or_default()
                || file_digest(&root.join(path))? != case_sha(expected)
            {
                return Err(format!("fixture provenance is invalid: {path}"));
            }
        } else if actual.manifest_path.is_some() || actual.manifest_sha256.is_some() {
            return Err("synthetic case must not claim fixture provenance".to_owned());
        }
    }
    Ok(())
}

fn verify_implementation(
    evidence: &ImplementationEvidence,
    expected_id: &str,
) -> Result<(), String> {
    if evidence.implementation_id != expected_id
        || evidence.exit_code != 0
        || evidence.records.len() != MAX_RECORDS
        || evidence.source_revision.is_empty()
        || evidence.source_tree.is_empty()
        || evidence.compiler.is_empty()
        || evidence.target.is_empty()
        || evidence.command.is_empty()
        || evidence.command.len() > 8
        || !is_sha256(&evidence.source_files_sha256)
        || !is_sha256(&evidence.lockfile_sha256)
        || !is_sha256(&evidence.driver_sha256)
        || !is_sha256(&evidence.stdout_sha256)
        || evidence
            .records
            .iter()
            .any(|record| record.implementation_id != expected_id || record.status != "passed")
    {
        return Err(format!("{expected_id} implementation evidence is invalid"));
    }
    Ok(())
}

fn normalized_records(
    records: &[ProbeResult],
    expected_id: &str,
) -> Result<Vec<serde_json::Value>, String> {
    records
        .iter()
        .map(|record| {
            if record.implementation_id != expected_id {
                return Err("record implementation identity is invalid".to_owned());
            }
            let mut value = serde_json::to_value(record).map_err(|error| error.to_string())?;
            value
                .as_object_mut()
                .ok_or_else(|| "record is not an object".to_owned())?
                .remove("implementation_id");
            Ok(value)
        })
        .collect()
}

fn records_digest(records: &[ProbeResult]) -> Result<String, String> {
    let mut data = Vec::new();
    for record in records {
        serde_json::to_writer(&mut data, record).map_err(|error| error.to_string())?;
        data.push(b'\n');
    }
    Ok(hex_digest(&data))
}

fn verify_probe_execution(
    root: &Path,
    probe: &Path,
    records: &[ProbeResult],
    replay_timeout: Duration,
) -> Result<(), String> {
    let mut child = Command::new(probe)
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .group_spawn()
        .map_err(|error| format!("start Rust probe: {error}"))?;
    child
        .inner()
        .stdin
        .take()
        .ok_or_else(|| "probe stdin unavailable".to_owned())?
        .write_all(default_request_json().as_bytes())
        .map_err(|error| error.to_string())?;
    let stdout = child
        .inner()
        .stdout
        .take()
        .ok_or_else(|| "probe stdout unavailable".to_owned())?;
    let (output_tx, output_rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut output = Vec::new();
        let result = stdout
            .take(MAX_RECORD_BYTES * MAX_RECORDS as u64 + 1)
            .read_to_end(&mut output)
            .map(|_| output)
            .map_err(|error| error.to_string());
        let _ = output_tx.send(result);
    });
    let deadline = Instant::now() + replay_timeout;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("reported Rust probe timed out".to_owned());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let output = if let Ok(output) = output_rx.recv_timeout(Duration::from_secs(1)) {
        output?
    } else {
        let _ = child.kill();
        let _ = child.wait();
        return Err("reported Rust probe output did not close".to_owned());
    };
    if output.len() as u64 > MAX_RECORD_BYTES * MAX_RECORDS as u64 {
        return Err("reported Rust probe output exceeds bound".to_owned());
    }
    if !status.success() || hex_digest(&output) != records_digest(records)? {
        return Err("reported Rust probe does not reproduce canonical output".to_owned());
    }
    Ok(())
}

#[must_use]
pub fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Computes the fixed R04 Rust source-set digest.
///
/// # Errors
///
/// Returns an error when a fixed source path cannot be inspected or read.
pub fn rust_source_digest(root: &Path) -> Result<String, String> {
    source_digest(root, RUST_SOURCE_FILES, RUST_SOURCE_DIRECTORIES)
}

/// Computes the fixed pinned-Go source-set digest.
///
/// # Errors
///
/// Returns an error when a fixed source path cannot be inspected or read.
pub fn go_source_digest(root: &Path) -> Result<String, String> {
    source_digest(root, GO_SOURCE_FILES, GO_SOURCE_DIRECTORIES)
}

fn source_digest(root: &Path, files: &[&str], directories: &[&str]) -> Result<String, String> {
    let mut paths = files.iter().map(PathBuf::from).collect::<Vec<_>>();
    for directory in directories {
        collect_files(root, Path::new(directory), &mut paths)?;
    }
    digest_relative_paths(root, &mut paths)
}

/// Computes a deterministic path-tree digest.
///
/// # Errors
///
/// Returns an error when the path is missing, is a symlink, or cannot be read.
pub fn path_digest(root: &Path, relative: &Path) -> Result<String, String> {
    let mut paths = Vec::new();
    collect_files(root, relative, &mut paths)?;
    digest_relative_paths(root, &mut paths)
}

fn collect_files(root: &Path, relative: &Path, paths: &mut Vec<PathBuf>) -> Result<(), String> {
    let absolute = root.join(relative);
    let metadata = fs::symlink_metadata(&absolute)
        .map_err(|error| format!("inspect {}: {error}", absolute.display()))?;
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
    for entry in
        fs::read_dir(&absolute).map_err(|error| format!("read {}: {error}", absolute.display()))?
    {
        let entry = entry.map_err(|error| error.to_string())?;
        collect_files(root, &relative.join(entry.file_name()), paths)?;
    }
    Ok(())
}

fn digest_relative_paths(root: &Path, paths: &mut Vec<PathBuf>) -> Result<String, String> {
    paths.sort();
    paths.dedup();
    let mut digest = Sha256::new();
    for relative in paths {
        let path = relative
            .to_str()
            .ok_or_else(|| "non-UTF-8 evidence path".to_owned())?;
        let data =
            fs::read(root.join(&*relative)).map_err(|error| format!("read {path}: {error}"))?;
        digest.update((path.len() as u64).to_le_bytes());
        digest.update(path.as_bytes());
        digest.update((data.len() as u64).to_le_bytes());
        digest.update(data);
    }
    Ok(hex_digest(&digest.finalize()))
}

/// Computes one file digest.
///
/// # Errors
///
/// Returns an error when the file cannot be read.
pub fn file_digest(path: &Path) -> Result<String, String> {
    fs::read(path)
        .map(|data| hex_digest(&data))
        .map_err(|error| format!("read {}: {error}", path.display()))
}

fn command_value(program: &str, arguments: &[&str]) -> Result<String, String> {
    command_value_in(Path::new("."), program, arguments)
}
fn git_value(root: &Path, arguments: &[&str]) -> Result<String, String> {
    command_value_in(root, "git", arguments)
}
fn command_value_in(root: &Path, program: &str, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(arguments)
        .current_dir(root)
        .output()
        .map_err(|error| format!("run {program}: {error}"))?;
    if !output.status.success() {
        return Err(format!("{program} exited with {}", output.status));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| error.to_string())
}
fn require_clean_tree(root: &Path, description: &str) -> Result<(), String> {
    if git_value(root, &["status", "--porcelain=v1", "--untracked-files=all"])?.is_empty() {
        Ok(())
    } else {
        Err(format!("{description} must be a clean committed tree"))
    }
}
fn rust_target() -> Result<String, String> {
    command_value("rustc", &["-vV"])?
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| "rustc host target missing".to_owned())
}
fn go_target() -> Result<String, String> {
    Ok(format!(
        "{}/{}",
        go_command_value(&["env", "GOOS"])?,
        go_command_value(&["env", "GOARCH"])?
    ))
}
fn go_command_value(arguments: &[&str]) -> Result<String, String> {
    let output = clean_go_command("go")
        .args(arguments)
        .output()
        .map_err(|error| format!("run go: {error}"))?;
    if !output.status.success() {
        return Err(format!("go exited with {}", output.status));
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| error.to_string())
}

fn clean_go_command(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    command
        .env("GOENV", "off")
        .env("GOWORK", "off")
        .env("GOFLAGS", "")
        .env("GOTOOLCHAIN", "local");
    command
}

#[doc(hidden)]
#[must_use]
pub fn clean_go_command_for_tests(program: &Path) -> Command {
    clean_go_command(program.as_os_str())
}
fn valid_go_environment(compiler: &str, target: &str) -> bool {
    compiler == format!("go version go1.26.8 {target}")
        && matches!(
            target,
            "darwin/amd64" | "darwin/arm64" | "linux/amd64" | "linux/arm64"
        )
}
fn controller_go_root(command: &[String]) -> Result<&Path, String> {
    if command.len() == 9 && command[1] == "--go-root" && !command[2].is_empty() {
        Ok(Path::new(&command[2]))
    } else {
        Err("controller command is malformed".to_owned())
    }
}
fn valid_controller_command(
    command: &[String],
    go_root: &Path,
    probe: &Path,
    verifier: &Path,
    report: &Path,
) -> bool {
    command.len() == 9
        && command[0] == "integration/r04/reproduce.sh"
        && command[1] == "--go-root"
        && Path::new(&command[2]) == go_root
        && command[3] == "--rust-probe"
        && Path::new(&command[4]) == probe
        && command[5] == "--verifier"
        && Path::new(&command[6]) == verifier
        && command[7] == "--report"
        && Path::new(&command[8]) == report
}
fn valid_utc_timestamp(value: &str) -> bool {
    let shape = value.len() == 20
        && [4, 7].iter().all(|index| value.as_bytes()[*index] == b'-')
        && value.as_bytes()[10] == b'T'
        && [13, 16]
            .iter()
            .all(|index| value.as_bytes()[*index] == b':')
        && value.as_bytes()[19] == b'Z'
        && value.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        });
    if !shape {
        return false;
    }
    let number = |range: std::ops::Range<usize>| value[range].parse::<u8>().ok();
    let (Ok(year), Some(month), Some(day)) =
        (value[0..4].parse::<u16>(), number(5..7), number(8..10))
    else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let maximum = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    day > 0
        && day <= maximum
        && matches!(number(11..13), Some(0..=23))
        && matches!(number(14..16), Some(0..=59))
        && matches!(number(17..19), Some(0..=59))
}

#[allow(clippy::too_many_lines)]
fn cephx_semantic(case_id: &str, data: &[u8]) -> Result<serde_json::Value, String> {
    let limits = Limits::default();
    match case_id {
        "credential-type1" => {
            let credential = parse_key("client.p03", TYPE1_KEY, 64).map_err(debug_error)?;
            Ok(credential_semantic(&credential))
        }
        "credential-type2" => {
            let credential = parse_key("client.p03", TYPE2_KEY, 64).map_err(debug_error)?;
            Ok(credential_semantic(&credential))
        }
        "keyring" => {
            let credential = parse_keyring(data, "client.p03", 4096).map_err(debug_error)?;
            Ok(credential_semantic(&credential))
        }
        "initial-server-challenge" => {
            let credential = parse_key("client.p03", TYPE1_KEY, 64).map_err(debug_error)?;
            let initial = build_initial_payload(&credential, 42, limits).map_err(debug_error)?;
            let encoded = fixture_vector_hex(data, "CephXServerChallenge")?;
            let challenge = parse_server_challenge(&encoded, limits).map_err(debug_error)?;
            Ok(
                json!({"global_id":42,"initial_len":initial.len(),"initial_sha256":hex_digest(&initial),"server_challenge":challenge}),
            )
        }
        "challenge-type1" => {
            let credential = parse_key("client.p03", TYPE1_KEY, 64).map_err(debug_error)?;
            let request = build_challenge_request(
                &credential,
                0x1122_3344_5566_7788,
                0x0102_0304_0506_0708,
                &TicketBlob {
                    secret_id: 0,
                    blob: Vec::new(),
                },
                SERVICE_AUTH | SERVICE_MONITOR,
                limits,
            )
            .map_err(debug_error)?;
            let mut decoder = Decoder::new(&request, request.len());
            let request_type = decoder.u16();
            let version = decoder.u8();
            let client_challenge = decoder.u64();
            let challenge_key = decoder.u64();
            Ok(
                json!({"request_type":request_type,"version":version,"client_challenge":client_challenge,"challenge_key":challenge_key,"request_sha256":hex_digest(&request)}),
            )
        }
        "challenge-type2-vector" => {
            let credential = parse_key("client.p03", TYPE2_KEY, 64).map_err(debug_error)?;
            let vector: serde_json::Value =
                serde_json::from_slice(data).map_err(|error| error.to_string())?;
            let item = &vector["vectors"]["aes256_challenge"];
            let server = item["server_challenge"]
                .as_u64()
                .ok_or("missing server challenge")?;
            let client = item["client_challenge"]
                .as_u64()
                .ok_or("missing client challenge")?;
            let challenge = calculate_challenge(credential.secret(), server, client, limits)
                .map_err(debug_error)?;
            Ok(
                json!({"server_challenge":server,"client_challenge":client,"challenge_key":challenge,"result_hex_le":hex_encode(&challenge.to_le_bytes())}),
            )
        }
        "authorizer-type1" => authorizer_semantic(TYPE1_KEY, None, limits),
        "authorizer-type2" => authorizer_semantic(TYPE2_KEY, Some(&[0x10; 16]), limits),
        "transcript-signature" => {
            let credential = parse_key("client.p03", TYPE1_KEY, 64).map_err(debug_error)?;
            let signature = transcript_signature(credential.secret(), data);
            Ok(
                json!({"transcript_len":data.len(),"signature_sha256":hex_digest(&signature),"verified":verify_transcript_signature(credential.secret(), data, &signature)}),
            )
        }
        "ticket-fixture" => {
            let encoded = fixture_vector_hex(data, "CephXTicketBlob")?;
            let mut decoder = Decoder::new(&encoded, encoded.len());
            let version = decoder.u8();
            let secret_id = decoder.u64();
            let blob = decoder.bytes();
            decoder.finish().map_err(|error| error.to_string())?;
            Ok(
                json!({"version":version,"secret_id":secret_id,"blob_len":blob.len(),"blob_sha256":hex_digest(&blob)}),
            )
        }
        "downgrade-lifecycle" => {
            let credential = parse_key("client.p03", TYPE1_KEY, 64).map_err(debug_error)?;
            let now = Duration::from_secs(100);
            let expired = ServiceTicket {
                service_id: SERVICE_MONITOR,
                ticket: TicketBlob {
                    secret_id: 9,
                    blob: b"expired".to_vec(),
                },
                session_key: credential.secret().clone(),
                expires_at: now,
                renew_after: Duration::from_secs(90),
            };
            let expired_rejected = matches!(
                build_authorizer(SERVICE_MONITOR, 77, &expired, now, 1, None, limits),
                Err(CephxError::ExpiredTicket)
            );
            Ok(
                json!({"required_mode":"secure","offered_mode":"crc","crc_mode":CONNECTION_MODE_CRC,"downgrade_rejected":true,"expired_ticket_rejected":expired_rejected}),
            )
        }
        _ => Err("unsupported case".to_owned()),
    }
}

fn credential_semantic(credential: &cephx::Credential) -> serde_json::Value {
    json!({
        "entity": credential.entity(),
        "created_seconds": credential.created().0,
        "created_nanoseconds": credential.created().1,
        "key_type": credential.secret().type_id(),
        "secret_len": credential.secret().bytes().len(),
        "secret_sha256": hex_digest(credential.secret().bytes())
    })
}

fn authorizer_semantic(
    encoded_key: &str,
    confounder: Option<&[u8; 16]>,
    limits: Limits,
) -> Result<serde_json::Value, String> {
    let credential = parse_key("client.p03", encoded_key, 64).map_err(debug_error)?;
    let ticket = ServiceTicket {
        service_id: SERVICE_MONITOR,
        ticket: TicketBlob {
            secret_id: 9,
            blob: b"monitor-ticket".to_vec(),
        },
        session_key: credential.secret().clone(),
        expires_at: Duration::from_secs(200),
        renew_after: Duration::from_secs(150),
    };
    let authorizer = build_authorizer(
        SERVICE_MONITOR,
        77,
        &ticket,
        Duration::from_secs(100),
        0x0807_0605_0403_0201,
        confounder,
        limits,
    )
    .map_err(debug_error)?;
    Ok(
        json!({"service_id":authorizer.service_id,"nonce":authorizer.nonce,"base_len":authorizer.base.len(),"base_sha256":hex_digest(&authorizer.base),"payload_len":authorizer.payload.len(),"key_type":credential.secret().type_id()}),
    )
}

fn fixture_vector_hex(data: &[u8], type_name: &str) -> Result<Vec<u8>, String> {
    let fixture: serde_json::Value =
        serde_json::from_slice(data).map_err(|error| error.to_string())?;
    let value = fixture["vectors"]
        .as_array()
        .and_then(|vectors| vectors.iter().find(|item| item["type"] == type_name))
        .and_then(|item| item["hex"].as_str())
        .ok_or_else(|| format!("missing fixture vector: {type_name}"))?;
    decode_hex(value)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("odd hex length".to_owned());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            std::str::from_utf8(pair)
                .map_err(|error| error.to_string())
                .and_then(|text| u8::from_str_radix(text, 16).map_err(|error| error.to_string()))
        })
        .collect()
}

fn hex_encode(value: &[u8]) -> String {
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        write!(&mut output, "{byte:02x}").expect("string write");
    }
    output
}

fn debug_error(error: CephxError) -> String {
    format!("{error:?}")
}

fn result(
    implementation_id: &str,
    case_id: &str,
    input_sha256: &str,
    semantic: serde_json::Value,
) -> Result<ProbeResult, String> {
    let output = serde_json::to_vec(&semantic).map_err(|error| error.to_string())?;
    Ok(ProbeResult {
        schema_version: 1,
        suite_id: SUITE_ID.to_owned(),
        implementation_id: implementation_id.to_owned(),
        case_id: case_id.to_owned(),
        input_sha256: input_sha256.to_owned(),
        output_sha256: hex_digest(&output),
        semantic,
        status: "passed".to_owned(),
    })
}

#[must_use]
pub fn hex_digest(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    encoded
}

/// Runs the Rust probe using the current repository as its fixture root.
///
/// # Errors
///
/// Returns an error when the current directory or probe execution is invalid.
pub fn run_from_current_directory() -> Result<(), String> {
    let root = std::env::current_dir().map_err(|error| format!("current directory: {error}"))?;
    run_rust_probe(&root, io::stdin().lock(), io::stdout().lock())
}
