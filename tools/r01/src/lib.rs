#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[path = "../../../src/entity_name.rs"]
mod entity_name;
use entity_name::EntityName;

pub const IMPLEMENTATION_RUST: &str = "rust";
pub const OPERATION: &str = "entity-name-round-trip";
pub const CASE_ID: &str = "p01/entity-name-client-1";
pub const FIXTURE_PATH: &str = "testdata/p01/entity-name-client-1.bin";
pub const FIXTURE_SHA256: &str = "0ea9e19802a23c4674e289fabeaa6e600262fb9ad25ae64fd4fb927651b6abe9";
pub const MAX_RECORD_BYTES: u64 = 4_096;
pub const FIXTURE_BYTES: usize = 9;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeRequest {
    pub schema_version: u32,
    pub case_id: String,
    pub operation: String,
    pub fixture: Fixture,
    pub limits: Limits,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fixture {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_record_bytes: u64,
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeResult {
    pub schema_version: u32,
    pub case_id: String,
    pub implementation_id: String,
    pub operation: String,
    pub fixture_sha256: String,
    pub fields: EntityNameFields,
    pub encoded_base64: String,
    pub encoded_sha256: String,
    pub status: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntityNameFields {
    pub entity_type: u8,
    pub number: String,
}

/// Runs the bounded Rust fixture probe.
///
/// # Errors
///
/// Returns an error when the request, fixture, codec, or output violates the R01 contract.
pub fn run_rust_probe(root: &Path, input: impl Read, output: impl Write) -> Result<(), String> {
    let request = read_request(input)?;
    validate_request(&request)?;

    let fixture_path = root.join(FIXTURE_PATH);
    let metadata =
        fs::metadata(&fixture_path).map_err(|error| format!("read fixture metadata: {error}"))?;
    if metadata.len() != FIXTURE_BYTES as u64 {
        return Err(format!(
            "fixture contains {} bytes, expected {FIXTURE_BYTES}",
            metadata.len()
        ));
    }
    let fixture = fs::read(&fixture_path).map_err(|error| format!("read fixture: {error}"))?;
    let fixture_hash = hex_digest(&fixture);
    if fixture_hash != FIXTURE_SHA256 {
        return Err(format!(
            "fixture hash is {fixture_hash}, expected {FIXTURE_SHA256}"
        ));
    }

    let entity = EntityName::decode(&fixture).map_err(|error| error.to_string())?;
    let encoded = entity.encode();
    let result = ProbeResult {
        schema_version: 1,
        case_id: CASE_ID.to_owned(),
        implementation_id: IMPLEMENTATION_RUST.to_owned(),
        operation: OPERATION.to_owned(),
        fixture_sha256: fixture_hash,
        fields: EntityNameFields {
            entity_type: entity.entity_type(),
            number: entity.number().to_string(),
        },
        encoded_base64: BASE64.encode(encoded),
        encoded_sha256: hex_digest(&encoded),
        status: "passed".to_owned(),
    };
    write_result(output, &result)
}

fn read_request(input: impl Read) -> Result<ProbeRequest, String> {
    let mut data = Vec::new();
    input
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|error| format!("read request: {error}"))?;
    if data.len() as u64 > MAX_RECORD_BYTES {
        return Err(format!("request exceeds {MAX_RECORD_BYTES} bytes"));
    }
    serde_json::from_slice(&data).map_err(|error| format!("decode request: {error}"))
}

fn validate_request(request: &ProbeRequest) -> Result<(), String> {
    if request.schema_version != 1
        || request.case_id != CASE_ID
        || request.operation != OPERATION
        || request.fixture.path != FIXTURE_PATH
        || request.fixture.sha256 != FIXTURE_SHA256
    {
        return Err("request identity does not match the supported R01 case".to_owned());
    }
    if request.limits.max_record_bytes != MAX_RECORD_BYTES
        || request.limits.max_input_bytes != FIXTURE_BYTES as u64
        || request.limits.max_output_bytes != FIXTURE_BYTES as u64
    {
        return Err("request limits do not match the supported R01 bounds".to_owned());
    }
    Ok(())
}

fn write_result(mut output: impl Write, result: &ProbeResult) -> Result<(), String> {
    let mut encoded =
        serde_json::to_vec(result).map_err(|error| format!("encode result: {error}"))?;
    encoded.push(b'\n');
    if encoded.len() as u64 > MAX_RECORD_BYTES {
        return Err("probe result exceeds record bound".to_owned());
    }
    output
        .write_all(&encoded)
        .map_err(|error| format!("write result: {error}"))
}

/// Returns the lowercase SHA-256 digest of `data`.
#[must_use]
pub fn hex_digest(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    encoded
}

/// Returns the canonical request accepted by the R01 probes.
#[must_use]
pub fn default_request_json() -> String {
    format!(
        "{{\"schema_version\":1,\"case_id\":\"{CASE_ID}\",\"operation\":\"{OPERATION}\",\"fixture\":{{\"path\":\"{FIXTURE_PATH}\",\"sha256\":\"{FIXTURE_SHA256}\"}},\"limits\":{{\"max_record_bytes\":{MAX_RECORD_BYTES},\"max_input_bytes\":{FIXTURE_BYTES},\"max_output_bytes\":{FIXTURE_BYTES}}}}}\n"
    )
}

/// Runs the Rust probe over standard input and output from the current repository root.
///
/// # Errors
///
/// Returns an error when probe execution fails.
pub fn run_from_current_directory() -> Result<(), String> {
    run_rust_probe(Path::new("."), io::stdin().lock(), io::stdout().lock())
}

pub const GO_REVISION: &str = "c8bb148a1379b51ef87256c27f366a05f8da4dc4";
pub const GO_TREE: &str = "c5039b6b50a05b942a902f70dc2fcb090463e8c7";
pub const GO_LOCKFILE_SHA256: &str =
    "aada9d87cdf1fc9761055ae34522bdc35421d952dcc19d6f5323dd2dc087333c";
pub const CEPH_IMAGE: &str =
    "quay.io/ceph/ceph@sha256:6bb1c8a42fbc0bf87938946990b65174466997bc11c31eb5a323225a779fd8f9";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeReport {
    pub schema_version: u32,
    pub case_id: String,
    pub operation: String,
    pub status: String,
    pub generated_at: String,
    pub fixture: ReportFixture,
    pub bounds: ReportBounds,
    pub rust: ImplementationEvidence,
    pub go: ImplementationEvidence,
    pub controller: ControllerEvidence,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportFixture {
    pub path: String,
    pub sha256: String,
    pub provenance_manifest_sha256: String,
    pub ceph_image: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportBounds {
    pub max_record_bytes: u64,
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationEvidence {
    pub implementation_id: String,
    pub source_revision: String,
    pub source_tree: String,
    pub source_files_sha256: String,
    pub features: Vec<String>,
    pub lockfile_sha256: String,
    pub compiler: String,
    pub target: String,
    pub driver_sha256: String,
    pub command: Vec<String>,
    pub exit_code: i32,
    pub stdout_sha256: String,
    pub result: ProbeResult,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerEvidence {
    pub path: String,
    pub sha256: String,
    pub command: Vec<String>,
}

struct VerificationContext<'a> {
    root: &'a Path,
    report_path: &'a Path,
    verifier_path: &'a Path,
    expected_rust_probe: &'a Path,
    go_compiler: &'a str,
    go_target: &'a str,
    verify_go_checkout: bool,
}

fn verify_report(context: &VerificationContext<'_>, data: &[u8]) -> Result<(), String> {
    let root = context.root;
    let report_path = context.report_path;
    let verifier_path = context.verifier_path;
    let expected_rust_probe = context.expected_rust_probe;
    let go_compiler = context.go_compiler;
    let go_target_value = context.go_target;
    let verify_go_checkout = context.verify_go_checkout;
    if data.len() as u64 > MAX_RECORD_BYTES * 4 {
        return Err("report exceeds 16384 bytes".to_owned());
    }
    let report: BridgeReport =
        serde_json::from_slice(data).map_err(|error| format!("decode report: {error}"))?;
    if report.schema_version != 1
        || report.case_id != CASE_ID
        || report.operation != OPERATION
        || report.status != "passed"
        || !valid_utc_timestamp(&report.generated_at)
    {
        return Err("report identity or status is invalid".to_owned());
    }
    if report.fixture.path != FIXTURE_PATH
        || report.fixture.sha256 != FIXTURE_SHA256
        || file_digest(&root.join(FIXTURE_PATH))? != FIXTURE_SHA256
        || report.fixture.provenance_manifest_sha256
            != file_digest(&root.join(format!("{FIXTURE_PATH}.json")))?
        || report.fixture.ceph_image != CEPH_IMAGE
    {
        return Err("report fixture evidence is stale or invalid".to_owned());
    }
    if report.bounds.max_record_bytes != MAX_RECORD_BYTES
        || report.bounds.max_input_bytes != FIXTURE_BYTES as u64
        || report.bounds.max_output_bytes != FIXTURE_BYTES as u64
    {
        return Err("report bounds are invalid".to_owned());
    }
    verify_implementation(&report.rust, IMPLEMENTATION_RUST)?;
    verify_implementation(&report.go, "go")?;
    if Path::new(&report.rust.command[0]) != expected_rust_probe
        || report.rust.source_revision != git_value(root, &["rev-parse", "HEAD"])?
        || report.rust.source_tree != git_value(root, &["rev-parse", "HEAD^{tree}"])?
        || report.rust.source_files_sha256 != source_digest(root)?
        || report.rust.features != Vec::<String>::new()
        || report.rust.lockfile_sha256 != file_digest(&root.join("Cargo.lock"))?
        || report.rust.compiler != command_value("rustc", &["--version"])?
        || report.rust.target != rust_target()?
        || report.rust.driver_sha256 != file_digest(Path::new(&report.rust.command[0]))?
        || report.rust.stdout_sha256 != result_stdout_digest(&report.rust.result)?
    {
        return Err("Rust evidence does not match the current candidate".to_owned());
    }
    if report.go.source_revision != GO_REVISION
        || report.go.source_tree != GO_TREE
        || report.go.source_files_sha256 != hex_digest(GO_TREE.as_bytes())
        || report.go.features != Vec::<String>::new()
        || report.go.lockfile_sha256 != GO_LOCKFILE_SHA256
        || report.go.compiler != go_compiler
        || report.go.target != go_target_value
        || !valid_go_environment(go_compiler, go_target_value)
        || report.go.driver_sha256 != path_digest(root, Path::new("tools/r01/go-probe"))?
        || report.go.command != ["go", "run", "./tools/rados-rs-r01-probe"]
        || report.go.stdout_sha256 != result_stdout_digest(&report.go.result)?
    {
        return Err("Go oracle revision is not the pinned R01 snapshot".to_owned());
    }
    if report.rust.result.fields != report.go.result.fields
        || report.rust.result.encoded_base64 != report.go.result.encoded_base64
        || report.rust.result.encoded_sha256 != report.go.result.encoded_sha256
    {
        return Err("Rust and Go probe results differ".to_owned());
    }
    if report.controller.path != "integration/r01/reproduce.sh"
        || report.controller.sha256 != file_digest(&root.join("integration/r01/reproduce.sh"))?
        || !valid_controller_command(
            &report.controller.command,
            report_path,
            verifier_path,
            &report.rust.command[0],
        )
    {
        return Err("controller evidence is invalid".to_owned());
    }
    if verify_go_checkout {
        let go_root = Path::new(&report.controller.command[2]);
        require_clean_tree(go_root, "Go oracle")?;
        if git_value(go_root, &["rev-parse", "HEAD"])? != GO_REVISION
            || git_value(go_root, &["rev-parse", "HEAD^{tree}"])? != GO_TREE
        {
            return Err("controller Go root is not the pinned R01 checkout".to_owned());
        }
    }
    verify_rust_probe_execution(root, &report.rust)?;
    Ok(())
}

fn verify_implementation(
    evidence: &ImplementationEvidence,
    expected_id: &str,
) -> Result<(), String> {
    if evidence.implementation_id != expected_id
        || evidence.result.implementation_id != expected_id
        || evidence.result.schema_version != 1
        || evidence.result.case_id != CASE_ID
        || evidence.result.operation != OPERATION
        || evidence.result.fixture_sha256 != FIXTURE_SHA256
        || evidence.result.fields.entity_type != 8
        || evidence.result.fields.number != "1"
        || evidence.result.encoded_base64 != "CAEAAAAAAAAA"
        || evidence.result.encoded_sha256 != FIXTURE_SHA256
        || evidence.result.status != "passed"
        || evidence.exit_code != 0
        || evidence.source_revision.is_empty()
        || evidence.source_tree.is_empty()
        || evidence.compiler.is_empty()
        || evidence.target.is_empty()
        || evidence.command.len() != 1 && expected_id == IMPLEMENTATION_RUST
        || !is_sha256(&evidence.source_files_sha256)
        || !is_sha256(&evidence.lockfile_sha256)
        || !is_sha256(&evidence.driver_sha256)
        || !is_sha256(&evidence.stdout_sha256)
    {
        return Err(format!("{expected_id} implementation evidence is invalid"));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Verifies a complete R01 bridge report against the candidate root and pinned oracle.
///
/// # Errors
///
/// Returns an error when report parsing or any evidence check fails.
pub fn verify_report_file(root: &Path, path: &Path) -> Result<(), String> {
    require_clean_tree(root, "Rust candidate")?;
    let mut data = Vec::new();
    fs::File::open(path)
        .map_err(|error| format!("open report: {error}"))?
        .take(MAX_RECORD_BYTES * 4 + 1)
        .read_to_end(&mut data)
        .map_err(|error| format!("read report: {error}"))?;
    let verifier = std::env::current_exe().map_err(|error| format!("locate verifier: {error}"))?;
    let rust_probe = verifier.with_file_name("rados-r01-probe");
    let go_compiler = command_value("go", &["version"])?;
    let go_target_value = go_target()?;
    verify_report(
        &VerificationContext {
            root,
            report_path: path,
            verifier_path: &verifier,
            expected_rust_probe: &rust_probe,
            go_compiler: &go_compiler,
            go_target: &go_target_value,
            verify_go_checkout: true,
        },
        &data,
    )
}

/// Computes a lowercase SHA-256 digest for one file.
///
/// # Errors
///
/// Returns an error when the file cannot be read.
pub fn file_digest(path: &Path) -> Result<String, String> {
    let data = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    Ok(hex_digest(&data))
}

/// Computes the deterministic digest of all shipped R01 candidate inputs.
///
/// # Errors
///
/// Returns an error when an input cannot be inspected or read.
pub fn source_digest(root: &Path) -> Result<String, String> {
    const FILES: &[&str] = &[
        "Cargo.lock",
        "Cargo.toml",
        "LICENSE",
        "README.md",
        "THIRD_PARTY_NOTICES",
        "deny.toml",
        "rust-toolchain.toml",
    ];
    const DIRECTORIES: &[&str] = &[
        ".github/workflows",
        "docs/r02",
        "docs/r01",
        "examples",
        "integration/r01",
        "src",
        "testdata/p01",
        "tools/r01",
    ];
    let mut paths = FILES.iter().map(PathBuf::from).collect::<Vec<_>>();
    for directory in DIRECTORIES {
        collect_files(root, Path::new(directory), &mut paths)?;
    }
    digest_relative_paths(root, &mut paths)
}

/// Computes a deterministic digest for a repository-relative file tree.
///
/// # Errors
///
/// Returns an error when the path cannot be inspected or read.
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
    let entries = fs::read_dir(&absolute)
        .map_err(|error| format!("read directory {}: {error}", absolute.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read directory entry: {error}"))?;
        collect_files(root, &relative.join(entry.file_name()), paths)?;
    }
    Ok(())
}

fn digest_relative_paths(root: &Path, paths: &mut Vec<PathBuf>) -> Result<String, String> {
    paths.sort();
    paths.dedup();
    let mut digest = Sha256::new();
    for relative in paths.iter() {
        let path = relative
            .to_str()
            .ok_or_else(|| format!("non-UTF-8 evidence path: {}", relative.display()))?;
        let data = fs::read(root.join(relative))
            .map_err(|error| format!("read evidence path {path}: {error}"))?;
        digest.update((path.len() as u64).to_le_bytes());
        digest.update(path.as_bytes());
        digest.update((data.len() as u64).to_le_bytes());
        digest.update(&data);
    }
    Ok(hex_digest(&digest.finalize()))
}

fn result_stdout_digest(result: &ProbeResult) -> Result<String, String> {
    let mut data = serde_json::to_vec(result).map_err(|error| format!("encode result: {error}"))?;
    data.push(b'\n');
    Ok(hex_digest(&data))
}

fn verify_rust_probe_execution(
    root: &Path,
    evidence: &ImplementationEvidence,
) -> Result<(), String> {
    let mut child = Command::new(&evidence.command[0])
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("start Rust probe: {error}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "Rust probe stdin is unavailable".to_owned())?
        .write_all(default_request_json().as_bytes())
        .map_err(|error| format!("write Rust probe request: {error}"))?;
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .ok_or_else(|| "Rust probe stdout is unavailable".to_owned())?
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut output)
        .map_err(|error| format!("read Rust probe result: {error}"))?;
    if output.len() as u64 > MAX_RECORD_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return Err("Rust probe result exceeds record bound".to_owned());
    }
    let status = child
        .wait()
        .map_err(|error| format!("wait for Rust probe: {error}"))?;
    let mut expected = serde_json::to_vec(&evidence.result)
        .map_err(|error| format!("encode expected Rust result: {error}"))?;
    expected.push(b'\n');
    if !status.success() || output != expected {
        return Err("reported Rust probe does not reproduce its result".to_owned());
    }
    Ok(())
}

fn git_value(root: &Path, arguments: &[&str]) -> Result<String, String> {
    command_value_in(root, "git", arguments)
}

fn require_clean_tree(root: &Path, description: &str) -> Result<(), String> {
    let status = git_value(root, &["status", "--porcelain=v1", "--untracked-files=all"])?;
    if status.is_empty() {
        Ok(())
    } else {
        Err(format!("{description} must be a clean committed tree"))
    }
}

fn command_value(program: &str, arguments: &[&str]) -> Result<String, String> {
    command_value_in(Path::new("."), program, arguments)
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
        .map_err(|error| format!("decode {program} output: {error}"))
}

fn rust_target() -> Result<String, String> {
    let verbose = command_value("rustc", &["-vV"])?;
    verbose
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| "rustc did not report a host target".to_owned())
}

fn go_target() -> Result<String, String> {
    Ok(format!(
        "{}/{}",
        command_value("go", &["env", "GOOS"])?,
        command_value("go", &["env", "GOARCH"])?
    ))
}

fn valid_go_environment(compiler: &str, target: &str) -> bool {
    compiler == format!("go version go1.26.8 {target}")
        && matches!(
            target,
            "darwin/amd64" | "darwin/arm64" | "linux/amd64" | "linux/arm64"
        )
}

fn valid_utc_timestamp(value: &str) -> bool {
    let valid_shape = value.len() == 20
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value.as_bytes()[10] == b'T'
        && value.as_bytes()[13] == b':'
        && value.as_bytes()[16] == b':'
        && value.as_bytes()[19] == b'Z'
        && value.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        });
    if !valid_shape {
        return false;
    }
    let number = |range: std::ops::Range<usize>| value[range].parse::<u8>().ok();
    let (Some(year), Some(month), Some(day)) =
        (value[0..4].parse::<u16>().ok(), number(5..7), number(8..10))
    else {
        return false;
    };
    let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let maximum_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => return false,
    };
    day > 0
        && day <= maximum_day
        && matches!(number(11..13), Some(0..=23))
        && matches!(number(14..16), Some(0..=59))
        && matches!(number(17..19), Some(0..=59))
}

fn valid_controller_command(
    command: &[String],
    report_path: &Path,
    verifier_path: &Path,
    rust_probe: &str,
) -> bool {
    command.len() == 9
        && command[0] == "integration/r01/reproduce.sh"
        && command[1] == "--go-root"
        && !command[2].is_empty()
        && command[3] == "--rust-probe"
        && command[4] == rust_probe
        && command[5] == "--verifier"
        && Path::new(&command[6]) == verifier_path
        && command[7] == "--report"
        && Path::new(&command[8]) == report_path
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TEST_GO_TARGET: &str = if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "darwin/arm64"
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        "darwin/amd64"
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        "linux/arm64"
    } else {
        "linux/amd64"
    };

    fn test_go_compiler() -> String {
        format!("go version go1.26.8 {TEST_GO_TARGET}")
    }

    #[test]
    fn rust_probe_round_trips_the_native_fixture() {
        let mut output = Vec::new();
        run_rust_probe(
            Path::new("../.."),
            default_request_json().as_bytes(),
            &mut output,
        )
        .expect("probe must pass");
        let value: serde_json::Value = serde_json::from_slice(&output).expect("valid result JSON");

        assert_eq!(value["implementation_id"], IMPLEMENTATION_RUST);
        assert_eq!(value["fields"]["entity_type"], 8);
        assert_eq!(value["fields"]["number"], "1");
        assert_eq!(value["encoded_sha256"], FIXTURE_SHA256);
    }

    #[test]
    fn probe_rejects_oversized_and_unknown_requests() {
        let oversized = vec![b' '; usize::try_from(MAX_RECORD_BYTES).expect("record bound") + 1];
        assert!(run_rust_probe(Path::new("../.."), oversized.as_slice(), Vec::new()).is_err());

        let unknown = default_request_json().replace(
            "\"schema_version\":1",
            "\"extra\":true,\"schema_version\":1",
        );
        assert!(run_rust_probe(Path::new("../.."), unknown.as_bytes(), Vec::new()).is_err());
    }

    #[test]
    fn probe_rejects_changed_identity_and_bounds() {
        let stale = default_request_json().replace(FIXTURE_SHA256, &"0".repeat(64));
        assert!(run_rust_probe(Path::new("../.."), stale.as_bytes(), Vec::new()).is_err());

        let unbounded =
            default_request_json().replace("\"max_input_bytes\":9", "\"max_input_bytes\":10");
        assert!(run_rust_probe(Path::new("../.."), unbounded.as_bytes(), Vec::new()).is_err());
    }

    fn probe_result(implementation_id: &str) -> ProbeResult {
        ProbeResult {
            schema_version: 1,
            case_id: CASE_ID.to_owned(),
            implementation_id: implementation_id.to_owned(),
            operation: OPERATION.to_owned(),
            fixture_sha256: FIXTURE_SHA256.to_owned(),
            fields: EntityNameFields {
                entity_type: 8,
                number: "1".to_owned(),
            },
            encoded_base64: "CAEAAAAAAAAA".to_owned(),
            encoded_sha256: FIXTURE_SHA256.to_owned(),
            status: "passed".to_owned(),
        }
    }

    fn test_probe(result: &ProbeResult) -> PathBuf {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "rados-r01-probe-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let output = serde_json::to_string(result).expect("encode probe result");
        fs::write(
            &path,
            format!("#!/bin/sh\nIFS= read -r request\nprintf '%s\\n' '{output}'\n"),
        )
        .expect("write test probe");
        let mut permissions = fs::metadata(&path)
            .expect("test probe metadata")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).expect("make test probe executable");
        path
    }

    fn verify_test_report(
        root: &Path,
        report_path: &Path,
        verifier: &Path,
        report: &[u8],
    ) -> Result<(), String> {
        let value: serde_json::Value = serde_json::from_slice(report).expect("decode test report");
        let rust_probe = Path::new(
            value["rust"]["command"][0]
                .as_str()
                .unwrap_or("/missing/rados-r01-probe"),
        );
        let go_compiler = test_go_compiler();
        verify_report(
            &VerificationContext {
                root,
                report_path,
                verifier_path: verifier,
                expected_rust_probe: rust_probe,
                go_compiler: &go_compiler,
                go_target: TEST_GO_TARGET,
                verify_go_checkout: false,
            },
            report,
        )
    }

    fn valid_report() -> (serde_json::Value, PathBuf, PathBuf, PathBuf) {
        let root = PathBuf::from("../..");
        let verifier = std::env::current_exe().expect("test executable");
        let report_path = PathBuf::from("/tmp/rados-r01-test-report.json");
        let rust_result = probe_result("rust");
        let go_result = probe_result("go");
        let executable = test_probe(&rust_result);
        let report = serde_json::json!({
            "schema_version": 1,
            "case_id": CASE_ID,
            "operation": OPERATION,
            "status": "passed",
            "generated_at": "2026-09-17T00:00:00Z",
            "fixture": {
                "path": FIXTURE_PATH,
                "sha256": FIXTURE_SHA256,
                "provenance_manifest_sha256": file_digest(&root.join(format!("{FIXTURE_PATH}.json"))).expect("manifest digest"),
                "ceph_image": CEPH_IMAGE
            },
            "bounds": {
                "max_record_bytes": MAX_RECORD_BYTES,
                "max_input_bytes": FIXTURE_BYTES,
                "max_output_bytes": FIXTURE_BYTES
            },
            "rust": {
                "implementation_id": "rust",
                "source_revision": git_value(&root, &["rev-parse", "HEAD"]).expect("Rust revision"),
                "source_tree": git_value(&root, &["rev-parse", "HEAD^{tree}"]).expect("Rust tree"),
                "source_files_sha256": source_digest(&root).expect("source digest"),
                "features": [],
                "lockfile_sha256": file_digest(&root.join("Cargo.lock")).expect("lockfile digest"),
                "compiler": command_value("rustc", &["--version"]).expect("Rust compiler"),
                "target": rust_target().expect("Rust target"),
                "driver_sha256": file_digest(&executable).expect("executable digest"),
                "command": [executable.to_string_lossy()],
                "exit_code": 0,
                "stdout_sha256": result_stdout_digest(&rust_result).expect("Rust stdout digest"),
                "result": rust_result
            },
            "go": {
                "implementation_id": "go",
                "source_revision": GO_REVISION,
                "source_tree": GO_TREE,
                "source_files_sha256": hex_digest(GO_TREE.as_bytes()),
                "features": [],
                "lockfile_sha256": GO_LOCKFILE_SHA256,
                "compiler": test_go_compiler(),
                "target": TEST_GO_TARGET,
                "driver_sha256": path_digest(&root, Path::new("tools/r01/go-probe")).expect("Go adapter digest"),
                "command": ["go", "run", "./tools/rados-rs-r01-probe"],
                "exit_code": 0,
                "stdout_sha256": result_stdout_digest(&go_result).expect("Go stdout digest"),
                "result": go_result
            },
            "controller": {
                "path": "integration/r01/reproduce.sh",
                "sha256": file_digest(&root.join("integration/r01/reproduce.sh")).expect("controller digest"),
                "command": ["integration/r01/reproduce.sh", "--go-root", "/tmp/go", "--rust-probe", executable.to_string_lossy(), "--verifier", verifier.to_string_lossy(), "--report", report_path.to_string_lossy()]
            }
        });
        (report, root, report_path, verifier)
    }

    #[test]
    fn verifier_accepts_complete_matching_report() {
        let (report, root, report_path, executable) = valid_report();
        let report = serde_json::to_vec(&report).expect("encode report");
        verify_test_report(&root, &report_path, &executable, &report).expect("report must pass");
    }

    #[test]
    fn verifier_rejects_stale_fixture_hash() {
        let (mut report, root, report_path, executable) = valid_report();
        report["fixture"]["sha256"] = serde_json::json!("0".repeat(64));
        assert!(
            verify_test_report(
                &root,
                &report_path,
                &executable,
                &serde_json::to_vec(&report).expect("encode report")
            )
            .is_err()
        );
    }

    #[test]
    fn verifier_rejects_missing_probe() {
        let (mut report, root, report_path, executable) = valid_report();
        report
            .as_object_mut()
            .expect("report object")
            .remove("rust");
        assert!(
            verify_test_report(
                &root,
                &report_path,
                &executable,
                &serde_json::to_vec(&report).expect("encode report")
            )
            .is_err()
        );
    }

    #[test]
    fn verifier_rejects_wrong_implementation_id() {
        let (mut report, root, report_path, executable) = valid_report();
        report["rust"]["implementation_id"] = serde_json::json!("go");
        assert!(
            verify_test_report(
                &root,
                &report_path,
                &executable,
                &serde_json::to_vec(&report).expect("encode report")
            )
            .is_err()
        );
    }

    #[test]
    fn verifier_rejects_stale_candidate_hash() {
        let (mut report, root, report_path, executable) = valid_report();
        report["rust"]["source_files_sha256"] = serde_json::json!("0".repeat(64));
        assert!(
            verify_test_report(
                &root,
                &report_path,
                &executable,
                &serde_json::to_vec(&report).expect("encode report")
            )
            .is_err()
        );
    }

    #[test]
    fn verifier_rejects_substituted_executable() {
        let (mut report, root, report_path, verifier) = valid_report();
        let substitute = test_probe(&probe_result("rust"));
        report["rust"]["command"][0] = serde_json::json!(substitute.to_string_lossy());
        report["rust"]["driver_sha256"] =
            serde_json::json!(file_digest(&substitute).expect("substitute digest"));
        assert!(
            verify_report(
                &VerificationContext {
                    root: &root,
                    report_path: &report_path,
                    verifier_path: &verifier,
                    expected_rust_probe: Path::new("/expected/rados-r01-probe"),
                    go_compiler: &test_go_compiler(),
                    go_target: TEST_GO_TARGET,
                    verify_go_checkout: false,
                },
                &serde_json::to_vec(&report).expect("encode report")
            )
            .is_err()
        );
    }

    #[test]
    fn timestamp_requires_a_real_calendar_date() {
        assert!(valid_utc_timestamp("2024-02-29T23:59:59Z"));
        assert!(!valid_utc_timestamp("2024-02-29T23:59:60Z"));
        assert!(!valid_utc_timestamp("2026-02-29T00:00:00Z"));
        assert!(!valid_utc_timestamp("2026-04-31T00:00:00Z"));
    }
}
