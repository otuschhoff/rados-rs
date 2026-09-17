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

#[allow(dead_code)]
#[path = "../../../src/wire/codec.rs"]
mod codec;
use codec::{Decoder, Encoder};

pub const CASE_ID: &str = "r02/versioned-envelope-newer-compatible";
pub const OPERATION: &str = "versioned-envelope-round-trip";
pub const INPUT_BASE64: &str = "AwEDAAAAAQL/";
pub const INPUT_SHA256: &str = "ddf6a266b64aecd343a549cf7f07562e2622236ec8cef93133a1b00372361edb";
pub const MAX_RECORD_BYTES: u64 = 4_096;
pub const INPUT_BYTES: usize = 9;
pub const LOCAL_VERSION: u8 = 2;
pub const STRUCT_VERSION: u8 = 3;
pub const STRUCT_COMPAT: u8 = 1;
pub const GO_REVISION: &str = "c8bb148a1379b51ef87256c27f366a05f8da4dc4";
pub const GO_TREE: &str = "c5039b6b50a05b942a902f70dc2fcb090463e8c7";
pub const GO_LOCKFILE_SHA256: &str =
    "aada9d87cdf1fc9761055ae34522bdc35421d952dcc19d6f5323dd2dc087333c";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeRequest {
    schema_version: u32,
    case_id: String,
    operation: String,
    local_version: u8,
    input: ProbeInput,
    limits: Bounds,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeInput {
    encoded_base64: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
struct Bounds {
    max_record_bytes: u64,
    max_input_bytes: u64,
    max_output_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeResult {
    schema_version: u32,
    case_id: String,
    implementation_id: String,
    operation: String,
    input_sha256: String,
    fields: EnvelopeFields,
    encoded_base64: String,
    encoded_sha256: String,
    status: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeFields {
    local_version: u8,
    struct_version: u8,
    struct_compat: u8,
    known_value: u16,
    trailing_base64: String,
}

/// Runs the strict bounded Rust envelope probe.
///
/// # Errors
///
/// Returns an error when the request, envelope, or output violates the R02 contract.
pub fn run_rust_probe(input: impl Read, output: impl Write) -> Result<(), String> {
    let request = read_request(input)?;
    validate_request(&request)?;
    let encoded = BASE64
        .decode(&request.input.encoded_base64)
        .map_err(|error| format!("decode input base64: {error}"))?;
    if encoded.len() != INPUT_BYTES || hex_digest(&encoded) != INPUT_SHA256 {
        return Err("input bytes do not match the fixed R02 case".to_owned());
    }

    let mut decoder = Decoder::new(&encoded, INPUT_BYTES);
    let (version, mut payload) = decoder.versioned(LOCAL_VERSION);
    let known_value = payload.u16();
    let trailing = payload.raw(payload.remaining());
    payload.finish().map_err(|error| error.to_string())?;
    if decoder.remaining() != 0 {
        return Err("bytes remain after the versioned envelope".to_owned());
    }
    decoder.finish().map_err(|error| error.to_string())?;

    let mut output_encoder = Encoder::new(INPUT_BYTES);
    output_encoder.versioned(version, STRUCT_COMPAT, |payload| {
        payload.u16(known_value);
        payload.raw(&trailing);
    });
    let reencoded = output_encoder.finish().map_err(|error| error.to_string())?;
    if reencoded != encoded {
        return Err("versioned envelope did not re-encode exactly".to_owned());
    }

    write_result(
        output,
        &ProbeResult {
            schema_version: 1,
            case_id: CASE_ID.to_owned(),
            implementation_id: "rust".to_owned(),
            operation: OPERATION.to_owned(),
            input_sha256: INPUT_SHA256.to_owned(),
            fields: EnvelopeFields {
                local_version: LOCAL_VERSION,
                struct_version: version,
                struct_compat: STRUCT_COMPAT,
                known_value,
                trailing_base64: BASE64.encode(trailing),
            },
            encoded_base64: BASE64.encode(&reencoded),
            encoded_sha256: hex_digest(&reencoded),
            status: "passed".to_owned(),
        },
    )
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
        || request.local_version != LOCAL_VERSION
        || request.input.encoded_base64 != INPUT_BASE64
        || request.input.sha256 != INPUT_SHA256
    {
        return Err("request identity does not match the supported R02 case".to_owned());
    }
    if request.limits.max_record_bytes != MAX_RECORD_BYTES
        || request.limits.max_input_bytes != INPUT_BYTES as u64
        || request.limits.max_output_bytes != INPUT_BYTES as u64
    {
        return Err("request limits do not match the supported R02 bounds".to_owned());
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

/// Returns the canonical request accepted by both probes.
#[must_use]
pub fn default_request_json() -> String {
    format!(
        "{{\"schema_version\":1,\"case_id\":\"{CASE_ID}\",\"operation\":\"{OPERATION}\",\"local_version\":{LOCAL_VERSION},\"input\":{{\"encoded_base64\":\"{INPUT_BASE64}\",\"sha256\":\"{INPUT_SHA256}\"}},\"limits\":{{\"max_record_bytes\":{MAX_RECORD_BYTES},\"max_input_bytes\":{INPUT_BYTES},\"max_output_bytes\":{INPUT_BYTES}}}}}\n"
    )
}

/// Runs the Rust probe over standard input and output.
///
/// # Errors
///
/// Returns an error when probe execution fails.
pub fn run_from_current_directory() -> Result<(), String> {
    run_rust_probe(io::stdin().lock(), io::stdout().lock())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeReport {
    schema_version: u32,
    case_id: String,
    operation: String,
    status: String,
    generated_at: String,
    input: ReportInput,
    bounds: Bounds,
    rust: ImplementationEvidence,
    go: ImplementationEvidence,
    artifacts: ArtifactEvidence,
    controller: ControllerEvidence,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportInput {
    encoded_base64: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImplementationEvidence {
    implementation_id: String,
    source_revision: String,
    source_tree: String,
    source_files_sha256: String,
    features: Vec<String>,
    lockfile_sha256: String,
    compiler: String,
    target: String,
    driver_sha256: String,
    command: Vec<String>,
    exit_code: i32,
    stdout_sha256: String,
    result: ProbeResult,
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
        return Err("report identity, status, or timestamp is invalid".to_owned());
    }
    if report.input.encoded_base64 != INPUT_BASE64 || report.input.sha256 != INPUT_SHA256 {
        return Err("report input evidence is stale or invalid".to_owned());
    }
    if report.bounds.max_record_bytes != MAX_RECORD_BYTES
        || report.bounds.max_input_bytes != INPUT_BYTES as u64
        || report.bounds.max_output_bytes != INPUT_BYTES as u64
    {
        return Err("report bounds are invalid".to_owned());
    }
    verify_implementation(&report.rust, "rust")?;
    verify_implementation(&report.go, "go")?;
    let root = context.root;
    if report.rust.command.len() != 1
        || Path::new(&report.rust.command[0]) != context.expected_rust_probe
        || report.rust.source_revision != git_value(root, &["rev-parse", "HEAD"])?
        || report.rust.source_tree != git_value(root, &["rev-parse", "HEAD^{tree}"])?
        || report.rust.source_files_sha256 != source_digest(root)?
        || !report.rust.features.is_empty()
        || report.rust.lockfile_sha256 != file_digest(&root.join("Cargo.lock"))?
        || report.rust.compiler != command_value("rustc", &["--version"])?
        || report.rust.target != rust_target()?
        || report.rust.driver_sha256 != file_digest(Path::new(&report.rust.command[0]))?
        || report.rust.stdout_sha256 != result_stdout_digest(&report.rust.result)?
    {
        return Err("Rust evidence does not match the current R02 candidate".to_owned());
    }
    if report.go.source_revision != GO_REVISION
        || report.go.source_tree != GO_TREE
        || report.go.source_files_sha256 != hex_digest(GO_TREE.as_bytes())
        || !report.go.features.is_empty()
        || report.go.lockfile_sha256 != GO_LOCKFILE_SHA256
        || report.go.compiler != context.go_compiler
        || report.go.target != context.go_target
        || !valid_go_environment(context.go_compiler, context.go_target)
        || report.go.driver_sha256 != report.artifacts.adapter_sha256
        || report.go.command != ["go", "run", "./tools/rados-rs-r02-probe"]
        || report.go.stdout_sha256 != result_stdout_digest(&report.go.result)?
    {
        return Err("Go oracle evidence does not match the pinned R02 snapshot".to_owned());
    }
    if report.rust.result != expected_result("rust")
        || report.go.result != expected_result("go")
        || result_without_implementation(&report.rust.result)
            != result_without_implementation(&report.go.result)
    {
        return Err("Rust and Go probe results differ from the fixed R02 result".to_owned());
    }
    if report.artifacts.adapter_path != "tools/r02/go-probe"
        || report.artifacts.adapter_sha256 != path_digest(root, Path::new("tools/r02/go-probe"))?
        || report.artifacts.schema_path != "integration/r02/report.schema.json"
        || report.artifacts.schema_sha256
            != file_digest(&root.join("integration/r02/report.schema.json"))?
    {
        return Err("adapter or report schema evidence is invalid".to_owned());
    }
    if report.controller.path != "integration/r02/reproduce.sh"
        || report.controller.sha256 != file_digest(&root.join("integration/r02/reproduce.sh"))?
        || !valid_controller_command(
            &report.controller.command,
            context.report_path,
            context.verifier_path,
            &report.rust.command[0],
        )
    {
        return Err("controller evidence is invalid".to_owned());
    }
    if context.verify_go_checkout {
        let go_root = Path::new(&report.controller.command[2]);
        require_clean_tree(go_root, "Go oracle")?;
        if git_value(go_root, &["rev-parse", "HEAD"])? != GO_REVISION
            || git_value(go_root, &["rev-parse", "HEAD^{tree}"])? != GO_TREE
        {
            return Err("controller Go root is not the pinned R02 checkout".to_owned());
        }
    }
    verify_rust_probe_execution(root, &report.rust)
}

fn verify_implementation(
    evidence: &ImplementationEvidence,
    expected_id: &str,
) -> Result<(), String> {
    if evidence.implementation_id != expected_id
        || evidence.result.implementation_id != expected_id
        || evidence.exit_code != 0
        || evidence.source_revision.is_empty()
        || evidence.source_tree.is_empty()
        || evidence.compiler.is_empty()
        || evidence.target.is_empty()
        || evidence.command.is_empty()
        || evidence.command.len() > 16
        || !is_sha256(&evidence.source_files_sha256)
        || !is_sha256(&evidence.lockfile_sha256)
        || !is_sha256(&evidence.driver_sha256)
        || !is_sha256(&evidence.stdout_sha256)
    {
        return Err(format!("{expected_id} implementation evidence is invalid"));
    }
    Ok(())
}

fn expected_result(implementation_id: &str) -> ProbeResult {
    ProbeResult {
        schema_version: 1,
        case_id: CASE_ID.to_owned(),
        implementation_id: implementation_id.to_owned(),
        operation: OPERATION.to_owned(),
        input_sha256: INPUT_SHA256.to_owned(),
        fields: EnvelopeFields {
            local_version: LOCAL_VERSION,
            struct_version: STRUCT_VERSION,
            struct_compat: STRUCT_COMPAT,
            known_value: 0x0201,
            trailing_base64: "/w==".to_owned(),
        },
        encoded_base64: INPUT_BASE64.to_owned(),
        encoded_sha256: INPUT_SHA256.to_owned(),
        status: "passed".to_owned(),
    }
}

fn result_without_implementation(result: &ProbeResult) -> ProbeResult {
    let mut result = result.clone();
    result.implementation_id.clear();
    result
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Verifies a bounded R02 bridge report against the current candidate and pinned oracle.
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
    let rust_probe = verifier.with_file_name("rados-r02-probe");
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

/// Computes a lowercase SHA-256 digest for one file.
///
/// # Errors
///
/// Returns an error when the file cannot be read.
pub fn file_digest(path: &Path) -> Result<String, String> {
    fs::read(path)
        .map(|data| hex_digest(&data))
        .map_err(|error| format!("read {}: {error}", path.display()))
}

/// Computes the deterministic digest of all R02 candidate inputs.
///
/// Generated reports and build output are intentionally outside this manifest.
///
/// # Errors
///
/// Returns an error when an input cannot be inspected or read.
pub fn source_digest(root: &Path) -> Result<String, String> {
    const FILES: &[&str] = &[
        "Cargo.lock",
        "Cargo.toml",
        ".github/workflows/ci.yml",
        ".github/workflows/differential.yml",
        "fuzz/Cargo.toml",
        "LICENSE",
        "README.md",
        "reference/go/internal/protocol/errno.go",
        "reference/imports.json",
        "RUST_THIRD_PARTY_NOTICES",
        "THIRD_PARTY_NOTICES",
        "deny.toml",
        "rust-toolchain.toml",
    ];
    const DIRECTORIES: &[&str] = &[
        "docs/r02",
        "examples",
        "fuzz/fuzz_targets",
        "fuzz/src",
        "integration/r02",
        "src",
        "testdata/p01",
        "tools/r02",
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
    for entry in fs::read_dir(&absolute)
        .map_err(|error| format!("read directory {}: {error}", absolute.display()))?
    {
        let entry = entry.map_err(|error| format!("read directory entry: {error}"))?;
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
            .ok_or_else(|| format!("non-UTF-8 evidence path: {}", relative.display()))?;
        let data = fs::read(root.join(&*relative))
            .map_err(|error| format!("read evidence path {path}: {error}"))?;
        digest.update((path.len() as u64).to_le_bytes());
        digest.update(path.as_bytes());
        digest.update((data.len() as u64).to_le_bytes());
        digest.update(data);
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

fn command_value(program: &str, arguments: &[&str]) -> Result<String, String> {
    command_value_in(Path::new("."), program, arguments)
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
    command_value("rustc", &["-vV"])?
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
    report: &Path,
    verifier: &Path,
    probe: &str,
) -> bool {
    command.len() == 9
        && command[0] == "integration/r02/reproduce.sh"
        && command[1] == "--go-root"
        && !command[2].is_empty()
        && command[3] == "--rust-probe"
        && command[4] == probe
        && command[5] == "--verifier"
        && Path::new(&command[6]) == verifier
        && command[7] == "--report"
        && Path::new(&command[8]) == report
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
    fn rust_probe_accepts_newer_compatible_envelope_and_reencodes_exactly() {
        let mut output = Vec::new();
        run_rust_probe(default_request_json().as_bytes(), &mut output).expect("probe must pass");
        let result: ProbeResult = serde_json::from_slice(&output).expect("valid result");
        assert_eq!(result, expected_result("rust"));
    }

    #[test]
    fn rust_probe_rejects_oversized_unknown_and_stale_input_requests() {
        let oversized = vec![b' '; usize::try_from(MAX_RECORD_BYTES).expect("record bound") + 1];
        assert!(run_rust_probe(oversized.as_slice(), Vec::new()).is_err());
        let unknown = default_request_json().replace(
            "\"schema_version\":1",
            "\"extra\":true,\"schema_version\":1",
        );
        assert!(run_rust_probe(unknown.as_bytes(), Vec::new()).is_err());
        let stale = default_request_json().replace(INPUT_SHA256, &"0".repeat(64));
        assert!(run_rust_probe(stale.as_bytes(), Vec::new()).is_err());
    }

    fn test_probe(result: &ProbeResult) -> PathBuf {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "rados-r02-probe-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let output = serde_json::to_string(result).expect("encode probe result");
        fs::write(
            &path,
            format!("#!/bin/sh\nIFS= read -r request\nprintf '%s\\n' '{output}'\n"),
        )
        .expect("write test probe");
        let mut permissions = fs::metadata(&path).expect("probe metadata").permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).expect("make probe executable");
        path
    }

    fn valid_report() -> (serde_json::Value, PathBuf, PathBuf, PathBuf, PathBuf) {
        let root = PathBuf::from("../..");
        let verifier = std::env::current_exe().expect("test executable");
        let report_path = PathBuf::from("/tmp/rados-r02-test-report.json");
        let rust_result = expected_result("rust");
        let go_result = expected_result("go");
        let probe = test_probe(&rust_result);
        let report = serde_json::json!({
            "schema_version": 1, "case_id": CASE_ID, "operation": OPERATION, "status": "passed",
            "generated_at": "2026-09-17T00:00:00Z",
            "input": {"encoded_base64": INPUT_BASE64, "sha256": INPUT_SHA256},
            "bounds": {"max_record_bytes": MAX_RECORD_BYTES, "max_input_bytes": INPUT_BYTES, "max_output_bytes": INPUT_BYTES},
            "rust": implementation_json(&root, &probe, "rust", &rust_result),
            "go": implementation_json(&root, &probe, "go", &go_result),
            "artifacts": {
                "adapter_path": "tools/r02/go-probe",
                "adapter_sha256": path_digest(&root, Path::new("tools/r02/go-probe")).expect("adapter digest"),
                "schema_path": "integration/r02/report.schema.json",
                "schema_sha256": file_digest(&root.join("integration/r02/report.schema.json")).expect("schema digest")
            },
            "controller": {
                "path": "integration/r02/reproduce.sh",
                "sha256": file_digest(&root.join("integration/r02/reproduce.sh")).expect("controller digest"),
                "command": ["integration/r02/reproduce.sh", "--go-root", "/tmp/go", "--rust-probe", probe.to_string_lossy(), "--verifier", verifier.to_string_lossy(), "--report", report_path.to_string_lossy()]
            }
        });
        (report, root, report_path, verifier, probe)
    }

    fn implementation_json(
        root: &Path,
        probe: &Path,
        id: &str,
        result: &ProbeResult,
    ) -> serde_json::Value {
        if id == "rust" {
            serde_json::json!({
                "implementation_id": id,
                "source_revision": git_value(root, &["rev-parse", "HEAD"]).expect("revision"),
                "source_tree": git_value(root, &["rev-parse", "HEAD^{tree}"]).expect("tree"),
                "source_files_sha256": source_digest(root).expect("source digest"), "features": [],
                "lockfile_sha256": file_digest(&root.join("Cargo.lock")).expect("lock digest"),
                "compiler": command_value("rustc", &["--version"]).expect("compiler"),
                "target": rust_target().expect("target"), "driver_sha256": file_digest(probe).expect("probe digest"),
                "command": [probe.to_string_lossy()], "exit_code": 0,
                "stdout_sha256": result_stdout_digest(result).expect("stdout digest"), "result": result
            })
        } else {
            serde_json::json!({
                "implementation_id": id, "source_revision": GO_REVISION, "source_tree": GO_TREE,
                "source_files_sha256": hex_digest(GO_TREE.as_bytes()), "features": [],
                "lockfile_sha256": GO_LOCKFILE_SHA256, "compiler": test_go_compiler(), "target": TEST_GO_TARGET,
                "driver_sha256": path_digest(root, Path::new("tools/r02/go-probe")).expect("adapter digest"),
                "command": ["go", "run", "./tools/rados-rs-r02-probe"], "exit_code": 0,
                "stdout_sha256": result_stdout_digest(result).expect("stdout digest"), "result": result
            })
        }
    }

    fn verify_test_report(
        report: &serde_json::Value,
        root: &Path,
        report_path: &Path,
        verifier: &Path,
        expected_probe: &Path,
    ) -> Result<(), String> {
        verify_report(
            &VerificationContext {
                root,
                report_path,
                verifier_path: verifier,
                expected_rust_probe: expected_probe,
                go_compiler: &test_go_compiler(),
                go_target: TEST_GO_TARGET,
                verify_go_checkout: false,
            },
            &serde_json::to_vec(report).expect("encode report"),
        )
    }

    #[test]
    fn verifier_accepts_complete_matching_report() {
        let (report, root, report_path, verifier, probe) = valid_report();
        verify_test_report(&report, &root, &report_path, &verifier, &probe).expect("report passes");
    }

    #[test]
    fn verifier_rejects_substituted_executable() {
        let (mut report, root, report_path, verifier, probe) = valid_report();
        let substitute = test_probe(&expected_result("rust"));
        report["rust"]["command"][0] = serde_json::json!(substitute.to_string_lossy());
        report["rust"]["driver_sha256"] =
            serde_json::json!(file_digest(&substitute).expect("digest"));
        assert!(verify_test_report(&report, &root, &report_path, &verifier, &probe).is_err());
    }

    #[test]
    fn verifier_rejects_stale_source_and_input_hashes() {
        let (mut report, root, report_path, verifier, probe) = valid_report();
        report["rust"]["source_files_sha256"] = serde_json::json!("0".repeat(64));
        assert!(verify_test_report(&report, &root, &report_path, &verifier, &probe).is_err());
        let (mut report, _, _, _, _) = valid_report();
        report["input"]["sha256"] = serde_json::json!("0".repeat(64));
        assert!(verify_test_report(&report, &root, &report_path, &verifier, &probe).is_err());
    }

    #[test]
    fn verifier_rejects_malformed_oversized_and_impossible_timestamp_reports() {
        let (mut report, root, report_path, verifier, probe) = valid_report();
        assert!(
            verify_report(
                &VerificationContext {
                    root: &root,
                    report_path: &report_path,
                    verifier_path: &verifier,
                    expected_rust_probe: &probe,
                    go_compiler: &test_go_compiler(),
                    go_target: TEST_GO_TARGET,
                    verify_go_checkout: false,
                },
                b"{"
            )
            .is_err()
        );
        assert!(
            verify_report(
                &VerificationContext {
                    root: &root,
                    report_path: &report_path,
                    verifier_path: &verifier,
                    expected_rust_probe: &probe,
                    go_compiler: &test_go_compiler(),
                    go_target: TEST_GO_TARGET,
                    verify_go_checkout: false,
                },
                &vec![b' '; usize::try_from(MAX_RECORD_BYTES).expect("record bound") * 4 + 1]
            )
            .is_err()
        );
        report["generated_at"] = serde_json::json!("2026-02-29T23:59:60Z");
        assert!(verify_test_report(&report, &root, &report_path, &verifier, &probe).is_err());
        assert!(valid_utc_timestamp("2024-02-29T23:59:59Z"));
    }
}
