//! R13 fuzz qualification report types, verifier, and inventory guard.
//!
//! This module implements the automated half of the R13 fuzz contract:
//!
//! * A strict, schema-bound report shape (`FuzzReport`) with three profiles:
//!   `pending`, `smoke`, and `certifying`.
//! * An inventory guard that fails when `fuzz/Cargo.toml`, the
//!   `fuzz/fuzz_targets/*.rs` filesystem, or [`crate::constants::FUZZ_TARGETS`]
//!   disagree on which parsers the campaign matrix must cover.
//! * A verifier that binds a report to the current repository: source digest,
//!   schema digest, per-target Rust source hash, per-target corpus tree hash,
//!   per-target log file hash, and the recorded exec-per-second/execution
//!   counters.
//!
//! The certifying gate is stricter than smoke (600 s vs 60 s per target and
//! `status == "passed"` on every campaign); the pending shape exists so a
//! canonical placeholder can live in the repository and still be rejected by
//! the certifying verifier.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use crate::constants::{
    FUZZ_CARGO_FUZZ_VERSION, FUZZ_CERTIFYING_MIN_SECONDS, FUZZ_LIVE_PATH,
    FUZZ_NIGHTLY_TOOLCHAIN, FUZZ_OUTPUT_DIR_NAME, FUZZ_PENDING_PATH, FUZZ_PROFILE_CERTIFYING,
    FUZZ_PROFILE_PENDING, FUZZ_PROFILE_SMOKE, FUZZ_REPORT_MAX_BYTES, FUZZ_SCHEMA_VERSION,
    FUZZ_SMOKE_MIN_SECONDS, FUZZ_SUITE_ID, FUZZ_TARGETS,
};
use crate::hash::{is_sha256_hex, lower_hex};
use crate::source::source_digest;

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FuzzReport {
    pub schema_version: u32,
    pub suite_id: String,
    pub profile: String,
    pub status: String,
    pub started_at: String,
    pub finished_at: String,
    pub source_sha256: String,
    pub schema_sha256: String,
    pub platform: Platform,
    pub toolchain: FuzzToolchain,
    pub campaigns: Vec<FuzzCampaign>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Platform {
    pub os: String,
    pub arch: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FuzzToolchain {
    pub nightly: String,
    pub rustc: String,
    pub cargo_fuzz: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FuzzCampaign {
    pub target: String,
    pub budget_seconds: u64,
    pub started_at: String,
    pub finished_at: String,
    pub executions: u64,
    pub executions_per_second: u64,
    pub corpus_sha256: String,
    pub target_sha256: String,
    pub output_path: String,
    pub output_sha256: String,
    pub status: String,
}

/// Structural minimum for a report of a given profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Pending,
    Smoke,
    Certifying,
}

impl Profile {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => FUZZ_PROFILE_PENDING,
            Self::Smoke => FUZZ_PROFILE_SMOKE,
            Self::Certifying => FUZZ_PROFILE_CERTIFYING,
        }
    }

    #[must_use]
    pub fn min_seconds(self) -> u64 {
        match self {
            Self::Pending => 0,
            Self::Smoke => FUZZ_SMOKE_MIN_SECONDS,
            Self::Certifying => FUZZ_CERTIFYING_MIN_SECONDS,
        }
    }

    /// # Errors
    ///
    /// Returns an explanation if `value` is not one of the recognised
    /// profile identifiers.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            FUZZ_PROFILE_PENDING => Ok(Self::Pending),
            FUZZ_PROFILE_SMOKE => Ok(Self::Smoke),
            FUZZ_PROFILE_CERTIFYING => Ok(Self::Certifying),
            other => Err(format!("unknown fuzz profile {other:?}")),
        }
    }
}

/// Enumerate the fuzz targets that are actually declared in
/// `fuzz/Cargo.toml` `[[bin]]` sections, sorted alphabetically.
///
/// # Errors
///
/// Returns an explanation if the file cannot be read, if it is not UTF-8,
/// or if any `[[bin]] name = "..."` entry cannot be parsed.
pub fn cargo_bin_targets(root: &Path) -> Result<Vec<String>, String> {
    let path = root.join("fuzz/Cargo.toml");
    let contents = fs::read_to_string(&path)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    let mut targets: Vec<String> = Vec::new();
    let mut in_bin = false;
    for raw in contents.lines() {
        let line = raw.trim();
        if line.starts_with('[') {
            in_bin = line == "[[bin]]";
            continue;
        }
        if !in_bin {
            continue;
        }
        if let Some(rest) = line.strip_prefix("name") {
            let after_equals = rest
                .trim_start()
                .strip_prefix('=')
                .ok_or_else(|| format!("malformed [[bin]] name in {}", path.display()))?
                .trim();
            let name = after_equals
                .strip_prefix('"')
                .and_then(|stripped| stripped.strip_suffix('"'))
                .ok_or_else(|| format!("malformed [[bin]] name in {}", path.display()))?;
            targets.push(name.to_owned());
            in_bin = false;
        }
    }
    targets.sort();
    Ok(targets)
}

/// Enumerate the fuzz targets that exist as `fuzz/fuzz_targets/*.rs` files.
///
/// # Errors
///
/// Returns an explanation if the directory cannot be walked or contains an
/// unexpected non-`.rs` entry.
pub fn filesystem_targets(root: &Path) -> Result<Vec<String>, String> {
    let path = root.join("fuzz/fuzz_targets");
    let mut targets: Vec<String> = Vec::new();
    for entry in fs::read_dir(&path)
        .map_err(|error| format!("read_dir {}: {error}", path.display()))?
    {
        let entry = entry.map_err(|error| format!("read_dir entry: {error}"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "fuzz target file name is not UTF-8".to_owned())?;
        let stem = name.strip_suffix(".rs").ok_or_else(|| {
            format!("unexpected non-Rust entry in fuzz/fuzz_targets: {name:?}")
        })?;
        targets.push(stem.to_owned());
    }
    targets.sort();
    Ok(targets)
}

/// Fail if the frozen constant list, the `[[bin]]` block set, and the
/// filesystem set disagree.
///
/// # Errors
///
/// Returns an explanation on any drift.
pub fn verify_inventory(root: &Path) -> Result<Vec<String>, String> {
    let expected: Vec<String> = FUZZ_TARGETS.iter().map(|target| (*target).to_owned()).collect();
    let cargo = cargo_bin_targets(root)?;
    if cargo != expected {
        return Err(format!(
            "fuzz/Cargo.toml declares {} targets; R13 constant declares {}",
            cargo.len(),
            expected.len()
        ));
    }
    let filesystem = filesystem_targets(root)?;
    if filesystem != expected {
        return Err(format!(
            "fuzz/fuzz_targets/ has {} .rs files; R13 constant declares {}",
            filesystem.len(),
            expected.len()
        ));
    }
    Ok(expected)
}

/// Parse strict JSON, reject unknown fields, trailing bytes, and reports
/// exceeding [`crate::constants::FUZZ_REPORT_MAX_BYTES`].
///
/// # Errors
///
/// Returns an explanation if the bytes do not decode, or if the shape does
/// not satisfy the profile-independent invariants.
pub fn verify_bytes(bytes: &[u8]) -> Result<FuzzReport, String> {
    if bytes.len() as u64 > FUZZ_REPORT_MAX_BYTES {
        return Err("fuzz report exceeds byte limit".into());
    }
    let mut stream = serde_json::Deserializer::from_slice(bytes).into_iter::<FuzzReport>();
    let report = match stream.next() {
        Some(result) => result.map_err(|error| format!("decode strict fuzz report: {error}"))?,
        None => return Err("empty fuzz report".into()),
    };
    if stream.next().is_some() {
        return Err("fuzz report has trailing JSON".into());
    }
    let consumed = stream.byte_offset();
    if bytes[consumed..]
        .iter()
        .any(|byte| !byte.is_ascii_whitespace())
    {
        return Err("fuzz report has trailing bytes".into());
    }
    validate_shape(&report)?;
    Ok(report)
}

/// Reject a report that does not satisfy the certifying gate. Reads only the
/// report bytes; does not touch git or the filesystem.
///
/// # Errors
///
/// Returns an explanation on any invariant violation.
pub fn verify_certifying_bytes(bytes: &[u8]) -> Result<FuzzReport, String> {
    let report = verify_bytes(bytes)?;
    require_profile(&report, Profile::Certifying)?;
    Ok(report)
}

/// Verify a report file bound to the repository at `root`.
///
/// * Confirms the schema digest matches
///   `integration/r13/fuzz-report.schema.json` on disk.
/// * Confirms the source digest matches the current `git ls-files` closure.
/// * Confirms each campaign's `target_sha256`, `corpus_sha256`, and
///   `output_sha256` match the on-disk artefacts (target Rust source under
///   `fuzz/fuzz_targets/`, corpus tree under `--corpus-root`, log under
///   the report's parent directory).
///
/// The `profile` parameter is the minimum gate this call requires: pending,
/// smoke, or certifying.
///
/// # Errors
///
/// Returns an explanation on any invariant violation, unreadable file, or
/// hash mismatch.
pub fn verify_report(
    root: &Path,
    report_path: &Path,
    corpus_root: &Path,
    profile: Profile,
) -> Result<FuzzReport, String> {
    let bytes = fs::read(report_path)
        .map_err(|error| format!("read {}: {error}", report_path.display()))?;
    let report = verify_bytes(&bytes)?;
    require_profile(&report, profile)?;

    // Pending is a placeholder shape: it does not bind schema/source
    // digests or per-target artefacts. The certifying gate is the only
    // profile that binds live evidence; smoke is a bounded prefix.
    if profile == Profile::Pending {
        return Ok(report);
    }

    let schema_path = root.join("integration/r13/fuzz-report.schema.json");
    let schema_bytes = fs::read(&schema_path)
        .map_err(|error| format!("read {}: {error}", schema_path.display()))?;
    if report.schema_sha256 != lower_hex(&sha2::Sha256::digest(&schema_bytes)) {
        return Err("fuzz schema digest does not match".into());
    }

    if report.source_sha256 != source_digest(root)? {
        return Err("fuzz source digest does not match repository state".into());
    }

    let report_dir = report_path
        .parent()
        .ok_or_else(|| "fuzz report has no parent directory".to_owned())?;
    verify_campaign_artifacts(root, report_dir, corpus_root, &report)?;
    Ok(report)
}

fn verify_campaign_artifacts(
    root: &Path,
    report_dir: &Path,
    corpus_root: &Path,
    report: &FuzzReport,
) -> Result<(), String> {
    for campaign in &report.campaigns {
        let target_path = root
            .join("fuzz/fuzz_targets")
            .join(format!("{}.rs", campaign.target));
        let target_bytes = fs::read(&target_path)
            .map_err(|error| format!("read {}: {error}", target_path.display()))?;
        if campaign.target_sha256 != lower_hex(&sha2::Sha256::digest(&target_bytes)) {
            return Err(format!(
                "fuzz target hash mismatch for {}: report does not match on-disk source",
                campaign.target
            ));
        }
        let corpus_dir = corpus_root.join(&campaign.target);
        let corpus_digest = tree_digest(&corpus_dir)?;
        if campaign.corpus_sha256 != corpus_digest {
            return Err(format!(
                "fuzz corpus hash mismatch for {}: report does not match {}",
                campaign.target,
                corpus_dir.display()
            ));
        }
        let output_path = report_dir.join(&campaign.output_path);
        let output_bytes = fs::read(&output_path)
            .map_err(|error| format!("read {}: {error}", output_path.display()))?;
        if campaign.output_sha256 != lower_hex(&sha2::Sha256::digest(&output_bytes)) {
            return Err(format!(
                "fuzz output hash mismatch for {}: report does not match {}",
                campaign.target,
                output_path.display()
            ));
        }
    }
    Ok(())
}

/// Aggregate SHA-256 of every file under `root`, sorted by relative path.
/// Empty directory returns the SHA-256 of the empty byte string; missing
/// directory is an error.
fn tree_digest(root: &Path) -> Result<String, String> {
    let mut files: Vec<(String, PathBuf)> = Vec::new();
    walk(root, root, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut aggregate = sha2::Sha256::new();
    for (relative, absolute) in files {
        let bytes = fs::read(&absolute)
            .map_err(|error| format!("read {}: {error}", absolute.display()))?;
        let file_hash = lower_hex(&sha2::Sha256::digest(&bytes));
        aggregate.update(format!("{file_hash}  {relative}\n").as_bytes());
    }
    Ok(lower_hex(&aggregate.finalize()))
}

fn walk(base: &Path, current: &Path, files: &mut Vec<(String, PathBuf)>) -> Result<(), String> {
    let entries = fs::read_dir(current)
        .map_err(|error| format!("read_dir {}: {error}", current.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read_dir entry: {error}"))?;
        let path = entry.path();
        let metadata = entry
            .metadata()
            .map_err(|error| format!("stat {}: {error}", path.display()))?;
        if metadata.is_dir() {
            walk(base, &path, files)?;
            continue;
        }
        let relative = path
            .strip_prefix(base)
            .map_err(|_| format!("path escapes corpus root: {}", path.display()))?
            .to_string_lossy()
            .into_owned();
        files.push((relative, path));
    }
    Ok(())
}

fn validate_shape(report: &FuzzReport) -> Result<(), String> {
    if report.schema_version != FUZZ_SCHEMA_VERSION || report.suite_id != FUZZ_SUITE_ID {
        return Err("fuzz report identity is invalid".into());
    }
    if !valid_timestamps(&report.started_at, &report.finished_at) {
        return Err("fuzz report timestamps are invalid".into());
    }
    if !is_sha256_hex(&report.source_sha256) || !is_sha256_hex(&report.schema_sha256) {
        return Err("fuzz report source or schema digest is not a lowercase SHA-256".into());
    }
    match (report.platform.os.as_str(), report.platform.arch.as_str()) {
        ("linux" | "darwin", "amd64" | "arm64") => {}
        _ => return Err("fuzz report platform is invalid".into()),
    }
    if report.toolchain.nightly != FUZZ_NIGHTLY_TOOLCHAIN
        || report.toolchain.cargo_fuzz != FUZZ_CARGO_FUZZ_VERSION
        || report.toolchain.rustc.is_empty()
    {
        return Err("fuzz toolchain identity does not match frozen constants".into());
    }
    validate_profile_shape(&report.profile, &report.status, &report.campaigns)?;
    Ok(())
}

fn validate_profile_shape(profile: &str, status: &str, campaigns: &[FuzzCampaign]) -> Result<(), String> {
    match profile {
        FUZZ_PROFILE_PENDING => {
            if status != FUZZ_PROFILE_PENDING {
                return Err("pending fuzz report must have status=pending".into());
            }
            if !campaigns.is_empty() {
                return Err("pending fuzz report must have zero campaigns".into());
            }
            Ok(())
        }
        FUZZ_PROFILE_SMOKE => validate_full_matrix(status, campaigns, FUZZ_SMOKE_MIN_SECONDS),
        FUZZ_PROFILE_CERTIFYING => {
            validate_full_matrix(status, campaigns, FUZZ_CERTIFYING_MIN_SECONDS)
        }
        other => Err(format!("fuzz report has unknown profile {other:?}")),
    }
}

fn validate_full_matrix(
    status: &str,
    campaigns: &[FuzzCampaign],
    minimum_seconds: u64,
) -> Result<(), String> {
    if !matches!(status, "passed" | "failed" | "interrupted") {
        return Err("fuzz report status must be passed, failed, or interrupted".into());
    }
    if campaigns.len() != FUZZ_TARGETS.len() {
        return Err(format!(
            "fuzz report has {} campaigns, expected {}",
            campaigns.len(),
            FUZZ_TARGETS.len()
        ));
    }
    let mut observed: BTreeSet<&str> = BTreeSet::new();
    for (index, campaign) in campaigns.iter().enumerate() {
        let expected = FUZZ_TARGETS[index];
        if campaign.target != expected {
            return Err(format!(
                "fuzz campaign at index {index} is {:?}, expected {expected:?}",
                campaign.target
            ));
        }
        if !observed.insert(expected) {
            return Err(format!("fuzz campaign {expected} appears twice"));
        }
        validate_campaign(campaign, minimum_seconds)?;
    }
    if status == "passed" && !campaigns.iter().all(|entry| entry.status == "passed") {
        return Err("fuzz report status=passed requires every campaign to have status=passed".into());
    }
    Ok(())
}

fn validate_campaign(campaign: &FuzzCampaign, minimum_seconds: u64) -> Result<(), String> {
    if !FUZZ_TARGETS.contains(&campaign.target.as_str()) {
        return Err(format!("fuzz campaign target {:?} is unknown", campaign.target));
    }
    if !valid_timestamps(&campaign.started_at, &campaign.finished_at) {
        return Err(format!(
            "fuzz campaign {} timestamps are invalid",
            campaign.target
        ));
    }
    if campaign.budget_seconds < minimum_seconds {
        return Err(format!(
            "fuzz campaign {} budget_seconds={} is below profile minimum {minimum_seconds}",
            campaign.target, campaign.budget_seconds
        ));
    }
    if !is_sha256_hex(&campaign.target_sha256)
        || !is_sha256_hex(&campaign.corpus_sha256)
        || !is_sha256_hex(&campaign.output_sha256)
    {
        return Err(format!(
            "fuzz campaign {} artefact hashes are not lowercase SHA-256",
            campaign.target
        ));
    }
    let expected_output = format!("{FUZZ_OUTPUT_DIR_NAME}/{}.log", campaign.target);
    if campaign.output_path != expected_output {
        return Err(format!(
            "fuzz campaign {} output_path is {:?}, expected {expected_output:?}",
            campaign.target, campaign.output_path
        ));
    }
    if !matches!(campaign.status.as_str(), "passed" | "failed" | "interrupted") {
        return Err(format!(
            "fuzz campaign {} has unknown status {:?}",
            campaign.target, campaign.status
        ));
    }
    if campaign.status == "passed" && (campaign.executions == 0 || campaign.executions_per_second == 0) {
        return Err(format!(
            "fuzz campaign {} reports status=passed but has zero executions",
            campaign.target
        ));
    }
    Ok(())
}

fn require_profile(report: &FuzzReport, profile: Profile) -> Result<(), String> {
    if report.profile != profile.as_str() {
        return Err(format!(
            "fuzz report profile is {:?}, required {:?}",
            report.profile,
            profile.as_str()
        ));
    }
    match profile {
        Profile::Pending => {
            if report.status != FUZZ_PROFILE_PENDING {
                return Err("fuzz report is not the canonical pending shape".into());
            }
        }
        Profile::Smoke | Profile::Certifying => {
            if report.status != "passed" {
                return Err(format!(
                    "fuzz report profile={} status must be passed, got {:?}",
                    profile.as_str(),
                    report.status
                ));
            }
        }
    }
    Ok(())
}

fn valid_timestamps(start: &str, finish: &str) -> bool {
    valid_timestamp(start) && valid_timestamp(finish) && start <= finish
}

fn valid_timestamp(value: &str) -> bool {
    value.len() == 20
        && value.ends_with('Z')
        && value.bytes().enumerate().all(|(index, byte)| match index {
            4 | 7 => byte == b'-',
            10 => byte == b'T',
            13 | 16 => byte == b':',
            19 => byte == b'Z',
            _ => byte.is_ascii_digit(),
        })
}

/// Canonical relative paths of the checked-in fuzz artefacts.
#[must_use]
pub fn live_report_path() -> &'static str {
    FUZZ_LIVE_PATH
}

#[must_use]
pub fn pending_report_path() -> &'static str {
    FUZZ_PENDING_PATH
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn valid_pending_value() -> Value {
        json!({
            "schema_version": FUZZ_SCHEMA_VERSION,
            "suite_id": FUZZ_SUITE_ID,
            "profile": FUZZ_PROFILE_PENDING,
            "status": FUZZ_PROFILE_PENDING,
            "started_at": "1970-01-01T00:00:00Z",
            "finished_at": "1970-01-01T00:00:00Z",
            "source_sha256": "0".repeat(64),
            "schema_sha256": "0".repeat(64),
            "platform": {"os": "linux", "arch": "amd64"},
            "toolchain": {
                "nightly": FUZZ_NIGHTLY_TOOLCHAIN,
                "rustc": "rustc 1.100.0-nightly (placeholder)",
                "cargo_fuzz": FUZZ_CARGO_FUZZ_VERSION,
            },
            "campaigns": [],
        })
    }

    fn valid_campaign(target: &str, budget: u64) -> Value {
        json!({
            "target": target,
            "budget_seconds": budget,
            "started_at": "2026-09-21T00:00:00Z",
            "finished_at": "2026-09-21T00:10:00Z",
            "executions": 1,
            "executions_per_second": 1,
            "corpus_sha256": "a".repeat(64),
            "target_sha256": "b".repeat(64),
            "output_path": format!("{FUZZ_OUTPUT_DIR_NAME}/{target}.log"),
            "output_sha256": "c".repeat(64),
            "status": "passed",
        })
    }

    fn valid_certifying_value() -> Value {
        let mut value = valid_pending_value();
        value["profile"] = json!(FUZZ_PROFILE_CERTIFYING);
        value["status"] = json!("passed");
        value["campaigns"] = Value::Array(
            FUZZ_TARGETS
                .iter()
                .map(|target| valid_campaign(target, FUZZ_CERTIFYING_MIN_SECONDS))
                .collect(),
        );
        value
    }

    fn encode(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).expect("encode fuzz report")
    }

    #[test]
    fn constant_target_list_has_42_entries() {
        assert_eq!(FUZZ_TARGETS.len(), 42);
    }

    #[test]
    fn constant_target_list_is_sorted() {
        let mut sorted = FUZZ_TARGETS.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted, FUZZ_TARGETS.to_vec());
    }

    #[test]
    fn pending_report_bytes_accepted_but_certifying_rejected() {
        let bytes = encode(&valid_pending_value());
        let report = verify_bytes(&bytes).expect("pending shape must decode");
        assert_eq!(report.profile, FUZZ_PROFILE_PENDING);
        let error = verify_certifying_bytes(&bytes).expect_err("pending must not certify");
        assert!(
            error.contains("profile"),
            "expected profile rejection, got {error:?}"
        );
    }

    #[test]
    fn certifying_report_passes_shape() {
        let bytes = encode(&valid_certifying_value());
        verify_bytes(&bytes).expect("certifying shape must decode");
        verify_certifying_bytes(&bytes).expect("certifying shape must gate");
    }

    #[test]
    fn certifying_rejects_short_budget() {
        let mut value = valid_certifying_value();
        value["campaigns"][0]["budget_seconds"] = json!(FUZZ_CERTIFYING_MIN_SECONDS - 1);
        let error = verify_bytes(&encode(&value)).expect_err("short budget must reject");
        assert!(error.contains("below profile minimum"), "got {error:?}");
    }

    #[test]
    fn smoke_rejects_below_60_seconds() {
        let mut value = valid_certifying_value();
        value["profile"] = json!(FUZZ_PROFILE_SMOKE);
        for entry in value["campaigns"].as_array_mut().unwrap() {
            entry["budget_seconds"] = json!(FUZZ_SMOKE_MIN_SECONDS);
        }
        // 60s smoke passes.
        verify_bytes(&encode(&value)).expect("60s smoke must decode");
        value["campaigns"][0]["budget_seconds"] = json!(FUZZ_SMOKE_MIN_SECONDS - 1);
        assert!(verify_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_unknown_target() {
        let mut value = valid_certifying_value();
        value["campaigns"][0]["target"] = json!("does_not_exist");
        value["campaigns"][0]["output_path"] =
            json!(format!("{FUZZ_OUTPUT_DIR_NAME}/does_not_exist.log"));
        assert!(verify_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_duplicate_target() {
        let mut value = valid_certifying_value();
        value["campaigns"][1] = valid_campaign(FUZZ_TARGETS[0], FUZZ_CERTIFYING_MIN_SECONDS);
        assert!(verify_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_out_of_order_target() {
        let mut value = valid_certifying_value();
        let swapped = value["campaigns"][0].clone();
        value["campaigns"][0] = value["campaigns"][1].clone();
        value["campaigns"][1] = swapped;
        assert!(verify_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_missing_campaign() {
        let mut value = valid_certifying_value();
        let mut array = value["campaigns"].as_array().unwrap().clone();
        array.pop();
        value["campaigns"] = Value::Array(array);
        assert!(verify_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_status_passed_with_failed_campaign() {
        let mut value = valid_certifying_value();
        value["campaigns"][0]["status"] = json!("failed");
        let error = verify_bytes(&encode(&value)).expect_err("status pass must gate campaigns");
        assert!(
            error.contains("every campaign") || error.contains("zero executions"),
            "got {error:?}"
        );
    }

    #[test]
    fn accepts_failed_report_with_failed_campaign_but_certifying_rejects() {
        let mut value = valid_certifying_value();
        value["status"] = json!("failed");
        value["campaigns"][0]["status"] = json!("failed");
        verify_bytes(&encode(&value)).expect("failed report shape must decode");
        let error = verify_certifying_bytes(&encode(&value))
            .expect_err("failed status must not gate certifying");
        assert!(error.contains("status must be passed"), "got {error:?}");
    }

    #[test]
    fn rejects_interrupted_zero_executions_on_passed_campaign() {
        let mut value = valid_certifying_value();
        value["campaigns"][0]["executions"] = json!(0);
        value["campaigns"][0]["executions_per_second"] = json!(0);
        assert!(verify_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_wrong_toolchain() {
        let mut value = valid_certifying_value();
        value["toolchain"]["nightly"] = json!("nightly-2025-01-01");
        assert!(verify_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_wrong_cargo_fuzz_version() {
        let mut value = valid_certifying_value();
        value["toolchain"]["cargo_fuzz"] = json!("cargo-fuzz 0.13.1");
        assert!(verify_bytes(&encode(&value)).is_err());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = encode(&valid_pending_value());
        bytes.extend_from_slice(b"garbage");
        assert!(verify_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_oversized_report() {
        let size = usize::try_from(FUZZ_REPORT_MAX_BYTES + 1).expect("budget fits usize");
        let oversized = vec![b'a'; size];
        assert!(verify_bytes(&oversized).is_err());
    }
}
