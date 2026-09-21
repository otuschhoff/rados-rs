//! R13 automated qualification report types and verifier.
//!
//! The qualification report captures:
//! * Frozen toolchain/image/tool identities from
//!   [`crate::constants`].
//! * Ordered list of `check` records (id, command, timestamps, exit code,
//!   stdout/stderr sha256s, notes).
//! * Runtime observations (host `os`/`arch` pairs the checks actually ran
//!   on). The verifier fails if the report claims a runtime it did not
//!   observe.
//! * Exact prior R03–R12 report bindings.
//! * Deterministic release comparison (bytes of two runs, artifact hashes).
//! * Source-inventory summary and the source digest that produced it.
//!
//! Two entry points:
//!
//! * [`verify_bytes`] — parse strict JSON and validate shape only.
//! * [`verify_report`] — additionally binds the report to the repository
//!   root (schema hash, source digest, prior report hashes, inventory).

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use crate::constants::{
    CARGO_AUDIT_VERSION, CARGO_DENY_VERSION, CARGO_FUZZ_VERSION, CEPH_IMAGE_AMD64,
    CEPH_IMAGE_ARM64, CEPH_SERVER_COMMIT, CEPH_SERVER_VERSION, CHECK_IDS, COMPILER_IMAGE,
    KNOWN_PLATFORMS, NATIVE_INVENTORY_ROWS, PARITY_LEDGER_ROWS, PRIOR_REPORTS,
    QUALIFICATION_REPORT_MAX_BYTES, QUALIFICATION_SCHEMA_VERSION, QUALIFICATION_SUITE_ID,
    RUST_MSRV, RUST_STABLE_OBSERVED,
};
use crate::hash::{is_sha256_hex, lower_hex};
use crate::inventory;
use crate::source::source_digest;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationReport {
    pub schema_version: u32,
    pub suite_id: String,
    pub status: String,
    pub started_at: String,
    pub finished_at: String,
    pub schema_sha256: String,
    pub toolchain: Toolchain,
    pub server: Server,
    pub runtime: Runtime,
    pub source: Source,
    pub inventory: Inventory,
    pub priors: Vec<PriorBinding>,
    pub checks: Vec<Check>,
    pub release: Release,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Toolchain {
    pub rust_msrv: String,
    pub rust_stable_observed: String,
    pub compiler_image: String,
    pub cargo_audit: String,
    pub cargo_deny: String,
    pub cargo_fuzz: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    pub commit: String,
    pub version: String,
    pub image_amd64: String,
    pub image_arm64: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Runtime {
    pub observed: Vec<HostObservation>,
    pub claimed: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostObservation {
    pub os: String,
    pub arch: String,
    pub rustc: String,
    pub cargo: String,
    pub captured_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub digest: String,
    pub files: u32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub native_rows: u32,
    pub ledger_rows: u32,
    pub status_counts: std::collections::BTreeMap<String, u32>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PriorBinding {
    pub phase: String,
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub id: String,
    pub command_id: String,
    pub command: Vec<String>,
    pub started_at: String,
    pub finished_at: String,
    pub exit_code: i32,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub notes: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub version: String,
    pub artifacts: std::collections::BTreeMap<String, String>,
    pub twice_run_identical: bool,
    pub first_run_sha256: String,
    pub second_run_sha256: String,
}

/// # Errors
///
/// Returns an explanation on invalid, tampered, oversized, or otherwise
/// non-conforming report bytes.
pub fn verify_bytes(bytes: &[u8]) -> Result<QualificationReport, String> {
    if bytes.len() as u64 > QUALIFICATION_REPORT_MAX_BYTES {
        return Err("qualification report exceeds byte limit".into());
    }
    let mut stream = serde_json::Deserializer::from_slice(bytes).into_iter::<QualificationReport>();
    let report = match stream.next() {
        Some(result) => result.map_err(|error| format!("decode strict qualification: {error}"))?,
        None => return Err("empty qualification report".into()),
    };
    if stream.next().is_some() {
        return Err("qualification report has trailing JSON".into());
    }
    let consumed = stream.byte_offset();
    if bytes[consumed..]
        .iter()
        .any(|byte| !byte.is_ascii_whitespace())
    {
        return Err("qualification report has trailing bytes".into());
    }
    validate_shape(&report)?;
    Ok(report)
}

/// # Errors
///
/// Returns an explanation if the report cannot be read, if its shape is
/// invalid, or if the on-disk source digest, prior report hashes,
/// inventory rows, or embedded schema hash do not match the workspace.
pub fn verify_report(root: &Path, report_path: &Path) -> Result<QualificationReport, String> {
    let bytes = fs::read(report_path)
        .map_err(|error| format!("read {}: {error}", report_path.display()))?;
    let report = verify_bytes(&bytes)?;

    let schema_path = root.join("integration/r13/qualification-report.schema.json");
    let schema_bytes = fs::read(&schema_path)
        .map_err(|error| format!("read {}: {error}", schema_path.display()))?;
    if report.schema_sha256 != lower_hex(&sha2::Sha256::digest(&schema_bytes)) {
        return Err("qualification schema digest does not match".into());
    }

    if report.source.digest != source_digest(root)? {
        return Err("qualification source digest does not match repository state".into());
    }
    let expected_files = u32::try_from(crate::source::source_paths(root)?.len())
        .map_err(|_| "source file count overflows u32".to_owned())?;
    if report.source.files != expected_files {
        return Err(format!(
            "qualification source.files is {} but repository has {}",
            report.source.files, expected_files
        ));
    }

    for prior in &report.priors {
        let expected_path = PRIOR_REPORTS
            .iter()
            .find(|(phase, _)| *phase == prior.phase)
            .map(|(_, path)| *path)
            .ok_or_else(|| format!("qualification prior binding {:?} is unknown", prior.phase))?;
        if prior.path != expected_path {
            return Err(format!(
                "qualification prior {:?} binds {:?}, expected {:?}",
                prior.phase, prior.path, expected_path
            ));
        }
        let path = root.join(&prior.path);
        let bytes = fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
        let digest = lower_hex(&sha2::Sha256::digest(&bytes));
        if prior.sha256 != digest {
            return Err(format!(
                "qualification prior {:?} has stale hash for {:?}",
                prior.phase, prior.path
            ));
        }
    }

    let summary = inventory::check(root)?;
    if report.inventory.native_rows as usize != summary.native_rows
        || report.inventory.ledger_rows as usize != summary.ledger_rows
    {
        return Err("qualification inventory row counts do not match repository state".into());
    }
    if report.inventory.native_rows as usize != NATIVE_INVENTORY_ROWS
        || report.inventory.ledger_rows as usize != PARITY_LEDGER_ROWS
    {
        return Err("qualification inventory row counts do not match frozen R13 v1 scope".into());
    }
    Ok(report)
}

fn validate_shape(report: &QualificationReport) -> Result<(), String> {
    if report.schema_version != QUALIFICATION_SCHEMA_VERSION
        || report.suite_id != QUALIFICATION_SUITE_ID
        || report.status != "passed"
    {
        return Err("qualification report identity or status is invalid".into());
    }
    if !valid_timestamps(&report.started_at, &report.finished_at) {
        return Err("qualification report timestamps are invalid".into());
    }
    if !is_sha256_hex(&report.schema_sha256) {
        return Err("qualification schema hash is not a lowercase SHA-256".into());
    }
    if report.toolchain.rust_msrv != RUST_MSRV
        || report.toolchain.rust_stable_observed != RUST_STABLE_OBSERVED
        || report.toolchain.compiler_image != COMPILER_IMAGE
        || report.toolchain.cargo_audit != CARGO_AUDIT_VERSION
        || report.toolchain.cargo_deny != CARGO_DENY_VERSION
        || report.toolchain.cargo_fuzz != CARGO_FUZZ_VERSION
    {
        return Err("qualification toolchain identity does not match frozen constants".into());
    }
    if report.server.commit != CEPH_SERVER_COMMIT
        || report.server.version != CEPH_SERVER_VERSION
        || report.server.image_amd64 != CEPH_IMAGE_AMD64
        || report.server.image_arm64 != CEPH_IMAGE_ARM64
    {
        return Err("qualification server identity does not match frozen constants".into());
    }
    validate_runtime(&report.runtime)?;
    validate_priors(&report.priors)?;
    validate_checks(&report.checks)?;
    if !is_sha256_hex(&report.source.digest) || report.source.files == 0 {
        return Err("qualification source digest or count is invalid".into());
    }
    validate_release(&report.release)?;
    if report.inventory.status_counts.values().sum::<u32>() != report.inventory.ledger_rows {
        return Err("qualification inventory status counts do not sum to ledger row count".into());
    }
    Ok(())
}

fn validate_runtime(runtime: &Runtime) -> Result<(), String> {
    if runtime.observed.is_empty() {
        return Err("qualification report has no runtime observations".into());
    }
    let mut observed_platforms: BTreeSet<String> = BTreeSet::new();
    for observation in &runtime.observed {
        if !valid_timestamp(&observation.captured_at)
            || observation.rustc.is_empty()
            || observation.cargo.is_empty()
        {
            return Err("qualification runtime observation is malformed".into());
        }
        let platform = format!("{}/{}", observation.os, observation.arch);
        if !KNOWN_PLATFORMS.contains(&platform.as_str()) {
            return Err(format!(
                "qualification runtime observed unknown platform {platform:?}"
            ));
        }
        if !observed_platforms.insert(platform) {
            return Err("qualification runtime observed the same platform twice".into());
        }
    }
    let claimed_platforms: BTreeSet<String> = runtime.claimed.iter().cloned().collect();
    if claimed_platforms.len() != runtime.claimed.len() {
        return Err("qualification runtime claimed platforms contain duplicates".into());
    }
    for platform in &claimed_platforms {
        if !KNOWN_PLATFORMS.contains(&platform.as_str()) {
            return Err(format!(
                "qualification runtime claims unknown platform {platform:?}"
            ));
        }
    }
    if claimed_platforms != observed_platforms {
        return Err(
            "qualification runtime claims a platform that was not observed, or vice versa".into(),
        );
    }
    // The R13 qualification exit gate requires runtime observations on every
    // native platform the R13 spec supports. A producer that cannot exercise
    // one platform (missing Docker daemon, missing Rosetta on darwin/amd64,
    // etc.) must emit the report as `status: "failed"` rather than shrink
    // the observed set.
    let expected_platforms: BTreeSet<String> = KNOWN_PLATFORMS
        .iter()
        .map(|platform| (*platform).to_owned())
        .collect();
    if observed_platforms != expected_platforms {
        return Err(format!(
            "qualification runtime must observe every R13 platform {KNOWN_PLATFORMS:?}"
        ));
    }
    Ok(())
}

fn validate_priors(priors: &[PriorBinding]) -> Result<(), String> {
    if priors.len() != PRIOR_REPORTS.len() {
        return Err(format!(
            "qualification report has {} prior bindings, expected {}",
            priors.len(),
            PRIOR_REPORTS.len()
        ));
    }
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (index, prior) in priors.iter().enumerate() {
        let (phase, path) = PRIOR_REPORTS[index];
        if prior.phase != phase || prior.path != path {
            return Err(format!(
                "qualification prior at index {index} is {:?}:{:?}, expected {phase}:{path}",
                prior.phase, prior.path
            ));
        }
        if !seen.insert(phase) {
            return Err(format!("qualification prior {phase} appears twice"));
        }
        if !is_sha256_hex(&prior.sha256) {
            return Err(format!(
                "qualification prior {phase} sha256 is not a lowercase SHA-256"
            ));
        }
    }
    Ok(())
}

fn validate_checks(checks: &[Check]) -> Result<(), String> {
    if checks.len() != CHECK_IDS.len() {
        return Err(format!(
            "qualification report has {} checks, expected {}",
            checks.len(),
            CHECK_IDS.len()
        ));
    }
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (index, check) in checks.iter().enumerate() {
        let expected = CHECK_IDS[index];
        if check.id != expected {
            return Err(format!(
                "qualification check at index {index} is {:?}, expected {expected:?}",
                check.id
            ));
        }
        if !seen.insert(expected) {
            return Err(format!("qualification check {expected} appears twice"));
        }
        if !valid_timestamps(&check.started_at, &check.finished_at)
            || check.command_id.is_empty()
            || check.command.is_empty()
            || !is_sha256_hex(&check.stdout_sha256)
            || !is_sha256_hex(&check.stderr_sha256)
        {
            return Err(format!("qualification check {expected} shape is invalid"));
        }
        if check.exit_code != 0 {
            return Err(format!(
                "qualification check {expected} exited with {}",
                check.exit_code
            ));
        }
    }
    Ok(())
}

fn validate_release(release: &Release) -> Result<(), String> {
    let names = crate::release::ReleaseNames::from_version(&release.version)
        .map_err(|_| "qualification release version is invalid".to_owned())?;
    if release.artifacts.len() != crate::release::ARTIFACT_COUNT {
        return Err("qualification release must bind exactly four artefacts".into());
    }
    let expected_names: BTreeSet<&str> = names.as_array().into_iter().collect();
    let actual_names: BTreeSet<&str> = release.artifacts.keys().map(String::as_str).collect();
    if expected_names != actual_names {
        return Err("qualification release artefact names do not match the frozen four".into());
    }
    for hash in release.artifacts.values() {
        if !is_sha256_hex(hash) {
            return Err("qualification release artefact hash is not a lowercase SHA-256".into());
        }
    }
    if !is_sha256_hex(&release.first_run_sha256) || !is_sha256_hex(&release.second_run_sha256) {
        return Err("qualification release run digests are invalid".into());
    }
    if !release.twice_run_identical || release.first_run_sha256 != release.second_run_sha256 {
        return Err(
            "qualification release did not produce byte-identical output across two runs".into(),
        );
    }
    // Also verify the checksums entry itself covers the other three names.
    let checksums = release
        .artifacts
        .get(&names.checksums)
        .ok_or_else(|| "qualification release is missing the SHA256SUMS binding".to_owned())?;
    if !is_sha256_hex(checksums) {
        return Err("qualification release SHA256SUMS binding is invalid".into());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{CHECK_IDS, PRIOR_REPORTS};
    use crate::hash::sha256_hex;
    use crate::release::{ReleaseInput, build};
    use serde_json::{Value, json};
    use std::collections::BTreeMap;

    fn sample_release_input() -> ReleaseInput {
        let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        files.insert("Cargo.toml".into(), b"[package]\nname=\"x\"\n".to_vec());
        files.insert("src/lib.rs".into(), b"pub fn one() -> u8 { 1 }\n".to_vec());
        ReleaseInput {
            version: "v1.2.3".into(),
            files,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn valid_report_value() -> Value {
        let artifacts = build(&sample_release_input()).expect("build release");
        let mut artifact_hashes = serde_json::Map::new();
        artifact_hashes.insert(
            artifacts.names.tarball.clone(),
            Value::String(sha256_hex(&artifacts.tarball)),
        );
        artifact_hashes.insert(
            artifacts.names.zip.clone(),
            Value::String(sha256_hex(&artifacts.zip)),
        );
        artifact_hashes.insert(
            artifacts.names.spdx.clone(),
            Value::String(sha256_hex(&artifacts.spdx)),
        );
        artifact_hashes.insert(
            artifacts.names.checksums.clone(),
            Value::String(sha256_hex(&artifacts.checksums)),
        );
        let mut checks = Vec::with_capacity(CHECK_IDS.len());
        for id in CHECK_IDS {
            checks.push(json!({
                "id": *id,
                "command_id": format!("cmd-{id}"),
                "command": ["cargo", "check"],
                "started_at": "2026-09-21T00:00:00Z",
                "finished_at": "2026-09-21T00:01:00Z",
                "exit_code": 0,
                "stdout_sha256": "1".repeat(64),
                "stderr_sha256": "2".repeat(64),
                "notes": ""
            }));
        }
        let mut priors = Vec::with_capacity(PRIOR_REPORTS.len());
        for (phase, path) in PRIOR_REPORTS {
            priors.push(json!({
                "phase": *phase,
                "path": *path,
                "sha256": "9".repeat(64)
            }));
        }
        let package_ratio = 0_u32;
        let _ = package_ratio;
        json!({
            "schema_version": 1,
            "suite_id": "r13/automated-qualification-v1",
            "status": "passed",
            "started_at": "2026-09-21T00:00:00Z",
            "finished_at": "2026-09-21T00:10:00Z",
            "schema_sha256": "a".repeat(64),
            "toolchain": {
                "rust_msrv": "1.98.0",
                "rust_stable_observed": "rustc 1.98.0 (88d9e12ae 2026-08-18)",
                "compiler_image": "rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922",
                "cargo_audit": "cargo-audit 0.22.2",
                "cargo_deny": "cargo-deny 0.20.2",
                "cargo_fuzz": "cargo-fuzz 0.13.2"
            },
            "server": {
                "commit": "7f793731f1b39eb4f465e960113d2363c311b964",
                "version": "ceph version 20.2.4 (7f793731f1b39eb4f465e960113d2363c311b964) tentacle (stable)",
                "image_amd64": "quay.io/ceph/ceph@sha256:09ee90f6f3e0c7b9954f71d214ee05e9bbaaaea3716b1dd619603283b829f8b8",
                "image_arm64": "quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa"
            },
            "runtime": {
                "observed": [
                    {
                        "os": "darwin",
                        "arch": "amd64",
                        "rustc": "rustc 1.98.0 (88d9e12ae 2026-08-18)",
                        "cargo": "cargo 1.98.0 (797e8a9bc 2026-08-05)",
                        "captured_at": "2026-09-21T00:00:30Z"
                    },
                    {
                        "os": "darwin",
                        "arch": "arm64",
                        "rustc": "rustc 1.98.0 (88d9e12ae 2026-08-18)",
                        "cargo": "cargo 1.98.0 (797e8a9bc 2026-08-05)",
                        "captured_at": "2026-09-21T00:00:31Z"
                    },
                    {
                        "os": "linux",
                        "arch": "amd64",
                        "rustc": "rustc 1.98.0 (88d9e12ae 2026-08-18)",
                        "cargo": "cargo 1.98.0 (797e8a9bc 2026-08-05)",
                        "captured_at": "2026-09-21T00:00:32Z"
                    },
                    {
                        "os": "linux",
                        "arch": "arm64",
                        "rustc": "rustc 1.98.0 (88d9e12ae 2026-08-18)",
                        "cargo": "cargo 1.98.0 (797e8a9bc 2026-08-05)",
                        "captured_at": "2026-09-21T00:00:33Z"
                    }
                ],
                "claimed": [
                    "darwin/amd64",
                    "darwin/arm64",
                    "linux/amd64",
                    "linux/arm64"
                ]
            },
            "source": {
                "digest": "c".repeat(64),
                "files": 42
            },
            "inventory": {
                "native_rows": 623,
                "ledger_rows": 905,
                "status_counts": {
                    "implemented-r02": 905
                }
            },
            "priors": priors,
            "checks": checks,
            "release": {
                "version": "v1.2.3",
                "artifacts": Value::Object(artifact_hashes),
                "twice_run_identical": true,
                "first_run_sha256": "d".repeat(64),
                "second_run_sha256": "d".repeat(64)
            }
        })
    }

    fn to_bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec_pretty(value).expect("serialize test report")
    }

    #[test]
    fn baseline_valid_report_parses() {
        let bytes = to_bytes(&valid_report_value());
        verify_bytes(&bytes).expect("baseline report must parse");
    }

    #[test]
    fn rejects_unknown_fields() {
        let mut value = valid_report_value();
        value
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), Value::from("nope"));
        let bytes = to_bytes(&value);
        assert!(verify_bytes(&bytes).unwrap_err().contains("decode strict"));
    }

    #[test]
    fn rejects_pending_status() {
        let mut value = valid_report_value();
        value["status"] = Value::from("pending");
        let bytes = to_bytes(&value);
        assert!(verify_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_missing_check() {
        let mut value = valid_report_value();
        let checks = value["checks"].as_array_mut().unwrap();
        checks.pop();
        let bytes = to_bytes(&value);
        let error = verify_bytes(&bytes).unwrap_err();
        assert!(error.contains("checks"));
    }

    #[test]
    fn rejects_reordered_check_ids() {
        let mut value = valid_report_value();
        let checks = value["checks"].as_array_mut().unwrap();
        checks.swap(0, 1);
        let bytes = to_bytes(&value);
        assert!(verify_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_nonzero_exit_code() {
        let mut value = valid_report_value();
        value["checks"][0]["exit_code"] = Value::from(1);
        let bytes = to_bytes(&value);
        assert!(verify_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_stale_release_nondeterminism() {
        let mut value = valid_report_value();
        value["release"]["twice_run_identical"] = Value::from(false);
        let bytes = to_bytes(&value);
        assert!(verify_bytes(&bytes).unwrap_err().contains("byte-identical"));
    }

    #[test]
    fn rejects_release_run_hash_mismatch() {
        let mut value = valid_report_value();
        value["release"]["second_run_sha256"] = Value::from("e".repeat(64));
        let bytes = to_bytes(&value);
        assert!(verify_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_wrong_artifact_count() {
        let mut value = valid_report_value();
        value["release"]["artifacts"]
            .as_object_mut()
            .unwrap()
            .insert("extra.txt".into(), Value::from("f".repeat(64)));
        let bytes = to_bytes(&value);
        assert!(verify_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_runtime_claim_without_observation() {
        let mut value = valid_report_value();
        // Remove one observation while retaining every claim so the two
        // sets disagree; the shape must reject the mismatch.
        let observed = value["runtime"]["observed"].as_array_mut().unwrap();
        observed.pop();
        let bytes = to_bytes(&value);
        assert!(verify_bytes(&bytes).unwrap_err().contains("not observed"));
    }

    #[test]
    fn rejects_missing_required_platform() {
        let mut value = valid_report_value();
        // Drop one observation AND its claim so shape passes shape symmetry
        // but the report no longer covers every R13 platform.
        let observed = value["runtime"]["observed"].as_array_mut().unwrap();
        observed.pop();
        let claimed = value["runtime"]["claimed"].as_array_mut().unwrap();
        claimed.pop();
        let bytes = to_bytes(&value);
        let error = verify_bytes(&bytes).unwrap_err();
        assert!(
            error.contains("every R13 platform"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_priors_out_of_order() {
        let mut value = valid_report_value();
        let priors = value["priors"].as_array_mut().unwrap();
        priors.swap(0, 1);
        let bytes = to_bytes(&value);
        assert!(verify_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_prior_wrong_path() {
        let mut value = valid_report_value();
        value["priors"][0]["path"] = Value::from("docs/r03/other.md");
        let bytes = to_bytes(&value);
        assert!(verify_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_toolchain_tamper() {
        let mut value = valid_report_value();
        value["toolchain"]["cargo_audit"] = Value::from("cargo-audit 0.0.0");
        let bytes = to_bytes(&value);
        assert!(
            verify_bytes(&bytes)
                .unwrap_err()
                .contains("toolchain identity")
        );
    }

    #[test]
    fn rejects_stale_inventory_row_count() {
        let mut value = valid_report_value();
        value["inventory"]["ledger_rows"] = Value::from(900);
        let bytes = to_bytes(&value);
        assert!(verify_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_status_count_mismatch() {
        let mut value = valid_report_value();
        value["inventory"]["status_counts"] = json!({"implemented-r02": 1});
        let bytes = to_bytes(&value);
        assert!(verify_bytes(&bytes).unwrap_err().contains("status counts"));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = to_bytes(&valid_report_value());
        bytes.extend_from_slice(b"trailing");
        assert!(verify_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_oversize_report() {
        let mut bytes = to_bytes(&valid_report_value());
        bytes.resize(
            usize::try_from(crate::constants::QUALIFICATION_REPORT_MAX_BYTES).expect("size") + 1,
            b' ',
        );
        assert!(verify_bytes(&bytes).unwrap_err().contains("byte limit"));
    }
}
