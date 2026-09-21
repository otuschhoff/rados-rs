#![forbid(unsafe_code)]
//! R13 detached human-review verifier.
//!
//! Adapts the immutable Go P12 review contract
//! (reference/archives/go-*.tar.gz, tools/p12-verify/review.go) to Rust with
//! R13 paths, base64-encoded Ed25519 detached signatures, and a canonical
//! payload the verifier can only reprint, never sign.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod budget;
pub mod candidate;
pub mod constants;
pub mod fuzz;
pub mod hash;
pub mod inventory;
pub mod qualify;
pub mod release;
pub mod source;

pub const REQUIRED_ROLES: [&str; 4] = [
    "security",
    "distributed-systems",
    "license/notices",
    "release-owner",
];

pub const HUMAN_REVIEW_PATH: &str = "docs/r13/human-review.json";
pub const REVIEWER_TRUST_PATH: &str = "docs/r13/reviewer-trust.json";
pub const CANDIDATE_REPORT_PATH: &str = "integration/r13/report.json";
pub const QUALIFICATION_REPORT_PATH: &str = "docs/r13/qualification-report.json";
pub const FUZZ_REPORT_PATH: &str = "docs/r13/fuzz-report.json";
pub const FUZZ_PROFILE: &str = "certifying";

pub const HUMAN_REVIEW_SCHEMA_VERSION: u32 = 2;
pub const REVIEWER_TRUST_SCHEMA_VERSION: u32 = 1;

const ED25519_PUBLIC_KEY_LEN: usize = 32;
const ED25519_SIGNATURE_LEN: usize = 64;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HumanReviewReport {
    pub schema_version: u32,
    pub status: String,
    pub required_roles: Vec<String>,
    pub reviewed_candidate: Option<ReviewedCandidate>,
    pub reviews: Vec<HumanReviewRecord>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReviewedCandidate {
    pub report: FileBinding,
    pub qualification: QualificationBinding,
    pub fuzz: FuzzBinding,
    pub release: ReviewedRelease,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileBinding {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QualificationBinding {
    pub path: String,
    pub status: String,
    pub sha256: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FuzzBinding {
    pub path: String,
    pub status: String,
    pub profile: String,
    pub sha256: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReviewedRelease {
    pub version: String,
    pub artifacts: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct HumanReviewRecord {
    pub role: String,
    pub key_id: String,
    pub reviewer_identity: String,
    pub reviewer_affiliation: String,
    pub started_at: String,
    pub completed_at: String,
    pub decision: String,
    pub unresolved_findings: FindingCounts,
    pub approval_reference: String,
    pub signature: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FindingCounts {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewerTrustPolicy {
    pub schema_version: u32,
    pub status: String,
    pub keys: Vec<TrustedKey>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TrustedKey {
    pub key_id: String,
    pub role: String,
    pub reviewer_identity: String,
    pub reviewer_affiliation: String,
    pub public_key: String,
}

/// Minimal candidate report shape required to bind a detached review.
///
/// Additional report fields must be added here explicitly to preserve the
/// Go P12 practice of strict decoding; the SHA-256 of the file bytes still
/// covers every byte of the report.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateReport {
    pub status: String,
    pub finished_at: String,
    pub reviews: Option<serde_json::Value>,
    pub qualification: QualificationBinding,
    pub fuzz: FuzzBinding,
    pub release: ReleaseEvidence,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseEvidence {
    pub version: String,
    pub artifacts: BTreeMap<String, String>,
}

// Canonical detached-review payload. Field order is contract-critical.
#[derive(Debug, Serialize)]
struct CanonicalReviewPayload<'a> {
    schema_version: u32,
    role: &'a str,
    key_id: &'a str,
    reviewer_identity: &'a str,
    reviewer_affiliation: &'a str,
    reviewed_report_path: &'a str,
    reviewed_report_sha256: &'a str,
    qualification_path: &'a str,
    qualification_sha256: &'a str,
    fuzz_path: &'a str,
    fuzz_sha256: &'a str,
    fuzz_profile: &'a str,
    release_version: &'a str,
    release_artifact_sha256: &'a BTreeMap<String, String>,
    decision: &'a str,
    started_at: &'a str,
    completed_at: &'a str,
    unresolved_findings: FindingCounts,
    approval_reference: &'a str,
}

#[derive(Debug)]
pub struct VerificationError(pub String);

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for VerificationError {}

impl VerificationError {
    fn boxed(message: impl Into<String>) -> Box<dyn Error> {
        Box::new(Self(message.into()))
    }
}

/// Decode strict JSON, rejecting unknown fields and trailing content.
fn decode_strict<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    kind: &str,
) -> Result<T, Box<dyn Error>> {
    let mut stream = serde_json::Deserializer::from_slice(bytes).into_iter::<T>();
    let value = match stream.next() {
        Some(result) => result.map_err(|error| {
            VerificationError::boxed(format!("decode strict {kind} JSON: {error}"))
        })?,
        None => return Err(VerificationError::boxed(format!("empty {kind} JSON"))),
    };
    if stream.next().is_some() {
        return Err(VerificationError::boxed(format!(
            "invalid {kind} JSON framing"
        )));
    }
    let consumed = stream.byte_offset();
    if bytes[consumed..]
        .iter()
        .any(|byte| !byte.is_ascii_whitespace())
    {
        return Err(VerificationError::boxed(format!("trailing {kind} bytes")));
    }
    Ok(value)
}

/// Verify the canonical pending state: both the review record and the trust
/// policy must be strict pending envelopes with no candidate, no reviews, and
/// no active keys. This is the ONLY state automated tooling may produce.
///
/// # Errors
///
/// Returns an error if either document is malformed, has trailing content,
/// declares the wrong schema version, is not pending, or contains any review
/// or key entry.
pub fn verify_pending(review_bytes: &[u8], trust_bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let review: HumanReviewReport = decode_strict(review_bytes, "human-review")?;
    check_pending_review_envelope(&review)?;
    let trust: ReviewerTrustPolicy = decode_strict(trust_bytes, "reviewer-trust")?;
    if trust.schema_version != REVIEWER_TRUST_SCHEMA_VERSION {
        return Err(VerificationError::boxed(
            "unexpected reviewer-trust schema version",
        ));
    }
    if trust.status != "pending" {
        return Err(VerificationError::boxed(
            "reviewer trust policy is not pending",
        ));
    }
    if !trust.keys.is_empty() {
        return Err(VerificationError::boxed(
            "pending reviewer trust policy must enrol no keys",
        ));
    }
    Ok(())
}

/// Backwards-compatible convenience: verify the pending human-review JSON
/// alone.
///
/// # Errors
///
/// Same as [`verify_pending`] but limited to the human-review document.
pub fn verify_pending_review(bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let review: HumanReviewReport = decode_strict(bytes, "human-review")?;
    check_pending_review_envelope(&review)
}

fn check_pending_review_envelope(review: &HumanReviewReport) -> Result<(), Box<dyn Error>> {
    if review.schema_version != HUMAN_REVIEW_SCHEMA_VERSION {
        return Err(VerificationError::boxed(
            "unexpected human-review schema version",
        ));
    }
    if review.status != "pending" {
        return Err(VerificationError::boxed(
            "automated tooling cannot approve human review",
        ));
    }
    if review.required_roles.as_slice() != REQUIRED_ROLES {
        return Err(VerificationError::boxed("unexpected review roles"));
    }
    if review.reviewed_candidate.is_some() || !review.reviews.is_empty() {
        return Err(VerificationError::boxed(
            "pending review must not claim a candidate or reviews",
        ));
    }
    Ok(())
}

/// Verify the fully approved review contract against the candidate report.
///
/// # Errors
///
/// Returns an error if any of the three JSON documents is malformed, if the
/// review status is not `approved`, if the candidate binding does not match
/// the report bytes, if the trust policy is not `active`, if any per-review
/// invariant fails, or if any Ed25519 signature is invalid.
pub fn verify_approved(
    review_bytes: &[u8],
    trust_bytes: &[u8],
    report_bytes: &[u8],
) -> Result<(), Box<dyn Error>> {
    let review: HumanReviewReport = decode_strict(review_bytes, "human-review")?;
    let trust: ReviewerTrustPolicy = decode_strict(trust_bytes, "reviewer-trust")?;
    let report: CandidateReport = decode_strict(report_bytes, "candidate-report")?;
    validate_approved(&review, &trust, &report, report_bytes)
}

#[allow(clippy::too_many_lines)]
fn validate_approved(
    review: &HumanReviewReport,
    trust: &ReviewerTrustPolicy,
    report: &CandidateReport,
    report_bytes: &[u8],
) -> Result<(), Box<dyn Error>> {
    if review.schema_version != HUMAN_REVIEW_SCHEMA_VERSION || review.status != "approved" {
        return Err(VerificationError::boxed(
            "human-review report is pending or has an invalid schema",
        ));
    }
    if review.required_roles.as_slice() != REQUIRED_ROLES {
        return Err(VerificationError::boxed(
            "human-review report lacks the exact required roles",
        ));
    }
    let candidate = review.reviewed_candidate.as_ref().ok_or_else(|| {
        VerificationError::boxed("human-review report lacks the candidate binding")
    })?;

    if report.status != "candidate" || report.reviews.is_some() {
        return Err(VerificationError::boxed(
            "reviewed report is not an immutable review-independent candidate",
        ));
    }
    if report.qualification.path != QUALIFICATION_REPORT_PATH
        || report.qualification.status != "passed"
    {
        return Err(VerificationError::boxed(
            "candidate qualification binding is missing or not passed",
        ));
    }
    if report.fuzz.path != FUZZ_REPORT_PATH
        || report.fuzz.status != "passed"
        || report.fuzz.profile != FUZZ_PROFILE
    {
        return Err(VerificationError::boxed(
            "candidate fuzz binding is missing, not passed, or not certifying",
        ));
    }
    if report.release.artifacts.len() != 4 {
        return Err(VerificationError::boxed(
            "candidate release must bind exactly four artifact hashes",
        ));
    }
    for hash in report.release.artifacts.values() {
        if !is_sha256_hex(hash) {
            return Err(VerificationError::boxed(
                "candidate release artifact hash is not a lowercase SHA-256",
            ));
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(report_bytes);
    let report_digest = hex_lower(hasher.finalize().as_slice());
    let want_candidate = ReviewedCandidate {
        report: FileBinding {
            path: CANDIDATE_REPORT_PATH.to_owned(),
            sha256: report_digest,
        },
        qualification: report.qualification.clone(),
        fuzz: report.fuzz.clone(),
        release: ReviewedRelease {
            version: report.release.version.clone(),
            artifacts: report.release.artifacts.clone(),
        },
    };
    if *candidate != want_candidate {
        return Err(VerificationError::boxed(
            "human-review candidate hash, qualification, version, or artifacts do not match the report",
        ));
    }

    let keys = validate_trust_policy(trust)?;
    if review.reviews.len() != REQUIRED_ROLES.len() {
        return Err(VerificationError::boxed(format!(
            "human-review report has {} reviews, want exactly {}",
            review.reviews.len(),
            REQUIRED_ROLES.len()
        )));
    }
    let finished = parse_rfc3339_utc(&report.finished_at)
        .map_err(|()| VerificationError::boxed("candidate completion timestamp is invalid"))?;

    let mut seen_roles: BTreeSet<&str> = BTreeSet::new();
    let mut seen_key_ids: BTreeSet<&str> = BTreeSet::new();
    let mut seen_reviewers: BTreeSet<String> = BTreeSet::new();
    for record in &review.reviews {
        if !REQUIRED_ROLES.contains(&record.role.as_str())
            || !seen_roles.insert(record.role.as_str())
        {
            return Err(VerificationError::boxed(format!(
                "human-review report has invalid or duplicate role {:?}",
                record.role
            )));
        }
        let Some(key) = keys.get(record.key_id.as_str()) else {
            return Err(VerificationError::boxed(format!(
                "human review {:?} does not match its trusted key identity and role",
                record.role
            )));
        };
        if !seen_key_ids.insert(record.key_id.as_str()) {
            return Err(VerificationError::boxed(format!(
                "human review {:?} reuses a trusted key ID",
                record.role
            )));
        }
        let reviewer = normalized_reviewer(&record.reviewer_identity, &record.reviewer_affiliation);
        if !seen_reviewers.insert(reviewer) {
            return Err(VerificationError::boxed(format!(
                "human review {:?} reuses a normalized reviewer identity",
                record.role
            )));
        }
        if key.role != record.role
            || key.reviewer_identity != record.reviewer_identity
            || key.reviewer_affiliation != record.reviewer_affiliation
        {
            return Err(VerificationError::boxed(format!(
                "human review {:?} does not match its trusted key identity and role",
                record.role
            )));
        }
        let started = parse_rfc3339_utc(&record.started_at).map_err(|()| {
            VerificationError::boxed(format!(
                "human review {:?} has an invalid started_at timestamp",
                record.role
            ))
        })?;
        let completed = parse_rfc3339_utc(&record.completed_at).map_err(|()| {
            VerificationError::boxed(format!(
                "human review {:?} has an invalid completed_at timestamp",
                record.role
            ))
        })?;
        if started <= finished
            || completed < started
            || record.decision != "approved"
            || record.unresolved_findings.critical != 0
            || record.unresolved_findings.high != 0
            || !valid_approval_reference(&record.approval_reference)
        {
            return Err(VerificationError::boxed(format!(
                "human review {:?} is incomplete, predates the candidate, or has unresolved critical/high findings",
                record.role
            )));
        }
        let payload = canonical_payload(review, record)?;
        let signature_bytes = BASE64.decode(record.signature.as_bytes()).map_err(|_| {
            VerificationError::boxed(format!(
                "human review {:?} signature is not valid base64",
                record.role
            ))
        })?;
        if signature_bytes.len() != ED25519_SIGNATURE_LEN
            || BASE64.encode(&signature_bytes) != record.signature
        {
            return Err(VerificationError::boxed(format!(
                "human review {:?} signature is not canonically encoded",
                record.role
            )));
        }
        let public_key_bytes = BASE64.decode(key.public_key.as_bytes()).map_err(|_| {
            VerificationError::boxed(format!(
                "trusted key {:?} public key is not valid base64",
                key.key_id
            ))
        })?;
        let public_array: [u8; ED25519_PUBLIC_KEY_LEN] =
            public_key_bytes.as_slice().try_into().map_err(|_| {
                VerificationError::boxed(format!(
                    "trusted key {:?} public key has the wrong length",
                    key.key_id
                ))
            })?;
        let verifying_key = VerifyingKey::from_bytes(&public_array).map_err(|_| {
            VerificationError::boxed(format!(
                "trusted key {:?} public key is not a valid Ed25519 point",
                key.key_id
            ))
        })?;
        let signature_array: [u8; ED25519_SIGNATURE_LEN] = signature_bytes
            .as_slice()
            .try_into()
            .expect("length checked");
        let signature = Signature::from_bytes(&signature_array);
        if verifying_key.verify_strict(&payload, &signature).is_err() {
            return Err(VerificationError::boxed(format!(
                "human review {:?} has an invalid Ed25519 signature",
                record.role
            )));
        }
    }
    Ok(())
}

fn validate_trust_policy(
    trust: &ReviewerTrustPolicy,
) -> Result<BTreeMap<&str, &TrustedKey>, Box<dyn Error>> {
    if trust.schema_version != REVIEWER_TRUST_SCHEMA_VERSION || trust.status != "active" {
        return Err(VerificationError::boxed(
            "reviewer trust policy is pending or has an invalid schema",
        ));
    }
    let mut keys: BTreeMap<&str, &TrustedKey> = BTreeMap::new();
    let mut roles: BTreeSet<&str> = BTreeSet::new();
    let mut public_keys: BTreeSet<Vec<u8>> = BTreeSet::new();
    let mut reviewers: BTreeSet<String> = BTreeSet::new();
    for key in &trust.keys {
        if !valid_token(&key.key_id)
            || keys.contains_key(key.key_id.as_str())
            || !REQUIRED_ROLES.contains(&key.role.as_str())
            || !roles.insert(key.role.as_str())
            || !non_blank_exact(&key.reviewer_identity)
            || !non_blank_exact(&key.reviewer_affiliation)
        {
            return Err(VerificationError::boxed(
                "reviewer trust policy has a duplicate, malformed, or unauthorized key",
            ));
        }
        let decoded = BASE64.decode(key.public_key.as_bytes()).map_err(|_| {
            VerificationError::boxed("reviewer trust policy has an unparsable public key")
        })?;
        if decoded.len() != ED25519_PUBLIC_KEY_LEN || BASE64.encode(&decoded) != key.public_key {
            return Err(VerificationError::boxed(
                "reviewer trust policy has a public key with the wrong length or non-canonical encoding",
            ));
        }
        if !public_keys.insert(decoded) {
            return Err(VerificationError::boxed(
                "reviewer trust policy authorizes the same public key twice",
            ));
        }
        let reviewer = normalized_reviewer(&key.reviewer_identity, &key.reviewer_affiliation);
        if !reviewers.insert(reviewer) {
            return Err(VerificationError::boxed(
                "reviewer trust policy authorizes the same reviewer twice",
            ));
        }
        keys.insert(key.key_id.as_str(), key);
    }
    if keys.len() != REQUIRED_ROLES.len() {
        return Err(VerificationError::boxed(
            "reviewer trust policy must authorize exactly one key for each required role",
        ));
    }
    Ok(keys)
}

/// Produce the canonical Ed25519 payload bytes for one review record.
///
/// # Errors
///
/// Returns an error if the review record is not bound to a candidate or if
/// the canonical serialization fails.
pub fn canonical_payload(
    review: &HumanReviewReport,
    record: &HumanReviewRecord,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let candidate = review
        .reviewed_candidate
        .as_ref()
        .ok_or_else(|| VerificationError::boxed("human-review report lacks a candidate binding"))?;
    let payload = CanonicalReviewPayload {
        schema_version: review.schema_version,
        role: &record.role,
        key_id: &record.key_id,
        reviewer_identity: &record.reviewer_identity,
        reviewer_affiliation: &record.reviewer_affiliation,
        reviewed_report_path: &candidate.report.path,
        reviewed_report_sha256: &candidate.report.sha256,
        qualification_path: &candidate.qualification.path,
        qualification_sha256: &candidate.qualification.sha256,
        fuzz_path: &candidate.fuzz.path,
        fuzz_sha256: &candidate.fuzz.sha256,
        fuzz_profile: &candidate.fuzz.profile,
        release_version: &candidate.release.version,
        release_artifact_sha256: &candidate.release.artifacts,
        decision: &record.decision,
        started_at: &record.started_at,
        completed_at: &record.completed_at,
        unresolved_findings: record.unresolved_findings.clone(),
        approval_reference: &record.approval_reference,
    };
    let mut bytes = serde_json::to_vec(&payload)
        .map_err(|error| VerificationError::boxed(format!("marshal canonical payload: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Reprint the canonical payload for a given role from a human-review file.
/// Never generates or handles signatures. Intended only for reviewers who
/// need the exact bytes to sign externally.
///
/// # Errors
///
/// Returns an error if the review JSON is malformed, if the role is unknown,
/// if the report SHA-256 or candidate binding disagrees with the report
/// bytes, or if the record does not exist for the requested role.
pub fn print_review_payload(
    role: &str,
    review_bytes: &[u8],
    report_bytes: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    if !REQUIRED_ROLES.contains(&role) {
        return Err(VerificationError::boxed(format!(
            "unknown review role {role:?}"
        )));
    }
    let review: HumanReviewReport = decode_strict(review_bytes, "human-review")?;
    let candidate = review
        .reviewed_candidate
        .as_ref()
        .ok_or_else(|| VerificationError::boxed("cannot reprint payload for a pending review"))?;
    let mut hasher = Sha256::new();
    hasher.update(report_bytes);
    let report_digest = hex_lower(hasher.finalize().as_slice());
    if candidate.report.path != CANDIDATE_REPORT_PATH || candidate.report.sha256 != report_digest {
        return Err(VerificationError::boxed(
            "human-review candidate binding does not match the supplied report",
        ));
    }
    let record = review
        .reviews
        .iter()
        .find(|record| record.role == role)
        .ok_or_else(|| VerificationError::boxed(format!("no review record for role {role:?}")))?;
    canonical_payload(&review, record)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_token(value: &str) -> bool {
    !value.is_empty() && value == value.trim() && !value.chars().any(char::is_whitespace)
}

fn non_blank_exact(value: &str) -> bool {
    value == value.trim() && !value.is_empty()
}

fn normalized_reviewer(identity: &str, affiliation: &str) -> String {
    let normalize = |value: &str| -> String {
        value
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
    };
    format!("{}\u{0}{}", normalize(identity), normalize(affiliation))
}

fn valid_approval_reference(value: &str) -> bool {
    if value.is_empty() || value != value.trim() {
        return false;
    }
    if value.chars().any(char::is_whitespace) {
        return false;
    }
    let Some(scheme_end) = value.find("://") else {
        return false;
    };
    let scheme = &value[..scheme_end];
    if scheme != "http" && scheme != "https" {
        return false;
    }
    let after = &value[scheme_end + 3..];
    let host_end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let host_and_userinfo = &after[..host_end];
    let host = host_and_userinfo
        .rsplit_once('@')
        .map_or(host_and_userinfo, |(_, right)| right);
    !host.is_empty()
        && host
            .chars()
            .all(|character| !character.is_ascii_control() && !character.is_whitespace())
}

// Parse a subset of RFC 3339 timestamps sufficient for review records:
// `YYYY-MM-DDTHH:MM:SS[.fraction]Z` with strictly numeric components. Only
// UTC (`Z`) is accepted so ordering between reviewers is unambiguous.
fn parse_rfc3339_utc(value: &str) -> Result<Timestamp, ()> {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return Err(());
    }
    let year: i64 = parse_digits(&bytes[0..4])?;
    let month: i64 = parse_digits(&bytes[5..7])?;
    let day: i64 = parse_digits(&bytes[8..10])?;
    let hour: i64 = parse_digits(&bytes[11..13])?;
    let minute: i64 = parse_digits(&bytes[14..16])?;
    let second: i64 = parse_digits(&bytes[17..19])?;
    let rest = &bytes[19..];
    let (fraction_nanos, tail) = if !rest.is_empty() && rest[0] == b'.' {
        let mut index = 1;
        while index < rest.len() && rest[index].is_ascii_digit() {
            index += 1;
        }
        if index == 1 {
            return Err(());
        }
        let digits = &rest[1..index];
        let mut nanos: i64 = 0;
        let mut consumed = 0;
        for byte in digits.iter().take(9) {
            nanos = nanos * 10 + i64::from(byte - b'0');
            consumed += 1;
        }
        for _ in consumed..9 {
            nanos *= 10;
        }
        (nanos, &rest[index..])
    } else {
        (0, rest)
    };
    if tail != b"Z" {
        return Err(());
    }
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return Err(());
    }
    let days = days_from_civil(year, month, day);
    let total_seconds = days * 86_400 + hour * 3_600 + minute * 60 + second;
    Ok(Timestamp {
        seconds: total_seconds,
        nanos: fraction_nanos,
    })
}

fn parse_digits(bytes: &[u8]) -> Result<i64, ()> {
    let mut value: i64 = 0;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return Err(());
        }
        value = value * 10 + i64::from(byte - b'0');
    }
    Ok(value)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    // Howard Hinnant's date algorithm; proleptic Gregorian days from 1970-01-01.
    let shifted_year = if month <= 2 { year - 1 } else { year };
    let era = if shifted_year >= 0 {
        shifted_year
    } else {
        shifted_year - 399
    } / 400;
    let year_of_era = shifted_year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Timestamp {
    seconds: i64,
    nanos: i64,
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod docs_tests;
