use std::collections::BTreeMap;
use std::fmt::Write as _;

use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{SigningKey, ed25519::signature::Signer};
use sha2::{Digest, Sha256};

use super::*;

const PENDING_REVIEW: &[u8] = br#"{
  "schema_version": 2,
  "status": "pending",
  "required_roles": [
    "security",
    "distributed-systems",
    "license/notices",
    "release-owner"
  ],
  "reviewed_candidate": null,
  "reviews": []
}
"#;

const PENDING_TRUST: &[u8] = br#"{
  "schema_version": 1,
  "status": "pending",
  "keys": []
}
"#;

fn sha_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for byte in digest {
        write!(out, "{byte:02x}").expect("write hex");
    }
    out
}

fn artifact_map() -> BTreeMap<String, String> {
    let mut artifacts = BTreeMap::new();
    artifacts.insert("SHA256SUMS".to_owned(), "1".repeat(64));
    artifacts.insert("rados-rs-v1.2.3.spdx.json".to_owned(), "2".repeat(64));
    artifacts.insert("rados-rs-v1.2.3.tar.gz".to_owned(), "3".repeat(64));
    artifacts.insert("rados-rs-v1.2.3.zip".to_owned(), "4".repeat(64));
    artifacts
}

fn candidate_report_bytes() -> Vec<u8> {
    let report = CandidateReport {
        status: "candidate".to_owned(),
        finished_at: "2026-09-16T10:00:00Z".to_owned(),
        reviews: None,
        qualification: QualificationBinding {
            path: QUALIFICATION_REPORT_PATH.to_owned(),
            status: "passed".to_owned(),
            sha256: "a".repeat(64),
        },
        fuzz: FuzzBinding {
            path: FUZZ_REPORT_PATH.to_owned(),
            status: "passed".to_owned(),
            profile: FUZZ_PROFILE.to_owned(),
            sha256: "b".repeat(64),
        },
        release: ReleaseEvidence {
            version: "v1.2.3".to_owned(),
            artifacts: artifact_map(),
        },
    };
    serde_json::to_vec(&report).expect("serialize candidate report")
}

struct SignedFixture {
    review: HumanReviewReport,
    trust: ReviewerTrustPolicy,
    report_bytes: Vec<u8>,
}

fn signed_fixture() -> SignedFixture {
    let report_bytes = candidate_report_bytes();
    let candidate_hash = sha_hex(&report_bytes);
    let artifacts = artifact_map();
    let candidate = ReviewedCandidate {
        report: FileBinding {
            path: CANDIDATE_REPORT_PATH.to_owned(),
            sha256: candidate_hash,
        },
        qualification: QualificationBinding {
            path: QUALIFICATION_REPORT_PATH.to_owned(),
            status: "passed".to_owned(),
            sha256: "a".repeat(64),
        },
        fuzz: FuzzBinding {
            path: FUZZ_REPORT_PATH.to_owned(),
            status: "passed".to_owned(),
            profile: FUZZ_PROFILE.to_owned(),
            sha256: "b".repeat(64),
        },
        release: ReviewedRelease {
            version: "v1.2.3".to_owned(),
            artifacts,
        },
    };
    let mut review = HumanReviewReport {
        schema_version: HUMAN_REVIEW_SCHEMA_VERSION,
        status: "approved".to_owned(),
        required_roles: REQUIRED_ROLES
            .iter()
            .map(|role| (*role).to_owned())
            .collect(),
        reviewed_candidate: Some(candidate),
        reviews: Vec::new(),
    };
    let mut trust = ReviewerTrustPolicy {
        schema_version: REVIEWER_TRUST_SCHEMA_VERSION,
        status: "active".to_owned(),
        keys: Vec::new(),
    };
    // Deterministic per-role signing keys derived from a public salt so tests
    // never require a randomness source or an externally-held private key.
    for (index, role) in REQUIRED_ROLES.iter().enumerate() {
        let mut seed = [0_u8; 32];
        for (offset, slot) in seed.iter_mut().enumerate() {
            *slot = u8::try_from((index + offset + 1) % 251).expect("seed byte");
        }
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = BASE64.encode(signing_key.verifying_key().to_bytes());
        let key_id = format!("test-{}", role.replace('/', "-"));
        let identity = format!("Test Reviewer {role}");
        let affiliation = "Test Organization".to_owned();
        trust.keys.push(TrustedKey {
            key_id: key_id.clone(),
            role: (*role).to_owned(),
            reviewer_identity: identity.clone(),
            reviewer_affiliation: affiliation.clone(),
            public_key,
        });
        let mut record = HumanReviewRecord {
            role: (*role).to_owned(),
            key_id,
            reviewer_identity: identity,
            reviewer_affiliation: affiliation,
            started_at: "2026-09-16T10:00:01Z".to_owned(),
            completed_at: "2026-09-16T10:01:00Z".to_owned(),
            decision: "approved".to_owned(),
            unresolved_findings: FindingCounts {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
            },
            approval_reference: format!(
                "https://approvals.example.test/r13/{}",
                role.replace('/', "-")
            ),
            signature: String::new(),
        };
        review.reviews.push(record.clone());
        let payload = canonical_payload(&review, &review.reviews[index]).expect("payload");
        let signature = signing_key.sign(&payload);
        record.signature = BASE64.encode(signature.to_bytes());
        review.reviews[index] = record;
    }
    SignedFixture {
        review,
        trust,
        report_bytes,
    }
}

fn marshal(value: &impl Serialize) -> Vec<u8> {
    serde_json::to_vec(value).expect("serialize")
}

#[test]
fn canonical_pending_review_and_trust_are_accepted() {
    verify_pending(PENDING_REVIEW, PENDING_TRUST).expect("canonical pending state");
}

#[test]
fn verify_pending_review_helper_matches_shipped_document() {
    let disk = std::fs::read("../../docs/r13/human-review.json").expect("read");
    verify_pending_review(&disk).expect("shipped pending review");
    let trust_disk = std::fs::read("../../docs/r13/reviewer-trust.json").expect("read");
    verify_pending(&disk, &trust_disk).expect("shipped pending state");
}

#[test]
fn automated_approval_is_rejected() {
    let forged = String::from_utf8(PENDING_REVIEW.to_vec())
        .expect("utf8")
        .replace("\"pending\"", "\"approved\"");
    assert!(verify_pending(forged.as_bytes(), PENDING_TRUST).is_err());
}

#[test]
fn pending_review_cannot_contain_claimed_evidence() {
    let forged = String::from_utf8(PENDING_REVIEW.to_vec())
        .expect("utf8")
        .replace("\"reviews\": []", "\"reviews\": [{}]");
    assert!(verify_pending_review(forged.as_bytes()).is_err());
}

#[test]
fn trailing_bytes_are_rejected() {
    let mut bytes = PENDING_REVIEW.to_vec();
    bytes.extend_from_slice(b" {}\n");
    assert!(verify_pending_review(&bytes).is_err());
}

#[test]
fn unknown_fields_are_rejected() {
    let forged = br#"{
        "schema_version": 2,
        "status": "pending",
        "required_roles": ["security","distributed-systems","license/notices","release-owner"],
        "reviewed_candidate": null,
        "reviews": [],
        "unexpected": true
    }"#;
    assert!(verify_pending_review(forged).is_err());
}

#[test]
fn pending_trust_must_list_no_keys() {
    let forged = br#"{
        "schema_version": 1,
        "status": "pending",
        "keys": [{"key_id":"x","role":"security","reviewer_identity":"n","reviewer_affiliation":"a","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]
    }"#;
    assert!(verify_pending(PENDING_REVIEW, forged).is_err());
}

#[test]
fn signed_review_round_trips() {
    let fixture = signed_fixture();
    verify_approved(
        &marshal(&fixture.review),
        &marshal(&fixture.trust),
        &fixture.report_bytes,
    )
    .expect("valid signed review");
}

#[test]
fn approved_review_requires_active_trust() {
    let mut fixture = signed_fixture();
    fixture.trust.status = "pending".to_owned();
    fixture.trust.keys.clear();
    let err = verify_approved(
        &marshal(&fixture.review),
        &marshal(&fixture.trust),
        &fixture.report_bytes,
    );
    assert!(err.is_err());
}

#[test]
fn pending_review_is_rejected_by_final_verifier() {
    let fixture = signed_fixture();
    let mut review = fixture.review;
    review.status = "pending".to_owned();
    assert!(
        verify_approved(
            &marshal(&review),
            &marshal(&fixture.trust),
            &fixture.report_bytes
        )
        .is_err()
    );
}

#[test]
fn tampered_signature_is_rejected() {
    let fixture = signed_fixture();
    let mut review = fixture.review;
    review.reviews[0].unresolved_findings.medium += 1;
    assert!(
        verify_approved(
            &marshal(&review),
            &marshal(&fixture.trust),
            &fixture.report_bytes
        )
        .is_err()
    );
}

#[test]
fn duplicate_role_is_rejected() {
    let fixture = signed_fixture();
    let mut review = fixture.review;
    review.reviews[1].role = review.reviews[0].role.clone();
    assert!(
        verify_approved(
            &marshal(&review),
            &marshal(&fixture.trust),
            &fixture.report_bytes
        )
        .is_err()
    );
}

#[test]
fn duplicate_key_id_is_rejected() {
    let fixture = signed_fixture();
    let mut trust = fixture.trust;
    trust.keys[1].key_id = trust.keys[0].key_id.clone();
    assert!(
        verify_approved(
            &marshal(&fixture.review),
            &marshal(&trust),
            &fixture.report_bytes
        )
        .is_err()
    );
}

#[test]
fn duplicate_public_key_is_rejected() {
    let fixture = signed_fixture();
    let mut trust = fixture.trust;
    trust.keys[1].public_key = trust.keys[0].public_key.clone();
    assert!(
        verify_approved(
            &marshal(&fixture.review),
            &marshal(&trust),
            &fixture.report_bytes
        )
        .is_err()
    );
}

#[test]
fn duplicate_normalized_reviewer_is_rejected() {
    let fixture = signed_fixture();
    let mut trust = fixture.trust;
    trust.keys[1].reviewer_identity = trust.keys[0].reviewer_identity.to_uppercase();
    trust.keys[1].reviewer_affiliation = trust.keys[0].reviewer_affiliation.to_uppercase();
    assert!(
        verify_approved(
            &marshal(&fixture.review),
            &marshal(&trust),
            &fixture.report_bytes
        )
        .is_err()
    );
}

#[test]
fn candidate_hash_mismatch_is_rejected() {
    let fixture = signed_fixture();
    let mut review = fixture.review;
    if let Some(candidate) = review.reviewed_candidate.as_mut() {
        candidate.report.sha256 = "0".repeat(64);
    }
    assert!(
        verify_approved(
            &marshal(&review),
            &marshal(&fixture.trust),
            &fixture.report_bytes
        )
        .is_err()
    );
}

#[test]
fn candidate_bytes_changed_is_rejected() {
    let fixture = signed_fixture();
    let mut bytes = fixture.report_bytes.clone();
    bytes.push(b'\n');
    assert!(verify_approved(&marshal(&fixture.review), &marshal(&fixture.trust), &bytes).is_err());
}

#[test]
fn review_start_must_be_strictly_after_candidate_finish() {
    let fixture = signed_fixture();
    let mut review = fixture.review;
    review.reviews[0].started_at = "2026-09-16T10:00:00Z".to_owned();
    assert!(
        verify_approved(
            &marshal(&review),
            &marshal(&fixture.trust),
            &fixture.report_bytes
        )
        .is_err()
    );
}

#[test]
fn completed_before_started_is_rejected() {
    let fixture = signed_fixture();
    let mut review = fixture.review;
    review.reviews[0].completed_at = "2026-09-16T10:00:00Z".to_owned();
    assert!(
        verify_approved(
            &marshal(&review),
            &marshal(&fixture.trust),
            &fixture.report_bytes
        )
        .is_err()
    );
}

#[test]
fn critical_finding_is_rejected() {
    let fixture = signed_fixture();
    let mut review = fixture.review;
    review.reviews[0].unresolved_findings.critical = 1;
    assert!(
        verify_approved(
            &marshal(&review),
            &marshal(&fixture.trust),
            &fixture.report_bytes
        )
        .is_err()
    );
}

#[test]
fn high_finding_is_rejected() {
    let fixture = signed_fixture();
    let mut review = fixture.review;
    review.reviews[0].unresolved_findings.high = 1;
    assert!(
        verify_approved(
            &marshal(&review),
            &marshal(&fixture.trust),
            &fixture.report_bytes
        )
        .is_err()
    );
}

#[test]
fn non_https_approval_reference_is_rejected() {
    let fixture = signed_fixture();
    let mut review = fixture.review;
    review.reviews[0].approval_reference = "approved by reviewer".to_owned();
    assert!(
        verify_approved(
            &marshal(&review),
            &marshal(&fixture.trust),
            &fixture.report_bytes
        )
        .is_err()
    );
}

#[test]
fn ftp_approval_reference_is_rejected() {
    let fixture = signed_fixture();
    let mut review = fixture.review;
    review.reviews[0].approval_reference = "ftp://approvals.example.test/r13/security".to_owned();
    assert!(
        verify_approved(
            &marshal(&review),
            &marshal(&fixture.trust),
            &fixture.report_bytes
        )
        .is_err()
    );
}

#[test]
fn whitespace_in_approval_reference_is_rejected() {
    let fixture = signed_fixture();
    let mut review = fixture.review;
    review.reviews[0].approval_reference = "https://approvals.example.test/ path".to_owned();
    assert!(
        verify_approved(
            &marshal(&review),
            &marshal(&fixture.trust),
            &fixture.report_bytes
        )
        .is_err()
    );
}

#[test]
fn wrong_key_role_is_rejected() {
    let fixture = signed_fixture();
    let mut review = fixture.review;
    review.reviews[0].key_id = review.reviews[1].key_id.clone();
    assert!(
        verify_approved(
            &marshal(&review),
            &marshal(&fixture.trust),
            &fixture.report_bytes
        )
        .is_err()
    );
}

#[test]
fn identity_mismatch_is_rejected() {
    let fixture = signed_fixture();
    let mut review = fixture.review;
    review.reviews[0].reviewer_identity = "Other Reviewer".to_owned();
    assert!(
        verify_approved(
            &marshal(&review),
            &marshal(&fixture.trust),
            &fixture.report_bytes
        )
        .is_err()
    );
}

#[test]
fn affiliation_mismatch_is_rejected() {
    let fixture = signed_fixture();
    let mut review = fixture.review;
    review.reviews[0].reviewer_affiliation = "Other Organization".to_owned();
    assert!(
        verify_approved(
            &marshal(&review),
            &marshal(&fixture.trust),
            &fixture.report_bytes
        )
        .is_err()
    );
}

#[test]
fn non_canonical_signature_encoding_is_rejected() {
    let fixture = signed_fixture();
    let mut review = fixture.review;
    // Decode, then re-encode with URL-safe alphabet so the standard-alphabet
    // check round-trips fail.
    let raw = BASE64
        .decode(review.reviews[0].signature.as_bytes())
        .expect("decode");
    let alternate = base64::engine::general_purpose::URL_SAFE.encode(raw);
    review.reviews[0].signature = alternate;
    assert!(
        verify_approved(
            &marshal(&review),
            &marshal(&fixture.trust),
            &fixture.report_bytes
        )
        .is_err()
    );
}

#[test]
fn wrong_candidate_path_is_rejected() {
    let fixture = signed_fixture();
    let mut review = fixture.review;
    if let Some(candidate) = review.reviewed_candidate.as_mut() {
        candidate.report.path = "integration/p12/report.json".to_owned();
    }
    assert!(
        verify_approved(
            &marshal(&review),
            &marshal(&fixture.trust),
            &fixture.report_bytes
        )
        .is_err()
    );
}

#[test]
fn wrong_qualification_path_in_report_is_rejected() {
    let fixture = signed_fixture();
    // Reserialize the report with a mismatched qualification path.
    let mut report: CandidateReport =
        serde_json::from_slice(&fixture.report_bytes).expect("deserialize");
    report.qualification.path = "docs/p12/qualification-report.json".to_owned();
    let bytes = serde_json::to_vec(&report).expect("serialize");
    assert!(verify_approved(&marshal(&fixture.review), &marshal(&fixture.trust), &bytes).is_err());
}

#[test]
fn wrong_fuzz_profile_in_report_is_rejected() {
    let fixture = signed_fixture();
    let mut report: CandidateReport =
        serde_json::from_slice(&fixture.report_bytes).expect("deserialize");
    report.fuzz.profile = "smoke".to_owned();
    let bytes = serde_json::to_vec(&report).expect("serialize");
    assert!(verify_approved(&marshal(&fixture.review), &marshal(&fixture.trust), &bytes).is_err());
}

#[test]
fn candidate_status_must_be_candidate() {
    let fixture = signed_fixture();
    let mut report: CandidateReport =
        serde_json::from_slice(&fixture.report_bytes).expect("deserialize");
    report.status = "passed".to_owned();
    let bytes = serde_json::to_vec(&report).expect("serialize");
    assert!(verify_approved(&marshal(&fixture.review), &marshal(&fixture.trust), &bytes).is_err());
}

#[test]
fn report_with_embedded_reviews_is_rejected() {
    let fixture = signed_fixture();
    let mut report: CandidateReport =
        serde_json::from_slice(&fixture.report_bytes).expect("deserialize");
    report.reviews = Some(serde_json::json!([]));
    let bytes = serde_json::to_vec(&report).expect("serialize");
    assert!(verify_approved(&marshal(&fixture.review), &marshal(&fixture.trust), &bytes).is_err());
}

#[test]
fn release_artifact_count_must_be_four() {
    let fixture = signed_fixture();
    let mut report: CandidateReport =
        serde_json::from_slice(&fixture.report_bytes).expect("deserialize");
    report.release.artifacts.pop_first();
    let bytes = serde_json::to_vec(&report).expect("serialize");
    assert!(verify_approved(&marshal(&fixture.review), &marshal(&fixture.trust), &bytes).is_err());
}

#[test]
fn canonical_payload_is_deterministic_and_newline_terminated() {
    let fixture = signed_fixture();
    let first = canonical_payload(&fixture.review, &fixture.review.reviews[0]).expect("first");
    let second = canonical_payload(&fixture.review, &fixture.review.reviews[0]).expect("second");
    assert_eq!(first, second);
    assert!(!first.is_empty());
    assert_eq!(*first.last().expect("non-empty"), b'\n');
    assert_ne!(first[first.len() - 2], b'\n');
}

#[test]
fn print_review_payload_returns_signing_bytes() {
    let fixture = signed_fixture();
    let bytes = print_review_payload("security", &marshal(&fixture.review), &fixture.report_bytes)
        .expect("payload");
    let want = canonical_payload(&fixture.review, &fixture.review.reviews[0]).expect("want");
    assert_eq!(bytes, want);
}

#[test]
fn print_review_payload_rejects_pending_review() {
    let err = print_review_payload("security", PENDING_REVIEW, &candidate_report_bytes());
    assert!(err.is_err());
}

#[test]
fn print_review_payload_rejects_unknown_role() {
    let fixture = signed_fixture();
    let err = print_review_payload(
        "ai-assistant",
        &marshal(&fixture.review),
        &fixture.report_bytes,
    );
    assert!(err.is_err());
}

#[test]
fn print_review_payload_rejects_mismatched_report() {
    let fixture = signed_fixture();
    let mut bytes = fixture.report_bytes.clone();
    bytes.push(b'\n');
    let err = print_review_payload("security", &marshal(&fixture.review), &bytes);
    assert!(err.is_err());
}

#[test]
fn shipped_schemas_are_valid_json() {
    for path in [
        "../../integration/r13/human-review.schema.json",
        "../../integration/r13/reviewer-trust.schema.json",
        "../../integration/r13/report.schema.json",
    ] {
        let bytes = std::fs::read(path).unwrap_or_else(|_| panic!("read {path}"));
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or_else(|_| panic!("parse {path}"));
        assert!(value.get("$schema").is_some(), "{path} missing $schema");
    }
}

#[test]
fn candidate_pending_matches_schema_null_renewals() {
    // The pending document must publish `session_renewals` and
    // `credential_renewals` as null with the sentinel renewal_measurement
    // string. Any drift silently breaks the honest-renewal contract.
    let bytes = std::fs::read("../../docs/r13/report.pending.json")
        .expect("read pending");
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).expect("parse pending");
    for transport in ["secure", "crc"] {
        let probe = value
            .get("probe")
            .and_then(|p| p.get(transport))
            .unwrap_or_else(|| panic!("missing probe.{transport}"));
        assert!(
            probe.get("session_renewals").is_some_and(serde_json::Value::is_null),
            "{transport} session_renewals must be null"
        );
        assert!(
            probe.get("credential_renewals").is_some_and(serde_json::Value::is_null),
            "{transport} credential_renewals must be null"
        );
        assert_eq!(
            probe.get("renewal_measurement").and_then(|v| v.as_str()),
            Some(crate::candidate::RENEWAL_MEASUREMENT_SENTINEL)
        );
        assert_eq!(
            probe.get("inflight_measurement").and_then(|v| v.as_str()),
            Some(crate::candidate::INFLIGHT_MEASUREMENT_SENTINEL)
        );
    }
}

#[test]
fn r13_shell_scripts_pass_syntax_check() {
    use std::path::Path;
    use std::process::Command;
    let scripts_dir = Path::new("../../integration/r13");
    let entries = std::fs::read_dir(scripts_dir).expect("read integration/r13");
    let mut checked = 0;
    for entry in entries {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("sh") {
            continue;
        }
        let output = Command::new("sh")
            .arg("-n")
            .arg(&path)
            .output()
            .expect("spawn sh -n");
        assert!(
            output.status.success(),
            "sh -n failed on {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        checked += 1;
    }
    assert!(checked >= 3, "expected at least three r13 shell scripts");
}
