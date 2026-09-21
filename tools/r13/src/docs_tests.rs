//! Verifier tests: the R13 documentation set references existing paths and
//! keeps its landed constants/counts in sync with the checked-in source.
//!
//! Runs from `tools/r13/`. Any workspace-root-relative path uses `../../` as
//! its base.

use std::fs;
use std::path::{Path, PathBuf};

use crate::constants::{
    BENCH_CONCURRENCIES, BENCH_ROWS_PER_RUN, BENCH_RUNS_PER_CANDIDATE, BENCH_SIZES,
    BENCH_WORKLOADS, CANDIDATE_CLUSTER_FSID, CANDIDATE_CLUSTER_MONITOR, CANDIDATE_CLUSTER_NETWORK,
    CANDIDATE_CLUSTER_POOL_MIN_SIZE, CANDIDATE_CLUSTER_POOL_NAME, CANDIDATE_CLUSTER_POOL_PG_NUM,
    CANDIDATE_CLUSTER_POOL_SIZE, CANDIDATE_CLUSTER_TICKET_TTL_SECONDS, CARGO_AUDIT_VERSION,
    CARGO_DENY_VERSION, CARGO_FUZZ_VERSION, CEPH_IMAGE_AMD64, CEPH_IMAGE_ARM64,
    CEPH_SERVER_COMMIT, CHECK_IDS, COMPILER_IMAGE, FUZZ_CERTIFYING_MIN_SECONDS,
    FUZZ_NIGHTLY_TOOLCHAIN, FUZZ_SMOKE_MIN_SECONDS, FUZZ_TARGETS, KNOWN_PLATFORMS,
    LEDGER_ALLOWED_STATUSES, NATIVE_INVENTORY_ROWS, PARITY_LEDGER_ROWS, RUST_MSRV,
    RUST_STABLE_OBSERVED,
};

fn workspace_root() -> PathBuf {
    Path::new("../../").canonicalize().expect("workspace root")
}

fn read_doc(rel: &str) -> String {
    let path = workspace_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("read {} failed: {error}", path.display());
    })
}

fn assert_contains(doc: &str, needle: &str, name: &str) {
    assert!(
        doc.contains(needle),
        "{name} is missing required token {needle:?}"
    );
}

fn assert_path_exists(doc: &str, doc_name: &str, rel: &str) {
    let full = workspace_root().join(rel);
    assert!(
        full.exists(),
        "{doc_name} references {rel} which does not exist under the workspace root"
    );
    // Sanity: the doc should actually mention the path fragment.
    assert!(
        doc.contains(rel) || doc.contains(&rel.replace("../../", "")),
        "{doc_name} does not reference {rel}"
    );
}

#[test]
fn every_documented_r13_file_exists() {
    let docs = [
        "docs/r13/README.md",
        "docs/r13/STATUS.md",
        "docs/r13/compatibility.md",
        "docs/r13/dependencies.md",
        "docs/r13/performance.md",
        "docs/r13/migration.md",
        "docs/r13/troubleshooting.md",
        "docs/r13/release.md",
        "docs/r13/automated-review.md",
        "docs/r13/human-review.md",
        "docs/r13/review-template.md",
        "docs/r13/human-review.json",
        "docs/r13/reviewer-trust.json",
        "docs/r13/report.pending.json",
        "docs/r13/qualification-report.pending.json",
        "docs/r13/fuzz-report.pending.json",
        "docs/decisions/0002-r13-qualification-contract.md",
    ];
    for doc in docs {
        let full = workspace_root().join(doc);
        assert!(full.exists(), "expected {doc} to exist");
    }
}

#[test]
fn readme_index_lists_r13_companion_documents() {
    let readme = read_doc("docs/r13/README.md");
    for section in [
        "STATUS.md",
        "compatibility.md",
        "dependencies.md",
        "performance.md",
        "migration.md",
        "troubleshooting.md",
        "release.md",
        "automated-review.md",
        "human-review.md",
        "review-template.md",
        "qualification-report.pending.json",
        "fuzz-report.pending.json",
        "report.pending.json",
    ] {
        assert_contains(&readme, section, "docs/r13/README.md");
    }
    // The index must state its own blocked status.
    assert!(
        readme.contains("blocked and pending") || readme.contains("**blocked"),
        "docs/r13/README.md must record its blocked/pending status"
    );
}

#[test]
fn readme_pins_msrv_and_toolchains() {
    let readme = read_doc("docs/r13/README.md");
    assert_contains(&readme, RUST_MSRV, "docs/r13/README.md");
    assert_contains(&readme, FUZZ_NIGHTLY_TOOLCHAIN, "docs/r13/README.md");
    assert_contains(&readme, CARGO_AUDIT_VERSION, "docs/r13/README.md");
    assert_contains(&readme, CARGO_DENY_VERSION, "docs/r13/README.md");
    assert_contains(&readme, CARGO_FUZZ_VERSION, "docs/r13/README.md");
}

#[test]
fn compatibility_doc_lists_msrv_and_features_and_platforms() {
    let doc = read_doc("docs/r13/compatibility.md");
    assert_contains(&doc, RUST_MSRV, "docs/r13/compatibility.md");
    assert_contains(&doc, RUST_STABLE_OBSERVED, "docs/r13/compatibility.md");
    assert_contains(&doc, FUZZ_NIGHTLY_TOOLCHAIN, "docs/r13/compatibility.md");
    for platform in KNOWN_PLATFORMS {
        assert_contains(&doc, platform, "docs/r13/compatibility.md");
    }
    for feature in [
        "r04-integration",
        "r05-integration",
        "r06-integration",
        "r07-integration",
        "r08-integration",
        "r09-integration",
        "r10-integration",
        "r11-integration",
        "r12-integration",
    ] {
        assert_contains(&doc, feature, "docs/r13/compatibility.md");
    }
    // Ledger dispositions callout.
    for status in ["deferred-r12", "intentional-omission-r12", "planned-not-implemented"] {
        assert_contains(&doc, status, "docs/r13/compatibility.md");
    }
    // Exact known counts.
    assert_contains(
        &doc,
        &format!("{NATIVE_INVENTORY_ROWS}"),
        "docs/r13/compatibility.md",
    );
    assert_contains(
        &doc,
        &format!("{PARITY_LEDGER_ROWS}"),
        "docs/r13/compatibility.md",
    );
}

#[test]
fn dependencies_doc_lists_every_production_dep() {
    let doc = read_doc("docs/r13/dependencies.md");
    for entry in [
        "aes",
        "aes-gcm",
        "base64",
        "cbc",
        "crc32c",
        "getrandom",
        "hickory-resolver",
        "hmac",
        "serde_json",
        "sha2",
        "tokio",
        "zeroize",
        "ed25519-dalek",
        "libfuzzer-sys",
        "sha1",
    ] {
        assert_contains(&doc, entry, "docs/r13/dependencies.md");
    }
    // Pinned versions must match Cargo.toml.
    for pin in [
        "=0.9.3", "=0.11.1", "=0.22.1", "=0.2.1", "=0.6.8", "=0.4.3",
        "=0.26.3", "=0.13.0", "=1.0.229", "=1.0.151", "=0.11.0",
        "=1.47.1", "=1.9.0", "=2.1.1", "=0.7.2", "=0.4.13",
    ] {
        assert_contains(&doc, pin, "docs/r13/dependencies.md");
    }
    // Ceph and compiler pins mentioned.
    assert_contains(&doc, CEPH_SERVER_COMMIT, "docs/r13/dependencies.md");
}

#[test]
fn performance_doc_lists_budget_and_matrix() {
    let doc = read_doc("docs/r13/performance.md");
    for size in BENCH_SIZES {
        let raw = size.to_string();
        let underscored = format_underscored(size);
        assert!(
            doc.contains(&raw) || doc.contains(&underscored),
            "docs/r13/performance.md missing bench size {size}"
        );
    }
    for concurrency in BENCH_CONCURRENCIES {
        assert_contains(&doc, &concurrency.to_string(), "docs/r13/performance.md");
    }
    for workload in BENCH_WORKLOADS {
        assert_contains(&doc, workload, "docs/r13/performance.md");
    }
    assert_contains(
        &doc,
        &format!("{BENCH_ROWS_PER_RUN}"),
        "docs/r13/performance.md",
    );
    assert_contains(
        &doc,
        &format!("{BENCH_RUNS_PER_CANDIDATE}"),
        "docs/r13/performance.md",
    );
    // Budget floors as decimal strings.
    assert_contains(&doc, "0.10", "docs/r13/performance.md");
    assert_contains(&doc, "8.0", "docs/r13/performance.md");
    assert_contains(&doc, "2 684 354 560", "docs/r13/performance.md");
    assert_contains(&doc, "1 000 000", "docs/r13/performance.md");
    assert_contains(&doc, "42 949 672 960", "docs/r13/performance.md");
}

#[test]
fn release_doc_documents_deterministic_artifacts_and_lgpl() {
    let doc = read_doc("docs/r13/release.md");
    for artifact in [".crate", ".zip", ".spdx.json", "SHA256SUMS"] {
        assert_contains(&doc, artifact, "docs/r13/release.md");
    }
    assert_contains(&doc, "LGPL-2.1-only", "docs/r13/release.md");
    assert_contains(&doc, "technical guidance", "docs/r13/release.md");
    assert_contains(&doc, "not legal advice", "docs/r13/release.md");
    assert_contains(&doc, "separate authorization", "docs/r13/release.md");
    assert_contains(&doc, "publish = false", "docs/r13/release.md");
    for role in ["security", "distributed-systems", "license/notices", "release-owner"] {
        assert_contains(&doc, role, "docs/r13/release.md");
    }
}

#[test]
fn automated_review_doc_states_non_substitution() {
    let doc = read_doc("docs/r13/automated-review.md");
    for phrase in [
        "not** approve",
        "not** hold",
        "not** fabricate",
        "not** create release tags",
        "not** claim legal",
    ] {
        assert_contains(&doc, phrase, "docs/r13/automated-review.md");
    }
}

#[test]
fn troubleshooting_doc_covers_each_producer() {
    let doc = read_doc("docs/r13/troubleshooting.md");
    for section in ["qualify.sh", "validate-fuzz.sh", "reproduce.sh", "rados-r13-verify"] {
        assert_contains(&doc, section, "docs/r13/troubleshooting.md");
    }
}

#[test]
fn adr_0002_fixes_identity_and_gate_shape() {
    let doc = read_doc("docs/decisions/0002-r13-qualification-contract.md");
    assert_contains(
        &doc,
        CANDIDATE_CLUSTER_FSID,
        "docs/decisions/0002-r13-qualification-contract.md",
    );
    assert_contains(
        &doc,
        CANDIDATE_CLUSTER_NETWORK,
        "docs/decisions/0002-r13-qualification-contract.md",
    );
    assert_contains(
        &doc,
        CANDIDATE_CLUSTER_MONITOR,
        "docs/decisions/0002-r13-qualification-contract.md",
    );
    assert_contains(
        &doc,
        CANDIDATE_CLUSTER_POOL_NAME,
        "docs/decisions/0002-r13-qualification-contract.md",
    );
    assert_contains(
        &doc,
        &format!("size={CANDIDATE_CLUSTER_POOL_SIZE}"),
        "docs/decisions/0002-r13-qualification-contract.md",
    );
    assert_contains(
        &doc,
        &format!("min_size={CANDIDATE_CLUSTER_POOL_MIN_SIZE}"),
        "docs/decisions/0002-r13-qualification-contract.md",
    );
    assert_contains(
        &doc,
        &format!("pg_num={CANDIDATE_CLUSTER_POOL_PG_NUM}"),
        "docs/decisions/0002-r13-qualification-contract.md",
    );
    assert_contains(
        &doc,
        &format!("{CANDIDATE_CLUSTER_TICKET_TTL_SECONDS} s"),
        "docs/decisions/0002-r13-qualification-contract.md",
    );
    assert_contains(
        &doc,
        RUST_MSRV,
        "docs/decisions/0002-r13-qualification-contract.md",
    );
    assert_contains(
        &doc,
        FUZZ_NIGHTLY_TOOLCHAIN,
        "docs/decisions/0002-r13-qualification-contract.md",
    );
    // Fuzz certifying budget wall clock.
    assert_contains(
        &doc,
        &format!("{FUZZ_CERTIFYING_MIN_SECONDS}"),
        "docs/decisions/0002-r13-qualification-contract.md",
    );
    // Fuzz target count referenced in ADR body.
    let target_count = FUZZ_TARGETS.len();
    assert_contains(
        &doc,
        &target_count.to_string(),
        "docs/decisions/0002-r13-qualification-contract.md",
    );
    for image in [COMPILER_IMAGE, CEPH_IMAGE_AMD64, CEPH_IMAGE_ARM64] {
        // Image digests are long; the ADR uses a truncated form via `…`.
        // Check the leading twelve characters of the digest as the anchor.
        let prefix: String = image.chars().take(12).collect();
        assert_contains(&doc, &prefix, "docs/decisions/0002-r13-qualification-contract.md");
    }
}

#[test]
fn readme_references_docs_and_adr_have_valid_paths() {
    let readme = read_doc("README.md");
    for path in [
        "docs/r13/README.md",
        "docs/r13/STATUS.md",
        "docs/r13/compatibility.md",
        "docs/r13/dependencies.md",
        "docs/r13/performance.md",
        "docs/r13/migration.md",
        "docs/r13/troubleshooting.md",
        "docs/r13/release.md",
        "docs/r13/automated-review.md",
        "docs/r13/human-review.md",
        "docs/decisions/0002-r13-qualification-contract.md",
    ] {
        assert_path_exists(&readme, "README.md", path);
    }
}

#[test]
fn compatibility_documents_actual_ledger_status_counts() {
    let doc = read_doc("docs/r13/compatibility.md");
    for status in LEDGER_ALLOWED_STATUSES {
        // Every allow-list status must be either explained in the doc or
        // explicitly listed in the ledger dispositions section.
        // We assert on the three critical dispositions here; others are
        // covered by inventory tests.
        if matches!(*status, "deferred-r12" | "intentional-omission-r12" | "planned-not-implemented") {
            assert_contains(&doc, status, "docs/r13/compatibility.md");
        }
    }
    // Explicitly stated deferred-r12 row count.
    assert_contains(&doc, "19 rows", "docs/r13/compatibility.md");
}

fn format_underscored(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    let bytes = s.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        let from_end = bytes.len() - index;
        if index > 0 && from_end.is_multiple_of(3) {
            out.push('_');
        }
        out.push(*byte as char);
    }
    out
}

#[test]
fn ledger_check_all_known_status_counts_match_documented_totals() {
    // Verifies the compatibility narrative uses the real ledger status
    // distribution for the three explicitly named dispositions. Prevents
    // drift where the doc claims a stale count.
    let ledger = read_doc("docs/r00/parity-ledger.csv");
    let mut count_deferred = 0_usize;
    let mut count_intentional = 0_usize;
    let mut count_planned = 0_usize;
    for (index, line) in ledger.lines().enumerate() {
        if index == 0 || line.is_empty() {
            continue;
        }
        // Status is the trailing comma-separated field, ignoring quoted commas.
        let status = trailing_status(line).expect("status field");
        match status {
            "deferred-r12" => count_deferred += 1,
            "intentional-omission-r12" => count_intentional += 1,
            "planned-not-implemented" => count_planned += 1,
            _ => {}
        }
    }
    assert_eq!(count_deferred, 19, "documented deferred-r12 count drifted");
    assert_eq!(
        count_intentional, 118,
        "documented intentional-omission-r12 count drifted"
    );
    assert_eq!(
        count_planned, 0,
        "documented planned-not-implemented count drifted"
    );
    let doc = read_doc("docs/r13/compatibility.md");
    for (count, label) in [
        (count_deferred, "deferred-r12"),
        (count_intentional, "intentional-omission-r12"),
        (count_planned, "planned-not-implemented"),
    ] {
        let expected = format!("{count} rows");
        assert!(
            doc.contains(&expected),
            "docs/r13/compatibility.md must state '{expected}' for {label}"
        );
    }
}

fn trailing_status(row: &str) -> Option<&str> {
    let mut in_quotes = false;
    let mut last_split = None;
    for (index, byte) in row.as_bytes().iter().enumerate() {
        match *byte {
            b'"' => in_quotes = !in_quotes,
            b',' if !in_quotes => last_split = Some(index),
            _ => {}
        }
    }
    last_split.map(|idx| &row[idx + 1..])
}

#[test]
fn check_ids_smoke_size_and_ordering() {
    // The R13 ADR claims exactly 24 canonical check ids. Preserve that
    // count via a decorative assertion so anyone changing CHECK_IDS also
    // updates ADR 0002.
    assert_eq!(CHECK_IDS.len(), 24, "CHECK_IDS count drifted");
    assert_eq!(FUZZ_SMOKE_MIN_SECONDS, 60);
    assert_eq!(FUZZ_CERTIFYING_MIN_SECONDS, 600);
    assert_eq!(FUZZ_TARGETS.len(), 42);
}

#[test]
fn dependencies_matches_root_cargo_manifest() {
    // The docs/r13/dependencies.md table must reference every top-level
    // production dep in the root Cargo.toml. This test catches accidental
    // drift when a dependency is added or removed.
    let manifest = read_doc("Cargo.toml");
    let start = manifest.find("[dependencies]").expect("[dependencies]");
    let end = manifest[start..].find("\n[").map_or(manifest.len(), |offset| start + offset);
    let block = &manifest[start..end];
    let doc = read_doc("docs/r13/dependencies.md");
    for line in block.lines().skip(1) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some(name) = trimmed.split('=').next() else { continue };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        assert!(
            doc.contains(name),
            "docs/r13/dependencies.md missing production crate {name}"
        );
    }
}

#[test]
fn readme_pending_states_are_honest() {
    let readme = read_doc("docs/r13/README.md");
    assert_contains(&readme, "blocked and pending", "docs/r13/README.md");
    for phrase in [
        "not produced",
        "24-hour",
        "four detached Ed25519",
        "no crate publish",
    ] {
        assert_contains(&readme, phrase, "docs/r13/README.md");
    }
}
