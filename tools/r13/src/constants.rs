//! Frozen R13 identity constants.
//!
//! These values are immutable for the R13 automated qualification contract
//! and MUST match the pinned tool/image versions verified against the R12
//! evidence baseline. They are copied here so `rados-r13-qualify` and its
//! verifier do not need to re-open R12's crate at runtime.

pub const RUST_MSRV: &str = "1.98.0";
pub const RUST_STABLE_OBSERVED: &str = "rustc 1.98.0 (88d9e12ae 2026-08-18)";

pub const COMPILER_IMAGE: &str =
    "rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922";
pub const CEPH_IMAGE_AMD64: &str =
    "quay.io/ceph/ceph@sha256:09ee90f6f3e0c7b9954f71d214ee05e9bbaaaea3716b1dd619603283b829f8b8";
pub const CEPH_IMAGE_ARM64: &str =
    "quay.io/ceph/ceph@sha256:6e6bc7b28fa1b334108a3646af5533dfb50db508efdf5b358eb7dd0dd37a48aa";
pub const CEPH_SERVER_COMMIT: &str = "7f793731f1b39eb4f465e960113d2363c311b964";
pub const CEPH_SERVER_VERSION: &str =
    "ceph version 20.2.4 (7f793731f1b39eb4f465e960113d2363c311b964) tentacle (stable)";

pub const CARGO_AUDIT_VERSION: &str = "cargo-audit 0.22.2";
pub const CARGO_DENY_VERSION: &str = "cargo-deny 0.20.2";
pub const CARGO_FUZZ_VERSION: &str = "cargo-fuzz 0.13.2";

pub const NATIVE_INVENTORY_PATH: &str = "reference/go/docs/p00/api-inventory.csv";
pub const PARITY_LEDGER_PATH: &str = "docs/r00/parity-ledger.csv";
pub const NATIVE_INVENTORY_ROWS: usize = 623;
pub const PARITY_LEDGER_ROWS: usize = 905;

/// Statuses considered "resolved" for the R13 v1 scope. The `deferred-r12`
/// status is closed outside the R13 v1 exit gate but remains a valid ledger
/// disposition. Any status outside this list is treated as unresolved.
pub const LEDGER_ALLOWED_STATUSES: &[&str] = &[
    "adapted-r12",
    "deferred-r12",
    "implemented-r02",
    "implemented-r05",
    "implemented-r07",
    "implemented-r08",
    "implemented-r09",
    "implemented-r10",
    "implemented-r11",
    "implemented-r12",
    "intentional-omission-r12",
    "planned-not-implemented",
];

/// Canonical ordered list of qualification check identifiers.
pub const CHECK_IDS: &[&str] = &[
    "toolchain-msrv",
    "toolchain-stable",
    "features",
    "build",
    "test",
    "clippy",
    "doc",
    "audit",
    "deny",
    "package",
    "example",
    "inventory",
    "deterministic-release",
    "source-digest",
    "prior-r03",
    "prior-r04",
    "prior-r05",
    "prior-r06",
    "prior-r07",
    "prior-r08",
    "prior-r09",
    "prior-r10",
    "prior-r11",
    "prior-r12",
];

/// Ordered priors bound by the qualification report. The path is the fixed
/// artifact under `docs/rNN/` a passing report must reference.
pub const PRIOR_REPORTS: &[(&str, &str)] = &[
    ("r03", "docs/r03/STATUS.md"),
    ("r04", "docs/r04/live-integration-report.json"),
    ("r05", "docs/r05/live-integration-report.json"),
    ("r06", "docs/r06/STATUS.md"),
    ("r07", "docs/r07/live-integration-report.json"),
    ("r08", "docs/r08/live-qualification-report.json"),
    ("r09", "docs/r09/live-qualification-report.json"),
    ("r10", "docs/r10/live-qualification-report.json"),
    ("r11", "docs/r11/live-qualification-report.json"),
    ("r12", "docs/r12/live-qualification-report.json"),
];

/// R13 qualification report artefact identity.
pub const QUALIFICATION_SUITE_ID: &str = "r13/automated-qualification-v1";
pub const QUALIFICATION_SCHEMA_VERSION: u32 = 1;
pub const QUALIFICATION_REPORT_MAX_BYTES: u64 = 524_288;
pub const QUALIFICATION_PENDING_PATH: &str = "docs/r13/qualification-report.pending.json";
pub const QUALIFICATION_LIVE_PATH: &str = "docs/r13/qualification-report.json";

/// Recognised host platforms for runtime observations.
pub const KNOWN_PLATFORMS: &[&str] =
    &["linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64"];

// -----------------------------------------------------------------------------
// Fuzz contract constants (R13 v1)
// -----------------------------------------------------------------------------

/// Frozen nightly toolchain used to build every fuzz target. Matches the R12
/// pinned host toolchain so cargo-fuzz produces reproducible binaries.
pub const FUZZ_NIGHTLY_TOOLCHAIN: &str = "nightly-2026-09-01";
pub const FUZZ_CARGO_FUZZ_VERSION: &str = "cargo-fuzz 0.13.2";
pub const FUZZ_SUITE_ID: &str = "r13/fuzz-validation-v1";
pub const FUZZ_SCHEMA_VERSION: u32 = 1;
pub const FUZZ_REPORT_MAX_BYTES: u64 = 1_048_576;
pub const FUZZ_LIVE_PATH: &str = "docs/r13/fuzz-report.json";
pub const FUZZ_PENDING_PATH: &str = "docs/r13/fuzz-report.pending.json";
pub const FUZZ_OUTPUT_DIR_NAME: &str = "fuzz-validation-logs";
/// Canonical in-repo path holding one deterministic seed corpus per fuzz
/// target. Excluded from the crate package by the root `Cargo.toml`
/// `exclude = ["fuzz"]` clause and excluded from the R13 source digest
/// because [`crate::source::SOURCE_PATHSPECS`] does not list
/// `fuzz/corpus/**`. Producer and verifier read/write this path.
pub const FUZZ_CORPUS_ROOT: &str = "fuzz/corpus";

/// Per-target minimum wall clock seconds. Smoke exists so continuous
/// integration can exercise every parser in bounded time; certifying is the
/// release gate. Pending has no run time because it records that no campaign
/// has yet been executed.
pub const FUZZ_SMOKE_MIN_SECONDS: u64 = 60;
pub const FUZZ_CERTIFYING_MIN_SECONDS: u64 = 600;

/// Recognised profile identifiers, in escalation order.
pub const FUZZ_PROFILE_PENDING: &str = "pending";
pub const FUZZ_PROFILE_SMOKE: &str = "smoke";
pub const FUZZ_PROFILE_CERTIFYING: &str = "certifying";
pub const FUZZ_PROFILES: [&str; 3] = [
    FUZZ_PROFILE_PENDING,
    FUZZ_PROFILE_SMOKE,
    FUZZ_PROFILE_CERTIFYING,
];

/// Canonical alphabetically sorted enumeration of every fuzz target the R13
/// contract is willing to certify. This list is duplicated on purpose: any
/// drift from `fuzz/Cargo.toml` or `fuzz/fuzz_targets/*.rs` breaks
/// [`crate::fuzz::verify_inventory`] instead of silently omitting or
/// injecting a target.
pub const FUZZ_TARGETS: [&str; 42] = [
    "banner",
    "bounded_session_scripts",
    "cephx_auth_session_reply",
    "cephx_authorizer",
    "cephx_credentials",
    "cephx_server_challenge",
    "controls",
    "crc_frame",
    "entity_address",
    "entity_address_vector",
    "messages",
    "primitive_decoder",
    "r05_config",
    "r05_monmap",
    "r05_monmap_message",
    "r05_osdmap",
    "r05_osdmap_full_message",
    "r05_osdmap_incremental",
    "r05_osdmap_incremental_message",
    "r06_crush_decode",
    "r06_crush_place",
    "r06_object_mapping",
    "r06_osdmap_place_object",
    "r07_osd_backoff",
    "r07_osd_reply",
    "r08_mutation_recovery",
    "r08_mutation_reply",
    "r08_mutation_request",
    "r09_compound",
    "r09_enumeration",
    "r09_metadata",
    "r10_class",
    "r10_lock",
    "r10_watch",
    "r11_snapshot",
    "r11_sparse",
    "r11_special",
    "r12_command",
    "r12_inconsistent",
    "r12_stats",
    "secure_frame",
    "versioned_envelope",
];

// -----------------------------------------------------------------------------
// R13 candidate (endurance) contract constants
// -----------------------------------------------------------------------------

/// Candidate report identity.
pub const CANDIDATE_SCHEMA_VERSION: u32 = 2;
pub const CANDIDATE_REPORT_LIVE_PATH: &str = "integration/r13/report.json";
pub const CANDIDATE_REPORT_PENDING_PATH: &str = "docs/r13/report.pending.json";
pub const CANDIDATE_REPORT_SCHEMA_PATH: &str = "integration/r13/report.schema.json";
pub const CANDIDATE_REPRODUCE_COMMAND: &str = "./integration/r13/reproduce.sh";
pub const CANDIDATE_REPORT_MAX_BYTES: u64 = 4_194_304;

/// Source binding identity.
pub const CANDIDATE_SOURCE_REPOSITORY: &str = "https://github.com/otuschhoff/rados-rs.git";
pub const CANDIDATE_SOURCE_IDENTITY: &str = "content-addressed-artifacts";

/// Cluster identity (fresh R13, isolated from Go P12).
pub const CANDIDATE_CLUSTER_FSID: &str = "41111111-2222-4333-8444-131313131313";
pub const CANDIDATE_CLUSTER_NETWORK: &str = "172.30.114.0/24";
pub const CANDIDATE_CLUSTER_MONITOR: &str = "v2:172.30.114.10:3300";
pub const CANDIDATE_CLUSTER_POOL_NAME: &str = "r13-data";
pub const CANDIDATE_CLUSTER_POOL_SIZE: u32 = 2;
pub const CANDIDATE_CLUSTER_POOL_MIN_SIZE: u32 = 1;
pub const CANDIDATE_CLUSTER_POOL_PG_NUM: u32 = 16;
pub const CANDIDATE_CLUSTER_OSDS: u32 = 3;
pub const CANDIDATE_CLUSTER_TICKET_TTL_SECONDS: u32 = 900;
pub const CANDIDATE_CLUSTER_MIN_MANAGERS_WHEN_EXERCISED: u32 = 2;
pub const CANDIDATE_TRANSPORTS: [&str; 2] = ["secure", "crc"];

/// Server platform identity (matches R08+ evidence).
pub const CANDIDATE_KNOWN_SERVER_PLATFORMS: [&str; 2] = ["linux/amd64", "linux/arm64"];

/// Endurance certifying thresholds. Twenty-four wall-clock hours, 15 minute
/// longest connection (strict `>`), and 24 credential-refresh reconnects.
pub const CANDIDATE_MIN_CERTIFYING_DURATION_NS: u64 = 86_400_000_000_000;
pub const CANDIDATE_MIN_LONGEST_CONNECTION_NS: u64 = 900_000_000_000;
pub const CANDIDATE_MIN_RECONNECTS: u64 = 24;
pub const CANDIDATE_PROBE_MAX_SAMPLES: usize = 2000;

/// Release artefact retention path (four artefacts atomically staged there).
pub const CANDIDATE_RELEASE_ARTIFACTS_PATH: &str = "docs/r13/release-artifacts";
pub const CANDIDATE_RELEASE_ARTIFACT_COUNT: usize = 4;

/// Benchmark matrix dimensions.
pub const BENCH_SIZES: [u64; 4] = [4096, 65536, 1_048_576, 4_194_304];
pub const BENCH_CONCURRENCIES: [u32; 3] = [1, 16, 64];
pub const BENCH_WORKLOADS: [&str; 3] = ["read", "write", "mixed"];
pub const BENCH_ROWS_PER_RUN: usize = 36;
pub const BENCH_RUNS_PER_CANDIDATE: usize = 4;
pub const BENCH_IMPLEMENTATIONS: [&str; 2] = ["rust", "native"];

/// Approved conservative R08-derived benchmark budget (four immutable bounds).
pub const BENCH_MIN_NATIVE_THROUGHPUT_RATIO: f64 = 0.10;
pub const BENCH_MAX_NATIVE_P99_RATIO: f64 = 8.0;
pub const BENCH_MAX_RSS_BYTES: u64 = 2_684_354_560;
pub const BENCH_MAX_ALLOCATIONS: u64 = 1_000_000;
pub const BENCH_MAX_ALLOCATED_BYTES: u64 = 42_949_672_960;
