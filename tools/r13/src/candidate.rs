//! R13 candidate (endurance) report types and verifier.
//!
//! Adapts the frozen Go P12 endurance-candidate architecture
//! (`reference/archives/go-*.tar.gz`, `tools/p12-verify/main.go`) to Rust
//! with an isolated R13 cluster identity (fresh FSID, 172.30.114.0/24
//! subnet, `r13-data` pool), Rust/native benchmark implementations, and
//! self-reference-free source binding via [`crate::source`].
//!
//! Two verification modes:
//!
//! * [`verify_bytes`] validates the report shape only.
//! * [`verify_report`] additionally binds the report to the current tree
//!   (fuzz, qualification, release artefacts, source artefact map, schema
//!   digest).

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use crate::budget::{BenchmarkRun, approved_budget, evaluate_budget, validate_run_shape};
use crate::constants::{
    CANDIDATE_CLUSTER_FSID, CANDIDATE_CLUSTER_MIN_MANAGERS_WHEN_EXERCISED,
    CANDIDATE_CLUSTER_MONITOR, CANDIDATE_CLUSTER_NETWORK, CANDIDATE_CLUSTER_OSDS,
    CANDIDATE_CLUSTER_POOL_MIN_SIZE, CANDIDATE_CLUSTER_POOL_NAME, CANDIDATE_CLUSTER_POOL_PG_NUM,
    CANDIDATE_CLUSTER_POOL_SIZE, CANDIDATE_CLUSTER_TICKET_TTL_SECONDS,
    CANDIDATE_KNOWN_SERVER_PLATFORMS, CANDIDATE_MIN_CERTIFYING_DURATION_NS,
    CANDIDATE_MIN_LONGEST_CONNECTION_NS, CANDIDATE_MIN_RECONNECTS, CANDIDATE_PROBE_MAX_SAMPLES,
    CANDIDATE_RELEASE_ARTIFACT_COUNT, CANDIDATE_RELEASE_ARTIFACTS_PATH,
    CANDIDATE_REPORT_MAX_BYTES, CANDIDATE_REPORT_SCHEMA_PATH, CANDIDATE_REPRODUCE_COMMAND,
    CANDIDATE_SCHEMA_VERSION, CANDIDATE_SOURCE_IDENTITY, CANDIDATE_SOURCE_REPOSITORY,
    CANDIDATE_TRANSPORTS, CEPH_IMAGE_AMD64, CEPH_IMAGE_ARM64, CEPH_SERVER_COMMIT,
    CEPH_SERVER_VERSION, FUZZ_LIVE_PATH, FUZZ_PROFILE_CERTIFYING, QUALIFICATION_LIVE_PATH,
};
use crate::fuzz;
use crate::hash::{is_sha256_hex, lower_hex};
use crate::qualify;
use crate::release::ReleaseNames;
use crate::source::source_artifacts;

pub const STATUS_CANDIDATE: &str = "candidate";
pub const STATUS_NON_CERTIFYING: &str = "non-certifying";

// -------------------------------------------------------------- report types

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct CandidateReport {
    pub schema_version: u32,
    pub status: String,
    pub command: String,
    pub started_at: String,
    pub finished_at: String,
    pub qualification: Option<QualificationBinding>,
    pub fuzz: Option<FuzzBinding>,
    pub reviews: Option<serde_json::Value>,
    pub source: Source,
    pub server: Server,
    pub cluster: Cluster,
    pub probe: ProbeSet,
    pub churn: Churn,
    pub benchmark: Benchmark,
    pub release: ReleaseEvidence,
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
pub struct Source {
    pub repository: String,
    pub identity: String,
    pub artifacts: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Server {
    pub repository: String,
    pub source_anchor_commit: String,
    pub version: String,
    pub image: String,
    pub platform: String,
    pub binaries: ServerBinaries,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerBinaries {
    pub mon_sha256: String,
    pub osd_sha256: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Cluster {
    pub fsid: String,
    pub network: String,
    pub monitors: Vec<String>,
    pub osds: u32,
    pub managers: u32,
    pub manager_behavior_exercised: bool,
    pub pool: Pool,
    pub external_defaults: bool,
    pub service_ticket_ttl_seconds: u32,
    pub transports: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Pool {
    pub name: String,
    pub size: u32,
    pub min_size: u32,
    pub pg_num: u32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProbeSet {
    pub secure: ProbeReport,
    pub crc: ProbeReport,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProbeReport {
    pub transport: String,
    pub requested_duration_ns: u64,
    pub elapsed_ns: u64,
    pub monotonic_duration_satisfied: bool,
    pub operations: u64,
    pub writes: u64,
    pub reads: u64,
    pub stats: u64,
    pub removes: u64,
    pub appends: u64,
    pub append_once_verifications: u64,
    pub duplicate_mutations_detected: u64,
    pub reconnects: u64,
    pub session_renewals: Option<u64>,
    pub longest_connection_ns: u64,
    pub credential_renewals: Option<Vec<CredentialRenewal>>,
    pub renewal_measurement: String,
    pub samples: Vec<ResourceSample>,
    pub inflight_measurement: String,
    pub maximum_configured_sample_count: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct CredentialRenewal {
    pub service: String,
    pub service_id: i32,
    pub session_id: u64,
    pub due_generation: u64,
    pub completed_generation: u64,
    pub due_at: String,
    pub completed_at: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ResourceSample {
    pub elapsed_ns: u64,
    pub rss_bytes: u64,
    pub threads: u64,
    pub heap_bytes: u64,
    pub inflight: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Churn {
    pub monitor_restarts: u64,
    pub monitor_recoveries: u64,
    pub osd_restarts: u64,
    pub osd_recoveries: u64,
    pub final_osd_stat: FinalOsdStat,
    pub final_health: FinalHealth,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FinalOsdStat {
    pub epoch: u64,
    pub num_osds: u64,
    pub num_up_osds: u64,
    pub num_in_osds: u64,
    pub num_remapped_pgs: u64,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FinalHealth {
    pub status: String,
    pub checks: BTreeMap<String, serde_json::Value>,
    pub mutes: Vec<serde_json::Value>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Benchmark {
    pub performed: bool,
    pub runs: Vec<BenchmarkRun>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ReleaseEvidence {
    pub performed: bool,
    pub version: Option<String>,
    pub path: Option<String>,
    pub reproducible: bool,
    pub artifacts: BTreeMap<String, String>,
}

// -------------------------------------------------------------- entry points

/// Verify a candidate report from a byte slice with shape-only checks.
///
/// # Errors
///
/// Returns an explanation if the bytes decode, framing, envelope, identity,
/// probe, churn, benchmark, or release invariants fail. Does NOT touch the
/// filesystem beyond the bytes provided.
pub fn verify_bytes(
    bytes: &[u8],
    allow_non_certifying: bool,
) -> Result<CandidateReport, String> {
    if bytes.len() as u64 > CANDIDATE_REPORT_MAX_BYTES {
        return Err(format!(
            "candidate report exceeds byte limit ({} > {})",
            bytes.len(),
            CANDIDATE_REPORT_MAX_BYTES
        ));
    }
    let mut stream = serde_json::Deserializer::from_slice(bytes).into_iter::<CandidateReport>();
    let report = match stream.next() {
        Some(result) => result.map_err(|error| format!("decode strict candidate: {error}"))?,
        None => return Err("empty candidate report".into()),
    };
    if stream.next().is_some() {
        return Err("candidate report has trailing JSON".into());
    }
    let consumed = stream.byte_offset();
    if bytes[consumed..].iter().any(|byte| !byte.is_ascii_whitespace()) {
        return Err("candidate report has trailing bytes".into());
    }
    validate_shape(&report, allow_non_certifying)?;
    Ok(report)
}

/// Verify a candidate report file bound to the workspace at `root`.
///
/// # Errors
///
/// Returns an explanation on any shape violation, schema-digest mismatch,
/// stale source artefact map, stale release artefacts, failed fuzz binding,
/// failed qualification binding, or missing certifying evidence when
/// `allow_non_certifying` is false.
pub fn verify_report(
    root: &Path,
    report_path: &Path,
    allow_non_certifying: bool,
) -> Result<CandidateReport, String> {
    let bytes = fs::read(report_path)
        .map_err(|error| format!("read {}: {error}", report_path.display()))?;
    let report = verify_bytes(&bytes, allow_non_certifying)?;
    validate_source_binding(root, &report)?;
    validate_qualification_binding(root, &report)?;
    validate_fuzz_binding(root, &report)?;
    validate_release_binding(root, &report)?;
    Ok(report)
}

// --------------------------------------------------------- shape validation

fn validate_shape(report: &CandidateReport, allow_non_certifying: bool) -> Result<(), String> {
    if report.schema_version != CANDIDATE_SCHEMA_VERSION {
        return Err(format!(
            "candidate schema_version is {}, expected {}",
            report.schema_version, CANDIDATE_SCHEMA_VERSION
        ));
    }
    if !valid_timestamps(&report.started_at, &report.finished_at) {
        return Err("candidate timestamps are invalid or non-monotonic".into());
    }
    if report.reviews.is_some() {
        return Err("candidate report must set reviews to null".into());
    }
    match report.status.as_str() {
        STATUS_CANDIDATE => {}
        STATUS_NON_CERTIFYING => {
            if !allow_non_certifying {
                return Err(
                    "report is non-certifying; use allow_non_certifying only for quick evidence"
                        .into(),
                );
            }
        }
        other => return Err(format!("invalid candidate status {other:?}")),
    }
    validate_source_shape(&report.source)?;
    validate_server(&report.server)?;
    validate_cluster(&report.cluster)?;
    validate_probe("secure", &report.probe.secure)?;
    validate_probe("crc", &report.probe.crc)?;
    // Enforce that the recorded wall-clock interval covers each probe's runtime.
    let elapsed_bound = report.probe.secure.elapsed_ns.max(report.probe.crc.elapsed_ns);
    if !timestamps_cover(&report.started_at, &report.finished_at, elapsed_bound)? {
        return Err("candidate timestamps do not cover the probe elapsed time".into());
    }
    validate_churn(&report.churn)?;
    validate_release_shape(report)?;
    validate_qualification_shape(report)?;
    validate_fuzz_shape(report)?;
    if report.status == STATUS_CANDIDATE {
        validate_certification(report)?;
    } else {
        validate_non_certifying(report)?;
    }
    Ok(())
}

fn validate_source_shape(source: &Source) -> Result<(), String> {
    if source.repository != CANDIDATE_SOURCE_REPOSITORY
        || source.identity != CANDIDATE_SOURCE_IDENTITY
    {
        return Err("candidate source identity does not match frozen constants".into());
    }
    if source.artifacts.is_empty() {
        return Err("candidate source.artifacts is empty".into());
    }
    for (path, sha) in &source.artifacts {
        if path.is_empty() || !is_sha256_hex(sha) {
            return Err(format!(
                "candidate source.artifacts entry {path:?} has an invalid hash"
            ));
        }
    }
    Ok(())
}

fn validate_server(server: &Server) -> Result<(), String> {
    if server.repository != "https://github.com/ceph/ceph.git"
        || server.source_anchor_commit != CEPH_SERVER_COMMIT
        || server.version != CEPH_SERVER_VERSION
    {
        return Err("candidate server identity does not match frozen constants".into());
    }
    if !CANDIDATE_KNOWN_SERVER_PLATFORMS.contains(&server.platform.as_str()) {
        return Err(format!(
            "candidate server platform {:?} is not recognised",
            server.platform
        ));
    }
    let expected_image = match server.platform.as_str() {
        "linux/amd64" => CEPH_IMAGE_AMD64,
        "linux/arm64" => CEPH_IMAGE_ARM64,
        _ => unreachable!("platform validated above"),
    };
    if server.image != expected_image {
        return Err(format!(
            "candidate server image does not match the pinned {} digest",
            server.platform
        ));
    }
    if !is_sha256_hex(&server.binaries.mon_sha256) || !is_sha256_hex(&server.binaries.osd_sha256) {
        return Err("candidate server binary hashes are not lowercase SHA-256".into());
    }
    Ok(())
}

fn validate_cluster(cluster: &Cluster) -> Result<(), String> {
    if cluster.fsid != CANDIDATE_CLUSTER_FSID {
        return Err(format!(
            "candidate cluster fsid is {:?}, expected {CANDIDATE_CLUSTER_FSID}",
            cluster.fsid
        ));
    }
    if cluster.network != CANDIDATE_CLUSTER_NETWORK {
        return Err(format!(
            "candidate cluster network is {:?}, expected {CANDIDATE_CLUSTER_NETWORK}",
            cluster.network
        ));
    }
    if cluster.monitors != vec![CANDIDATE_CLUSTER_MONITOR.to_owned()] {
        return Err("candidate cluster monitors list is invalid".into());
    }
    if cluster.osds != CANDIDATE_CLUSTER_OSDS {
        return Err(format!(
            "candidate cluster osds is {}, expected {CANDIDATE_CLUSTER_OSDS}",
            cluster.osds
        ));
    }
    if cluster.pool.name != CANDIDATE_CLUSTER_POOL_NAME
        || cluster.pool.size != CANDIDATE_CLUSTER_POOL_SIZE
        || cluster.pool.min_size != CANDIDATE_CLUSTER_POOL_MIN_SIZE
        || cluster.pool.pg_num != CANDIDATE_CLUSTER_POOL_PG_NUM
    {
        return Err("candidate cluster pool identity does not match frozen constants".into());
    }
    if cluster.external_defaults {
        return Err("candidate cluster external_defaults must be false".into());
    }
    if cluster.service_ticket_ttl_seconds != CANDIDATE_CLUSTER_TICKET_TTL_SECONDS {
        return Err(format!(
            "candidate cluster service_ticket_ttl_seconds is {}, expected {}",
            cluster.service_ticket_ttl_seconds, CANDIDATE_CLUSTER_TICKET_TTL_SECONDS
        ));
    }
    if cluster.transports.iter().map(String::as_str).collect::<Vec<_>>() != CANDIDATE_TRANSPORTS {
        return Err("candidate cluster transports must be exactly [secure, crc]".into());
    }
    if cluster.manager_behavior_exercised
        && cluster.managers < CANDIDATE_CLUSTER_MIN_MANAGERS_WHEN_EXERCISED
    {
        return Err(format!(
            "manager behavior exercised requires at least {} managers, got {}",
            CANDIDATE_CLUSTER_MIN_MANAGERS_WHEN_EXERCISED, cluster.managers
        ));
    }
    Ok(())
}

fn validate_probe(transport: &str, probe: &ProbeReport) -> Result<(), String> {
    if probe.transport != transport
        || probe.requested_duration_ns == 0
        || probe.elapsed_ns < probe.requested_duration_ns
        || !probe.monotonic_duration_satisfied
        || probe.operations == 0
    {
        return Err(format!(
            "{transport} probe has invalid identity, duration, or operation count"
        ));
    }
    for (name, counter) in [
        ("writes", probe.writes),
        ("reads", probe.reads),
        ("stats", probe.stats),
        ("removes", probe.removes),
        ("appends", probe.appends),
        ("append_once_verifications", probe.append_once_verifications),
    ] {
        if counter != probe.operations {
            return Err(format!(
                "{transport} probe {name} counter {counter} does not equal operations {}",
                probe.operations
            ));
        }
    }
    if probe.duplicate_mutations_detected != 0 {
        return Err(format!(
            "{transport} probe reports {} duplicate mutations",
            probe.duplicate_mutations_detected
        ));
    }
    if probe.reconnects > probe.operations
        || probe.longest_connection_ns == 0
        || probe.longest_connection_ns > probe.elapsed_ns
    {
        return Err(format!(
            "{transport} probe has invalid reconnect or connection counters"
        ));
    }
    if probe.inflight_measurement != INFLIGHT_MEASUREMENT_SENTINEL {
        return Err(format!("{transport} probe has invalid inflight evidence"));
    }
    if probe.renewal_measurement != RENEWAL_MEASUREMENT_SENTINEL {
        return Err(format!("{transport} probe has invalid renewal evidence"));
    }
    if probe.session_renewals.is_some() {
        return Err(format!(
            "{transport} probe session_renewals must be null (unavailable through the public API)"
        ));
    }
    if probe.credential_renewals.is_some() {
        return Err(format!(
            "{transport} probe credential_renewals must be null (unavailable through the public API)"
        ));
    }
    validate_samples(transport, probe)?;
    Ok(())
}

pub const INFLIGHT_MEASUREMENT_SENTINEL: &str =
    "in-flight operation counts are unavailable through the public API; reported as null";
pub const RENEWAL_MEASUREMENT_SENTINEL: &str =
    "completed renewal telemetry is unavailable through the public API; reported as null";

fn validate_samples(transport: &str, probe: &ProbeReport) -> Result<(), String> {
    let samples = &probe.samples;
    if samples.len() < 2
        || samples.len() > CANDIDATE_PROBE_MAX_SAMPLES
        || u64::try_from(samples.len()).unwrap_or(u64::MAX) > probe.maximum_configured_sample_count
        || probe.maximum_configured_sample_count < 2
        || probe.maximum_configured_sample_count > CANDIDATE_PROBE_MAX_SAMPLES as u64
    {
        return Err(format!(
            "{transport} probe sample count is outside configured bounds"
        ));
    }
    let first = &samples[0];
    let mut previous_elapsed = 0_u64;
    for (index, sample) in samples.iter().enumerate() {
        if sample.rss_bytes == 0
            || sample.heap_bytes == 0
            || sample.threads == 0
            || sample.inflight.is_some()
            || sample.elapsed_ns > probe.elapsed_ns
            || (index > 0 && sample.elapsed_ns <= previous_elapsed)
        {
            return Err(format!(
                "{transport} probe resource sample {index} is invalid or unordered"
            ));
        }
        // Bounded resource growth relative to the first sample. Uses the same
        // ceilings as the frozen Go P12 harness (RSS 256 MiB, heap 128 MiB,
        // threads 256) so the R13 bound is at least as tight.
        if growth(sample.rss_bytes, first.rss_bytes) > 256 << 20
            || growth(sample.heap_bytes, first.heap_bytes) > 128 << 20
            || growth(sample.threads, first.threads) > 256
        {
            return Err(format!(
                "{transport} probe resource sample {index} exceeds an explicit growth ceiling"
            ));
        }
        previous_elapsed = sample.elapsed_ns;
    }
    Ok(())
}

fn growth(current: u64, baseline: u64) -> u64 {
    current.saturating_sub(baseline)
}

fn validate_churn(churn: &Churn) -> Result<(), String> {
    if churn.monitor_recoveries > churn.monitor_restarts
        || churn.osd_recoveries > churn.osd_restarts
    {
        return Err("churn recovery counters exceed restart counters".into());
    }
    let stat = &churn.final_osd_stat;
    if stat.epoch == 0
        || stat.num_osds != u64::from(CANDIDATE_CLUSTER_OSDS)
        || stat.num_up_osds != u64::from(CANDIDATE_CLUSTER_OSDS)
        || stat.num_in_osds != u64::from(CANDIDATE_CLUSTER_OSDS)
        || stat.num_remapped_pgs != 0
    {
        return Err(
            "final cluster does not have exactly three OSDs up/in and zero remapped PGs".into(),
        );
    }
    if churn.final_health.status != "HEALTH_OK" {
        return Err("final cluster health is not HEALTH_OK".into());
    }
    // Normalise the `ceph health --format json` output: the `checks` map is
    // keyed by Ceph's alert name and each value carries a `severity` and a
    // `muted` boolean. Muted checks and pure informational entries never
    // fail HEALTH_OK; anything at severity WARN or ERR is a live warning or
    // error and MUST fail the certifying gate.
    for (name, value) in &churn.final_health.checks {
        let muted = value
            .get("muted")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        if muted {
            continue;
        }
        let severity = value
            .get("severity")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let normalised = severity.to_ascii_uppercase();
        match normalised.as_str() {
            "" | "HEALTH_OK" | "INFO" => {}
            "HEALTH_WARN" | "WARN" | "WARNING" | "HEALTH_ERR" | "ERR" | "ERROR" => {
                return Err(format!(
                    "final cluster health check {name:?} is {severity:?}, not HEALTH_OK"
                ));
            }
            other => {
                return Err(format!(
                    "final cluster health check {name:?} has unrecognised severity {other:?}"
                ));
            }
        }
    }
    Ok(())
}

fn validate_release_shape(report: &CandidateReport) -> Result<(), String> {
    match report.status.as_str() {
        STATUS_NON_CERTIFYING => {
            let release = &report.release;
            if release.performed
                || release.version.is_some()
                || release.path.is_some()
                || release.reproducible
                || !release.artifacts.is_empty()
            {
                return Err(
                    "non-certifying report must not claim release generation".into(),
                );
            }
        }
        STATUS_CANDIDATE => {
            let release = &report.release;
            let version = release
                .version
                .as_ref()
                .ok_or_else(|| "certifying report release version is missing".to_owned())?;
            let path = release
                .path
                .as_ref()
                .ok_or_else(|| "certifying report release path is missing".to_owned())?;
            if !release.performed
                || !release.reproducible
                || path != CANDIDATE_RELEASE_ARTIFACTS_PATH
            {
                return Err(
                    "certifying report lacks reproducible retained release evidence".into(),
                );
            }
            let names = ReleaseNames::from_version(version)
                .map_err(|_| "certifying release version is not semver-shaped".to_owned())?;
            if release.artifacts.len() != CANDIDATE_RELEASE_ARTIFACT_COUNT {
                return Err(
                    "certifying release must bind exactly four artefact hashes".into(),
                );
            }
            let expected: std::collections::BTreeSet<&str> = names.as_array().into_iter().collect();
            let actual: std::collections::BTreeSet<&str> =
                release.artifacts.keys().map(String::as_str).collect();
            if expected != actual {
                return Err(
                    "certifying release artefact names do not match the frozen four".into(),
                );
            }
            for hash in release.artifacts.values() {
                if !is_sha256_hex(hash) {
                    return Err(
                        "certifying release artefact hash is not a lowercase SHA-256".into(),
                    );
                }
            }
        }
        other => return Err(format!("unknown status {other:?}")),
    }
    Ok(())
}

fn validate_qualification_shape(report: &CandidateReport) -> Result<(), String> {
    match report.status.as_str() {
        STATUS_NON_CERTIFYING => {
            if report.qualification.is_some() {
                return Err(
                    "non-certifying report must record qualification as null".into(),
                );
            }
        }
        STATUS_CANDIDATE => {
            let binding = report
                .qualification
                .as_ref()
                .ok_or_else(|| "candidate report is missing qualification".to_owned())?;
            if binding.path != QUALIFICATION_LIVE_PATH
                || binding.status != "passed"
                || !is_sha256_hex(&binding.sha256)
            {
                return Err("candidate qualification binding is invalid".into());
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_fuzz_shape(report: &CandidateReport) -> Result<(), String> {
    match report.status.as_str() {
        STATUS_NON_CERTIFYING => {
            if report.fuzz.is_some() {
                return Err(
                    "non-certifying report must record fuzz as null".into(),
                );
            }
        }
        STATUS_CANDIDATE => {
            let binding = report
                .fuzz
                .as_ref()
                .ok_or_else(|| "candidate report is missing fuzz".to_owned())?;
            if binding.path != FUZZ_LIVE_PATH
                || binding.status != "passed"
                || binding.profile != FUZZ_PROFILE_CERTIFYING
                || !is_sha256_hex(&binding.sha256)
            {
                return Err("candidate fuzz binding is invalid".into());
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_non_certifying(report: &CandidateReport) -> Result<(), String> {
    if report.command == CANDIDATE_REPRODUCE_COMMAND {
        return Err(
            "non-certifying report must not claim the certifying reproduce command".into(),
        );
    }
    if report.benchmark.performed || !report.benchmark.runs.is_empty() {
        return Err("non-certifying report must not include benchmark evidence".into());
    }
    Ok(())
}

fn validate_certification(report: &CandidateReport) -> Result<(), String> {
    if report.command != CANDIDATE_REPRODUCE_COMMAND {
        return Err(format!(
            "candidate command is {:?}, expected {CANDIDATE_REPRODUCE_COMMAND}",
            report.command
        ));
    }
    for (name, probe) in [
        ("secure", &report.probe.secure),
        ("crc", &report.probe.crc),
    ] {
        if probe.requested_duration_ns < CANDIDATE_MIN_CERTIFYING_DURATION_NS
            || probe.elapsed_ns < CANDIDATE_MIN_CERTIFYING_DURATION_NS
            || probe.reconnects < CANDIDATE_MIN_RECONNECTS
            || probe.longest_connection_ns <= CANDIDATE_MIN_LONGEST_CONNECTION_NS
        {
            return Err(format!(
                "{name} probe does not prove 24-hour, reconnect, and long-connection requirements"
            ));
        }
    }
    if report.churn.monitor_restarts < 1
        || report.churn.monitor_recoveries < 1
        || report.churn.osd_restarts < u64::from(CANDIDATE_CLUSTER_OSDS)
        || report.churn.osd_recoveries < u64::from(CANDIDATE_CLUSTER_OSDS)
    {
        return Err(format!(
            "candidate churn must include a monitor restart+recovery and every OSD (>= {CANDIDATE_CLUSTER_OSDS}) restart+recovery"
        ));
    }
    if !report.benchmark.performed {
        return Err("candidate report did not perform the benchmark".into());
    }
    for run in &report.benchmark.runs {
        validate_run_shape(run)?;
    }
    evaluate_budget(&report.benchmark.runs, approved_budget())
        .map_err(|error| format!("benchmark budget: {error}"))?;
    Ok(())
}

// ------------------------------------------------------------ live bindings

fn validate_source_binding(root: &Path, report: &CandidateReport) -> Result<(), String> {
    let expected = source_artifacts(root)?;
    if expected.len() != report.source.artifacts.len() {
        return Err(format!(
            "candidate source.artifacts has {} entries, workspace has {}",
            report.source.artifacts.len(),
            expected.len()
        ));
    }
    for (path, sha) in &expected {
        match report.source.artifacts.get(path) {
            Some(actual) if actual == sha => {}
            Some(_) => {
                return Err(format!(
                    "candidate source.artifacts hash mismatch for {path}"
                ));
            }
            None => {
                return Err(format!(
                    "candidate source.artifacts missing workspace path {path}"
                ));
            }
        }
    }
    Ok(())
}

fn validate_qualification_binding(root: &Path, report: &CandidateReport) -> Result<(), String> {
    let Some(binding) = report.qualification.as_ref() else {
        return Ok(());
    };
    let path = root.join(&binding.path);
    let bytes = fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let digest = lower_hex(&sha2::Sha256::digest(&bytes));
    if binding.sha256 != digest {
        return Err("candidate qualification report hash mismatch".into());
    }
    qualify::verify_report(root, &path)
        .map_err(|error| format!("bound qualification verification failed: {error}"))?;
    Ok(())
}

fn validate_fuzz_binding(root: &Path, report: &CandidateReport) -> Result<(), String> {
    let Some(binding) = report.fuzz.as_ref() else {
        return Ok(());
    };
    let path = root.join(&binding.path);
    let bytes = fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let digest = lower_hex(&sha2::Sha256::digest(&bytes));
    if binding.sha256 != digest {
        return Err("candidate fuzz report hash mismatch".into());
    }
    let corpus = root.join(crate::constants::FUZZ_CORPUS_ROOT);
    fuzz::verify_report(root, &path, &corpus, fuzz::Profile::Certifying)
        .map_err(|error| format!("bound fuzz verification failed: {error}"))?;
    Ok(())
}

fn validate_release_binding(root: &Path, report: &CandidateReport) -> Result<(), String> {
    if report.status == STATUS_NON_CERTIFYING {
        return Ok(());
    }
    let directory = root.join(CANDIDATE_RELEASE_ARTIFACTS_PATH);
    let entries = fs::read_dir(&directory)
        .map_err(|error| format!("read {}: {error}", directory.display()))?;
    let mut on_disk: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("read_dir entry: {error}"))?;
        let metadata = entry
            .metadata()
            .map_err(|error| format!("stat {}: {error}", entry.path().display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(format!(
                "retained release directory contains non-regular entry {}",
                entry.path().display()
            ));
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "retained release entry has a non-UTF-8 name".to_owned())?;
        let bytes = fs::read(entry.path())
            .map_err(|error| format!("read {}: {error}", entry.path().display()))?;
        on_disk.insert(name, bytes);
    }
    if on_disk.len() != CANDIDATE_RELEASE_ARTIFACT_COUNT {
        return Err(format!(
            "retained release directory has {} files, expected {}",
            on_disk.len(),
            CANDIDATE_RELEASE_ARTIFACT_COUNT
        ));
    }
    for (name, expected_hash) in &report.release.artifacts {
        let bytes = on_disk
            .get(name)
            .ok_or_else(|| format!("retained release is missing {name}"))?;
        let digest = lower_hex(&sha2::Sha256::digest(bytes));
        if *expected_hash != digest {
            return Err(format!(
                "retained release artefact {name} does not match the reported hash"
            ));
        }
    }
    Ok(())
}

// -------------------------------------------------------- schema binding

/// Return the SHA-256 of `integration/r13/report.schema.json` for use by
/// artifact manifests. Not required by the verifier because the schema is
/// self-describing.
///
/// # Errors
///
/// Returns an explanation if the schema file cannot be read.
pub fn schema_digest(root: &Path) -> Result<String, String> {
    let path = root.join(CANDIDATE_REPORT_SCHEMA_PATH);
    let bytes = fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
    Ok(lower_hex(&sha2::Sha256::digest(bytes)))
}

// -------------------------------------------------------- misc helpers

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

fn valid_timestamps(start: &str, finish: &str) -> bool {
    valid_timestamp(start) && valid_timestamp(finish) && start < finish
}

fn timestamps_cover(started: &str, finished: &str, elapsed_ns: u64) -> Result<bool, String> {
    let start = parse_epoch_seconds(started)?;
    let end = parse_epoch_seconds(finished)?;
    if end < start {
        return Err("finished_at precedes started_at".into());
    }
    let span_ns = u64::try_from(end - start)
        .map_err(|_| "elapsed span overflows u64".to_owned())?
        .saturating_mul(1_000_000_000);
    Ok(span_ns >= elapsed_ns)
}

fn parse_epoch_seconds(value: &str) -> Result<i64, String> {
    let bytes = value.as_bytes();
    if !valid_timestamp(value) {
        return Err(format!("invalid timestamp {value:?}"));
    }
    let year: i64 = parse_digits(&bytes[0..4])?;
    let month: i64 = parse_digits(&bytes[5..7])?;
    let day: i64 = parse_digits(&bytes[8..10])?;
    let hour: i64 = parse_digits(&bytes[11..13])?;
    let minute: i64 = parse_digits(&bytes[14..16])?;
    let second: i64 = parse_digits(&bytes[17..19])?;
    let shifted_year = if month <= 2 { year - 1 } else { year };
    let era = if shifted_year >= 0 { shifted_year } else { shifted_year - 399 } / 400;
    let year_of_era = shifted_year - era * 400;
    let month_index = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Ok(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

fn parse_digits(bytes: &[u8]) -> Result<i64, String> {
    let mut value: i64 = 0;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return Err("timestamp digit is not numeric".into());
        }
        value = value * 10 + i64::from(byte - b'0');
    }
    Ok(value)
}

#[cfg(test)]
mod tests;
