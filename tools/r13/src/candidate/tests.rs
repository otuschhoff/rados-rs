use super::*;
use crate::budget::{BenchmarkResources, BenchmarkRow, BenchmarkRun};
use crate::constants::{
    BENCH_CONCURRENCIES, BENCH_ROWS_PER_RUN, BENCH_SIZES, BENCH_WORKLOADS,
    CANDIDATE_MIN_CERTIFYING_DURATION_NS, CANDIDATE_MIN_RECONNECTS, CEPH_IMAGE_ARM64,
};
use serde_json::{Value, json};

fn synth_probe(transport: &str, duration_ns: u64, reconnects: u64) -> ProbeReport {
    let operations = 100_u64;
    let elapsed_ns = duration_ns + 1;
    // Keep longest_connection strictly less than elapsed so shape validation
    // passes; the certifying path additionally requires it to exceed
    // CANDIDATE_MIN_LONGEST_CONNECTION_NS which is verified separately.
    let longest = elapsed_ns.saturating_sub(1);
    ProbeReport {
        transport: transport.to_owned(),
        requested_duration_ns: duration_ns,
        elapsed_ns,
        monotonic_duration_satisfied: true,
        operations,
        writes: operations,
        reads: operations,
        stats: operations,
        removes: operations,
        appends: operations,
        append_once_verifications: operations,
        duplicate_mutations_detected: 0,
        reconnects,
        session_renewals: None,
        longest_connection_ns: longest,
        credential_renewals: None,
        renewal_measurement: RENEWAL_MEASUREMENT_SENTINEL.to_owned(),
        samples: vec![
            ResourceSample {
                elapsed_ns: 1_000_000,
                rss_bytes: 100_000_000,
                threads: 4,
                heap_bytes: 5_000_000,
                inflight: None,
            },
            ResourceSample {
                elapsed_ns: 2_000_000,
                rss_bytes: 100_100_000,
                threads: 5,
                heap_bytes: 5_050_000,
                inflight: None,
            },
        ],
        inflight_measurement: INFLIGHT_MEASUREMENT_SENTINEL.to_owned(),
        maximum_configured_sample_count: 8,
    }
}

fn synth_bench_run(
    implementation: &str,
    transport: &str,
    elapsed_ns: u64,
) -> BenchmarkRun {
    let mut rows = Vec::with_capacity(BENCH_ROWS_PER_RUN);
    for size in BENCH_SIZES {
        for concurrency in BENCH_CONCURRENCIES {
            for workload in BENCH_WORKLOADS {
                let operations = u64::from(concurrency) * 2;
                let bytes = size * operations;
                #[allow(clippy::cast_precision_loss)]
                let throughput = (bytes as f64) * 1e9 / (elapsed_ns as f64);
                #[allow(clippy::cast_precision_loss)]
                let iops = (operations as f64) * 1e9 / (elapsed_ns as f64);
                rows.push(BenchmarkRow {
                    size_bytes: size,
                    concurrency,
                    workload: (*workload).to_owned(),
                    operations,
                    bytes,
                    elapsed_ns,
                    throughput_bytes_per_second: throughput,
                    iops,
                    p50_ns: elapsed_ns / 100,
                    p95_ns: elapsed_ns / 20,
                    p99_ns: elapsed_ns / 10,
                });
            }
        }
    }
    let (allocations, allocated_bytes) = if implementation == "rust" {
        (Some(1000), Some(1_048_576))
    } else {
        (None, None)
    };
    BenchmarkRun {
        implementation: implementation.to_owned(),
        transport: transport.to_owned(),
        environment: json!({"host": "test"}),
        resources: BenchmarkResources {
            cpu_user_ns: 1_000_000,
            cpu_system_ns: 1_000_000,
            allocations,
            allocated_bytes,
            max_rss_bytes: 512 * 1024 * 1024,
        },
        rows,
    }
}

fn certifying_report() -> CandidateReport {
    #![allow(clippy::too_many_lines)]
    let duration = CANDIDATE_MIN_CERTIFYING_DURATION_NS;
    let started_at = "2026-09-21T00:00:00Z".to_owned();
    let finished_at = "2026-09-22T01:00:00Z".to_owned();
    let mut source_artifacts = BTreeMap::new();
    for i in 0..100 {
        source_artifacts.insert(format!("path/{i:03}"), "a".repeat(64));
    }
    CandidateReport {
        schema_version: CANDIDATE_SCHEMA_VERSION,
        status: STATUS_CANDIDATE.to_owned(),
        command: CANDIDATE_REPRODUCE_COMMAND.to_owned(),
        started_at,
        finished_at,
        qualification: Some(QualificationBinding {
            path: QUALIFICATION_LIVE_PATH.to_owned(),
            status: "passed".to_owned(),
            sha256: "b".repeat(64),
        }),
        fuzz: Some(FuzzBinding {
            path: FUZZ_LIVE_PATH.to_owned(),
            status: "passed".to_owned(),
            profile: FUZZ_PROFILE_CERTIFYING.to_owned(),
            sha256: "c".repeat(64),
        }),
        reviews: None,
        source: Source {
            repository: CANDIDATE_SOURCE_REPOSITORY.to_owned(),
            identity: CANDIDATE_SOURCE_IDENTITY.to_owned(),
            artifacts: source_artifacts,
        },
        server: Server {
            repository: "https://github.com/ceph/ceph.git".to_owned(),
            source_anchor_commit: CEPH_SERVER_COMMIT.to_owned(),
            version: CEPH_SERVER_VERSION.to_owned(),
            image: CEPH_IMAGE_ARM64.to_owned(),
            platform: "linux/arm64".to_owned(),
            binaries: ServerBinaries {
                mon_sha256: "d".repeat(64),
                osd_sha256: "e".repeat(64),
            },
        },
        cluster: Cluster {
            fsid: CANDIDATE_CLUSTER_FSID.to_owned(),
            network: CANDIDATE_CLUSTER_NETWORK.to_owned(),
            monitors: vec![CANDIDATE_CLUSTER_MONITOR.to_owned()],
            osds: CANDIDATE_CLUSTER_OSDS,
            managers: 2,
            manager_behavior_exercised: false,
            pool: Pool {
                name: CANDIDATE_CLUSTER_POOL_NAME.to_owned(),
                size: CANDIDATE_CLUSTER_POOL_SIZE,
                min_size: CANDIDATE_CLUSTER_POOL_MIN_SIZE,
                pg_num: CANDIDATE_CLUSTER_POOL_PG_NUM,
            },
            external_defaults: false,
            service_ticket_ttl_seconds: CANDIDATE_CLUSTER_TICKET_TTL_SECONDS,
            transports: vec!["secure".to_owned(), "crc".to_owned()],
        },
        probe: ProbeSet {
            secure: synth_probe("secure", duration, CANDIDATE_MIN_RECONNECTS),
            crc: synth_probe("crc", duration, CANDIDATE_MIN_RECONNECTS),
        },
        churn: Churn {
            monitor_restarts: 2,
            monitor_recoveries: 2,
            osd_restarts: 3,
            osd_recoveries: 3,
            final_osd_stat: FinalOsdStat {
                epoch: 100,
                num_osds: u64::from(CANDIDATE_CLUSTER_OSDS),
                num_up_osds: u64::from(CANDIDATE_CLUSTER_OSDS),
                num_in_osds: u64::from(CANDIDATE_CLUSTER_OSDS),
                num_remapped_pgs: 0,
                extra: BTreeMap::new(),
            },
            final_health: FinalHealth {
                status: "HEALTH_OK".to_owned(),
                checks: BTreeMap::new(),
                mutes: Vec::new(),
                extra: BTreeMap::new(),
            },
        },
        benchmark: Benchmark {
            performed: true,
            runs: vec![
                synth_bench_run("rust", "secure", 2_000_000),
                synth_bench_run("rust", "crc", 2_000_000),
                synth_bench_run("native", "secure", 1_000_000),
                synth_bench_run("native", "crc", 1_000_000),
            ],
        },
        release: {
            let mut artifacts = BTreeMap::new();
            let names = crate::release::ReleaseNames::from_version("v1.2.3").expect("names");
            artifacts.insert(names.tarball.clone(), "1".repeat(64));
            artifacts.insert(names.zip.clone(), "2".repeat(64));
            artifacts.insert(names.spdx.clone(), "3".repeat(64));
            artifacts.insert(names.checksums.clone(), "4".repeat(64));
            ReleaseEvidence {
                performed: true,
                version: Some("v1.2.3".to_owned()),
                path: Some(CANDIDATE_RELEASE_ARTIFACTS_PATH.to_owned()),
                reproducible: true,
                artifacts,
            }
        },
    }
}

fn non_certifying_report() -> CandidateReport {
    let mut report = certifying_report();
    report.status = STATUS_NON_CERTIFYING.to_owned();
    report.command = format!("{CANDIDATE_REPRODUCE_COMMAND} --quick");
    report.qualification = None;
    report.fuzz = None;
    report.benchmark = Benchmark {
        performed: false,
        runs: Vec::new(),
    };
    report.release = ReleaseEvidence {
        performed: false,
        version: None,
        path: None,
        reproducible: false,
        artifacts: BTreeMap::new(),
    };
    // Non-certifying probes still need shape validity but do not need to
    // exceed the 24h threshold.
    report.probe.secure = synth_probe("secure", 60_000_000_000, 0);
    report.probe.crc = synth_probe("crc", 60_000_000_000, 0);
    report.churn.monitor_restarts = 0;
    report.churn.monitor_recoveries = 0;
    report.churn.osd_restarts = 0;
    report.churn.osd_recoveries = 0;
    report
}

fn encode(report: &CandidateReport) -> Vec<u8> {
    serde_json::to_vec(report).expect("encode report")
}

fn encode_pretty(report: &CandidateReport) -> Vec<u8> {
    serde_json::to_vec_pretty(report).expect("encode report")
}

#[test]
fn certifying_report_shape_passes() {
    let report = certifying_report();
    let bytes = encode(&report);
    verify_bytes(&bytes, false).expect("certifying shape must pass");
}

#[test]
fn non_certifying_report_shape_passes_when_allowed() {
    let report = non_certifying_report();
    let bytes = encode(&report);
    let error = verify_bytes(&bytes, false).expect_err("must reject non-certifying by default");
    assert!(error.contains("non-certifying"), "unexpected error: {error}");
    verify_bytes(&bytes, true).expect("non-certifying with allow flag");
}

#[test]
fn quick_output_status_is_non_certifying_and_rejected_for_final() {
    let report = non_certifying_report();
    assert_eq!(report.status, STATUS_NON_CERTIFYING);
    assert!(report.command.ends_with("--quick"));
    let bytes = encode(&report);
    assert!(verify_bytes(&bytes, false).is_err());
}

#[test]
fn duration_downgrade_rejected() {
    let mut report = certifying_report();
    // Downgrade the secure probe to a one-hour run that still passes shape
    // (elapsed >= requested, longest < elapsed) but falls short of the
    // 24-hour certifying gate.
    report.probe.secure = synth_probe("secure", 3_600_000_000_000, CANDIDATE_MIN_RECONNECTS);
    let bytes = encode(&report);
    let error = verify_bytes(&bytes, false).unwrap_err();
    assert!(error.contains("24-hour"), "expected 24h, got {error}");
}

#[test]
fn missing_monitor_churn_rejected() {
    let mut report = certifying_report();
    report.churn.monitor_restarts = 0;
    report.churn.monitor_recoveries = 0;
    let bytes = encode(&report);
    let error = verify_bytes(&bytes, false).unwrap_err();
    assert!(error.contains("churn"), "got {error}");
}

#[test]
fn missing_osd_churn_rejected() {
    let mut report = certifying_report();
    report.churn.osd_restarts = 1;
    report.churn.osd_recoveries = 1;
    let bytes = encode(&report);
    let error = verify_bytes(&bytes, false).unwrap_err();
    assert!(error.contains("OSD"), "got {error}");
}

#[test]
fn duplicate_mutation_rejected() {
    let mut report = certifying_report();
    report.probe.crc.duplicate_mutations_detected = 1;
    let bytes = encode(&report);
    assert!(verify_bytes(&bytes, false).is_err());
}

#[test]
fn resource_bound_growth_rejected() {
    let mut report = certifying_report();
    report.probe.secure.samples[1].rss_bytes =
        report.probe.secure.samples[0].rss_bytes + (400 << 20);
    let bytes = encode(&report);
    let error = verify_bytes(&bytes, false).unwrap_err();
    assert!(error.contains("growth"), "got {error}");
}

#[test]
fn benchmark_budget_enforced() {
    let mut report = certifying_report();
    report.benchmark.runs[0].resources.max_rss_bytes = crate::constants::BENCH_MAX_RSS_BYTES + 1;
    let bytes = encode(&report);
    let error = verify_bytes(&bytes, false).unwrap_err();
    assert!(error.contains("RSS"), "got {error}");
}

#[test]
fn stale_release_binding_rejected_by_shape() {
    let mut report = certifying_report();
    report.release.reproducible = false;
    let bytes = encode(&report);
    assert!(verify_bytes(&bytes, false).is_err());
}

#[test]
fn release_mismatch_rejected() {
    let mut report = certifying_report();
    // Change one artefact name so it does not match the semver-derived four.
    let key = report.release.artifacts.keys().next().unwrap().clone();
    let hash = report.release.artifacts.remove(&key).unwrap();
    report.release.artifacts.insert("bogus-name.txt".to_owned(), hash);
    let bytes = encode(&report);
    let error = verify_bytes(&bytes, false).unwrap_err();
    assert!(error.contains("release artefact names"), "got {error}");
}

#[test]
fn unknown_fields_rejected() {
    let mut value: Value = serde_json::from_slice(&encode_pretty(&certifying_report())).unwrap();
    value.as_object_mut().unwrap().insert("extra".into(), Value::from("nope"));
    let bytes = serde_json::to_vec(&value).unwrap();
    let error = verify_bytes(&bytes, false).unwrap_err();
    assert!(error.contains("decode strict"), "got {error}");
}

#[test]
fn report_size_bounded() {
    let mut bytes = encode_pretty(&certifying_report());
    // Pad to exceed the byte limit.
    let target =
        usize::try_from(CANDIDATE_REPORT_MAX_BYTES).expect("size fits usize") + 1;
    bytes.resize(target, b' ');
    let error = verify_bytes(&bytes, false).unwrap_err();
    assert!(error.contains("byte limit"), "got {error}");
}

#[test]
fn trailing_bytes_rejected() {
    let mut bytes = encode(&certifying_report());
    bytes.extend_from_slice(b"garbage");
    assert!(verify_bytes(&bytes, false).is_err());
}

#[test]
fn wrong_command_rejected() {
    let mut report = certifying_report();
    report.command = "./bogus".to_owned();
    let bytes = encode(&report);
    assert!(verify_bytes(&bytes, false).is_err());
}

#[test]
fn wrong_cluster_fsid_rejected() {
    let mut report = certifying_report();
    report.cluster.fsid = "00000000-0000-0000-0000-000000000000".to_owned();
    let bytes = encode(&report);
    assert!(verify_bytes(&bytes, false).is_err());
}

#[test]
fn wrong_cluster_network_rejected() {
    let mut report = certifying_report();
    report.cluster.network = "10.0.0.0/24".to_owned();
    let bytes = encode(&report);
    assert!(verify_bytes(&bytes, false).is_err());
}

#[test]
fn manager_behavior_requires_two_managers() {
    let mut report = certifying_report();
    report.cluster.manager_behavior_exercised = true;
    report.cluster.managers = 1;
    let bytes = encode(&report);
    let error = verify_bytes(&bytes, false).unwrap_err();
    assert!(error.contains("manager"), "got {error}");
}

#[test]
fn reviews_must_be_null() {
    let mut value: Value = serde_json::from_slice(&encode_pretty(&certifying_report())).unwrap();
    value["reviews"] = json!({"kind": "spurious"});
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(verify_bytes(&bytes, false).is_err());
}

#[test]
fn quick_command_not_reproduce() {
    let report = non_certifying_report();
    assert_ne!(report.command, CANDIDATE_REPRODUCE_COMMAND);
}

#[test]
fn stale_qualification_binding_rejected() {
    let mut report = certifying_report();
    report
        .qualification
        .as_mut()
        .expect("qualification present")
        .path = "docs/r13/other.json".to_owned();
    let bytes = encode(&report);
    assert!(verify_bytes(&bytes, false).is_err());
}

#[test]
fn stale_fuzz_binding_rejected() {
    let mut report = certifying_report();
    report.fuzz.as_mut().expect("fuzz present").profile = "smoke".to_owned();
    let bytes = encode(&report);
    assert!(verify_bytes(&bytes, false).is_err());
}
