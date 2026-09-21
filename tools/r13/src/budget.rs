//! R08-derived conservative benchmark budget.
//!
//! The Rust R13 endurance candidate compares four benchmark runs (rust
//! and native, each on the secure and CRC transports). The budget is
//! immutable and enforces:
//!
//! * Every `rust/<T>` row throughput must reach at least
//!   [`BENCH_MIN_NATIVE_THROUGHPUT_RATIO`] of the paired `native/<T>` row.
//! * Every `rust/<T>` row p99 latency must stay within
//!   [`BENCH_MAX_NATIVE_P99_RATIO`] of the paired `native/<T>` row.
//! * The Rust runs' peak RSS, allocation count, and allocated bytes must
//!   stay within the frozen limits.

use crate::constants::{
    BENCH_CONCURRENCIES, BENCH_IMPLEMENTATIONS, BENCH_MAX_ALLOCATED_BYTES,
    BENCH_MAX_ALLOCATIONS, BENCH_MAX_NATIVE_P99_RATIO, BENCH_MAX_RSS_BYTES,
    BENCH_MIN_NATIVE_THROUGHPUT_RATIO, BENCH_ROWS_PER_RUN, BENCH_RUNS_PER_CANDIDATE, BENCH_SIZES,
    BENCH_WORKLOADS, CANDIDATE_TRANSPORTS,
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy)]
pub struct BenchmarkBudget {
    pub minimum_native_throughput_ratio: f64,
    pub maximum_native_p99_ratio: f64,
    pub maximum_rss_bytes: u64,
    pub maximum_allocations: u64,
    pub maximum_allocated_bytes: u64,
}

#[must_use]
pub fn approved_budget() -> BenchmarkBudget {
    BenchmarkBudget {
        minimum_native_throughput_ratio: BENCH_MIN_NATIVE_THROUGHPUT_RATIO,
        maximum_native_p99_ratio: BENCH_MAX_NATIVE_P99_RATIO,
        maximum_rss_bytes: BENCH_MAX_RSS_BYTES,
        maximum_allocations: BENCH_MAX_ALLOCATIONS,
        maximum_allocated_bytes: BENCH_MAX_ALLOCATED_BYTES,
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkRun {
    pub implementation: String,
    pub transport: String,
    pub environment: serde_json::Value,
    pub resources: BenchmarkResources,
    pub rows: Vec<BenchmarkRow>,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkResources {
    pub cpu_user_ns: u64,
    pub cpu_system_ns: u64,
    pub allocations: Option<u64>,
    pub allocated_bytes: Option<u64>,
    pub max_rss_bytes: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkRow {
    pub size_bytes: u64,
    pub concurrency: u32,
    pub workload: String,
    pub operations: u64,
    pub bytes: u64,
    pub elapsed_ns: u64,
    pub throughput_bytes_per_second: f64,
    pub iops: f64,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
}

/// Return the row key used to identify a matrix coordinate.
#[must_use]
pub fn row_key(row: &BenchmarkRow) -> String {
    format!(
        "size={}/concurrency={}/workload={}",
        row.size_bytes, row.concurrency, row.workload
    )
}

/// Validate the shape of a single benchmark run.
///
/// # Errors
///
/// Returns an explanation if the implementation/transport pair is unknown,
/// the resources are invalid, the row count differs from
/// [`BENCH_ROWS_PER_RUN`], or any row has an invalid coordinate or counter
/// combination.
pub fn validate_run_shape(run: &BenchmarkRun) -> Result<(), String> {
    if !BENCH_IMPLEMENTATIONS.contains(&run.implementation.as_str()) {
        return Err(format!(
            "benchmark run has unknown implementation {:?}",
            run.implementation
        ));
    }
    if !CANDIDATE_TRANSPORTS.contains(&run.transport.as_str()) {
        return Err(format!(
            "benchmark run has unknown transport {:?}",
            run.transport
        ));
    }
    if run.resources.max_rss_bytes == 0
        || (run.resources.cpu_user_ns == 0 && run.resources.cpu_system_ns == 0)
    {
        return Err(format!(
            "benchmark run {}/{} has invalid resource counters",
            run.implementation, run.transport
        ));
    }
    match run.implementation.as_str() {
        "rust" => {
            // Allocations and allocated bytes are only reported when the
            // runtime instruments them; the public API does not expose an
            // allocation counter, so they are permitted to be null and the
            // budget skips those checks in that case.
        }
        "native" => {
            if run.resources.allocations.is_some() || run.resources.allocated_bytes.is_some() {
                return Err(format!(
                    "benchmark run native/{} must not report managed allocation counters",
                    run.transport
                ));
            }
        }
        other => {
            return Err(format!("benchmark run has unknown implementation {other:?}"));
        }
    }
    validate_rows(run)
}

fn validate_rows(run: &BenchmarkRun) -> Result<(), String> {
    if run.rows.len() != BENCH_ROWS_PER_RUN {
        return Err(format!(
            "benchmark run {}/{} has {} rows, want {}",
            run.implementation,
            run.transport,
            run.rows.len(),
            BENCH_ROWS_PER_RUN
        ));
    }
    let mut seen = std::collections::BTreeSet::<String>::new();
    for row in &run.rows {
        if !BENCH_SIZES.contains(&row.size_bytes)
            || !BENCH_CONCURRENCIES.contains(&row.concurrency)
            || !BENCH_WORKLOADS.contains(&row.workload.as_str())
        {
            return Err(format!("benchmark row has invalid coordinate {}", row_key(row)));
        }
        let key = row_key(row);
        if !seen.insert(key.clone()) {
            return Err(format!("benchmark row {key} appears twice"));
        }
        let expected_operations = u64::from(row.concurrency) * 2;
        if row.operations != expected_operations
            || row.bytes != row.size_bytes * row.operations
            || row.elapsed_ns == 0
            || !finite_positive(row.throughput_bytes_per_second)
            || !finite_positive(row.iops)
            || row.p50_ns == 0
            || row.p50_ns > row.p95_ns
            || row.p95_ns > row.p99_ns
        {
            return Err(format!("benchmark row {key} has invalid counters"));
        }
        #[allow(clippy::cast_precision_loss)]
        let expected_throughput = (row.bytes as f64) * 1e9 / (row.elapsed_ns as f64);
        #[allow(clippy::cast_precision_loss)]
        let expected_iops = (row.operations as f64) * 1e9 / (row.elapsed_ns as f64);
        if !metrics_equal(row.throughput_bytes_per_second, expected_throughput)
            || !metrics_equal(row.iops, expected_iops)
        {
            return Err(format!(
                "benchmark row {key} derived metrics disagree with counters"
            ));
        }
    }
    Ok(())
}

/// Full-matrix validation. Requires exactly four runs (rust and native on
/// secure and crc), with matching coordinates.
///
/// # Errors
///
/// Returns an explanation if any run is missing, duplicated, or fails
/// [`validate_run_shape`].
pub fn validate_matrix(runs: &[BenchmarkRun]) -> Result<(), String> {
    if runs.len() != BENCH_RUNS_PER_CANDIDATE {
        return Err(format!(
            "benchmark has {} runs, want {}",
            runs.len(),
            BENCH_RUNS_PER_CANDIDATE
        ));
    }
    let mut seen = std::collections::BTreeSet::<String>::new();
    for run in runs {
        validate_run_shape(run)?;
        let key = format!("{}/{}", run.implementation, run.transport);
        if !seen.insert(key.clone()) {
            return Err(format!("duplicate benchmark run {key}"));
        }
    }
    for implementation in BENCH_IMPLEMENTATIONS {
        for transport in CANDIDATE_TRANSPORTS {
            let key = format!("{implementation}/{transport}");
            if !seen.contains(&key) {
                return Err(format!("missing benchmark run {key}"));
            }
        }
    }
    Ok(())
}

/// Enforce the approved conservative R08-derived budget.
///
/// # Errors
///
/// Returns an explanation on any threshold violation.
pub fn evaluate_budget(runs: &[BenchmarkRun], budget: BenchmarkBudget) -> Result<(), String> {
    validate_matrix(runs)?;
    let mut indexed = std::collections::BTreeMap::<String, &BenchmarkRun>::new();
    for run in runs {
        indexed.insert(format!("{}/{}", run.implementation, run.transport), run);
    }
    for transport in CANDIDATE_TRANSPORTS {
        let rust_run = indexed
            .get(&format!("rust/{transport}"))
            .ok_or_else(|| format!("missing rust/{transport}"))?;
        let native_run = indexed
            .get(&format!("native/{transport}"))
            .ok_or_else(|| format!("missing native/{transport}"))?;
        evaluate_resources(rust_run, budget)
            .map_err(|error| format!("rust/{transport}: {error}"))?;
        let mut native_by_key = std::collections::BTreeMap::<String, &BenchmarkRow>::new();
        for row in &native_run.rows {
            native_by_key.insert(row_key(row), row);
        }
        for rust_row in &rust_run.rows {
            let native_row = native_by_key.get(&row_key(rust_row)).ok_or_else(|| {
                format!("rust/{transport}: native row {} missing", row_key(rust_row))
            })?;
            if !finite_positive(native_row.throughput_bytes_per_second)
                || native_row.p99_ns == 0
                || rust_row.p99_ns == 0
            {
                return Err(format!(
                    "invalid benchmark metric at {}",
                    row_key(rust_row)
                ));
            }
            let throughput_ratio =
                rust_row.throughput_bytes_per_second / native_row.throughput_bytes_per_second;
            if throughput_ratio < budget.minimum_native_throughput_ratio {
                return Err(format!(
                    "rust/{transport} {}: throughput ratio {:.3} < {:.3}",
                    row_key(rust_row),
                    throughput_ratio,
                    budget.minimum_native_throughput_ratio
                ));
            }
            #[allow(clippy::cast_precision_loss)]
            let p99_ratio = (rust_row.p99_ns as f64) / (native_row.p99_ns as f64);
            if p99_ratio > budget.maximum_native_p99_ratio {
                return Err(format!(
                    "rust/{transport} {}: p99 ratio {:.3} > {:.3}",
                    row_key(rust_row),
                    p99_ratio,
                    budget.maximum_native_p99_ratio
                ));
            }
        }
    }
    Ok(())
}

fn evaluate_resources(run: &BenchmarkRun, budget: BenchmarkBudget) -> Result<(), String> {
    if run.resources.max_rss_bytes == 0 || run.resources.max_rss_bytes > budget.maximum_rss_bytes {
        return Err(format!(
            "max RSS {} exceeds budget {}",
            run.resources.max_rss_bytes, budget.maximum_rss_bytes
        ));
    }
    if let Some(allocations) = run.resources.allocations
        && allocations > budget.maximum_allocations
    {
        return Err(format!(
            "allocations {allocations} exceed budget {}",
            budget.maximum_allocations
        ));
    }
    if let Some(allocated_bytes) = run.resources.allocated_bytes
        && allocated_bytes > budget.maximum_allocated_bytes
    {
        return Err(format!(
            "allocated_bytes {allocated_bytes} exceed budget {}",
            budget.maximum_allocated_bytes
        ));
    }
    Ok(())
}

fn metrics_equal(actual: f64, expected: f64) -> bool {
    let tolerance = expected.abs().mul_add(1e-6, 1e-6);
    (actual - expected).abs() <= tolerance
}

fn finite_positive(value: f64) -> bool {
    value > 0.0 && value.is_finite()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synth_row(size: u64, concurrency: u32, workload: &str, elapsed_ns: u64) -> BenchmarkRow {
        let operations = u64::from(concurrency) * 2;
        let bytes = size * operations;
        #[allow(clippy::cast_precision_loss)]
        let throughput = (bytes as f64) * 1e9 / (elapsed_ns as f64);
        #[allow(clippy::cast_precision_loss)]
        let iops = (operations as f64) * 1e9 / (elapsed_ns as f64);
        BenchmarkRow {
            size_bytes: size,
            concurrency,
            workload: workload.to_owned(),
            operations,
            bytes,
            elapsed_ns,
            throughput_bytes_per_second: throughput,
            iops,
            p50_ns: elapsed_ns / 100,
            p95_ns: elapsed_ns / 20,
            p99_ns: elapsed_ns / 10,
        }
    }

    fn synth_run(implementation: &str, transport: &str, elapsed_ns: u64) -> BenchmarkRun {
        let mut rows = Vec::with_capacity(BENCH_ROWS_PER_RUN);
        for size in BENCH_SIZES {
            for concurrency in BENCH_CONCURRENCIES {
                for workload in BENCH_WORKLOADS {
                    rows.push(synth_row(size, concurrency, workload, elapsed_ns));
                }
            }
        }
        let (allocations, allocated_bytes) = if implementation == "rust" {
            (Some(1000), Some(1024 * 1024))
        } else {
            (None, None)
        };
        BenchmarkRun {
            implementation: implementation.to_owned(),
            transport: transport.to_owned(),
            environment: serde_json::json!({"host": "test"}),
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

    #[test]
    fn balanced_matrix_passes_budget() {
        let runs = vec![
            synth_run("rust", "secure", 2_000_000),
            synth_run("rust", "crc", 2_000_000),
            synth_run("native", "secure", 1_000_000),
            synth_run("native", "crc", 1_000_000),
        ];
        evaluate_budget(&runs, approved_budget()).expect("balanced matrix must pass");
    }

    #[test]
    fn missing_run_rejected() {
        let runs = vec![
            synth_run("rust", "secure", 2_000_000),
            synth_run("native", "secure", 1_000_000),
            synth_run("native", "crc", 1_000_000),
        ];
        assert!(evaluate_budget(&runs, approved_budget()).is_err());
    }

    #[test]
    fn rss_budget_enforced() {
        let mut runs = vec![
            synth_run("rust", "secure", 2_000_000),
            synth_run("rust", "crc", 2_000_000),
            synth_run("native", "secure", 1_000_000),
            synth_run("native", "crc", 1_000_000),
        ];
        runs[0].resources.max_rss_bytes = BENCH_MAX_RSS_BYTES + 1;
        assert!(evaluate_budget(&runs, approved_budget()).unwrap_err().contains("RSS"));
    }

    #[test]
    fn allocations_budget_enforced() {
        let mut runs = vec![
            synth_run("rust", "secure", 2_000_000),
            synth_run("rust", "crc", 2_000_000),
            synth_run("native", "secure", 1_000_000),
            synth_run("native", "crc", 1_000_000),
        ];
        runs[0].resources.allocations = Some(BENCH_MAX_ALLOCATIONS + 1);
        assert!(evaluate_budget(&runs, approved_budget()).is_err());
    }

    #[test]
    fn allocated_bytes_budget_enforced() {
        let mut runs = vec![
            synth_run("rust", "secure", 2_000_000),
            synth_run("rust", "crc", 2_000_000),
            synth_run("native", "secure", 1_000_000),
            synth_run("native", "crc", 1_000_000),
        ];
        runs[0].resources.allocated_bytes = Some(BENCH_MAX_ALLOCATED_BYTES + 1);
        assert!(evaluate_budget(&runs, approved_budget()).is_err());
    }

    #[test]
    fn throughput_ratio_enforced() {
        // Rust rows use elapsed 200 s (very slow); native rows use 1 ms so
        // rust/native throughput ratio ≪ 0.10. Rows stay internally
        // consistent so validate_run_shape does not reject them first.
        let runs = vec![
            synth_run("rust", "secure", 200_000_000_000),
            synth_run("rust", "crc", 200_000_000_000),
            synth_run("native", "secure", 1_000_000),
            synth_run("native", "crc", 1_000_000),
        ];
        assert!(evaluate_budget(&runs, approved_budget()).unwrap_err().contains("throughput"));
    }

    #[test]
    fn p99_ratio_enforced() {
        let mut runs = vec![
            synth_run("rust", "secure", 2_000_000),
            synth_run("rust", "crc", 2_000_000),
            synth_run("native", "secure", 1_000_000),
            synth_run("native", "crc", 1_000_000),
        ];
        for row in &mut runs[0].rows {
            row.p99_ns *= 100;
        }
        assert!(evaluate_budget(&runs, approved_budget()).unwrap_err().contains("p99"));
    }

    #[test]
    fn duplicate_row_rejected() {
        let mut run = synth_run("rust", "secure", 2_000_000);
        run.rows[0] = run.rows[1].clone();
        assert!(validate_run_shape(&run).is_err());
    }
}
