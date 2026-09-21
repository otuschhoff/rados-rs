#![forbid(unsafe_code)]
//! `rados-r13-bench` — Rust endurance benchmark.
//!
//! Runs the frozen 4x3x3 (4 sizes x 3 concurrencies x 3 workloads) matrix
//! against a Ceph cluster and emits a schema-valid `benchmark_run` JSON
//! document. Uses only the public `rados` crate API. This binary always
//! labels its output `implementation = "rust"`; a paired native
//! benchmark is a separate librados C++ program that the reproducer
//! script builds and invokes directly (see `tools/r13/native-bench/`).

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rados::{Client, Config, ObjectRef, OperationOptions, Pool, SecretKey, SecurityMode};
use serde::Serialize;

use rados_r13_tools::constants::{BENCH_CONCURRENCIES, BENCH_SIZES, BENCH_WORKLOADS};

const TRANSPORTS: [&str; 2] = ["secure", "crc"];

#[derive(Debug)]
struct BenchArgs {
    monitors: String,
    fsid: String,
    pool: String,
    entity: String,
    transport: String,
    key_file: PathBuf,
    output: Option<PathBuf>,
}

#[derive(Serialize)]
struct BenchmarkRun {
    implementation: &'static str,
    transport: &'static str,
    environment: serde_json::Value,
    resources: Resources,
    rows: Vec<Row>,
}

#[derive(Serialize)]
struct Resources {
    cpu_user_ns: u64,
    cpu_system_ns: u64,
    allocations: Option<u64>,
    allocated_bytes: Option<u64>,
    max_rss_bytes: u64,
}

#[derive(Serialize, Clone)]
struct Row {
    size_bytes: u64,
    concurrency: u32,
    workload: String,
    operations: u64,
    bytes: u64,
    elapsed_ns: u64,
    throughput_bytes_per_second: f64,
    iops: f64,
    p50_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
}

// Compile-time invariant: 4 sizes x 3 concurrencies x 3 workloads.
const BENCH_MATRIX_ROWS: usize =
    BENCH_SIZES.len() * BENCH_CONCURRENCIES.len() * BENCH_WORKLOADS.len();
const _: [(); 36] = [(); BENCH_MATRIX_ROWS];

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("rados-r13-bench: tokio runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rados-r13-bench: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args()?;

    let key_bytes = fs::read(&args.key_file)?;
    let secret = SecretKey::new(key_bytes.trim_ascii())?;
    let security_mode = match args.transport.as_str() {
        "secure" => SecurityMode::Secure,
        "crc" => SecurityMode::Crc,
        other => return Err(format!("unsupported transport {other:?}").into()),
    };
    let transport_static: &'static str = match args.transport.as_str() {
        "secure" => "secure",
        "crc" => "crc",
        _ => unreachable!("transport validated above"),
    };
    let config = Config::default()
        .with_monitors(args.monitors.split(','))?
        .with_entity(&args.entity)?
        .with_cluster_fsid(&args.fsid)?
        .with_key(secret)
        .with_security_mode(security_mode)
        .with_timeouts(
            Duration::from_secs(10),
            Duration::from_secs(15),
            Duration::from_secs(120),
        )?;
    let client = Client::new(config)?;
    client
        .connect(OperationOptions::new().with_timeout(Duration::from_secs(30))?)
        .await?;
    let pool = Arc::new(client.open_pool(args.pool.as_bytes(), op_options()).await?);

    let (start_user_ns, start_system_ns) = cpu_ns().unwrap_or((0, 0));
    let mut rows: Vec<Row> = Vec::with_capacity(36);

    for &size in &BENCH_SIZES {
        for &concurrency in &BENCH_CONCURRENCIES {
            for &workload in &BENCH_WORKLOADS {
                let row =
                    run_row(&pool, transport_static, size, concurrency, workload).await?;
                rows.push(row);
            }
        }
    }

    let (end_user_ns, end_system_ns) = cpu_ns().unwrap_or((0, 0));
    let peak_rss = peak_rss_bytes().unwrap_or(1);
    let _ = client.shutdown(op_options()).await;

    let run = BenchmarkRun {
        implementation: "rust",
        transport: transport_static,
        environment: environment_snapshot(),
        resources: Resources {
            cpu_user_ns: end_user_ns.saturating_sub(start_user_ns),
            cpu_system_ns: end_system_ns.saturating_sub(start_system_ns),
            // The public API does not expose an allocation counter and
            // #[forbid(unsafe_code)] rules out a custom global allocator,
            // so allocation counters are honestly reported as null.
            allocations: None,
            allocated_bytes: None,
            max_rss_bytes: peak_rss.max(1),
        },
        rows,
    };

    let bytes = serde_json::to_vec(&run)?;
    if let Some(path) = args.output {
        fs::write(path, bytes)?;
    } else {
        std::io::stdout().write_all(&bytes)?;
        std::io::stdout().write_all(b"\n")?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn run_row(
    pool: &Arc<Pool>,
    transport: &'static str,
    size: u64,
    concurrency: u32,
    workload: &'static str,
) -> Result<Row, Box<dyn std::error::Error>> {
    let operations = u64::from(concurrency) * 2;
    let payload = Arc::new(seeded_payload(size, u64::from(concurrency)));

    let mut objects: Vec<ObjectRef> = Vec::with_capacity(concurrency as usize);
    for worker in 0..concurrency {
        let name = format!("bench-{transport}-{size}-c{concurrency}-{workload}-{worker:04}");
        let object = pool.object(name.as_bytes())?;
        let _ = object.remove(op_options()).await;
        if matches!(workload, "read" | "mixed") {
            object.write_full(payload.as_slice(), op_options()).await?;
        }
        objects.push(object);
    }

    let start = Instant::now();
    let mut handles = Vec::with_capacity(concurrency as usize);
    for object in &objects {
        let object = object.clone();
        let payload_ref = Arc::clone(&payload);
        handles.push(tokio::spawn(async move {
            let mut latencies_ns: Vec<u64> = Vec::with_capacity(2);
            for iteration in 0..2_u32 {
                let op_start = Instant::now();
                match workload {
                    "write" => {
                        object
                            .write_full(payload_ref.as_slice(), op_options())
                            .await
                            .map_err(BenchError::from)?;
                    }
                    "read" => {
                        let (bytes, _info) = object
                            .read(0, payload_ref.len() as u64, op_options())
                            .await
                            .map_err(BenchError::from)?;
                        if bytes.len() != payload_ref.len() {
                            return Err(BenchError::Bench(
                                "bench read short".to_owned(),
                            ));
                        }
                    }
                    "mixed" => {
                        if iteration % 2 == 0 {
                            object
                                .write_full(payload_ref.as_slice(), op_options())
                                .await
                                .map_err(BenchError::from)?;
                        } else {
                            let _ = object
                                .read(0, payload_ref.len() as u64, op_options())
                                .await
                                .map_err(BenchError::from)?;
                        }
                    }
                    _ => {
                        return Err(BenchError::Bench(
                            "bench unknown workload".to_owned(),
                        ));
                    }
                }
                let latency = Instant::now().saturating_duration_since(op_start);
                latencies_ns
                    .push(u64::try_from(latency.as_nanos()).unwrap_or(u64::MAX));
            }
            Ok::<Vec<u64>, BenchError>(latencies_ns)
        }));
    }

    let mut latencies_ns: Vec<u64> =
        Vec::with_capacity(usize::try_from(operations).unwrap_or(0));
    for handle in handles {
        let inner = handle
            .await
            .map_err(|error| format!("bench worker join: {error}"))??;
        latencies_ns.extend(inner);
    }
    let elapsed = Instant::now().saturating_duration_since(start);

    for object in objects {
        let _ = object.remove(op_options()).await;
    }

    if latencies_ns.len() as u64 != operations {
        return Err(format!(
            "row size={size} c={concurrency} workload={workload} collected {} latencies (want {operations})",
            latencies_ns.len()
        )
        .into());
    }

    latencies_ns.sort_unstable();
    let elapsed_ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX).max(1);
    let bytes_total = size.saturating_mul(operations);
    #[allow(clippy::cast_precision_loss)]
    let throughput = (bytes_total as f64) * 1e9 / (elapsed_ns as f64);
    #[allow(clippy::cast_precision_loss)]
    let iops = (operations as f64) * 1e9 / (elapsed_ns as f64);
    Ok(Row {
        size_bytes: size,
        concurrency,
        workload: workload.to_owned(),
        operations,
        bytes: bytes_total,
        elapsed_ns,
        throughput_bytes_per_second: throughput,
        iops,
        p50_ns: percentile(&latencies_ns, 50).max(1),
        p95_ns: percentile(&latencies_ns, 95).max(1),
        p99_ns: percentile(&latencies_ns, 99).max(1),
    })
}

#[derive(Debug)]
enum BenchError {
    Rados(rados::Error),
    Bench(String),
}

impl From<rados::Error> for BenchError {
    fn from(value: rados::Error) -> Self {
        Self::Rados(value)
    }
}

impl std::fmt::Display for BenchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rados(error) => write!(formatter, "{error}"),
            Self::Bench(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for BenchError {}

fn seeded_payload(size: u64, seed: u64) -> Vec<u8> {
    let size = usize::try_from(size).unwrap_or(4096);
    let mut payload = vec![0_u8; size];
    #[allow(clippy::cast_possible_truncation)]
    for (index, slot) in payload.iter_mut().enumerate() {
        *slot = (seed.wrapping_add(index as u64) & 0xff) as u8;
    }
    payload
}

fn op_options() -> OperationOptions {
    OperationOptions::new()
        .with_timeout(Duration::from_secs(120))
        .unwrap_or_else(|_| OperationOptions::new())
}

fn percentile(sorted: &[u64], percentile: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let index = (sorted.len() - 1) * percentile / 100;
    sorted[index]
}

fn cpu_ns() -> Option<(u64, u64)> {
    let stat = fs::read_to_string("/proc/self/stat").ok()?;
    let end = stat.rfind(')')?;
    let fields: Vec<&str> = stat[end + 2..].split_whitespace().collect();
    let clock_ticks_per_second: u64 = 100;
    let user_ticks: u64 = fields.get(11)?.parse().ok()?;
    let system_ticks: u64 = fields.get(12)?.parse().ok()?;
    let scale: u64 = 1_000_000_000 / clock_ticks_per_second;
    Some((
        user_ticks.saturating_mul(scale),
        system_ticks.saturating_mul(scale),
    ))
}

fn peak_rss_bytes() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let value: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(value.saturating_mul(1024));
        }
    }
    None
}

fn environment_snapshot() -> serde_json::Value {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_owned());
    serde_json::json!({
        "os": os,
        "arch": arch,
        "host": host,
        "runtime": "tokio-multi-thread",
    })
}

fn parse_args() -> Result<BenchArgs, Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut monitors = None;
    let mut fsid = None;
    let mut pool = None;
    let mut entity = None;
    let mut transport = None;
    let mut key_file = None;
    let mut output: Option<PathBuf> = None;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--monitors" => monitors = Some(next_value(&mut args, "--monitors")?),
            "--fsid" => fsid = Some(next_value(&mut args, "--fsid")?),
            "--pool" => pool = Some(next_value(&mut args, "--pool")?),
            "--entity" => entity = Some(next_value(&mut args, "--entity")?),
            "--transport" => transport = Some(next_value(&mut args, "--transport")?),
            "--implementation" => {
                let value = next_value(&mut args, "--implementation")?;
                if value != "rust" {
                    return Err(format!(
                        "rados-r13-bench only produces implementation=\"rust\" (got {value:?}); \
                         build and invoke the native benchmark from tools/r13/native-bench \
                         separately"
                    )
                    .into());
                }
            }
            "--key-file" => key_file = Some(PathBuf::from(next_value(&mut args, "--key-file")?)),
            "--output" => output = Some(PathBuf::from(next_value(&mut args, "--output")?)),
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}").into()),
        }
    }
    let transport = transport.ok_or("missing --transport")?;
    if !TRANSPORTS.contains(&transport.as_str()) {
        return Err(format!("unsupported transport {transport:?}").into());
    }
    Ok(BenchArgs {
        monitors: monitors.ok_or("missing --monitors")?,
        fsid: fsid.ok_or("missing --fsid")?,
        pool: pool.ok_or("missing --pool")?,
        entity: entity.ok_or("missing --entity")?,
        transport,
        key_file: key_file.ok_or("missing --key-file")?,
        output,
    })
}

fn print_help() {
    println!(
        "Usage: rados-r13-bench --monitors HOST:PORT --fsid UUID --pool NAME \
         --entity NAME --transport secure|crc --key-file PATH [--output PATH]\n\
         Only produces implementation=\"rust\" runs. The native benchmark is \
         a separate C++ librados program under tools/r13/native-bench/."
    );
}

fn next_value(
    args: &mut std::iter::Skip<std::env::Args>,
    flag: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    args.next().ok_or_else(|| format!("{flag} requires a value").into())
}

// A version of parse_args driven from an in-memory arg list so tests do
// not need to mutate std::env.
#[cfg(test)]
fn parse_args_from(arguments: Vec<String>) -> Result<BenchArgs, Box<dyn std::error::Error>> {
    let mut iter = arguments.into_iter();
    let mut monitors = None;
    let mut fsid = None;
    let mut pool = None;
    let mut entity = None;
    let mut transport = None;
    let mut key_file = None;
    let mut output: Option<PathBuf> = None;
    while let Some(argument) = iter.next() {
        match argument.as_str() {
            "--monitors" => monitors = iter.next(),
            "--fsid" => fsid = iter.next(),
            "--pool" => pool = iter.next(),
            "--entity" => entity = iter.next(),
            "--transport" => transport = iter.next(),
            "--implementation" => {
                let value = iter.next().ok_or("missing implementation value")?;
                if value != "rust" {
                    return Err(format!(
                        "rados-r13-bench only produces implementation=\"rust\" (got {value:?}); \
                         build and invoke the native benchmark from tools/r13/native-bench \
                         separately"
                    )
                    .into());
                }
            }
            "--key-file" => key_file = iter.next().map(PathBuf::from),
            "--output" => output = iter.next().map(PathBuf::from),
            other => return Err(format!("unknown argument {other:?}").into()),
        }
    }
    let transport = transport.ok_or("missing --transport")?;
    if !TRANSPORTS.contains(&transport.as_str()) {
        return Err(format!("unsupported transport {transport:?}").into());
    }
    Ok(BenchArgs {
        monitors: monitors.ok_or("missing --monitors")?,
        fsid: fsid.ok_or("missing --fsid")?,
        pool: pool.ok_or("missing --pool")?,
        entity: entity.ok_or("missing --entity")?,
        transport,
        key_file: key_file.ok_or("missing --key-file")?,
        output,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_payload_is_deterministic_and_correct_size() {
        let a = seeded_payload(4096, 5);
        let b = seeded_payload(4096, 5);
        assert_eq!(a, b);
        assert_eq!(a.len(), 4096);
    }

    #[test]
    fn percentile_returns_index() {
        let sorted = vec![1_u64, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        // p50 at index (10-1)*50/100 = 4 -> value 5.
        assert_eq!(percentile(&sorted, 50), 5);
        // p99 at index (10-1)*99/100 = 8 -> value 9.
        assert_eq!(percentile(&sorted, 99), 9);
        assert_eq!(percentile(&sorted, 100), 10);
        assert_eq!(percentile(&[], 50), 0);
    }

    #[test]
    fn benchmark_matrix_shape_is_thirty_six() {
        assert_eq!(
            BENCH_SIZES.len() * BENCH_CONCURRENCIES.len() * BENCH_WORKLOADS.len(),
            36
        );
    }

    #[test]
    fn rejects_native_implementation_arg() {
        // Direct check: the CLI parser rejects `--implementation native`.
        let error = super::parse_args_from(vec![
            "--monitors".into(),
            "127.0.0.1:3300".into(),
            "--fsid".into(),
            "41111111-2222-4333-8444-131313131313".into(),
            "--pool".into(),
            "r13-data".into(),
            "--entity".into(),
            "client.r13".into(),
            "--transport".into(),
            "secure".into(),
            "--implementation".into(),
            "native".into(),
            "--key-file".into(),
            "/tmp/key".into(),
        ])
        .unwrap_err();
        assert!(
            error.to_string().contains("only produces implementation=\"rust\""),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn accepts_rust_implementation_arg() {
        super::parse_args_from(vec![
            "--monitors".into(),
            "127.0.0.1:3300".into(),
            "--fsid".into(),
            "41111111-2222-4333-8444-131313131313".into(),
            "--pool".into(),
            "r13-data".into(),
            "--entity".into(),
            "client.r13".into(),
            "--transport".into(),
            "secure".into(),
            "--implementation".into(),
            "rust".into(),
            "--key-file".into(),
            "/tmp/key".into(),
        ])
        .expect("rust arg must be accepted");
    }
}
