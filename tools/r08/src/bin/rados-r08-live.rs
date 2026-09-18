#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use rados::{CancellationToken, Config, ErrorKind, OperationOptions, SecretKey};
use serde::Serialize;

const PAYLOAD_BYTES: usize = 4096;
const OPERATIONS: u32 = 128;

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct SuiteReport {
    create: bool,
    write: bool,
    write_full: bool,
    append: bool,
    truncate: bool,
    zero: bool,
    remove: bool,
    performance: Performance,
}

#[derive(Serialize)]
struct Performance {
    implementation: &'static str,
    workload: &'static str,
    payload_bytes: usize,
    concurrency: usize,
    operations: u32,
    elapsed_seconds: f64,
    operations_per_second: f64,
    latency_p50_microseconds: f64,
    latency_p95_microseconds: f64,
    latency_p99_microseconds: f64,
    cpu_user_seconds: f64,
    cpu_system_seconds: f64,
    allocation_metric: AllocationMetric,
    retained_bytes: u64,
    peak_rss_bytes: u64,
}

#[derive(Serialize)]
struct AllocationMetric {
    name: &'static str,
    value: usize,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("rados-r08-live: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = arguments()?;
    let action = required(&arguments, "action")?;
    let client = connect(&arguments).await?;
    let pool = client.open_pool("r08-data", options()).await?;
    match action {
        "suite" => {
            let report = run_suite(&client, &pool).await?;
            serde_json::to_writer(std::io::stdout(), &report)?;
            println!();
        }
        "cross-write" => {
            let object = pool.object("cross-client")?;
            object.create(true, options()).await?;
            object
                .write_full(required(&arguments, "value")?.as_bytes(), options())
                .await?;
        }
        "cross-require-remove" => {
            let object = pool.object("cross-client")?;
            let expected = required(&arguments, "value")?.as_bytes();
            let (actual, _) = object.read(0, 4096, options()).await?;
            require(actual == expected, "cross-client value mismatch")?;
            object.remove(options()).await?;
            require(
                object
                    .read(0, 1, options())
                    .await
                    .is_err_and(|error| error.kind() == ErrorKind::NotFound),
                "cross-client remove was not visible",
            )?;
        }
        "failover" => run_failover(&pool, required(&arguments, "control")?).await?,
        _ => return Err(format!("unsupported --action {action}").into()),
    }
    client.shutdown(options()).await?;
    Ok(())
}

async fn connect(
    arguments: &HashMap<String, String>,
) -> Result<rados::Client, Box<dyn std::error::Error>> {
    let key = fs::read(required(arguments, "key")?)?;
    let config = Config::default()
        .with_monitors(required(arguments, "monitors")?.split(','))?
        .with_entity("client.r08")?
        .with_cluster_fsid(required(arguments, "fsid")?)?
        .with_key(SecretKey::new(key.trim_ascii())?)
        .with_timeouts(
            Duration::from_secs(10),
            Duration::from_secs(15),
            Duration::from_secs(180),
        )?;
    let client = rados::Client::new(config)?;
    client.connect(options()).await?;
    Ok(client)
}

async fn run_suite(
    client: &rados::Client,
    pool: &rados::Pool,
) -> Result<SuiteReport, Box<dyn std::error::Error>> {
    let object = pool.object("rust-mutations")?;
    let _ = object.remove(options()).await;
    object.create(true, options()).await?;
    object.write(0, b"abcdef", options()).await?;
    require(read_all(&object).await? == b"abcdef", "write mismatch")?;
    object.write_full(b"0123456789", options()).await?;
    object.append(b"AB", options()).await?;
    require(
        read_all(&object).await? == b"0123456789AB",
        "append mismatch",
    )?;
    object.truncate(8, options()).await?;
    object.zero(2, 3, options()).await?;
    require(
        read_all(&object).await? == b"01\x00\x00\x00567",
        "truncate/zero mismatch",
    )?;

    let flush_a = pool.object("rust-flush-a")?;
    let flush_b = pool.object("rust-flush-b")?;
    let (first, second) = tokio::join!(
        flush_a.write_full(b"first", options()),
        flush_b.write_full(b"second", options())
    );
    first?;
    second?;
    client.flush(options()).await?;
    require(
        read_all(&flush_a).await? == b"first",
        "flush first mismatch",
    )?;
    require(
        read_all(&flush_b).await? == b"second",
        "flush second mismatch",
    )?;

    let cancellation = CancellationToken::new();
    cancellation.cancel();
    let cancelled = object.append(b"never", options().with_cancellation(cancellation));
    require(
        cancelled
            .await
            .is_err_and(|error| error.kind() == ErrorKind::Canceled),
        "pre-cancelled mutation was admitted",
    )?;
    let dropped = object.append(b"dropped", options());
    drop(dropped);
    client.flush(options()).await?;
    require(
        read_all(&object).await? == b"01\x00\x00\x00567",
        "dropped future mutated object",
    )?;
    object.remove(options()).await?;
    require(
        object
            .read(0, 1, options())
            .await
            .is_err_and(|error| error.kind() == ErrorKind::NotFound),
        "remove was not visible",
    )?;

    let performance = benchmark(pool).await?;
    Ok(SuiteReport {
        create: true,
        write: true,
        write_full: true,
        append: true,
        truncate: true,
        zero: true,
        remove: true,
        performance,
    })
}

async fn run_failover(pool: &rados::Pool, control: &str) -> Result<(), Box<dyn std::error::Error>> {
    let object = pool.object("append-once")?;
    object.write_full(b"base", options()).await?;
    fs::write(Path::new(control).join("ready"), [])?;
    wait_for(Path::new(control).join("go")).await?;
    let append = tokio::spawn(async move { object.append(b"-once", options()).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    fs::write(Path::new(control).join("submitted"), [])?;
    append
        .await?
        .map_err(|error| format!("append recovery: {error:?}"))?;
    let object = pool.object("append-once")?;
    require(
        read_all(&object).await? == b"base-once",
        "append was duplicated or lost",
    )?;
    fs::write(Path::new(control).join("passed"), [])?;
    Ok(())
}

async fn benchmark(pool: &rados::Pool) -> Result<Performance, Box<dyn std::error::Error>> {
    let payload = (0_u8..=255).cycle().take(PAYLOAD_BYTES).collect::<Vec<_>>();
    let object = pool.object("rust-performance")?;
    object.write_full(&payload, options()).await?;
    let (user_before, system_before) = cpu_seconds()?;
    let started = Instant::now();
    let mut latencies = Vec::with_capacity(usize::try_from(OPERATIONS)?);
    for _ in 0..OPERATIONS {
        let operation_started = Instant::now();
        object.write_full(&payload, options()).await?;
        latencies.push(operation_started.elapsed().as_secs_f64() * 1_000_000.0);
    }
    let elapsed = started.elapsed().as_secs_f64();
    let (user_after, system_after) = cpu_seconds()?;
    latencies.sort_by(f64::total_cmp);
    let peak_rss_bytes = peak_rss_bytes()?;
    Ok(Performance {
        implementation: "rust",
        workload: "write-full-baseline-v1",
        payload_bytes: PAYLOAD_BYTES,
        concurrency: 1,
        operations: OPERATIONS,
        elapsed_seconds: elapsed,
        operations_per_second: f64::from(OPERATIONS) / elapsed,
        latency_p50_microseconds: percentile(&latencies, 50),
        latency_p95_microseconds: percentile(&latencies, 95),
        latency_p99_microseconds: percentile(&latencies, 99),
        cpu_user_seconds: user_after - user_before,
        cpu_system_seconds: system_after - system_before,
        allocation_metric: AllocationMetric {
            name: "mutation_payload_owned_bytes",
            value: payload.capacity() * usize::try_from(OPERATIONS)?,
        },
        retained_bytes: payload.capacity() as u64,
        peak_rss_bytes,
    })
}

async fn read_all(object: &rados::ObjectRef) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(object.read(0, 1 << 20, options()).await?.0)
}

fn options() -> OperationOptions {
    OperationOptions::new().with_deadline(Instant::now() + Duration::from_secs(180))
}

async fn wait_for(path: impl AsRef<Path>) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(90);
    while !path.as_ref().exists() {
        if Instant::now() >= deadline {
            return Err("control wait timed out".into());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Ok(())
}

fn cpu_seconds() -> Result<(f64, f64), Box<dyn std::error::Error>> {
    let stat = fs::read_to_string("/proc/self/stat")?;
    let end = stat.rfind(')').ok_or("malformed /proc/self/stat")?;
    let fields = stat[end + 2..].split_whitespace().collect::<Vec<_>>();
    let user = f64::from(fields.get(11).ok_or("missing utime")?.parse::<u32>()?) / 100.0;
    let system = f64::from(fields.get(12).ok_or("missing stime")?.parse::<u32>()?) / 100.0;
    Ok((user, system))
}

fn peak_rss_bytes() -> Result<u64, Box<dyn std::error::Error>> {
    let status = fs::read_to_string("/proc/self/status")?;
    let value = |name: &str| -> Result<u64, Box<dyn std::error::Error>> {
        let line = status
            .lines()
            .find(|line| line.starts_with(name))
            .ok_or("missing memory field")?;
        Ok(line
            .split_whitespace()
            .nth(1)
            .ok_or("missing memory value")?
            .parse::<u64>()?
            * 1024)
    };
    value("VmHWM:")
}

fn percentile(values: &[f64], percentile: usize) -> f64 {
    values[(values.len() - 1) * percentile / 100]
}

fn arguments() -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut result = HashMap::new();
    let mut values = std::env::args().skip(1);
    while let Some(name) = values.next() {
        let value = values
            .next()
            .ok_or_else(|| format!("missing value for {name}"))?;
        let name = name
            .strip_prefix("--")
            .ok_or_else(|| format!("invalid argument {name}"))?;
        result.insert(name.to_owned(), value);
    }
    Ok(result)
}

fn required<'a>(
    arguments: &'a HashMap<String, String>,
    name: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    arguments
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| format!("missing --{name}").into())
}

fn require(condition: bool, message: &'static str) -> Result<(), Box<dyn std::error::Error>> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
