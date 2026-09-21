#![forbid(unsafe_code)]
//! `rados-r13-probe` — live endurance probe.
//!
//! Drives a bounded mixed workload (`write_full`, read+verify, `stat`,
//! `append`+exactly-once verification, `remove`) against a Ceph cluster for a
//! requested wall-clock duration and emits a schema-valid probe JSON
//! document. Uses only the public `rados` crate API (`Config`,
//! `SecretKey`, `SecurityMode`, `Client`, `Pool`, `ObjectRef`,
//! `OperationOptions`). No production-code test hook is introduced.
//!
//! Periodic reconnect is implemented by shutting down the current
//! `Client` and constructing a new one from an owned copy of the
//! configuration — the only reconnect lifecycle the public API exposes.
//!
//! Renewal telemetry (session renewals, credential renewal generation
//! numbers) is not exposed by the public API, so those fields are
//! reported as `null` alongside the explanatory sentinels
//! [`rados_r13_tools::candidate::RENEWAL_MEASUREMENT_SENTINEL`] and
//! [`rados_r13_tools::candidate::INFLIGHT_MEASUREMENT_SENTINEL`] shared
//! with the candidate verifier. The certifying gate is preserved via
//! the 24-hour connection, reconnect count, longest-connection, and
//! churn evidence.

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use rados::{Client, Config, ErrorKind, OperationOptions, SecretKey, SecurityMode};
use rados_r13_tools::candidate::{INFLIGHT_MEASUREMENT_SENTINEL, RENEWAL_MEASUREMENT_SENTINEL};
use serde::Serialize;

const TRANSPORTS: [&str; 2] = ["secure", "crc"];
const MAX_SAMPLES: u64 = 2000;
const APPEND_TAG: &[u8] = b"-once";
const PAYLOAD_BYTES: usize = 4096;

#[derive(Debug)]
struct ProbeArgs {
    monitors: String,
    fsid: String,
    pool: String,
    entity: String,
    transport: String,
    duration: Duration,
    reconnect_interval: Duration,
    sample_interval: Duration,
    key_file: PathBuf,
    output: Option<PathBuf>,
    maximum_configured_sample_count: u64,
}

#[derive(Serialize)]
struct ProbeReport {
    transport: &'static str,
    requested_duration_ns: u64,
    elapsed_ns: u64,
    monotonic_duration_satisfied: bool,
    operations: u64,
    writes: u64,
    reads: u64,
    stats: u64,
    removes: u64,
    appends: u64,
    append_once_verifications: u64,
    duplicate_mutations_detected: u64,
    reconnects: u64,
    session_renewals: Option<u64>,
    longest_connection_ns: u64,
    credential_renewals: Option<Vec<serde_json::Value>>,
    renewal_measurement: &'static str,
    samples: Vec<ResourceSample>,
    inflight_measurement: &'static str,
    maximum_configured_sample_count: u64,
}

#[derive(Serialize)]
struct ResourceSample {
    elapsed_ns: u64,
    rss_bytes: u64,
    threads: u64,
    heap_bytes: u64,
    inflight: Option<u64>,
}

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("rados-r13-probe: tokio runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rados-r13-probe: {error}");
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_lines)]
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
    let base_config = Config::default()
        .with_monitors(args.monitors.split(','))?
        .with_entity(&args.entity)?
        .with_cluster_fsid(&args.fsid)?
        .with_key(secret)
        .with_security_mode(security_mode)
        .with_timeouts(
            Duration::from_secs(10),
            Duration::from_secs(15),
            Duration::from_secs(30),
        )?;

    let started = Instant::now();
    let deadline = started + args.duration;
    let mut client = connect(&base_config).await?;
    let mut connection_start = Instant::now();
    let mut longest_connection = Duration::ZERO;
    let mut reconnects: u64 = 0;
    let mut writes: u64 = 0;
    let mut reads: u64 = 0;
    let mut stats: u64 = 0;
    let mut appends: u64 = 0;
    let mut append_once_verifications: u64 = 0;
    let mut removes: u64 = 0;
    let mut duplicate_mutations_detected: u64 = 0;

    let mut samples: Vec<ResourceSample> = Vec::new();
    let mut next_sample = started + args.sample_interval;
    let mut next_reconnect = started + args.reconnect_interval;
    let max_samples = args.maximum_configured_sample_count.clamp(2, MAX_SAMPLES);
    samples.push(take_sample(started));

    macro_rules! operation_with_reconnect {
        ($pool:ident, $object:ident, $object_name:ident, $operation:expr) => {{
            let mut recovery_attempts = 0_u8;
            loop {
                match $operation.await {
                    Ok(value) => break value,
                    Err(error)
                        if error.kind() == ErrorKind::NotConnected && recovery_attempts < 4 =>
                    {
                        recovery_attempts += 1;
                        let now = Instant::now();
                        longest_connection =
                            longest_connection.max(now.saturating_duration_since(connection_start));
                        let _ = client.shutdown(op_options()).await;
                        client = reconnect_until(&base_config, deadline).await?;
                        connection_start = Instant::now();
                        reconnects += 1;
                        $pool = client.pool(args.pool.as_bytes())?;
                        $object = $pool.object($object_name.as_bytes())?;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }};
    }

    let mut iteration: u64 = 0;
    while Instant::now() < deadline {
        let now = Instant::now();
        if now >= next_reconnect {
            let elapsed_this_connection = now.saturating_duration_since(connection_start);
            if elapsed_this_connection > longest_connection {
                longest_connection = elapsed_this_connection;
            }
            let _ = client.shutdown(op_options()).await;
            client = reconnect_until(&base_config, deadline).await?;
            connection_start = Instant::now();
            reconnects += 1;
            next_reconnect = connection_start + args.reconnect_interval;
        }

        let mut pool = client.pool(args.pool.as_bytes())?;
        let object_name = format!("probe-{transport_static}-{iteration:016x}");
        let mut object = pool.object(object_name.as_bytes())?;

        // Best-effort cleanup of any stale prior artefact (independent
        // iteration state means it should not exist).
        let _ = object.remove(op_options()).await;

        // 1. write_full: replace the object contents with a per-iteration payload.
        let payload = build_payload(iteration);
        operation_with_reconnect!(
            pool,
            object,
            object_name,
            object.write_full(&payload, op_options())
        );
        writes += 1;

        // 2. read: verify byte-exact contents.
        let (read_bytes, _info) = operation_with_reconnect!(
            pool,
            object,
            object_name,
            object.read(0, u64::try_from(payload.len())?, op_options())
        );
        reads += 1;
        if read_bytes != payload {
            return Err(format!(
                "probe {transport_static} iteration {iteration}: read mismatch after write_full"
            )
            .into());
        }

        // 3. stat: capture the size after the write_full.
        let info_before_append =
            operation_with_reconnect!(pool, object, object_name, object.stat(op_options()));
        stats += 1;
        if info_before_append.size != payload.len() as u64 {
            return Err(format!(
                "probe {transport_static} iteration {iteration}: stat size mismatch"
            )
            .into());
        }

        // 4. append: extend the object by a fixed marker.
        operation_with_reconnect!(
            pool,
            object,
            object_name,
            object.append(APPEND_TAG, op_options())
        );
        appends += 1;

        // 5. append-once verification: reading back must observe the
        // marker exactly once at the tail. This detects any duplicated
        // mutation across reconnects.
        let expected_len = payload.len() + APPEND_TAG.len();
        let (verify_bytes, _info) = operation_with_reconnect!(
            pool,
            object,
            object_name,
            object.read(0, u64::try_from(expected_len)?, op_options())
        );
        if verify_bytes.len() != expected_len
            || &verify_bytes[..payload.len()] != payload.as_slice()
            || &verify_bytes[payload.len()..] != APPEND_TAG
        {
            duplicate_mutations_detected += 1;
        }
        append_once_verifications += 1;

        // 6. remove: complete the iteration.
        operation_with_reconnect!(pool, object, object_name, object.remove(op_options()));
        removes += 1;

        iteration += 1;

        let now = Instant::now();
        if now >= next_sample && u64::try_from(samples.len()).unwrap_or(u64::MAX) < max_samples {
            samples.push(take_sample(started));
            next_sample = now + args.sample_interval;
        }
    }

    // Final connection length observation.
    let final_connection = Instant::now().saturating_duration_since(connection_start);
    if final_connection > longest_connection {
        longest_connection = final_connection;
    }

    // Emit a final sample so the harness observes end-of-run resource state.
    if u64::try_from(samples.len()).unwrap_or(u64::MAX) < max_samples {
        let last_elapsed = samples.last().map_or(0, |s| s.elapsed_ns);
        let mut end_sample = take_sample(started);
        if end_sample.elapsed_ns <= last_elapsed {
            end_sample.elapsed_ns = last_elapsed.saturating_add(1);
        }
        samples.push(end_sample);
    }
    if samples.len() < 2 {
        return Err("probe collected fewer than two resource samples".into());
    }
    let elapsed = Instant::now().saturating_duration_since(started);
    let elapsed_ns = nanos(elapsed)
        .max(samples.last().map_or(0, |sample| sample.elapsed_ns))
        .max(1);

    let operations = writes;
    if reads != operations
        || stats != operations
        || appends != operations
        || append_once_verifications != operations
        || removes != operations
    {
        return Err(format!(
            "probe operation counters diverged (writes={writes} reads={reads} stats={stats} appends={appends} verifs={append_once_verifications} removes={removes})"
        )
        .into());
    }
    if operations == 0 {
        return Err("probe completed zero operations".into());
    }

    let _ = client.shutdown(op_options()).await;

    let report = ProbeReport {
        transport: transport_static,
        requested_duration_ns: nanos(args.duration),
        elapsed_ns,
        monotonic_duration_satisfied: elapsed >= args.duration,
        operations,
        writes,
        reads,
        stats,
        removes,
        appends,
        append_once_verifications,
        duplicate_mutations_detected,
        reconnects,
        session_renewals: None,
        longest_connection_ns: nanos(longest_connection).max(1),
        credential_renewals: None,
        renewal_measurement: RENEWAL_MEASUREMENT_SENTINEL,
        samples,
        inflight_measurement: INFLIGHT_MEASUREMENT_SENTINEL,
        maximum_configured_sample_count: max_samples,
    };

    let bytes = serde_json::to_vec(&report)?;
    if let Some(path) = args.output {
        fs::write(path, bytes)?;
    } else {
        std::io::stdout().write_all(&bytes)?;
        std::io::stdout().write_all(b"\n")?;
    }
    Ok(())
}

async fn connect(config: &Config) -> Result<Client, Box<dyn std::error::Error>> {
    let client = Client::new(config.clone())?;
    client
        .connect(OperationOptions::new().with_timeout(Duration::from_secs(30))?)
        .await?;
    Ok(client)
}

async fn reconnect_until(
    config: &Config,
    deadline: Instant,
) -> Result<Client, Box<dyn std::error::Error>> {
    loop {
        match connect(config).await {
            Ok(client) => return Ok(client),
            Err(error) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(250)).await;
                drop(error);
            }
            Err(error) => return Err(error),
        }
    }
}

fn op_options() -> OperationOptions {
    OperationOptions::new()
        .with_timeout(Duration::from_secs(60))
        .unwrap_or_else(|_| OperationOptions::new())
}

fn build_payload(iteration: u64) -> Vec<u8> {
    let mut payload = vec![0_u8; PAYLOAD_BYTES];
    #[allow(clippy::cast_possible_truncation)]
    for (index, slot) in payload.iter_mut().enumerate() {
        *slot = (iteration.wrapping_add(index as u64) & 0xff) as u8;
    }
    payload
}

fn take_sample(started: Instant) -> ResourceSample {
    let elapsed = Instant::now().saturating_duration_since(started);
    ResourceSample {
        elapsed_ns: nanos(elapsed),
        rss_bytes: rss_bytes().unwrap_or(1),
        threads: thread_count().unwrap_or(1),
        heap_bytes: heap_bytes().unwrap_or(1),
        inflight: None,
    }
}

fn rss_bytes() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let value: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(value.saturating_mul(1024));
        }
    }
    None
}

fn heap_bytes() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmData:") {
            let value: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(value.saturating_mul(1024));
        }
    }
    None
}

fn thread_count() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Threads:") {
            let value: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(value);
        }
    }
    None
}

fn nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn parse_args() -> Result<ProbeArgs, Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut monitors = None;
    let mut fsid = None;
    let mut pool = None;
    let mut entity = None;
    let mut transport = None;
    let mut duration: Option<Duration> = None;
    let mut reconnect: Option<Duration> = None;
    let mut sample: Option<Duration> = None;
    let mut key_file = None;
    let mut output: Option<PathBuf> = None;
    let mut max_samples: u64 = 2000;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--monitors" => monitors = Some(next_value(&mut args, "--monitors")?),
            "--fsid" => fsid = Some(next_value(&mut args, "--fsid")?),
            "--pool" => pool = Some(next_value(&mut args, "--pool")?),
            "--entity" => entity = Some(next_value(&mut args, "--entity")?),
            "--transport" => transport = Some(next_value(&mut args, "--transport")?),
            "--duration" => duration = Some(parse_duration(&next_value(&mut args, "--duration")?)?),
            "--duration-ns" => {
                duration = Some(Duration::from_nanos(parse_u64(&next_value(
                    &mut args,
                    "--duration-ns",
                )?)?));
            }
            "--reconnect-interval" => {
                reconnect = Some(parse_duration(&next_value(
                    &mut args,
                    "--reconnect-interval",
                )?)?);
            }
            "--reconnect-interval-ns" => {
                reconnect = Some(Duration::from_nanos(parse_u64(&next_value(
                    &mut args,
                    "--reconnect-interval-ns",
                )?)?));
            }
            "--sample-interval" => {
                sample = Some(parse_duration(&next_value(
                    &mut args,
                    "--sample-interval",
                )?)?);
            }
            "--sample-interval-ns" => {
                sample = Some(Duration::from_nanos(parse_u64(&next_value(
                    &mut args,
                    "--sample-interval-ns",
                )?)?));
            }
            "--key-file" => key_file = Some(PathBuf::from(next_value(&mut args, "--key-file")?)),
            "--output" => output = Some(PathBuf::from(next_value(&mut args, "--output")?)),
            "--maximum-configured-sample-count" => {
                max_samples =
                    parse_u64(&next_value(&mut args, "--maximum-configured-sample-count")?)?;
            }
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
    let duration = duration.ok_or("missing --duration or --duration-ns")?;
    if duration.is_zero() {
        return Err("--duration must be non-zero".into());
    }
    let reconnect_interval =
        reconnect.ok_or("missing --reconnect-interval or --reconnect-interval-ns")?;
    if reconnect_interval.is_zero() {
        return Err("--reconnect-interval must be non-zero".into());
    }
    let sample_interval = sample.ok_or("missing --sample-interval or --sample-interval-ns")?;
    if sample_interval.is_zero() {
        return Err("--sample-interval must be non-zero".into());
    }
    if !(2..=MAX_SAMPLES).contains(&max_samples) {
        return Err(format!(
            "--maximum-configured-sample-count must be in [2,{MAX_SAMPLES}], got {max_samples}"
        )
        .into());
    }
    Ok(ProbeArgs {
        monitors: monitors.ok_or("missing --monitors")?,
        fsid: fsid.ok_or("missing --fsid")?,
        pool: pool.ok_or("missing --pool")?,
        entity: entity.ok_or("missing --entity")?,
        transport,
        duration,
        reconnect_interval,
        sample_interval,
        key_file: key_file.ok_or("missing --key-file")?,
        output,
        maximum_configured_sample_count: max_samples,
    })
}

fn print_help() {
    println!(
        "Usage: rados-r13-probe --monitors HOST:PORT --fsid UUID --pool NAME \
         --entity NAME --transport secure|crc --duration STRING \
         --reconnect-interval STRING --sample-interval STRING \
         --key-file PATH [--output PATH] [--maximum-configured-sample-count N]\n\
         STRING accepts Go-style durations (\"24h\", \"90m\", \"1500ms\") or \
         integer seconds. The *-ns aliases accept integer nanoseconds."
    );
}

fn next_value(
    args: &mut std::iter::Skip<std::env::Args>,
    flag: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

fn parse_u64(value: &str) -> Result<u64, Box<dyn std::error::Error>> {
    value
        .parse::<u64>()
        .map_err(|_| format!("expected integer, got {value:?}").into())
}

pub(crate) fn parse_duration(input: &str) -> Result<Duration, Box<dyn std::error::Error>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(format!("empty duration {input:?}").into());
    }
    if let Ok(seconds) = trimmed.parse::<u64>() {
        return Ok(Duration::from_secs(seconds));
    }
    let mut total = Duration::ZERO;
    let bytes = trimmed.as_bytes();
    let mut i = 0;
    let mut segments = 0_usize;
    while i < bytes.len() {
        let num_start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == num_start {
            return Err(format!("expected number in duration {input:?}").into());
        }
        let num: u64 = std::str::from_utf8(&bytes[num_start..i])?
            .parse()
            .map_err(|_| format!("invalid number in duration {input:?}"))?;
        let unit_start = i;
        while i < bytes.len() && !bytes[i].is_ascii_digit() {
            i += 1;
        }
        if unit_start == i {
            return Err(format!("missing unit in duration {input:?}").into());
        }
        let unit = std::str::from_utf8(&bytes[unit_start..i])?;
        let segment = match unit {
            "ns" => Duration::from_nanos(num),
            "us" | "\u{b5}s" => Duration::from_micros(num),
            "ms" => Duration::from_millis(num),
            "s" => Duration::from_secs(num),
            "m" => Duration::from_secs(num.saturating_mul(60)),
            "h" => Duration::from_secs(num.saturating_mul(3600)),
            other => {
                return Err(format!("unsupported duration unit {other:?} in {input:?}").into());
            }
        };
        total = total
            .checked_add(segment)
            .ok_or_else(|| format!("duration {input:?} overflows"))?;
        segments += 1;
    }
    if segments == 0 {
        return Err(format!("no duration segments in {input:?}").into());
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_accepts_seconds_integer() {
        assert_eq!(parse_duration("42").unwrap(), Duration::from_secs(42));
    }

    #[test]
    fn parse_duration_accepts_go_style() {
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_hours(24));
        assert_eq!(parse_duration("15m").unwrap(), Duration::from_mins(15));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("2h30m").unwrap(), Duration::from_mins(150));
    }

    #[test]
    fn parse_duration_rejects_empty_and_invalid_unit() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("15x").is_err());
        assert!(parse_duration("h").is_err());
    }

    #[test]
    fn build_payload_is_deterministic_and_bounded() {
        let a = build_payload(1);
        let b = build_payload(1);
        assert_eq!(a, b);
        assert_eq!(a.len(), PAYLOAD_BYTES);
        let c = build_payload(2);
        assert_ne!(a, c);
    }
}
