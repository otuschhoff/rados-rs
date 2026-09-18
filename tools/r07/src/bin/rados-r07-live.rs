#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use rados::{Config, ErrorKind, OperationOptions, SecretKey};
use serde::Serialize;

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct Report {
    ranged_read: bool,
    full_read: bool,
    empty_read: bool,
    namespace_read: bool,
    locator_read: bool,
    stat: bool,
    missing: bool,
    primary_change: bool,
    stat_size: u64,
    stat_mtime_seconds: i64,
    stat_mtime_nanosecond: u32,
    version: u64,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("rados-r07-live: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = arguments()?;
    let monitors = required(&arguments, "monitors")?;
    let key = fs::read(required(&arguments, "key")?)?;
    let expected = fs::read(required(&arguments, "data")?)?;
    let control = required(&arguments, "control")?;
    let config = Config::default()
        .with_monitors(monitors.split(','))?
        .with_entity("client.p06")?
        .with_cluster_fsid(required(&arguments, "fsid")?)?
        .with_key(SecretKey::new(trim_ascii(&key))?)
        .with_timeouts(
            Duration::from_secs(10),
            Duration::from_secs(15),
            Duration::from_secs(10),
        )?;
    let client = rados::Client::new(config)?;
    let deadline = Instant::now() + Duration::from_secs(90);
    let options = || OperationOptions::new().with_deadline(deadline);
    client.connect(options()).await?;
    let pool = client.open_pool("p06-data", options()).await?;

    let (ranged, ranged_info) = pool.object("binary")?.read(3, 17, options()).await?;
    require(ranged == expected[3..20], "ranged read mismatch")?;
    require(ranged_info.version > 0, "ranged read version is zero")?;
    let full_length = u64::try_from(expected.len())?.saturating_add(1024);
    let (full, full_info) = pool
        .object("binary")?
        .read(0, full_length, options())
        .await?;
    require(full == expected, "full read mismatch")?;
    require(full_info.version > 0, "full read version is zero")?;
    let stat = pool.object("binary")?.stat(options()).await?;
    require(
        stat.size == u64::try_from(expected.len())?,
        "stat size mismatch",
    )?;
    require(
        stat.modified_at > std::time::UNIX_EPOCH,
        "stat mtime is zero",
    )?;
    require(stat.version > 0, "stat version is zero")?;
    let modified = stat.modified_at.duration_since(std::time::UNIX_EPOCH)?;
    let (empty, _) = pool.object("empty")?.read(0, 1, options()).await?;
    require(empty.is_empty(), "empty object returned data")?;
    let (namespace, _) = pool
        .clone()
        .with_namespace("space")?
        .object("namespaced")?
        .read(0, 64, options())
        .await?;
    require(namespace == b"namespace-value", "namespace read mismatch")?;
    let (locator, _) = pool
        .clone()
        .with_locator("routing-key")?
        .object("located")?
        .read(0, 64, options())
        .await?;
    require(locator == b"locator-value", "locator read mismatch")?;
    let missing = pool.object("missing")?.read(0, 1, options()).await;
    require(
        missing.is_err_and(|error| error.kind() == ErrorKind::NotFound),
        "missing object did not return NotFound",
    )?;

    fs::write(Path::new(control).join("ready"), [])?;
    while !Path::new(control).join("remapped").exists() {
        if Instant::now() >= deadline {
            return Err("primary-change wait timed out".into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (after, after_info) = pool
        .object("binary")?
        .read(0, u64::try_from(expected.len())?, options())
        .await?;
    require(after == expected, "post-remap read mismatch")?;
    require(after_info.version > 0, "post-remap version is zero")?;
    client.shutdown(options()).await?;

    serde_json::to_writer(
        std::io::stdout(),
        &Report {
            ranged_read: true,
            full_read: true,
            empty_read: true,
            namespace_read: true,
            locator_read: true,
            stat: true,
            missing: true,
            primary_change: true,
            stat_size: stat.size,
            stat_mtime_seconds: i64::try_from(modified.as_secs())?,
            stat_mtime_nanosecond: modified.subsec_nanos(),
            version: stat.version,
        },
    )?;
    println!();
    Ok(())
}

fn arguments() -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut result = HashMap::new();
    let mut values = std::env::args().skip(1);
    while let Some(name) = values.next() {
        let Some(value) = values.next() else {
            return Err(format!("missing value for {name}").into());
        };
        let Some(name) = name.strip_prefix("--") else {
            return Err(format!("invalid argument {name}").into());
        };
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

fn trim_ascii(value: &[u8]) -> &[u8] {
    value.trim_ascii()
}

fn require(condition: bool, message: &'static str) -> Result<(), Box<dyn std::error::Error>> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
