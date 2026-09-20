#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rados::{Client, Config, OperationOptions, SecretKey};
use serde::Serialize;

const ADMIN_ENTITY: &str = "client.p12-admin";
const IO_ENTITY: &str = "client.p12-io";
const DATA_POOL: &str = "p12-data";
const NATIVE_APP_POOL: &str = "p12-native-app";
const RUST_CREATED_POOL: &str = "p12-rust-created";
const APPLICATION_NAME: &str = "p12app";

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct AdminReport {
    cluster_stats: bool,
    pool_stats: bool,
    monitor_command: bool,
    manager_command: bool,
    osd_command: bool,
    pg_command: bool,
    pool_create_delete: bool,
    application_enable_list: bool,
    application_metadata_set_get_list_remove: bool,
    session_addresses: Vec<String>,
    blocklist: bool,
    inconsistent_pgs: bool,
    inconsistent_objects: bool,
    command_error_output_preserved: bool,
}

#[derive(Serialize)]
struct RecoveryReport {
    manager_before_failover: bool,
    manager_after_failover: bool,
    io_after_manager_loss: bool,
}

#[derive(Serialize)]
struct LeastPrivilegeReport {
    write_read_without_manager: bool,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("rados-r12-live: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = arguments()?;
    let mode = required(&arguments, "mode")?;
    let entity = arguments
        .get("entity")
        .cloned()
        .unwrap_or_else(|| default_entity(mode).to_owned());
    let client = connect(&arguments, &entity).await?;
    match mode {
        "admin" => run_admin(&arguments, &client).await?,
        "recovery" => run_recovery(&arguments, &client).await?,
        "least" => run_least(&client).await?,
        other => return Err(format!("unknown --mode {other}").into()),
    }
    client.shutdown(options()).await?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn run_admin(
    arguments: &HashMap<String, String>,
    client: &Client,
) -> Result<(), Box<dyn std::error::Error>> {
    let pg = required(arguments, "pg")?;
    let osd = required(arguments, "osd")?.parse::<i64>()?;

    let stats = client.cluster_stats(options()).await?;
    require(
        stats.kib > 0 && stats.kib_available <= stats.kib,
        "invalid cluster stats",
    )?;

    let data_pool = client.open_pool(DATA_POOL, options()).await?;
    data_pool
        .object("stats-object")?
        .write_full(b"p12-stats", options())
        .await?;
    let pool_stats = data_pool.stats(options()).await?;
    require(
        pool_stats.objects > 0 && pool_stats.bytes_used > 0,
        "invalid pool stats",
    )?;

    let (mon, mon_status) = client
        .monitor_command(br#"{"prefix":"status","format":"json"}"#, b"", options())
        .await;
    mon_status?;
    require(!mon.output.is_empty(), "empty monitor command output")?;

    let (mgr, mgr_status) = client
        .manager_command(br#"{"prefix":"pg dump","format":"json"}"#, b"", options())
        .await;
    mgr_status?;
    require(!mgr.output.is_empty(), "empty manager command output")?;

    let (osd_reply, osd_status) = client
        .osd_command(osd, br#"{"prefix":"version"}"#, b"", options())
        .await;
    osd_status?;
    require(
        !osd_reply.output.is_empty() || !osd_reply.status.is_empty(),
        "empty OSD command result",
    )?;

    let pg_command = format!(r#"{{"prefix":"pg","cmd":"query","pgid":"{pg}"}}"#);
    let (pg_reply, pg_status) = client
        .pg_command(pg, pg_command.as_bytes(), b"", options())
        .await;
    pg_status?;
    require(!pg_reply.output.is_empty(), "empty PG command output")?;

    client.create_pool(RUST_CREATED_POOL, options()).await?;
    client.open_pool(RUST_CREATED_POOL, options()).await?;
    client.delete_pool(RUST_CREATED_POOL, options()).await?;
    require(
        client
            .open_pool(RUST_CREATED_POOL, options())
            .await
            .is_err(),
        "deleted pool remained visible",
    )?;

    let application_pool = client.open_pool(NATIVE_APP_POOL, options()).await?;
    application_pool
        .enable_application(APPLICATION_NAME, true, options())
        .await?;
    let applications = application_pool.list_applications(options())?;
    require(
        applications.iter().any(|name| name == APPLICATION_NAME),
        "enabled application missing from list",
    )?;
    application_pool
        .set_application_metadata(APPLICATION_NAME, "owner", "rust", options())
        .await?;
    let metadata = application_pool.list_application_metadata(APPLICATION_NAME, options())?;
    require(
        metadata.get("owner").map(String::as_str) == Some("rust"),
        "unexpected application metadata listing",
    )?;
    let value = application_pool.get_application_metadata(APPLICATION_NAME, "owner", options())?;
    require(value == "rust", "unexpected application metadata value")?;
    application_pool
        .remove_application_metadata(APPLICATION_NAME, "owner", options())
        .await?;
    require(
        application_pool
            .get_application_metadata(APPLICATION_NAME, "owner", options())
            .is_err(),
        "removed application metadata remained visible",
    )?;

    let session_addresses = client.session_addresses();
    require(!session_addresses.is_empty(), "no session addresses")?;

    client
        .blocklist("v2:192.0.2.254:6800/1", Duration::from_secs(60), options())
        .await?;

    let pool_id = data_pool.id().ok_or("unresolved data pool")?;
    client.list_inconsistent_pgs(pool_id, options()).await?;
    client.list_inconsistent_objects(pg, options()).await?;

    let invalid_command = br#"{"prefix":"rados-r12-command-that-does-not-exist"}"#;
    let (failure, failure_status) = client
        .monitor_command(
            br#"{"prefix":"osd pool get","pool":"missing-p12-pool","var":"size","format":"json"}"#,
            b"",
            options(),
        )
        .await;
    require(
        failure_status.is_err() && !failure.status.is_empty(),
        "monitor command error did not preserve status",
    )?;
    let (failure, failure_status) = client
        .manager_command(invalid_command, b"", options())
        .await;
    require(
        failure_status.is_err() && !failure.status.is_empty(),
        "manager command error did not preserve status",
    )?;
    let (failure, failure_status) = client
        .osd_command(osd, invalid_command, b"", options())
        .await;
    require(
        failure_status.is_err() && !failure.status.is_empty(),
        "OSD command error did not preserve status",
    )?;
    let (failure, failure_status) = client.pg_command(pg, invalid_command, b"", options()).await;
    require(
        failure_status.is_err() && !failure.status.is_empty(),
        "PG command error did not preserve status",
    )?;

    serde_json::to_writer(
        std::io::stdout().lock(),
        &AdminReport {
            cluster_stats: true,
            pool_stats: true,
            monitor_command: true,
            manager_command: true,
            osd_command: true,
            pg_command: true,
            pool_create_delete: true,
            application_enable_list: true,
            application_metadata_set_get_list_remove: true,
            session_addresses,
            blocklist: true,
            inconsistent_pgs: true,
            inconsistent_objects: true,
            command_error_output_preserved: true,
        },
    )?;
    writeln!(std::io::stdout().lock())?;
    Ok(())
}

async fn run_recovery(
    arguments: &HashMap<String, String>,
    client: &Client,
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = PathBuf::from(required(arguments, "coordination-dir")?);

    let (before, before_status) = client
        .manager_command(br#"{"prefix":"pg dump","format":"json"}"#, b"", options())
        .await;
    before_status?;
    require(!before.output.is_empty(), "manager before failover empty")?;

    signal_and_wait(&directory, "ready", "continue").await?;

    let (after, after_status) = client
        .manager_command(br#"{"prefix":"pg dump","format":"json"}"#, b"", options())
        .await;
    after_status?;
    require(!after.output.is_empty(), "manager after failover empty")?;

    signal_and_wait(&directory, "failover-done", "managerless").await?;

    let pool = client.open_pool(DATA_POOL, options()).await?;
    let object = pool.object("managerless-existing-client")?;
    object.write_full(b"managerless", options()).await?;
    let (data, _) = object.read(0, 64, options()).await?;
    require(data == b"managerless", "managerless read mismatch")?;

    serde_json::to_writer(
        std::io::stdout().lock(),
        &RecoveryReport {
            manager_before_failover: true,
            manager_after_failover: true,
            io_after_manager_loss: true,
        },
    )?;
    writeln!(std::io::stdout().lock())?;
    Ok(())
}

async fn run_least(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let pool = client.open_pool(DATA_POOL, options()).await?;
    let object = pool.object("least-privilege")?;
    object.write_full(b"least", options()).await?;
    let (data, _) = object.read(0, 64, options()).await?;
    require(data == b"least", "least privilege read mismatch")?;
    serde_json::to_writer(
        std::io::stdout().lock(),
        &LeastPrivilegeReport {
            write_read_without_manager: true,
        },
    )?;
    writeln!(std::io::stdout().lock())?;
    Ok(())
}

async fn signal_and_wait(
    directory: &Path,
    signal: &str,
    wait: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(directory.join(signal), b"ready\n")?;
    let target = directory.join(wait);
    let deadline = Instant::now() + Duration::from_secs(130);
    loop {
        if target.exists() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for {}", target.display()).into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn connect(
    arguments: &HashMap<String, String>,
    entity: &str,
) -> Result<Client, Box<dyn std::error::Error>> {
    let key = fs::read(required(arguments, "key")?)?;
    let config = Config::default()
        .with_monitors(required(arguments, "monitors")?.split(','))?
        .with_entity(entity.to_owned())?
        .with_cluster_fsid(required(arguments, "fsid")?.to_owned())?
        .with_key(SecretKey::new(key.trim_ascii())?)
        .with_timeouts(
            Duration::from_secs(10),
            Duration::from_secs(20),
            Duration::from_secs(20),
        )?;
    let client = Client::new(config)?;
    client.connect(options()).await?;
    Ok(client)
}

fn options() -> OperationOptions {
    OperationOptions::new().with_deadline(Instant::now() + Duration::from_secs(140))
}

fn arguments() -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut result = HashMap::new();
    let mut values = std::env::args().skip(1);
    while let Some(name) = values.next() {
        let value = values.next().ok_or("missing argument value")?;
        let name = name
            .strip_prefix("--")
            .ok_or("invalid argument")?
            .to_owned();
        result.insert(name, value);
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

fn default_entity(mode: &str) -> &'static str {
    match mode {
        "least" => IO_ENTITY,
        _ => ADMIN_ENTITY,
    }
}

fn require(condition: bool, message: &'static str) -> Result<(), Box<dyn std::error::Error>> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
