//! Hidden qualification adapters for R05 evidence and fuzzing.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::maps::{
    Limits, apply_osdmap_incremental, decode_monmap, decode_osdmap, decode_osdmap_incremental,
};
use crate::mon::messages::{
    MESSAGE_MON_MAP, MESSAGE_OSD_MAP, MessageLimits, decode_monmap_message, decode_osdmap_batch,
    decode_osdmap_batch_maps,
};
use crate::msgr::message::{Message, MessageHeader, MessageLengths};
use crate::{Client, Config, OperationOptions, SecurityMode};

const MAP_LIMITS: Limits = Limits {
    max_bytes: 32 << 20,
    max_monitors: 64,
    max_addresses: 64,
    max_locations: 64,
    max_pools: 4096,
    max_osds: 65_536,
    max_pg_mappings: 1 << 20,
    max_collection_entries: 1 << 20,
};

/// Runs one fixed production configuration case and returns its canonical summary.
#[must_use]
pub fn config_case(case_id: &str, fixture_root: &Path) -> Value {
    let result = match case_id {
        "defaults" => Ok((Config::default(), Vec::new())),
        "global-entity-precedence" => Config::parse(
            b"[global]\nname = client.r05\nmon host = v1:192.0.2.1:6789, v2:192.0.2.2:3300\noperation timeout = 4s\nfuture option = ignored\n[client.r05]\nmon_host = [v2:192.0.2.3:3300,192.0.2.4:3300]\nms_mode = crc\n",
        )
        .map(|config| (config, Vec::new())),
        "explicit-env" => Config::default()
            .parse_env("RADOS_R05")
            .map(|config| (config, Vec::new())),
        "args-remainder" => Config::default().parse_args([
            "input",
            "--unknown",
            "value",
            "--id=test",
            "--mon-host",
            "v1:192.0.2.9:6789,v2:192.0.2.10:3300",
            "--operation-timeout=1h2m3.004005006s",
            "--",
            "--cluster=ignored",
        ]),
        "key-over-keyring" => {
            let keyring = fixture_root.join("keyring");
            Config::default().parse_args([
                "--keyring".to_owned(),
                keyring.display().to_string(),
                "--key".to_owned(),
                "AQB7AAAAyAEAABAAMTIzNDU2Nzg5MDEyMzQ1Ng==".to_owned(),
            ])
        }
        "keyring-expansion" => {
            let pattern = fixture_root.join("$cluster.$name.keyring");
            Config::default()
                .with_option("cluster", "r05")
                .and_then(|config| config.with_option("name", "client.r05"))
                .and_then(|config| config.with_option("keyring", &pattern.display().to_string()))
                .map(|config| (config, Vec::new()))
        }
        "duration-syntax" => Config::default()
            .with_option("dial_timeout", "1h2m3.004005006s")
            .and_then(|config| config.with_option("handshake_timeout", "250ms"))
            .and_then(|config| config.with_option("operation_timeout", "1us"))
            .map(|config| (config, Vec::new())),
        "unknown-retained" => Config::default()
            .with_option("future-option", " enabled ")
            .map(|config| (config, Vec::new())),
        "reject-include" => Config::parse(b"[global]\ninclude = /tmp/ceph.conf\n")
            .map(|config| (config, Vec::new())),
        "reject-duration" => Config::default()
            .with_option("operation_timeout", "0s")
            .map(|config| (config, Vec::new())),
        "reject-monitor-bound" => Config::default()
            .with_option("mon_host", &vec!["v2:192.0.2.1:3300"; 65].join(","))
            .map(|config| (config, Vec::new())),
        _ => return json!({"status":"unknown-case"}),
    };
    match result {
        Ok((config, remainder)) => summarize_config(&config, &remainder),
        Err(error) => json!({"status":"error","kind":format!("{:?}", error.kind())}),
    }
}

fn summarize_config(config: &Config, remainder: &[String]) -> Value {
    let key_sha256 = config.key().map(|key| hex_digest(key.expose()));
    json!({
        "status":"ok",
        "cluster":config.cluster(),
        "entity":config.entity(),
        "monitors":config.monitors(),
        "fsid":config.cluster_fsid(),
        "key_sha256":key_sha256,
        "keyring":config.option("keyring"),
        "mode":match config.security_mode() { SecurityMode::Secure => "secure", SecurityMode::Crc => "crc" },
        "dial_timeout":config.option("dial_timeout"),
        "handshake_timeout":config.option("handshake_timeout"),
        "operation_timeout":config.option("operation_timeout"),
        "future_option":config.option("future_option"),
        "remainder":remainder,
    })
}

/// Decodes a P04 map fixture with production code and returns canonical semantics.
///
/// # Errors
///
/// Returns an error for an unknown kind or rejected fixture.
pub fn map_summary(kind: &str, data: &[u8]) -> Result<Value, String> {
    match kind {
        "monmap" => {
            let map = decode_monmap(data, MAP_LIMITS).map_err(|error| error.to_string())?;
            Ok(json!({
                "kind":"monmap","fsid":map.fsid().to_string(),"epoch":map.epoch(),
                "monitor_count":map.monitors().len(),"ranks":map.ranks(),
                "persistent_features":map.persistent_features(),
                "optional_features":map.optional_features(),
                "minimum_monitor_release":map.minimum_monitor_release(),
                "election_strategy":map.election_strategy(),
                "stretch_mode":map.stretch_mode_enabled(),
            }))
        }
        "osdmap" => {
            let map = decode_osdmap(data, MAP_LIMITS).map_err(|error| error.to_string())?;
            let mut pools = map.pool_names().map(str::to_owned).collect::<Vec<_>>();
            pools.sort();
            Ok(json!({
                "kind":"osdmap","fsid":map.fsid().to_string(),"epoch":map.epoch(),
                "pool_count":map.pools().len(),"pools":pools,"crc":map.crc(),
                "crc_verified":map.crc_verified(),"sort_bitwise":map.sort_bitwise(),
                "applied_incremental":map.applied_incremental(),
            }))
        }
        "incremental" => {
            let map =
                decode_osdmap_incremental(data, MAP_LIMITS).map_err(|error| error.to_string())?;
            Ok(json!({
                "kind":"incremental","fsid":map.fsid().to_string(),"epoch":map.epoch(),
                "incremental_crc":map.incremental_crc(),"full_crc":map.full_crc(),
            }))
        }
        _ => Err("unknown map kind".to_owned()),
    }
}

/// Applies a production-decoded incremental to a production-decoded full map.
#[must_use]
pub fn map_convergence(full: &[u8], incremental: &[u8]) -> bool {
    let Ok(full) = decode_osdmap(full, MAP_LIMITS) else {
        return false;
    };
    let Ok(incremental) = decode_osdmap_incremental(incremental, MAP_LIMITS) else {
        return false;
    };
    apply_osdmap_incremental(&full, &incremental, MAP_LIMITS).is_ok()
}

/// Feeds arbitrary bytes to the production configuration parser.
pub fn fuzz_config(data: &[u8]) {
    let _ = Config::parse(data);
}

/// Feeds arbitrary bytes to one production map decoder.
pub fn fuzz_map(kind: u8, data: &[u8]) {
    match kind % 3 {
        0 => drop(decode_monmap(data, MAP_LIMITS)),
        1 => drop(decode_osdmap(data, MAP_LIMITS)),
        _ => drop(decode_osdmap_incremental(data, MAP_LIMITS)),
    }
}

/// Feeds arbitrary front-segment bytes to a production monitor map-message decoder.
pub fn fuzz_map_message(kind: u8, data: &[u8]) {
    let Ok(front_length) = u32::try_from(data.len()) else {
        return;
    };
    let osdmap = !kind.is_multiple_of(2);
    let message = Message {
        header: MessageHeader {
            message_type: if osdmap {
                MESSAGE_OSD_MAP
            } else {
                MESSAGE_MON_MAP
            },
            version: if osdmap { 4 } else { 0 },
            compat_version: if osdmap { 3 } else { 0 },
            ..MessageHeader::default()
        },
        lengths: MessageLengths {
            front: front_length,
            ..MessageLengths::default()
        },
        front: data.to_vec(),
        middle: Vec::new(),
        data: Vec::new(),
    };
    if osdmap {
        if let Ok(batch) = decode_osdmap_batch(
            &message,
            MessageLimits {
                max_bytes: MAP_LIMITS.max_bytes,
                max_maps: 64,
            },
        ) {
            drop(decode_osdmap_batch_maps(&batch, MAP_LIMITS));
        }
    } else {
        drop(decode_monmap_message(&message, MAP_LIMITS));
    }
}

fn hex_digest(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
        output
    })
}

/// Runs the bounded R05 public-client live qualification command.
///
/// # Errors
///
/// Returns an error when arguments, configuration, connection, or expectations fail.
pub fn run_cli() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    let mut config_path = None;
    let mut expected = Vec::new();
    let mut absent = Vec::new();
    let mut control_dir = None;
    let mut disposable_pool = None;
    let mut failover_pool = None;
    let mut timeout = Duration::from_secs(60);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--config" => config_path = arguments.next(),
            "--expect-pool" => expected.push(arguments.next().ok_or("missing pool")?),
            "--absent-pool" => absent.push(arguments.next().ok_or("missing pool")?),
            "--control-dir" => control_dir = arguments.next().map(PathBuf::from),
            "--disposable-pool" => disposable_pool = arguments.next(),
            "--failover-pool" => failover_pool = arguments.next(),
            "--timeout-seconds" => {
                timeout = Duration::from_secs(
                    arguments.next().ok_or("missing timeout")?.parse().map_err(|_| "invalid timeout")?,
                );
            }
            _ => return Err("usage: rados-r05-live --config PATH [--expect-pool NAME] [--absent-pool NAME] [--control-dir PATH --disposable-pool NAME --failover-pool NAME] [--timeout-seconds N]".to_owned()),
        }
    }
    let path = config_path.ok_or("missing --config")?;
    let config = Config::load(path).map_err(|error| error.to_string())?;
    if config.security_mode() != SecurityMode::Secure || timeout.is_zero() {
        return Err("live qualification requires secure mode and a positive timeout".to_owned());
    }
    if control_dir.is_some() != (disposable_pool.is_some() && failover_pool.is_some()) {
        return Err("control mode requires its directory and both pool names".to_owned());
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let report = runtime.block_on(async move {
        tokio::time::timeout(timeout, async move {
            let client = Client::new(config).map_err(|error| error.to_string())?;
            eprintln!("rados-r05-live: connecting");
            client.connect(OperationOptions::new()).await.map_err(|error| error.to_string())?;
            eprintln!("rados-r05-live: connected");
            let initial_pools = wait_for_pools(&client, &expected, &absent).await?;
            eprintln!("rados-r05-live: initial pools observed");
            let report = if let (Some(control_dir), Some(disposable_pool), Some(failover_pool)) =
                (control_dir, disposable_pool, failover_pool)
            {
                fs::write(control_dir.join("ready"), b"ready\n").map_err(|error| error.to_string())?;
                let created_pools = wait_for_pools(&client, std::slice::from_ref(&disposable_pool), &[]).await?;
                eprintln!("rados-r05-live: disposable pool creation observed");
                fs::write(control_dir.join("created"), b"created\n").map_err(|error| error.to_string())?;
                let deleted_pools = wait_for_pools(&client, &[], std::slice::from_ref(&disposable_pool)).await?;
                eprintln!("rados-r05-live: disposable pool deletion observed");
                fs::write(control_dir.join("deleted"), b"deleted\n").map_err(|error| error.to_string())?;
                let failover_pools = wait_for_pools(&client, std::slice::from_ref(&failover_pool), &[]).await?;
                eprintln!("rados-r05-live: post-failover pool observed");
                json!({
                    "schema_version":1,
                    "fsid":client.fsid(),
                    "instance_id":client.instance_id(),
                    "configured_security":"secure",
                    "authenticated":true,
                    "initial_pools":initial_pools,
                    "created_pools":created_pools,
                    "deleted_pools":deleted_pools,
                    "failover_pools":failover_pools,
                })
            } else {
                json!({"schema_version":1,"fsid":client.fsid(),"instance_id":client.instance_id(),"pools":initial_pools,"configured_security":"secure","authenticated":true})
            };
            client
                .shutdown(OperationOptions::new())
                .await
                .map_err(|error| error.to_string())?;
            Ok::<_, String>(report)
        }).await.map_err(|_| "live probe timeout".to_owned())?
    })?;
    println!(
        "{}",
        serde_json::to_string(&report).map_err(|error| error.to_string())?
    );
    Ok(())
}

async fn wait_for_pools(
    client: &Client,
    expected: &[String],
    absent: &[String],
) -> Result<Vec<String>, String> {
    loop {
        let pools = client
            .list_pools(OperationOptions::new())
            .await
            .map_err(|error| error.to_string())?;
        if expected.iter().all(|name| pools.contains(name))
            && absent.iter().all(|name| !pools.contains(name))
        {
            return Ok(pools);
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Reads and summarizes a fixture from disk for qualification tools.
///
/// # Errors
///
/// Returns an error when the fixture cannot be read or decoded.
pub fn fixture_summary(kind: &str, path: &Path) -> Result<Value, String> {
    let data = fs::read(path).map_err(|error| error.to_string())?;
    map_summary(kind, &data)
}
