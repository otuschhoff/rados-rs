#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant, UNIX_EPOCH};

use rados::{
    ChecksumType, Config, ErrorKind, OmapEntry, OperationOptions, SecretKey, Snapshot,
    SnapshotContext, WriteOp,
};
use serde::Serialize;

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct Report {
    named_create_list_lookup: bool,
    named_read_snapshot: bool,
    named_rollback: bool,
    named_remove: bool,
    self_managed_create: bool,
    self_managed_write_context: bool,
    self_managed_read: bool,
    self_managed_rollback: bool,
    self_managed_remove: bool,
    snapshot_context_validation: bool,
    write_same: bool,
    checksum: bool,
    checksum_hex: String,
    allocation_hint: bool,
    sparse_read: bool,
    copy_from: bool,
    copy_from2: bool,
    replicated_capabilities: bool,
    ec_capabilities: bool,
    ec_write_read: bool,
    ec_overwrite_rejected: bool,
    ec_write_same_rejected: bool,
    ec_checksum: bool,
    ec_allocation_hint: bool,
    ec_sparse_read: bool,
    ec_copy_from: bool,
    ec_omap_rejected: bool,
    ec_alignment_evidence: bool,
    native_seed_read: bool,
    required_alignment: u64,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("rados-r11-live: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = arguments()?;
    let client = connect(&arguments).await?;
    let named = client.open_pool("p11-named", options()).await?;
    let self_managed = client.open_pool("p11-self", options()).await?;
    let ec = client.open_pool("p11-ec", options()).await?;

    exercise_named(&named)
        .await
        .map_err(|error| format!("named snapshots: {error}"))?;
    exercise_self_managed(&self_managed)
        .await
        .map_err(|error| format!("self-managed snapshots: {error}"))?;
    exercise_invalid_context(&self_managed)
        .await
        .map_err(|error| format!("invalid snapshot context: {error}"))?;
    let (checksum_hex, alignment) = exercise_specialized(&named, &ec)
        .await
        .map_err(|error| format!("specialized I/O: {error}"))?;
    verify_native_seed(&named, &self_managed)
        .await
        .map_err(|error| format!("native seed: {error}"))?;
    fs::write(
        Path::new(required(&arguments, "coordination-dir")?).join("rust-complete"),
        [],
    )?;

    serde_json::to_writer(
        std::io::stdout(),
        &Report {
            named_create_list_lookup: true,
            named_read_snapshot: true,
            named_rollback: true,
            named_remove: true,
            self_managed_create: true,
            self_managed_write_context: true,
            self_managed_read: true,
            self_managed_rollback: true,
            self_managed_remove: true,
            snapshot_context_validation: true,
            write_same: true,
            checksum: true,
            checksum_hex,
            allocation_hint: true,
            sparse_read: true,
            copy_from: true,
            copy_from2: true,
            replicated_capabilities: true,
            ec_capabilities: true,
            ec_write_read: true,
            ec_overwrite_rejected: true,
            ec_write_same_rejected: true,
            ec_checksum: true,
            ec_allocation_hint: true,
            ec_sparse_read: true,
            ec_copy_from: true,
            ec_omap_rejected: true,
            ec_alignment_evidence: true,
            native_seed_read: true,
            required_alignment: alignment,
        },
    )?;
    println!();
    client.shutdown(options()).await?;
    Ok(())
}

async fn exercise_named(pool: &rados::Pool) -> Result<(), Box<dyn std::error::Error>> {
    let object = pool.object("rust-named")?;
    object.write_full(b"named-before", options()).await?;
    pool.create_snapshot("rust-snapshot", options()).await?;
    let snapshot = pool.lookup_snapshot("rust-snapshot", options())?;
    require(
        snapshot.id != 0
            && snapshot.name == "rust-snapshot"
            && snapshot.created_at > UNIX_EPOCH
            && contains_snapshot(&pool.list_snapshots(options())?, &snapshot),
        "named snapshot metadata",
    )?;
    object.write_full(b"named-after", options()).await?;
    expect_data(
        &pool
            .clone()
            .with_read_snapshot(snapshot.id)
            .object("rust-named")?,
        b"named-before",
        "named snapshot read",
    )
    .await?;
    object
        .rollback_to_snapshot("rust-snapshot", options())
        .await?;
    expect_data(&object, b"named-before", "named rollback read").await?;
    pool.remove_snapshot("rust-snapshot", options()).await?;
    require(
        pool.lookup_snapshot("rust-snapshot", options()).is_err(),
        "removed named snapshot remained visible",
    )?;
    object.write_full(b"rust-final", options()).await?;
    pool.create_snapshot("rust-native-check", options()).await?;
    object.write_full(b"rust-head", options()).await?;
    Ok(())
}

async fn exercise_self_managed(pool: &rados::Pool) -> Result<(), Box<dyn std::error::Error>> {
    let object = pool.object("rust-self")?;
    object.write_full(b"self-before", options()).await?;
    let snapshot = pool.create_self_managed_snapshot(options()).await?;
    require(snapshot != 0, "zero self-managed snapshot")?;
    let write_pool = pool.clone().with_write_snapshot(SnapshotContext {
        sequence: snapshot,
        snapshots: vec![snapshot],
    });
    write_pool
        .object("rust-self")?
        .write_full(b"self-after", options())
        .await?;
    expect_data(
        &pool
            .clone()
            .with_read_snapshot(snapshot)
            .object("rust-self")?,
        b"self-before",
        "self-managed snapshot read",
    )
    .await?;
    write_pool
        .object("rust-self")?
        .rollback_to_self_managed_snapshot(snapshot, options())
        .await?;
    expect_data(&object, b"self-before", "self-managed rollback read").await?;
    pool.remove_self_managed_snapshot(snapshot, options())
        .await?;
    Ok(())
}

async fn exercise_invalid_context(pool: &rados::Pool) -> Result<(), Box<dyn std::error::Error>> {
    let object = pool.object("invalid-context")?;
    object.write_full(b"stable", options()).await?;
    let invalid = pool.clone().with_write_snapshot(SnapshotContext {
        sequence: 1,
        snapshots: vec![1, 1],
    });
    let error = invalid
        .object("invalid-context")?
        .write_full(b"changed", options())
        .await
        .expect_err("invalid snapshot context accepted a mutation");
    require(
        error.kind() == ErrorKind::InvalidArgument,
        "invalid context error kind",
    )?;
    expect_data(
        &invalid.object("invalid-context")?,
        b"stable",
        "invalid-context read",
    )
    .await
}

async fn exercise_specialized(
    replicated: &rados::Pool,
    ec: &rados::Pool,
) -> Result<(String, u64), Box<dyn std::error::Error>> {
    require(
        !replicated.is_erasure_coded(options())?
            && !replicated.requires_alignment(options())?
            && replicated.required_alignment(options())? == 0,
        "replicated capabilities",
    )?;
    let alignment = ec.required_alignment(options())?;
    require(
        ec.is_erasure_coded(options())? && ec.requires_alignment(options())? && alignment > 0,
        "EC capabilities",
    )?;

    let object = replicated.object("specialized")?;
    object.write_same(0, 16, b"ab", options()).await?;
    expect_data(&object, b"abababababababab", "write-same read").await?;
    let checksum_object = replicated.object("checksum")?;
    checksum_object
        .write_full(b"abababababababab", options())
        .await?;
    let checksum = checksum_object
        .checksum(ChecksumType::Crc32c, [0; 4], 0, 16, 8, options())
        .await?;
    require(
        checksum == hex_bytes("02000000f5be862af5be862a")?,
        "CRC32C checksum",
    )?;
    object.set_allocation_hint(4096, 1024, options()).await?;
    object.zero(4, 4, options()).await?;
    let (extents, _) = object.sparse_read(0, 16, options()).await?;
    require(!extents.is_empty(), "empty replicated sparse read")?;
    let info = object.stat(options()).await?;
    let copy = replicated.object("rust-copy")?;
    copy.copy_from(&object, info.version, options()).await?;
    expect_data(&copy, b"abab\0\0\0\0abababab", "copy-from read").await?;
    let copy2 = replicated.object("rust-copy-from2")?;
    copy2
        .copy_from2(&object, info.version, 1, 8, options())
        .await?;
    expect_data(&copy2, b"abab\0\0\0\0abababab", "copy-from2 read").await?;

    let ec_object = ec.object("ec-specialized")?;
    let aligned = vec![b'e'; usize::try_from(alignment)?];
    ec_object.write_full(&aligned, options()).await?;
    expect_data(&ec_object, &aligned, "EC write-full read").await?;
    require_unsupported(ec_object.write(0, b"x", options()).await)?;
    require_unsupported(ec_object.write_same(0, alignment, b"ec", options()).await)?;
    require(
        !ec_object
            .checksum(
                ChecksumType::Crc32c,
                [0; 4],
                0,
                alignment,
                alignment,
                options(),
            )
            .await?
            .is_empty(),
        "empty EC checksum",
    )?;
    ec_object
        .set_allocation_hint(alignment, alignment, options())
        .await?;
    require(
        !ec_object
            .sparse_read(0, alignment, options())
            .await?
            .0
            .is_empty(),
        "empty EC sparse read",
    )?;
    let ec_info = ec_object.stat(options()).await?;
    ec.object("ec-copy")?
        .copy_from(&ec_object, ec_info.version, options())
        .await?;
    let omap = WriteOp::new().set_omap([OmapEntry {
        key: b"key".to_vec(),
        value: b"value".to_vec(),
    }])?;
    require_unsupported(ec_object.execute_write(omap, options()).await)?;
    Ok((lower_hex(&checksum), alignment))
}

async fn verify_native_seed(
    named: &rados::Pool,
    self_managed: &rados::Pool,
) -> Result<(), Box<dyn std::error::Error>> {
    expect_data(
        &named.object("native-named")?,
        b"native-before",
        "native named read",
    )
    .await?;
    expect_data(
        &self_managed.object("native-self")?,
        b"native-before",
        "native self-managed read",
    )
    .await
}

async fn expect_data(
    object: &rados::ObjectRef,
    expected: &[u8],
    label: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (data, _) = object
        .read(0, expected.len() as u64 + 1, options())
        .await
        .map_err(|error| format!("{label}: {error}"))?;
    if data == expected {
        Ok(())
    } else {
        Err(format!("{label}: object data mismatch").into())
    }
}

fn contains_snapshot(values: &[Snapshot], target: &Snapshot) -> bool {
    values.iter().any(|value| value == target)
}

fn require_unsupported<T>(result: rados::Result<T>) -> Result<(), Box<dyn std::error::Error>> {
    match result {
        Err(error) if error.kind() == ErrorKind::Unsupported => Ok(()),
        Err(error) => Err(format!("expected unsupported error, got {error}").into()),
        Ok(_) => Err("operation unexpectedly succeeded".into()),
    }
}

async fn connect(
    arguments: &HashMap<String, String>,
) -> Result<rados::Client, Box<dyn std::error::Error>> {
    let key = fs::read(required(arguments, "key")?)?;
    let config = Config::default()
        .with_monitors(required(arguments, "monitors")?.split(','))?
        .with_entity("client.p11")?
        .with_cluster_fsid(required(arguments, "fsid")?)?
        .with_key(SecretKey::new(key.trim_ascii())?)
        .with_timeouts(
            Duration::from_secs(10),
            Duration::from_secs(20),
            Duration::from_secs(4),
        )?;
    let client = rados::Client::new(config)?;
    client.connect(options()).await?;
    Ok(client)
}

fn options() -> OperationOptions {
    OperationOptions::new().with_deadline(Instant::now() + Duration::from_secs(120))
}

fn arguments() -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut result = HashMap::new();
    let mut values = std::env::args().skip(1);
    while let Some(name) = values.next() {
        let value = values.next().ok_or("missing argument value")?;
        result.insert(
            name.strip_prefix("--").ok_or("invalid argument")?.into(),
            value,
        );
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

fn hex_bytes(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    require(value.len().is_multiple_of(2), "odd hex length")?;
    (0..value.len())
        .step_by(2)
        .map(|offset| Ok(u8::from_str_radix(&value[offset..offset + 2], 16)?))
        .collect()
}

fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(result, "{byte:02x}").expect("String write");
    }
    result
}

fn require(condition: bool, message: &'static str) -> Result<(), Box<dyn std::error::Error>> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}
