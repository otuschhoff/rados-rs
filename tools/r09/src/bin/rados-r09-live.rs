#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use rados::{
    Config, ObjectCursor, OmapEntry, OperationOptions, Pool, ReadOp, SecretKey, SubOperationFlags,
    WriteOp, compare_object_cursors,
};
use serde::Serialize;

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct Report {
    native_metadata: bool,
    binary_metadata: bool,
    omap_pagination: bool,
    compound_read: bool,
    compound_atomicity: bool,
    cross_client_contention: bool,
    enumeration: bool,
    namespaces: bool,
    cursor_continuation: bool,
    cursor_partitioning: bool,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("rados-r09-live: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = arguments()?;
    let first = connect(&arguments).await?;
    let second = connect(&arguments).await?;
    let pool_name = arguments.get("pool").map_or("p08-data", String::as_str);
    let first_pool = first.open_pool(pool_name, options()).await?;
    let second_pool = second.open_pool(pool_name, options()).await?;
    run_suite(
        &first_pool,
        &second_pool,
        arguments.get("coordination-dir").map(String::as_str),
    )
    .await?;
    first.flush(options()).await?;
    second.flush(options()).await?;
    first.close();
    second.close();
    serde_json::to_writer(
        std::io::stdout(),
        &Report {
            native_metadata: true,
            binary_metadata: true,
            omap_pagination: true,
            compound_read: true,
            compound_atomicity: true,
            cross_client_contention: true,
            enumeration: true,
            namespaces: true,
            cursor_continuation: true,
            cursor_partitioning: true,
        },
    )?;
    println!();
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn run_suite(
    first_pool: &Pool,
    second_pool: &Pool,
    coordination: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let native = first_pool.object("native-metadata")?;
    require(
        native.get_xattr("binary", options()).await? == [0, 1, 0xff, 2],
        "native xattr",
    )?;
    let attributes = native.list_xattrs(options()).await?;
    require(
        attributes.len() == 2 && attributes[0].name == b"alpha" && attributes[1].name == b"binary",
        "native xattr list",
    )?;
    let first_page = native.list_omap([], 2, options()).await?;
    require(
        first_page.values.len() == 2 && first_page.more,
        "first OMAP page",
    )?;
    let second_page = native
        .list_omap(&first_page.values[1].key, 2, options())
        .await?;
    require(
        second_page.values.len() == 1 && !second_page.more,
        "second OMAP page",
    )?;
    require(
        first_page.values[0].key == [0, b'a']
            && first_page.values[1].key == b"b"
            && second_page.values[0].key == [0xff],
        "binary OMAP ordering",
    )?;

    let read_result = native
        .execute_read(ReadOp::new().read(0, 16)?.get_xattr("binary")?, options())
        .await?;
    require(
        read_result.results.len() == 2
            && read_result.results[0].data == b"native"
            && read_result.results[1].data == [0, 1, 0xff, 2],
        "compound read",
    )?;
    let optional = ReadOp::new()
        .get_xattr("missing")?
        .set_flags(0, SubOperationFlags::FAIL_OK)?
        .read(0, 16)?;
    let optional_result = native.execute_read(optional, options()).await?;
    require(
        optional_result.results[0].error.is_some() && optional_result.results[1].data == b"native",
        "FAIL_OK",
    )?;
    native
        .execute_write(
            WriteOp::new()
                .assert_version(read_result.version)?
                .write_full(b"native")?,
            options(),
        )
        .await?;

    let lifecycle = first_pool.object("omap-lifecycle")?;
    lifecycle
        .execute_write(
            WriteOp::new()
                .write_full(b"stable")?
                .set_omap_header([0, 0xff, 1])?
                .set_omap([
                    omap(b"keep", b"value"),
                    omap(b"range-a", b"a"),
                    omap(b"range-b", b"b"),
                    omap(b"remove", &[2, 0, 3]),
                ])?,
            options(),
        )
        .await?;
    lifecycle
        .execute_write(
            WriteOp::new()
                .compare_omap(b"keep", b"value")?
                .write_full(b"stable")?,
            options(),
        )
        .await?;
    require(
        lifecycle.get_omap_header(options()).await? == [0, 0xff, 1],
        "OMAP header",
    )?;
    let selected = lifecycle
        .get_omap(
            [b"missing".to_vec(), b"keep".to_vec(), b"range-b".to_vec()],
            options(),
        )
        .await?;
    require(
        selected.len() == 2 && selected[0].key == b"keep" && selected[1].key == b"range-b",
        "keyed OMAP",
    )?;
    lifecycle
        .execute_write(
            WriteOp::new()
                .remove_omap([b"remove".to_vec()])?
                .remove_omap_range(b"range-a", b"range-z")?,
            options(),
        )
        .await?;
    let page = lifecycle.list_omap([], 4, options()).await?;
    require(
        page.values.len() == 1 && page.values[0].key == b"keep",
        "OMAP removal",
    )?;
    require(
        lifecycle
            .execute_write(
                WriteOp::new()
                    .write_full(b"changed")?
                    .compare_omap(b"keep", b"wrong")?,
                options(),
            )
            .await
            .is_err(),
        "failed OMAP compare",
    )?;
    require(read_all(&lifecycle).await? == b"stable", "OMAP atomicity")?;
    lifecycle
        .execute_write(WriteOp::new().clear_omap()?, options())
        .await?;
    require(
        lifecycle
            .list_omap([], 4, options())
            .await?
            .values
            .is_empty(),
        "OMAP clear",
    )?;

    let atomic = first_pool.object("compound-atomic")?;
    atomic.write_full(b"before", options()).await?;
    require(
        atomic
            .execute_write(
                WriteOp::new()
                    .write_full(b"changed")?
                    .compare_extent(0, b"wrong")?,
                options(),
            )
            .await
            .is_err(),
        "compound failure",
    )?;
    require(read_all(&atomic).await? == b"before", "compound rollback")?;

    let contended = first_pool.object("contended")?;
    contended.write_full(b"seed", options()).await?;
    let first_op = WriteOp::new()
        .compare_extent(0, b"seed")?
        .write_full(b"winner-0")?;
    let second_op = WriteOp::new()
        .compare_extent(0, b"seed")?
        .write_full(b"winner-1")?;
    let first_object = first_pool.object("contended")?;
    let second_object = second_pool.object("contended")?;
    let (first_result, second_result) = tokio::join!(
        first_object.execute_write(first_op, options()),
        second_object.execute_write(second_op, options())
    );
    require(
        usize::from(first_result.is_ok()) + usize::from(second_result.is_ok()) == 1,
        "contention winner",
    )?;

    first_pool
        .object("go-metadata")?
        .execute_write(
            WriteOp::new()
                .write_full(b"rust")?
                .set_xattr("binary", [0xfe, 0, 0xfd])?
                .set_omap([omap(&[0, b'g'], &[1, 0, 2]), omap(b"z", b"last")])?,
            options(),
        )
        .await?;

    for name in ["enum-a", "enum-b", "enum-c", "enum-d", "enum-e"] {
        first_pool.object(name)?.write_full([], options()).await?;
    }
    let namespace_pool = first_pool.clone().with_namespace("space")?;
    for name in ["ns-a", "ns-b"] {
        namespace_pool
            .object(name)?
            .write_full([], options())
            .await?;
    }
    let (default_names, pages) = list_all(first_pool, 2, coordination).await?;
    require(
        pages >= 2
            && contains(
                &default_names,
                &[b"enum-a", b"enum-b", b"enum-c", b"enum-d", b"enum-e"],
            ),
        "default enumeration",
    )?;
    require(
        !default_names.iter().any(|name| name == b"ns-a"),
        "default namespace isolation",
    )?;
    let (namespace_names, namespace_pages) = list_all(&namespace_pool, 1, None).await?;
    require(
        namespace_pages >= 2 && set(&namespace_names) == set(&[b"ns-a".to_vec(), b"ns-b".to_vec()]),
        "named namespace enumeration",
    )?;

    let begin = first_pool.begin_object_cursor()?;
    let end = first_pool.end_object_cursor()?;
    let boundaries = first_pool.split_cursor(&begin, &end, 8)?;
    require(
        boundaries.len() == 9 && boundaries[8].is_end(),
        "cursor split",
    )?;
    require(
        boundaries
            .windows(2)
            .all(|pair| compare_object_cursors(&pair[0], &pair[1]) == Ok(std::cmp::Ordering::Less)),
        "cursor ordering",
    )?;
    let mut partition_names = Vec::new();
    let mut seen = HashSet::new();
    for pair in boundaries.windows(2) {
        for name in list_range(first_pool, &pair[0], &pair[1], 2).await? {
            require(seen.insert(name.clone()), "partition duplicate")?;
            partition_names.push(name);
        }
    }
    require(
        set(&partition_names) == set(&default_names),
        "partition union",
    )?;
    Ok(())
}

async fn connect(
    arguments: &HashMap<String, String>,
) -> Result<rados::Client, Box<dyn std::error::Error>> {
    let key = fs::read(required(arguments, "key")?)?;
    let config = Config::default()
        .with_monitors(required(arguments, "monitors")?.split(','))?
        .with_entity("client.p08")?
        .with_cluster_fsid(required(arguments, "fsid")?)?
        .with_key(SecretKey::new(key.trim_ascii())?)
        .with_timeouts(
            Duration::from_secs(10),
            Duration::from_secs(15),
            Duration::from_secs(120),
        )?;
    let client = rados::Client::new(config)?;
    client.connect(options()).await?;
    Ok(client)
}

async fn list_all(
    pool: &Pool,
    limit: u64,
    coordination: Option<&str>,
) -> Result<(Vec<Vec<u8>>, usize), Box<dyn std::error::Error>> {
    let mut cursor = pool.begin_object_cursor()?;
    let mut names = Vec::new();
    let mut pages = 0;
    while !cursor.is_end() {
        let page = pool.list_objects(&cursor, limit, options()).await?;
        pages += 1;
        names.extend(page.values.into_iter().map(|entry| entry.name));
        cursor = page.next;
        if pages == 1
            && let Some(directory) = coordination
        {
            let directory = Path::new(directory);
            fs::write(directory.join("enumeration-ready"), b"ready\n")?;
            wait_for(directory.join("map-changed")).await?;
        }
        require(pages <= 1000, "enumeration termination")?;
    }
    Ok((names, pages))
}

async fn list_range(
    pool: &Pool,
    begin: &ObjectCursor,
    end: &ObjectCursor,
    limit: u64,
) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut cursor = begin.clone();
    let mut names = Vec::new();
    for _ in 0..=1000 {
        let page = pool
            .list_objects_range(&cursor, end, limit, options())
            .await?;
        names.extend(page.values.into_iter().map(|entry| entry.name));
        if !page.more {
            return Ok(names);
        }
        cursor = page.next;
    }
    Err("range enumeration did not terminate".into())
}

async fn read_all(object: &rados::ObjectRef) -> Result<Vec<u8>, rados::Error> {
    Ok(object.read(0, 1 << 20, options()).await?.0)
}

fn omap(key: &[u8], value: &[u8]) -> OmapEntry {
    OmapEntry {
        key: key.to_vec(),
        value: value.to_vec(),
    }
}
fn set(values: &[Vec<u8>]) -> HashSet<Vec<u8>> {
    values.iter().cloned().collect()
}
fn contains(values: &[Vec<u8>], wanted: &[&[u8]]) -> bool {
    wanted
        .iter()
        .all(|wanted| values.iter().any(|value| value == wanted))
}
fn options() -> OperationOptions {
    OperationOptions::new().with_deadline(Instant::now() + Duration::from_secs(120))
}

async fn wait_for(path: impl AsRef<Path>) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(90);
    while !path.as_ref().exists() {
        if Instant::now() >= deadline {
            return Err("control wait timed out".into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
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
