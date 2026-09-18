#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[allow(
    dead_code,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]
#[path = "../../../src/crush/mod.rs"]
mod crush;
#[allow(dead_code)]
#[path = "../../../src/protocol/address.rs"]
mod protocol_address;
#[allow(dead_code)]
#[path = "../../../src/protocol/features.rs"]
mod protocol_features;
#[allow(dead_code)]
#[path = "../../../src/wire/mod.rs"]
mod wire;

mod protocol {
    pub(crate) mod address {
        pub(crate) use crate::protocol_address::*;
    }
    pub(crate) mod features {
        pub(crate) use crate::protocol_features::*;
    }
}

#[allow(dead_code, unused_imports)]
mod maps;

pub const SUITE_ID: &str = "r06/placement-v1";
pub const GO_REVISION: &str = "c8bb148a1379b51ef87256c27f366a05f8da4dc4";
pub const GO_TREE: &str = "c5039b6b50a05b942a902f70dc2fcb090463e8c7";
pub const MAX_RECORD_BYTES: u64 = 16_384;
pub const MAX_RECORDS: usize = 11;
pub const MAX_INPUT_BYTES: u64 = 1 << 20;
pub const MAX_OUTPUT_BYTES: u64 = 4_096;
pub const MAX_REPORT_BYTES: u64 = 262_144;
const IN_WEIGHT: u32 = 0x1_0000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub struct Bounds {
    max_record_bytes: u64,
    max_records: usize,
    max_input_bytes: u64,
    max_output_bytes: u64,
    max_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaseInput {
    case_id: String,
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeRequest {
    schema_version: u32,
    suite_id: String,
    implementation_ids: Vec<String>,
    cases: Vec<CaseInput>,
    bounds: Bounds,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeResult {
    schema_version: u32,
    suite_id: String,
    implementation_id: String,
    case_id: String,
    input_sha256: String,
    output_sha256: String,
    semantic: Value,
    status: String,
}

#[derive(Clone, Copy)]
enum CaseKind {
    Direct {
        rule: u32,
        weights: &'static [u32],
    },
    Object {
        pg_count: u32,
        weights: &'static [u32],
        upmap: bool,
    },
    ErasureObject {
        weights: &'static [u32],
        primary_affinity: bool,
    },
}

struct Case {
    id: &'static str,
    path: &'static str,
    kind: CaseKind,
}

const P05_IN: &[u32] = &[IN_WEIGHT; 4];
const P05_OUT: &[u32] = &[IN_WEIGHT, 0, IN_WEIGHT, IN_WEIGHT];
const P10_IN: &[u32] = &[IN_WEIGHT; 3];
const P10_OUT: &[u32] = &[IN_WEIGHT, 0, IN_WEIGHT];
const CASES: &[Case] = &[
    Case {
        id: "p05-direct-baseline",
        path: "testdata/r06/p05/mappings.txt",
        kind: CaseKind::Direct {
            rule: 0,
            weights: P05_IN,
        },
    },
    Case {
        id: "p05-direct-osd1-out",
        path: "testdata/r06/p05/mappings-osd1-out.txt",
        kind: CaseKind::Direct {
            rule: 0,
            weights: P05_OUT,
        },
    },
    Case {
        id: "p05-object-baseline",
        path: "testdata/r06/p05/object-mappings.txt",
        kind: CaseKind::Object {
            pg_count: 256,
            weights: P05_IN,
            upmap: false,
        },
    },
    Case {
        id: "p05-object-pg32",
        path: "testdata/r06/p05/object-mappings-pg32.txt",
        kind: CaseKind::Object {
            pg_count: 32,
            weights: P05_IN,
            upmap: false,
        },
    },
    Case {
        id: "p05-object-osd1-out",
        path: "testdata/r06/p05/object-mappings-osd1-out.txt",
        kind: CaseKind::Object {
            pg_count: 32,
            weights: P05_OUT,
            upmap: false,
        },
    },
    Case {
        id: "p05-object-upmap",
        path: "testdata/r06/p05/object-mappings-upmap.txt",
        kind: CaseKind::Object {
            pg_count: 256,
            weights: P05_IN,
            upmap: true,
        },
    },
    Case {
        id: "p10-erasure-baseline",
        path: "testdata/r06/p10/mappings.txt",
        kind: CaseKind::Direct {
            rule: 2,
            weights: P10_IN,
        },
    },
    Case {
        id: "p10-erasure-osd1-out",
        path: "testdata/r06/p10/mappings-osd1-out.txt",
        kind: CaseKind::Direct {
            rule: 2,
            weights: P10_OUT,
        },
    },
    Case {
        id: "p10-erasure-object-baseline",
        path: "testdata/r06/p10/object-placements.jsonl",
        kind: CaseKind::ErasureObject {
            weights: P10_IN,
            primary_affinity: false,
        },
    },
    Case {
        id: "p10-erasure-object-osd1-out",
        path: "testdata/r06/p10/object-placements-osd1-out.jsonl",
        kind: CaseKind::ErasureObject {
            weights: P10_OUT,
            primary_affinity: false,
        },
    },
    Case {
        id: "p10-erasure-object-primary-affinity",
        path: "testdata/r06/p10/object-placements-primary-affinity.jsonl",
        kind: CaseKind::ErasureObject {
            weights: P10_IN,
            primary_affinity: true,
        },
    },
];

fn bounds() -> Bounds {
    Bounds {
        max_record_bytes: MAX_RECORD_BYTES,
        max_records: MAX_RECORDS,
        max_input_bytes: MAX_INPUT_BYTES,
        max_output_bytes: MAX_OUTPUT_BYTES,
        max_seconds: 30,
    }
}

fn digest(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .fold(String::new(), |mut output, byte| {
            write!(output, "{byte:02x}").expect("write to String");
            output
        })
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let data = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    if data.len() as u64 > MAX_INPUT_BYTES {
        return Err(format!("input exceeds bound: {}", path.display()));
    }
    Ok(data)
}

fn parse_osds(value: &str) -> Result<Vec<i32>, String> {
    let body = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or("invalid OSD array")?;
    body.split(',')
        .map(|item| {
            item.parse()
                .map_err(|error| format!("invalid OSD {item}: {error}"))
        })
        .collect()
}

fn crush_map(root: &Path, corpus: &str) -> Result<crush::Map, String> {
    let data = read_bounded(&root.join(format!("testdata/r06/{corpus}/crushmap.bin")))?;
    crush::Map::decode(
        &data,
        crush::DecodeLimits {
            max_bytes: 1 << 20,
            max_buckets: 1_024,
            max_rules: 256,
            max_items: 65_536,
            max_names: 65_536,
        },
    )
    .map_err(|error| format!("decode CRUSH map: {error:?}"))
}

fn upmap(root: &Path) -> Result<HashMap<maps::PG, Vec<maps::OSDRemap>>, String> {
    let text = String::from_utf8(read_bounded(
        &root.join("testdata/r06/p05/upmap-commands.txt"),
    )?)
    .map_err(|error| error.to_string())?;
    let mut result = HashMap::new();
    for line in text.lines() {
        let row = line
            .strip_prefix("ceph osd pg-upmap-items 1.")
            .ok_or("invalid upmap row")?;
        let fields = row.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 3 {
            return Err("invalid upmap field count".to_owned());
        }
        let seed = u32::from_str_radix(fields[0], 16).map_err(|error| error.to_string())?;
        let from = fields[1]
            .parse()
            .map_err(|error| format!("invalid upmap source: {error}"))?;
        let to = fields[2]
            .parse()
            .map_err(|error| format!("invalid upmap target: {error}"))?;
        result
            .entry(maps::PG {
                pool: 1,
                seed,
                preferred: -1,
            })
            .or_insert_with(Vec::new)
            .push(maps::OSDRemap { from, to });
    }
    if result.len() != 20 {
        return Err("upmap command count is not 20".to_owned());
    }
    Ok(result)
}

fn canonical_line(value: &Value, output: &mut Vec<u8>) -> Result<(), String> {
    serde_json::to_writer(&mut *output, value).map_err(|error| error.to_string())?;
    output.push(b'\n');
    Ok(())
}

fn direct_semantic(root: &Path, case: &Case, rule: u32, weights: &[u32]) -> Result<Value, String> {
    let corpus = if case.id.starts_with("p05") {
        "p05"
    } else {
        "p10"
    };
    let map = crush_map(root, corpus)?;
    let text = String::from_utf8(read_bounded(&root.join(case.path))?)
        .map_err(|error| error.to_string())?;
    let prefix = format!("CRUSH rule {rule} x ");
    let mut actual = Vec::new();
    let mut native = Vec::new();
    let mut rows = 0_u32;
    for line in text.lines() {
        let row = line.strip_prefix(&prefix).ok_or("invalid direct row")?;
        let (seed, encoded) = row.split_once(' ').ok_or("incomplete direct row")?;
        let seed = seed.parse::<u32>().map_err(|error| error.to_string())?;
        let expected = parse_osds(encoded)?;
        let osds = map
            .place(rule, seed, 3, weights)
            .map_err(|_| format!("place seed {seed}"))?;
        if osds != expected {
            return Err(format!("native CRUSH mismatch for seed {seed}"));
        }
        canonical_line(
            &json!({"osds": osds, "rule": rule, "seed": seed}),
            &mut actual,
        )?;
        canonical_line(
            &json!({"osds": expected, "rule": rule, "seed": seed}),
            &mut native,
        )?;
        rows += 1;
    }
    if rows != 256 {
        return Err(format!("{} has {rows} rows", case.id));
    }
    Ok(
        json!({"kind":"direct","row_count":rows,"normalized_sha256":digest(&actual),"native_normalized_sha256":digest(&native)}),
    )
}

fn object_semantic(
    root: &Path,
    case: &Case,
    pg_count: u32,
    weights: &[u32],
    use_upmap: bool,
) -> Result<Value, String> {
    let crush_data = read_bounded(&root.join("testdata/r06/p05/crushmap.bin"))?;
    let remaps = if use_upmap {
        upmap(root)?
    } else {
        HashMap::new()
    };
    let osd_map = maps::r06_osd_map(crush_data, pg_count, weights.to_vec(), remaps);
    let text = String::from_utf8(read_bounded(&root.join(case.path))?)
        .map_err(|error| error.to_string())?;
    let mut actual = Vec::new();
    let mut native = Vec::new();
    let mut rows = 0_u32;
    for line in text.lines() {
        let row = line.strip_prefix("object '").ok_or("invalid object row")?;
        let (object, row) = row.split_once("' -> 1.").ok_or("invalid object identity")?;
        let (pg, encoded) = row.split_once(" -> ").ok_or("incomplete object row")?;
        let pg = u32::from_str_radix(pg, 16).map_err(|error| error.to_string())?;
        let osds = parse_osds(encoded)?;
        let placement = osd_map
            .place_object(1, object.as_bytes(), b"", b"")
            .map_err(|error| error.to_string())?;
        let primary = osds.first().copied().ok_or("empty native object set")?;
        if placement.pg.seed != pg
            || placement.up != osds
            || placement.acting != osds
            || placement.up_primary != primary
            || placement.acting_primary != primary
            || (!use_upmap && placement.raw != osds)
        {
            return Err(format!("native object mismatch for {object}"));
        }
        canonical_line(
            &json!({"acting":placement.acting,"acting_primary":placement.acting_primary,"object":object,"pg":placement.pg.seed,"placement_seed":placement.placement_seed,"primary_shard":placement.primary_shard,"raw":placement.raw,"raw_hash":placement.raw_hash,"raw_pg":placement.raw_pg.seed,"sharded":placement.sharded,"up":placement.up,"up_primary":placement.up_primary}),
            &mut actual,
        )?;
        canonical_line(&json!({"object":object,"osds":osds,"pg":pg}), &mut native)?;
        rows += 1;
    }
    if rows != 128 {
        return Err(format!("{} has {rows} rows", case.id));
    }
    Ok(
        json!({"kind":"object","row_count":rows,"normalized_sha256":digest(&actual),"native_normalized_sha256":digest(&native)}),
    )
}

fn pg_seed(value: &str) -> Result<u32, String> {
    let (_, seed) = value.split_once('.').ok_or("invalid PG")?;
    u32::from_str_radix(seed, 16).map_err(|error| error.to_string())
}

fn json_osds(value: &Value, field: &str) -> Result<Vec<i32>, String> {
    value[field]
        .as_array()
        .ok_or_else(|| format!("{field} is not an array"))?
        .iter()
        .map(|osd| {
            i32::try_from(osd.as_i64().ok_or("OSD is not an integer")?)
                .map_err(|error| error.to_string())
        })
        .collect()
}

fn erasure_object_semantic(
    root: &Path,
    case: &Case,
    weights: &[u32],
    use_primary_affinity: bool,
) -> Result<Value, String> {
    let crush_data = read_bounded(&root.join("testdata/r06/p10/crushmap.bin"))?;
    let text = String::from_utf8(read_bounded(&root.join(case.path))?)
        .map_err(|error| error.to_string())?;
    let mut actual = Vec::new();
    let mut native = Vec::new();
    let mut rows = 0_u32;
    for line in text.lines() {
        let expected: Value = serde_json::from_str(line).map_err(|error| error.to_string())?;
        let object = expected["object"].as_str().ok_or("missing object")?;
        let raw_hash = pg_seed(expected["raw_pgid"].as_str().ok_or("missing raw PG")?)?;
        let pg_seed = pg_seed(expected["pgid"].as_str().ok_or("missing PG")?)?;
        let up = json_osds(&expected, "up")?;
        let acting = json_osds(&expected, "acting")?;
        let up_primary = i32::try_from(
            expected["up_primary"]
                .as_i64()
                .ok_or("missing up primary")?,
        )
        .map_err(|error| error.to_string())?;
        let acting_primary = i32::try_from(
            expected["acting_primary"]
                .as_i64()
                .ok_or("missing acting primary")?,
        )
        .map_err(|error| error.to_string())?;
        let pg = maps::PG {
            pool: 3,
            seed: pg_seed,
            preferred: -1,
        };
        let pg_temp = if acting == up {
            HashMap::new()
        } else {
            HashMap::from([(pg, acting.clone())])
        };
        let primary_temp = if acting_primary == up_primary {
            HashMap::new()
        } else {
            HashMap::from([(pg, acting_primary)])
        };
        let affinity = if use_primary_affinity {
            vec![0, IN_WEIGHT, IN_WEIGHT]
        } else {
            Vec::new()
        };
        let osd_map = maps::r06_erasure_map(
            crush_data.clone(),
            weights.to_vec(),
            affinity,
            pg_temp,
            primary_temp,
        );
        let placement = osd_map
            .place_object(3, object.as_bytes(), b"", b"")
            .map_err(|error| error.to_string())?;
        let primary_shard = i8::try_from(
            acting
                .iter()
                .position(|&osd| osd == acting_primary)
                .ok_or("acting primary is not in set")?,
        )
        .map_err(|error| error.to_string())?;
        if placement.raw_hash != raw_hash
            || placement.raw_pg.seed != raw_hash
            || placement.pg.seed != pg_seed
            || placement.raw != up
            || placement.up != up
            || placement.up_primary != up_primary
            || placement.acting != acting
            || placement.acting_primary != acting_primary
            || placement.primary_shard != primary_shard
            || !placement.sharded
        {
            return Err(format!("native erasure object mismatch for {object}"));
        }
        canonical_line(
            &json!({"acting":placement.acting,"acting_primary":placement.acting_primary,"object":object,"pg":placement.pg.seed,"placement_seed":placement.placement_seed,"primary_shard":placement.primary_shard,"raw":placement.raw,"raw_hash":placement.raw_hash,"raw_pg":placement.raw_pg.seed,"sharded":placement.sharded,"up":placement.up,"up_primary":placement.up_primary}),
            &mut actual,
        )?;
        canonical_line(
            &json!({"acting":acting,"acting_primary":acting_primary,"object":object,"pg":pg_seed,"primary_shard":primary_shard,"raw_hash":raw_hash,"up":up,"up_primary":up_primary}),
            &mut native,
        )?;
        rows += 1;
    }
    if rows != 128 {
        return Err(format!("{} has {rows} rows", case.id));
    }
    Ok(
        json!({"kind":"object","row_count":rows,"normalized_sha256":digest(&actual),"native_normalized_sha256":digest(&native)}),
    )
}

fn semantic(root: &Path, case: &Case) -> Result<Value, String> {
    match case.kind {
        CaseKind::Direct { rule, weights } => direct_semantic(root, case, rule, weights),
        CaseKind::Object {
            pg_count,
            weights,
            upmap,
        } => object_semantic(root, case, pg_count, weights, upmap),
        CaseKind::ErasureObject {
            weights,
            primary_affinity,
        } => erasure_object_semantic(root, case, weights, primary_affinity),
    }
}

fn expected_request(root: &Path) -> Result<ProbeRequest, String> {
    let cases = CASES
        .iter()
        .map(|case| {
            read_bounded(&root.join(case.path)).map(|data| CaseInput {
                case_id: case.id.to_owned(),
                path: case.path.to_owned(),
                sha256: digest(&data),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ProbeRequest {
        schema_version: 1,
        suite_id: SUITE_ID.to_owned(),
        implementation_ids: vec!["rust".into(), "go".into()],
        cases,
        bounds: bounds(),
    })
}

/// Builds the single fixed request accepted by both R06 probes.
///
/// # Errors
/// Returns an error when a required corpus file is missing, oversized, or unreadable.
pub fn default_request_json(root: &Path) -> Result<String, String> {
    let mut value =
        serde_json::to_string(&expected_request(root)?).map_err(|error| error.to_string())?;
    value.push('\n');
    Ok(value)
}

fn rust_results(root: &Path) -> Result<Vec<ProbeResult>, String> {
    CASES
        .iter()
        .map(|case| {
            let input = read_bounded(&root.join(case.path))?;
            let semantic = semantic(root, case)?;
            let canonical = serde_json::to_vec(&semantic).map_err(|error| error.to_string())?;
            if canonical.len() as u64 > MAX_OUTPUT_BYTES {
                return Err("semantic exceeds output bound".to_owned());
            }
            Ok(ProbeResult {
                schema_version: 1,
                suite_id: SUITE_ID.into(),
                implementation_id: "rust".into(),
                case_id: case.id.into(),
                input_sha256: digest(&input),
                output_sha256: digest(&canonical),
                semantic,
                status: "passed".into(),
            })
        })
        .collect()
}

/// Runs the bounded production-backed Rust placement probe.
///
/// # Errors
/// Returns an error for malformed input or any corpus, placement, or output failure.
pub fn run_rust_probe(
    root: &Path,
    mut reader: impl Read,
    mut writer: impl Write,
) -> Result<(), String> {
    let mut data = Vec::new();
    reader
        .by_ref()
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|error| error.to_string())?;
    if data.len() as u64 > MAX_RECORD_BYTES {
        return Err("request exceeds record bound".to_owned());
    }
    let request: ProbeRequest = serde_json::from_slice(&data).map_err(|error| error.to_string())?;
    if request != expected_request(root)? {
        return Err("request does not match fixed R06 suite".to_owned());
    }
    for result in rust_results(root)? {
        let encoded = serde_json::to_vec(&result).map_err(|error| error.to_string())?;
        if encoded.len() as u64 + 1 > MAX_RECORD_BYTES {
            return Err("result exceeds record bound".to_owned());
        }
        writer
            .write_all(&encoded)
            .and_then(|()| writer.write_all(b"\n"))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Runs the Rust probe using the current directory as its fixture root.
///
/// # Errors
/// Returns an error when the directory, request, corpus, or placement is invalid.
pub fn run_from_current_directory() -> Result<(), String> {
    run_rust_probe(
        &std::env::current_dir().map_err(|error| error.to_string())?,
        std::io::stdin().lock(),
        std::io::stdout().lock(),
    )
}

const FIXTURES: &[(&str, Option<&str>)] = &[
    (
        "testdata/r06/p05/crushmap.bin",
        Some("testdata/r06/p05/crushmap.bin.manifest.json"),
    ),
    (
        "testdata/r06/p05/mappings.txt",
        Some("testdata/r06/p05/mappings.txt.manifest.json"),
    ),
    (
        "testdata/r06/p05/mappings-osd1-out.txt",
        Some("testdata/r06/p05/mappings-osd1-out.txt.manifest.json"),
    ),
    (
        "testdata/r06/p05/object-mappings.txt",
        Some("testdata/r06/p05/object-mappings.txt.manifest.json"),
    ),
    (
        "testdata/r06/p05/object-mappings-pg32.txt",
        Some("testdata/r06/p05/object-mappings-pg32.txt.manifest.json"),
    ),
    (
        "testdata/r06/p05/object-mappings-osd1-out.txt",
        Some("testdata/r06/p05/object-mappings-osd1-out.txt.manifest.json"),
    ),
    (
        "testdata/r06/p05/object-mappings-upmap.txt",
        Some("testdata/r06/p05/object-mappings-upmap.txt.manifest.json"),
    ),
    (
        "testdata/r06/p05/upmap-commands.txt",
        Some("testdata/r06/p05/upmap-commands.txt.manifest.json"),
    ),
    (
        "testdata/r06/p10/crushmap.bin",
        Some("testdata/r06/p10/crushmap.bin.manifest.json"),
    ),
    (
        "testdata/r06/p10/mappings.txt",
        Some("testdata/r06/p10/mappings.txt.manifest.json"),
    ),
    (
        "testdata/r06/p10/mappings-osd1-out.txt",
        Some("testdata/r06/p10/mappings-osd1-out.txt.manifest.json"),
    ),
    (
        "testdata/r06/p10/object-placements.jsonl",
        Some("testdata/r06/p10/object-placements.jsonl.manifest.json"),
    ),
    (
        "testdata/r06/p10/object-placements-osd1-out.jsonl",
        Some("testdata/r06/p10/object-placements-osd1-out.jsonl.manifest.json"),
    ),
    (
        "testdata/r06/p10/object-placements-primary-affinity.jsonl",
        Some("testdata/r06/p10/object-placements-primary-affinity.jsonl.manifest.json"),
    ),
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FixtureEvidence {
    path: String,
    sha256: String,
    manifest_path: Option<String>,
    manifest_sha256: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ImplementationEvidence {
    implementation_id: String,
    source_revision: String,
    source_tree: String,
    source_before_sha256: String,
    source_after_sha256: String,
    lockfile_sha256: String,
    compiler: String,
    target: String,
    binary_path: String,
    binary_sha256: String,
    command: Vec<String>,
    exit_code: i32,
    stdout_sha256: String,
    records: Vec<ProbeResult>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactEvidence {
    adapter_path: String,
    adapter_sha256: String,
    schema_path: String,
    schema_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ControllerEvidence {
    path: String,
    sha256: String,
    command: Vec<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BridgeReport {
    schema_version: u32,
    suite_id: String,
    status: String,
    generated_at: String,
    bounds: Bounds,
    fixtures: Vec<FixtureEvidence>,
    rust: ImplementationEvidence,
    go: ImplementationEvidence,
    artifacts: ArtifactEvidence,
    controller: ControllerEvidence,
}

const RUST_SOURCE_FILES: &[&str] = &[
    "Cargo.lock",
    "Cargo.toml",
    "build.rs",
    "rust-toolchain.toml",
];
const RUST_SOURCE_DIRECTORIES: &[&str] = &[
    "src/crush",
    "src/maps",
    "src/protocol",
    "src/wire",
    "tools/r06",
    "integration/r06",
];
const GO_SOURCE_FILES: &[&str] = &["go.mod", "go.sum"];
const GO_SOURCE_DIRECTORIES: &[&str] = &["internal/crush", "internal/encoding", "internal/maps"];

/// Hashes one evidence file.
///
/// # Errors
/// Returns an error when the file cannot be read.
pub fn file_digest(path: &Path) -> Result<String, String> {
    fs::read(path)
        .map(|data| digest(&data))
        .map_err(|error| error.to_string())
}
/// Hashes a deterministic file or directory closure.
///
/// # Errors
/// Returns an error for missing, unreadable, symlinked, or non-UTF-8 paths.
pub fn path_digest(root: &Path, relative: &Path) -> Result<String, String> {
    let mut paths = Vec::new();
    collect_files(root, relative, &mut paths)?;
    digest_paths(root, &mut paths)
}
/// Hashes the fixed Rust source closure used by the R06 evidence.
///
/// # Errors
/// Returns an error when a source path cannot be inspected or read.
pub fn rust_source_digest(root: &Path) -> Result<String, String> {
    source_digest(root, RUST_SOURCE_FILES, RUST_SOURCE_DIRECTORIES)
}
/// Hashes the fixed pinned-Go production source closure.
///
/// # Errors
/// Returns an error when a source path cannot be inspected or read.
pub fn go_source_digest(root: &Path) -> Result<String, String> {
    source_digest(root, GO_SOURCE_FILES, GO_SOURCE_DIRECTORIES)
}
fn source_digest(root: &Path, files: &[&str], directories: &[&str]) -> Result<String, String> {
    let mut paths = files.iter().map(PathBuf::from).collect::<Vec<_>>();
    for directory in directories {
        collect_files(root, Path::new(directory), &mut paths)?;
    }
    digest_paths(root, &mut paths)
}
fn collect_files(root: &Path, relative: &Path, paths: &mut Vec<PathBuf>) -> Result<(), String> {
    let metadata = fs::symlink_metadata(root.join(relative))
        .map_err(|error| format!("inspect {}: {error}", relative.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "evidence path is a symlink: {}",
            relative.display()
        ));
    }
    if metadata.is_file() {
        paths.push(relative.to_owned());
        return Ok(());
    }
    for entry in fs::read_dir(root.join(relative)).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        collect_files(root, &relative.join(entry.file_name()), paths)?;
    }
    Ok(())
}
fn digest_paths(root: &Path, paths: &mut Vec<PathBuf>) -> Result<String, String> {
    paths.sort();
    paths.dedup();
    let mut value = Sha256::new();
    for relative in paths {
        let name = relative.to_str().ok_or("non-UTF-8 evidence path")?;
        let data = fs::read(root.join(&*relative)).map_err(|error| error.to_string())?;
        value.update((name.len() as u64).to_le_bytes());
        value.update(name.as_bytes());
        value.update((data.len() as u64).to_le_bytes());
        value.update(data);
    }
    Ok(digest(&value.finalize()))
}
fn git_value(root: &Path, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(root)
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("git command failed".to_owned());
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| error.to_string())
}
fn verify_rust_revision(root: &Path, revision: &str, tree: &str) -> Result<(), String> {
    let commit_reference = format!("{revision}^{{commit}}");
    let tree_reference = format!("{revision}^{{tree}}");
    if git_value(root, &["rev-parse", &commit_reference])? != revision
        || git_value(root, &["rev-parse", &tree_reference])? != tree
    {
        return Err("Rust revision provenance is invalid".to_owned());
    }
    let status = Command::new("git")
        .args(["merge-base", "--is-ancestor", revision, "HEAD"])
        .current_dir(root)
        .status()
        .map_err(|error| error.to_string())?;
    if !status.success() {
        return Err("Rust revision is not an ancestor of HEAD".to_owned());
    }
    Ok(())
}
fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn valid_timestamp(value: &str) -> bool {
    value.len() == 20
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(10) == Some(&b'T')
        && value.ends_with('Z')
}
fn records_digest(records: &[ProbeResult]) -> Result<String, String> {
    let mut data = Vec::new();
    for record in records {
        serde_json::to_writer(&mut data, record).map_err(|error| error.to_string())?;
        data.push(b'\n');
    }
    Ok(digest(&data))
}
fn normalized_records(records: &[ProbeResult], id: &str) -> Result<Vec<Value>, String> {
    records
        .iter()
        .map(|record| {
            if record.implementation_id != id {
                return Err("implementation mismatch".to_owned());
            }
            let mut value = serde_json::to_value(record).map_err(|error| error.to_string())?;
            value
                .as_object_mut()
                .ok_or("record is not object")?
                .remove("implementation_id");
            Ok(value)
        })
        .collect()
}

fn verify_shape(root: &Path, report: &BridgeReport) -> Result<(), String> {
    if report.schema_version != 1
        || report.suite_id != SUITE_ID
        || report.status != "passed"
        || report.bounds != bounds()
        || !valid_timestamp(&report.generated_at)
        || report.fixtures.len() != FIXTURES.len()
    {
        return Err("report identity, bounds, or fixture set is invalid".to_owned());
    }
    for (evidence, (path, manifest)) in report.fixtures.iter().zip(FIXTURES) {
        if evidence.path != *path
            || evidence.sha256 != file_digest(&root.join(path))?
            || evidence.manifest_path.as_deref() != *manifest
            || evidence.manifest_sha256
                != manifest
                    .map(|value| file_digest(&root.join(value)))
                    .transpose()?
        {
            return Err(format!("fixture evidence is invalid: {path}"));
        }
    }
    for (implementation, id) in [(&report.rust, "rust"), (&report.go, "go")] {
        if implementation.implementation_id != id
            || implementation.exit_code != 0
            || implementation.records.len() != MAX_RECORDS
            || implementation.source_before_sha256 != implementation.source_after_sha256
            || !is_sha256(&implementation.source_before_sha256)
            || !is_sha256(&implementation.lockfile_sha256)
            || !is_sha256(&implementation.binary_sha256)
            || implementation.stdout_sha256 != records_digest(&implementation.records)?
        {
            return Err(format!("{id} implementation evidence is invalid"));
        }
        for (record, case) in implementation.records.iter().zip(CASES) {
            let expected = semantic(root, case)?;
            let canonical =
                serde_json::to_vec(&record.semantic).map_err(|error| error.to_string())?;
            if record.schema_version != 1
                || record.suite_id != SUITE_ID
                || record.implementation_id != id
                || record.case_id != case.id
                || record.input_sha256 != file_digest(&root.join(case.path))?
                || record.output_sha256 != digest(&canonical)
                || record.status != "passed"
                || record.semantic.get("row_count") != expected.get("row_count")
                || record.semantic.get("native_normalized_sha256")
                    != expected.get("native_normalized_sha256")
            {
                return Err("record set, native digest, or ordering is invalid".to_owned());
            }
        }
    }
    if normalized_records(&report.rust.records, "rust")?
        != normalized_records(&report.go.records, "go")?
    {
        return Err("Rust and Go placement evidence diverges".to_owned());
    }
    Ok(())
}

/// Strictly verifies an R06 report, rebuilds both probes, and replays them.
///
/// # Errors
/// Returns an error for malformed, stale, substituted, divergent, or oversized evidence.
pub fn verify_report_file(root: &Path, report_path: &Path) -> Result<(), String> {
    let mut data = Vec::new();
    fs::File::open(report_path)
        .map_err(|error| error.to_string())?
        .take(MAX_REPORT_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|error| error.to_string())?;
    if data.len() as u64 > MAX_REPORT_BYTES || !data.ends_with(b"\n") || data.ends_with(b"\n\n") {
        return Err("report framing is invalid".to_owned());
    }
    let report: BridgeReport =
        serde_json::from_slice(&data).map_err(|error| format!("decode report: {error}"))?;
    verify_shape(root, &report)?;
    let verifier = std::env::current_exe().map_err(|error| error.to_string())?;
    let rust_probe = verifier.with_file_name("rados-r06-probe");
    let go_probe = verifier.with_file_name("rados-r06-go-probe");
    let go_root =
        if report.controller.command.len() == 5 && report.controller.command[1] == "--go-root" {
            Path::new(&report.controller.command[2])
        } else {
            return Err("controller command is malformed".to_owned());
        };
    if git_value(go_root, &["rev-parse", "HEAD"])? != GO_REVISION
        || git_value(go_root, &["rev-parse", "HEAD^{tree}"])? != GO_TREE
        || !git_value(
            go_root,
            &["status", "--porcelain=v1", "--untracked-files=all"],
        )?
        .is_empty()
    {
        return Err("Go oracle is not clean and pinned".to_owned());
    }
    verify_rust_revision(root, &report.rust.source_revision, &report.rust.source_tree)?;
    if report.rust.source_before_sha256 != rust_source_digest(root)?
        || report.rust.lockfile_sha256 != file_digest(&root.join("Cargo.lock"))?
        || !report.rust.compiler.starts_with("rustc 1.98.0 ")
        || Path::new(&report.rust.binary_path) != rust_probe
        || report.rust.binary_sha256 != file_digest(&rust_probe)?
        || report.rust.command != [rust_probe.to_string_lossy().as_ref()]
    {
        return Err("Rust source, toolchain, command, or binary evidence is invalid".to_owned());
    }
    if report.go.source_revision != GO_REVISION
        || report.go.source_tree != GO_TREE
        || report.go.source_before_sha256 != go_source_digest(go_root)?
        || report.go.lockfile_sha256 != file_digest(&go_root.join("go.sum"))?
        || report.go.compiler != format!("go version go1.26.8 {}", report.go.target)
        || Path::new(&report.go.binary_path) != go_probe
        || report.go.binary_sha256 != file_digest(&go_probe)?
        || report.go.command
            != [
                go_probe.to_string_lossy().as_ref(),
                "--fixture-root",
                root.to_string_lossy().as_ref(),
            ]
    {
        return Err("Go source, toolchain, command, or binary evidence is invalid".to_owned());
    }
    let canonical_report = fs::canonicalize(report_path).map_err(|error| error.to_string())?;
    let recorded_report =
        fs::canonicalize(&report.controller.command[4]).map_err(|error| error.to_string())?;
    if report.artifacts.adapter_path != "tools/r06/go-probe"
        || report.artifacts.adapter_sha256 != path_digest(root, Path::new("tools/r06/go-probe"))?
        || report.artifacts.schema_path != "integration/r06/report.schema.json"
        || report.artifacts.schema_sha256
            != file_digest(&root.join("integration/r06/report.schema.json"))?
        || report.controller.path != "integration/r06/reproduce.sh"
        || report.controller.sha256 != file_digest(&root.join("integration/r06/reproduce.sh"))?
        || report.controller.command[0] != "integration/r06/reproduce.sh"
        || report.controller.command[3] != "--report"
        || recorded_report != canonical_report
    {
        return Err("adapter, schema, or controller evidence is invalid".to_owned());
    }
    verify_rebuilt_probes(root, go_root, &report)?;
    replay(root, &rust_probe, &[], &report.rust.records)?;
    let root_argument = root.to_string_lossy();
    replay(
        root,
        &go_probe,
        &["--fixture-root", root_argument.as_ref()],
        &report.go.records,
    )
}
fn verify_rebuilt_probes(root: &Path, go_root: &Path, report: &BridgeReport) -> Result<(), String> {
    let rust_target = root.join("target/r06/source-build");
    let configure_cargo = |command: &mut Command| {
        command
            .env_remove("RUSTC")
            .env_remove("RUSTC_WRAPPER")
            .env_remove("RUSTFLAGS")
            .env_remove("RUSTDOCFLAGS")
            .env("RUSTUP_TOOLCHAIN", "1.98.0");
    };
    let mut clean = Command::new("cargo");
    clean.args([
        "clean",
        "--manifest-path",
        root.join("Cargo.toml").to_string_lossy().as_ref(),
        "-p",
        "rados-r06-tools",
        "--target-dir",
        rust_target.to_string_lossy().as_ref(),
    ]);
    configure_cargo(&mut clean);
    run_bounded_command(&mut clean, Duration::from_secs(120), "Rust probe clean")?;

    let mut build = Command::new("cargo");
    build.args([
        "build",
        "--manifest-path",
        root.join("Cargo.toml").to_string_lossy().as_ref(),
        "-p",
        "rados-r06-tools",
        "--bins",
        "--locked",
        "--target-dir",
        rust_target.to_string_lossy().as_ref(),
    ]);
    configure_cargo(&mut build);
    run_bounded_command(&mut build, Duration::from_secs(300), "Rust probe build")?;
    replay(
        root,
        &rust_target.join("debug/rados-r06-probe"),
        &[],
        &report.rust.records,
    )?;

    verify_rebuilt_go_probe(root, go_root, report)
}

fn verify_rebuilt_go_probe(
    root: &Path,
    go_root: &Path,
    report: &BridgeReport,
) -> Result<(), String> {
    let clone = root
        .join("target/r06")
        .join(format!("verify-go-{}", std::process::id()));
    let rebuilt = root.join("target/r06/rados-r06-go-probe.rebuilt");
    if clone.exists() || rebuilt.exists() {
        return Err("Go rebuild path already exists".to_owned());
    }
    let result: Result<(), String> = (|| {
        let mut clone_command = Command::new("git");
        clone_command.args([
            "clone",
            "--quiet",
            "--no-hardlinks",
            go_root.to_string_lossy().as_ref(),
            clone.to_string_lossy().as_ref(),
        ]);
        run_bounded_command(
            &mut clone_command,
            Duration::from_secs(120),
            "Go oracle clone",
        )?;
        let mut apply_patch = Command::new("git");
        apply_patch.args([
            "-C",
            clone.to_string_lossy().as_ref(),
            "apply",
            root.join("tools/r06/go-probe/placement.patch")
                .to_string_lossy()
                .as_ref(),
        ]);
        run_bounded_command(
            &mut apply_patch,
            Duration::from_secs(30),
            "Go qualification patch",
        )?;
        let adapter = clone.join("tools/rados-rs-r06-probe");
        fs::create_dir_all(&adapter).map_err(|error| error.to_string())?;
        for name in ["main.go", "main_test.go"] {
            fs::copy(
                root.join("tools/r06/go-probe").join(name),
                adapter.join(name),
            )
            .map_err(|error| error.to_string())?;
        }
        fs::copy(
            root.join("tools/r06/go-probe/maps_adapter.go.in"),
            clone.join("internal/maps/r06_adapter.go"),
        )
        .map_err(|error| error.to_string())?;
        let mut go_build = Command::new("go");
        go_build
            .args([
                "-C",
                clone.to_string_lossy().as_ref(),
                "build",
                "-trimpath",
                "-o",
                rebuilt.to_string_lossy().as_ref(),
                "./tools/rados-rs-r06-probe",
            ])
            .env("GOENV", "off")
            .env("GOWORK", "off")
            .env("GOFLAGS", "")
            .env("GOTOOLCHAIN", "go1.26.8");
        run_bounded_command(&mut go_build, Duration::from_secs(300), "Go probe build")?;
        let root_argument = root.to_string_lossy();
        replay(
            root,
            &rebuilt,
            &["--fixture-root", root_argument.as_ref()],
            &report.go.records,
        )?;
        Ok(())
    })();
    let clone_cleanup = fs::remove_dir_all(&clone);
    let binary_cleanup = fs::remove_file(&rebuilt);
    result?;
    clone_cleanup.map_err(|error| error.to_string())?;
    binary_cleanup.map_err(|error| error.to_string())?;
    Ok(())
}
fn run_bounded_command(
    command: &mut Command,
    timeout: Duration,
    description: &str,
) -> Result<(), String> {
    let mut child = command
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("{description}: {error}"))?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            return if status.success() {
                Ok(())
            } else {
                Err(format!("{description} failed"))
            };
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{description} timed out"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn replay(
    root: &Path,
    probe: &Path,
    arguments: &[&str],
    records: &[ProbeResult],
) -> Result<(), String> {
    let mut child = Command::new(probe)
        .args(arguments)
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| error.to_string())?;
    child
        .stdin
        .take()
        .ok_or("probe stdin unavailable")?
        .write_all(default_request_json(root)?.as_bytes())
        .map_err(|error| error.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            let output = child
                .wait_with_output()
                .map_err(|error| error.to_string())?;
            if !status.success()
                || output.stdout.len() as u64 > MAX_RECORD_BYTES * MAX_RECORDS as u64
                || digest(&output.stdout) != records_digest(records)?
            {
                return Err("probe replay differs".to_owned());
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("probe replay timed out".to_owned());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_fixed_corpora_use_production_placement() {
        let results = rust_results(Path::new("../..")).expect("R06 corpus results");
        assert_eq!(results.len(), MAX_RECORDS);
        assert_eq!(
            results
                .iter()
                .map(|result| result.semantic["row_count"].as_u64().unwrap())
                .sum::<u64>(),
            1_920
        );
        assert_eq!(results[5].semantic["kind"], "object");
        assert_eq!(results[7].semantic["kind"], "direct");
    }

    #[test]
    fn request_is_strict_and_bounded() {
        let root = Path::new("../..");
        let request = default_request_json(root).expect("request");
        assert_eq!(request.matches('\n').count(), 1);
        assert!(run_rust_probe(root, request.as_bytes(), Vec::new()).is_ok());
        assert!(run_rust_probe(root, &br#"{"unknown":true}"#[..], Vec::new()).is_err());
        assert!(
            run_rust_probe(
                root,
                vec![b' '; usize::try_from(MAX_RECORD_BYTES).unwrap() + 1].as_slice(),
                Vec::new()
            )
            .is_err()
        );
    }

    fn shape_report(root: &Path) -> BridgeReport {
        let rust_records = rust_results(root).unwrap();
        let mut go_records = rust_records.clone();
        for record in &mut go_records {
            record.implementation_id = "go".into();
        }
        let implementation = |id: &str, records: Vec<ProbeResult>| ImplementationEvidence {
            implementation_id: id.into(),
            source_revision: "revision".into(),
            source_tree: "tree".into(),
            source_before_sha256: "0".repeat(64),
            source_after_sha256: "0".repeat(64),
            lockfile_sha256: "1".repeat(64),
            compiler: "compiler".into(),
            target: "target".into(),
            binary_path: "/probe".into(),
            binary_sha256: "2".repeat(64),
            command: vec!["/probe".into()],
            exit_code: 0,
            stdout_sha256: records_digest(&records).unwrap(),
            records,
        };
        BridgeReport {
            schema_version: 1,
            suite_id: SUITE_ID.into(),
            status: "passed".into(),
            generated_at: "2026-09-18T00:00:00Z".into(),
            bounds: bounds(),
            fixtures: FIXTURES
                .iter()
                .map(|(path, manifest)| FixtureEvidence {
                    path: (*path).into(),
                    sha256: file_digest(&root.join(path)).unwrap(),
                    manifest_path: manifest.map(str::to_owned),
                    manifest_sha256: manifest.map(|value| file_digest(&root.join(value)).unwrap()),
                })
                .collect(),
            rust: implementation("rust", rust_records),
            go: implementation("go", go_records),
            artifacts: ArtifactEvidence {
                adapter_path: "tools/r06/go-probe".into(),
                adapter_sha256: "3".repeat(64),
                schema_path: "integration/r06/report.schema.json".into(),
                schema_sha256: "4".repeat(64),
            },
            controller: ControllerEvidence {
                path: "integration/r06/reproduce.sh".into(),
                sha256: "5".repeat(64),
                command: vec![],
            },
        }
    }
    #[test]
    fn verifier_rejects_record_tampering() {
        let root = Path::new("../..");
        let mut report = shape_report(root);
        report.go.records[0].semantic["row_count"] = json!(0);
        assert!(verify_shape(root, &report).is_err());
    }
    #[test]
    fn verifier_rejects_native_digest_tampering() {
        let root = Path::new("../..");
        let mut report = shape_report(root);
        report.rust.records[0].semantic["native_normalized_sha256"] = json!("0".repeat(64));
        report.rust.stdout_sha256 = records_digest(&report.rust.records).unwrap();
        assert!(verify_shape(root, &report).is_err());
    }
    #[test]
    fn verifier_rejects_source_toctou_tampering() {
        let root = Path::new("../..");
        let mut report = shape_report(root);
        report.go.source_after_sha256 = "f".repeat(64);
        assert!(verify_shape(root, &report).is_err());
    }
    #[test]
    fn verifier_rejects_fixture_set_tampering() {
        let root = Path::new("../..");
        let mut report = shape_report(root);
        report.fixtures.pop();
        assert!(verify_shape(root, &report).is_err());
    }

    #[test]
    fn rust_revision_provenance_requires_a_real_ancestor() {
        let root = Path::new("../..");
        let revision = git_value(root, &["rev-parse", "HEAD"]).unwrap();
        let tree = git_value(root, &["rev-parse", "HEAD^{tree}"]).unwrap();
        assert!(verify_rust_revision(root, &revision, &tree).is_ok());
        assert!(verify_rust_revision(root, &"0".repeat(40), &tree).is_err());
        assert!(verify_rust_revision(root, &revision, &"0".repeat(40)).is_err());
    }
}
