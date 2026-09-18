use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use crate::crush::{DecodeLimits, Map};
use crate::protocol::address::EntityAddrVec;

use super::*;

const IN_WEIGHT: u32 = 0x1_0000;

fn fixture_root(corpus: &str) -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let local = manifest.join("testdata/r06").join(corpus);
    if local.is_dir() {
        local
    } else {
        manifest.join("../../testdata/r06").join(corpus)
    }
}

fn fixture(root: &Path, name: &str) -> Vec<u8> {
    fs::read(root.join(name))
        .unwrap_or_else(|error| panic!("read required R06 fixture {name}: {error}"))
}

fn fixture_text(root: &Path, name: &str) -> String {
    String::from_utf8(fixture(root, name))
        .unwrap_or_else(|error| panic!("R06 fixture {name} is not UTF-8: {error}"))
}

fn decode_map(root: &Path) -> Map {
    Map::decode(
        &fixture(root, "crushmap.bin"),
        DecodeLimits {
            max_bytes: 1 << 20,
            max_buckets: 1_024,
            max_rules: 256,
            max_items: 65_536,
            max_names: 65_536,
        },
    )
    .expect("decode native CRUSH map")
}

fn parse_osds(encoded: &str) -> Vec<i32> {
    let body = encoded
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or_else(|| panic!("invalid OSD list {encoded:?}"));
    if body.is_empty() {
        return Vec::new();
    }
    body.split(',')
        .map(|value| {
            value
                .parse()
                .unwrap_or_else(|error| panic!("invalid OSD {value:?}: {error}"))
        })
        .collect()
}

fn verify_direct_corpus(root: &Path, name: &str, rule: u32, weights: &[u32]) {
    let crush = decode_map(root);
    let prefix = format!("CRUSH rule {rule} x ");
    let text = fixture_text(root, name);
    let mut rows = 0;
    for line in text.lines() {
        let row = line
            .strip_prefix(&prefix)
            .unwrap_or_else(|| panic!("invalid CRUSH row {line:?}"));
        let (seed, encoded) = row
            .split_once(' ')
            .unwrap_or_else(|| panic!("incomplete CRUSH row {line:?}"));
        let seed = seed
            .parse::<u32>()
            .unwrap_or_else(|error| panic!("invalid seed {seed:?}: {error}"));
        let expected = parse_osds(encoded);
        let actual = crush
            .place(rule, seed, 3, weights)
            .unwrap_or_else(|_| panic!("place native seed {seed}"));
        assert_eq!(actual, expected, "native CRUSH seed {seed}");
        rows += 1;
    }
    assert_eq!(rows, 256, "native CRUSH row count");
}

fn pool(pg_count: u32) -> Pool {
    Pool {
        id: 1,
        name: "p05".into(),
        pool_type: 1,
        size: 3,
        minimum_size: 0,
        crush_rule: 0,
        object_hash: 2,
        pg_count,
        placement_pg_count: pg_count,
        stripe_width: 0,
        flags: 1,
        snapshot_sequence: 0,
        snapshots: BTreeMap::new(),
        erasure_code_profile: String::new(),
        application_metadata: HashMap::new(),
        options: HashMap::new(),
    }
}

fn osd_map(root: &Path, pg_count: u32, weights: Vec<u32>) -> OSDMap {
    OSDMap {
        fsid: Fsid([1; 16]),
        epoch: 1,
        created: UTime::default(),
        modified: UTime::default(),
        pools: HashMap::from([(1, pool(pg_count))]),
        name_to_id: HashMap::from([("p05".into(), 1)]),
        pool_max: 1,
        flags: 0,
        max_osd: 4,
        osd_state: vec![3; 4],
        osd_weight: weights,
        client_addresses: vec![EntityAddrVec(Vec::new()); 4],
        pg_temp: HashMap::new(),
        primary_temp: HashMap::new(),
        primary_affinity: Vec::new(),
        crush_data: fixture(root, "crushmap.bin"),
        erasure_code_profiles: HashMap::new(),
        pg_upmap: HashMap::new(),
        pg_upmap_items: HashMap::new(),
        crush_version: 0,
        new_removed_snapshots: HashMap::new(),
        new_purged_snapshots: HashMap::new(),
        last_up_change: UTime::default(),
        last_in_change: UTime::default(),
        pg_upmap_primaries: HashMap::new(),
        crc: 0,
        crc_verified: false,
        applied_incremental: false,
    }
}

fn read_upmap(root: &Path) -> HashMap<PG, Vec<OSDRemap>> {
    let mut result: HashMap<PG, Vec<OSDRemap>> = HashMap::new();
    let text = fixture_text(root, "upmap-commands.txt");
    let prefix = "ceph osd pg-upmap-items 1.";
    for line in text.lines() {
        let row = line
            .strip_prefix(prefix)
            .unwrap_or_else(|| panic!("invalid upmap command {line:?}"));
        let mut fields = row.split(' ');
        let seed = u32::from_str_radix(fields.next().expect("upmap PG"), 16)
            .expect("hexadecimal upmap PG");
        let from = fields
            .next()
            .expect("upmap source")
            .parse()
            .expect("integer upmap source");
        let to = fields
            .next()
            .expect("upmap target")
            .parse()
            .expect("integer upmap target");
        assert!(fields.next().is_none(), "extra upmap command fields");
        result
            .entry(PG {
                pool: 1,
                seed,
                preferred: -1,
            })
            .or_default()
            .push(OSDRemap { from, to });
    }
    assert_eq!(result.len(), 20, "upmap command count");
    result
}

fn verify_object_corpus(osd_map: &OSDMap, root: &Path, name: &str, assert_raw: bool) {
    let text = fixture_text(root, name);
    let mut rows = 0;
    for line in text.lines() {
        let row = line
            .strip_prefix("object '")
            .unwrap_or_else(|| panic!("invalid object row {line:?}"));
        let (object, row) = row
            .split_once("' -> 1.")
            .unwrap_or_else(|| panic!("invalid object identity {line:?}"));
        let (pg, encoded) = row
            .split_once(" -> ")
            .unwrap_or_else(|| panic!("incomplete object row {line:?}"));
        let pg = u32::from_str_radix(pg, 16).expect("hexadecimal object PG");
        let expected = parse_osds(encoded);
        let actual = osd_map
            .place_object(1, object.as_bytes(), b"", b"")
            .unwrap_or_else(|error| panic!("place native object {object:?}: {error}"));
        assert_eq!(actual.pg.seed, pg, "native object {object:?} PG");
        if assert_raw {
            assert_eq!(actual.raw, expected, "native object {object:?} raw set");
        }
        assert_eq!(actual.up, expected, "native object {object:?} up set");
        assert_eq!(
            actual.acting, expected,
            "native object {object:?} acting set"
        );
        assert_eq!(
            actual.up_primary, expected[0],
            "native object {object:?} up primary"
        );
        assert_eq!(
            actual.acting_primary, expected[0],
            "native object {object:?} acting primary"
        );
        rows += 1;
    }
    assert_eq!(rows, 128, "native object row count");
}

#[test]
fn p05_native_replicated_corpus_matches_production_placement() {
    let root = fixture_root("p05");
    verify_direct_corpus(&root, "mappings.txt", 0, &[IN_WEIGHT; 4]);
    verify_direct_corpus(
        &root,
        "mappings-osd1-out.txt",
        0,
        &[IN_WEIGHT, 0, IN_WEIGHT, IN_WEIGHT],
    );

    verify_object_corpus(
        &osd_map(&root, 256, vec![IN_WEIGHT; 4]),
        &root,
        "object-mappings.txt",
        true,
    );
    verify_object_corpus(
        &osd_map(&root, 32, vec![IN_WEIGHT; 4]),
        &root,
        "object-mappings-pg32.txt",
        true,
    );
    verify_object_corpus(
        &osd_map(&root, 32, vec![IN_WEIGHT, 0, IN_WEIGHT, IN_WEIGHT]),
        &root,
        "object-mappings-osd1-out.txt",
        true,
    );
    let mut upmap = osd_map(&root, 256, vec![IN_WEIGHT; 4]);
    upmap.pg_upmap_items = read_upmap(&root);
    verify_object_corpus(&upmap, &root, "object-mappings-upmap.txt", false);
}

#[test]
fn p10_native_erasure_corpus_matches_production_placement() {
    let root = fixture_root("p10");
    verify_direct_corpus(&root, "mappings.txt", 2, &[IN_WEIGHT; 3]);
    verify_direct_corpus(
        &root,
        "mappings-osd1-out.txt",
        2,
        &[IN_WEIGHT, 0, IN_WEIGHT],
    );
}

#[test]
fn p10_erasure_object_placement_preserves_missing_shard_slots() {
    let root = fixture_root("p10");
    let mut map = osd_map(&root, 32, vec![IN_WEIGHT, 0, IN_WEIGHT]);
    let pool = map.pools.get_mut(&1).expect("pool");
    pool.pool_type = 3;
    pool.crush_rule = 2;
    map.max_osd = 3;
    map.osd_state.truncate(3);
    map.client_addresses.truncate(3);

    let placement = map
        .place_object(1, b"erasure-object", b"", b"")
        .expect("place erasure object");
    assert_eq!(placement.raw.len(), 3);
    assert_eq!(placement.up.len(), 3);
    assert_eq!(placement.acting.len(), 3);
    assert!(placement.up.contains(&i32::MAX));
    assert_eq!(placement.up, placement.acting);
    assert_eq!(
        placement.acting[usize::try_from(placement.primary_shard).expect("primary shard")],
        placement.acting_primary
    );
}

fn verify_p10_object_corpus(root: &Path, name: &str, weights: Vec<u32>, affinity: bool) {
    let mut map = osd_map(root, 16, weights);
    let mut pool = map.pools.remove(&1).expect("default pool");
    pool.id = 3;
    pool.name = "p10-ec".into();
    pool.pool_type = 3;
    pool.crush_rule = 2;
    map.pools.insert(3, pool);
    map.name_to_id = HashMap::from([("p10-ec".into(), 3)]);
    map.pool_max = 3;
    map.max_osd = 3;
    map.osd_state.truncate(3);
    map.client_addresses.truncate(3);
    if affinity {
        map.primary_affinity = vec![0, IN_WEIGHT, IN_WEIGHT];
    }

    let text = fixture_text(root, name);
    let mut rows = 0;
    for line in text.lines() {
        let value: serde_json::Value = serde_json::from_str(line).expect("native JSON row");
        let object = value["object"].as_str().expect("object identity");
        let raw_pgid = value["raw_pgid"].as_str().expect("raw PG");
        let pgid = value["pgid"].as_str().expect("PG");
        let parse_seed = |encoded: &str| {
            let (_, seed) = encoded.split_once('.').expect("pool.seed PG");
            u32::from_str_radix(seed, 16).expect("hexadecimal PG seed")
        };
        let parse_set = |field: &str| {
            value[field]
                .as_array()
                .expect("OSD array")
                .iter()
                .map(|osd| i32::try_from(osd.as_i64().expect("OSD integer")).expect("i32 OSD"))
                .collect::<Vec<_>>()
        };
        let up = parse_set("up");
        let acting = parse_set("acting");
        let up_primary =
            i32::try_from(value["up_primary"].as_i64().expect("up primary")).expect("i32 primary");
        let acting_primary =
            i32::try_from(value["acting_primary"].as_i64().expect("acting primary"))
                .expect("i32 primary");
        let pg = PG {
            pool: 3,
            seed: parse_seed(pgid),
            preferred: -1,
        };
        map.pg_temp.clear();
        map.primary_temp.clear();
        if acting != up {
            map.pg_temp.insert(pg, acting.clone());
        }
        if acting_primary != up_primary {
            map.primary_temp.insert(pg, acting_primary);
        }
        let placement = map
            .place_object(3, object.as_bytes(), b"", b"")
            .expect("native EC object placement");
        assert_eq!(
            placement.raw_hash,
            parse_seed(raw_pgid),
            "{object} raw hash"
        );
        assert_eq!(placement.pg.seed, parse_seed(pgid), "{object} PG");
        assert_eq!(placement.up, up, "{object} up set");
        assert_eq!(placement.acting, acting, "{object} acting set");
        assert_eq!(placement.up_primary, up_primary, "{object} up primary");
        assert_eq!(
            placement.acting_primary, acting_primary,
            "{object} acting primary"
        );
        assert!(placement.sharded, "{object} sharded");
        assert_eq!(
            placement.acting[usize::try_from(placement.primary_shard).expect("shard index")],
            placement.acting_primary,
            "{object} primary shard"
        );
        rows += 1;
    }
    assert_eq!(rows, 128, "native EC object row count");
}

#[test]
fn p10_native_erasure_object_corpora_match_production_placement() {
    let root = fixture_root("p10");
    verify_p10_object_corpus(&root, "object-placements.jsonl", vec![IN_WEIGHT; 3], false);
    verify_p10_object_corpus(
        &root,
        "object-placements-osd1-out.jsonl",
        vec![IN_WEIGHT, 0, IN_WEIGHT],
        false,
    );
    verify_p10_object_corpus(
        &root,
        "object-placements-primary-affinity.jsonl",
        vec![IN_WEIGHT; 3],
        true,
    );
}

#[test]
fn certified_native_tunable_profiles_are_pinned() {
    let p05 = decode_map(&fixture_root("p05"));
    let p10 = decode_map(&fixture_root("p10"));
    assert_eq!(
        (p05.straw_calc_version, p05.allowed_bucket_algorithms),
        (0, 22)
    );
    assert_eq!(
        (p10.straw_calc_version, p10.allowed_bucket_algorithms),
        (1, 54)
    );
    assert_eq!((p05.msr_descents, p05.msr_collision_tries), (100, 100));
    assert_eq!((p10.msr_descents, p10.msr_collision_tries), (100, 100));
}
