use std::fs;
use std::path::Path;
use std::sync::Arc;

use super::store::{MapSnapshot, MapStore};
use super::*;

fn fixture_limits() -> Limits {
    Limits {
        max_bytes: 32 << 20,
        max_monitors: 64,
        max_addresses: 64,
        max_locations: 64,
        max_pools: 4096,
        max_osds: 65_536,
        max_pg_mappings: 1 << 20,
        max_collection_entries: 1 << 20,
    }
}

fn fixture(name: &str) -> Vec<u8> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture_root = if manifest.join("testdata/p04").is_dir() {
        manifest.join("testdata/p04")
    } else {
        manifest.join("../../testdata/p04")
    };
    let path = fixture_root.join(name);
    fs::read(path).unwrap_or_else(|error| panic!("read required P04 fixture {name}: {error}"))
}

#[test]
fn p04_ceph_dencoder_fixtures_decode() {
    let monmap_bytes = fixture("monmap-v9.bin");
    let osdmap_bytes = fixture("osdmap-v8.bin");
    let incremental_bytes = fixture("osdmap-incremental-v8.bin");
    let limits = fixture_limits();
    let monmap = Arc::new(decode_monmap(&monmap_bytes, limits).expect("P04 monmap"));
    let osdmap = Arc::new(decode_osdmap(&osdmap_bytes, limits).expect("P04 OSDMap"));
    decode_osdmap_incremental(&incremental_bytes, limits).expect("P04 incremental");

    let snapshot = MapSnapshot::new(monmap, osdmap).expect("snapshot");
    let store = MapStore::new(snapshot, 1);
    store.load().expect("load snapshot");
}

#[test]
fn p04_mgrmap_decodes_when_fixture_is_present() {
    let path = Path::new("testdata/p04/mgrmap-v14.bin");
    let Ok(bytes) = fs::read(path) else {
        return;
    };
    decode_mgrmap(&bytes, fixture_limits()).expect("P04 MgrMap");
}
