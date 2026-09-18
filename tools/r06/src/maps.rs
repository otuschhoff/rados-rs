use std::collections::{BTreeMap, HashMap};
use std::fmt;

use crate::protocol::address::EntityAddrVec;
use crate::wire::{Decoder, WireError};

#[path = "../../../src/maps/incremental.rs"]
mod incremental;
#[path = "../../../src/maps/mgrmap.rs"]
mod mgrmap;
#[path = "../../../src/maps/monmap.rs"]
mod monmap;
#[path = "../../../src/maps/osdmap.rs"]
mod osdmap;
#[allow(clippy::cast_possible_truncation)]
#[path = "../../../src/maps/placement.rs"]
mod placement;
#[path = "../../../src/maps/pool.rs"]
mod pool;
#[path = "../../../src/maps/store.rs"]
mod store;

pub(crate) use incremental::{
    OSDMapIncremental, apply_osdmap_incremental, decode_osdmap_incremental,
};
pub(crate) use mgrmap::{MgrMap, decode_mgrmap};
pub(crate) use monmap::{MonMap, decode_monmap};
pub(crate) use osdmap::{Interval, OSDMap, OSDRemap, PG, decode_osdmap};
pub(crate) use placement::ObjectPlacement;
pub(crate) use pool::Pool;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MapError {
    Wire(WireError),
    Malformed(&'static str),
    UnsupportedPlacement(&'static str),
    InvalidSequence,
    FsidMismatch,
    LockPoisoned,
}

impl fmt::Display for MapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => write!(formatter, "{error}"),
            Self::Malformed(reason) => write!(formatter, "malformed Ceph map: {reason}"),
            Self::UnsupportedPlacement(reason) => {
                write!(formatter, "unsupported Ceph placement: {reason}")
            }
            Self::InvalidSequence => formatter.write_str("invalid Ceph map epoch sequence"),
            Self::FsidMismatch => formatter.write_str("Ceph map FSID mismatch"),
            Self::LockPoisoned => formatter.write_str("Ceph map lock poisoned"),
        }
    }
}

impl std::error::Error for MapError {}
impl From<WireError> for MapError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}
pub(crate) type Result<T> = std::result::Result<T, MapError>;

#[allow(clippy::struct_field_names)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Limits {
    pub(crate) max_bytes: u32,
    pub(crate) max_monitors: u32,
    pub(crate) max_addresses: u32,
    pub(crate) max_locations: u32,
    pub(crate) max_pools: u32,
    pub(crate) max_osds: u32,
    pub(crate) max_pg_mappings: u32,
    pub(crate) max_collection_entries: u32,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Fsid(pub(crate) [u8; 16]);

impl fmt::Display for Fsid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self.0;
        write!(
            formatter,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            value[0],
            value[1],
            value[2],
            value[3],
            value[4],
            value[5],
            value[6],
            value[7],
            value[8],
            value[9],
            value[10],
            value[11],
            value[12],
            value[13],
            value[14],
            value[15]
        )
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct UTime {
    pub(crate) seconds: u32,
    pub(crate) nanoseconds: u32,
}
fn decode_utime(decoder: &mut Decoder<'_>) -> UTime {
    UTime {
        seconds: decoder.u32(),
        nanoseconds: decoder.u32(),
    }
}
fn bounded_count(decoder: &mut Decoder<'_>, maximum: u32, minimum_bytes: usize) -> Result<usize> {
    let count = decoder.u32();
    decoder.finish()?;
    if count > maximum {
        return Err(WireError::LimitExceeded.into());
    }
    let count = usize::try_from(count).map_err(|_| WireError::LimitExceeded)?;
    if minimum_bytes != 0 && count > decoder.remaining() / minimum_bytes {
        return Err(WireError::Malformed.into());
    }
    Ok(count)
}
fn decode_strings(decoder: &mut Decoder<'_>, maximum: u32) -> Result<Vec<String>> {
    let count = bounded_count(decoder, maximum, 4)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(decoder.string());
    }
    decoder.finish()?;
    Ok(values)
}
fn decode_u32s(decoder: &mut Decoder<'_>, maximum: u32) -> Result<Vec<u32>> {
    let count = bounded_count(decoder, maximum, 4)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(decoder.u32());
    }
    decoder.finish()?;
    Ok(values)
}
fn require_timestamp(value: UTime) -> Result<UTime> {
    if value.nanoseconds >= 1_000_000_000 {
        return Err(MapError::Malformed("invalid timestamp"));
    }
    Ok(value)
}

pub(crate) fn r06_osd_map(
    crush_data: Vec<u8>,
    pg_count: u32,
    weights: Vec<u32>,
    remaps: HashMap<PG, Vec<OSDRemap>>,
) -> OSDMap {
    let osd_count = weights.len();
    let pool = Pool {
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
    };
    OSDMap {
        fsid: Fsid([1; 16]),
        epoch: 1,
        created: UTime::default(),
        modified: UTime::default(),
        pools: HashMap::from([(1, pool)]),
        name_to_id: HashMap::from([("p05".into(), 1)]),
        pool_max: 1,
        flags: 0,
        max_osd: i32::try_from(osd_count).expect("R06 OSD count fits i32"),
        osd_state: vec![3; osd_count],
        osd_weight: weights,
        client_addresses: vec![EntityAddrVec(Vec::new()); osd_count],
        pg_temp: HashMap::new(),
        primary_temp: HashMap::new(),
        primary_affinity: Vec::new(),
        crush_data,
        erasure_code_profiles: HashMap::new(),
        pg_upmap: HashMap::new(),
        pg_upmap_items: remaps,
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

pub(crate) fn r06_erasure_map(
    crush_data: Vec<u8>,
    weights: Vec<u32>,
    primary_affinity: Vec<u32>,
    pg_temp: HashMap<PG, Vec<i32>>,
    primary_temp: HashMap<PG, i32>,
) -> OSDMap {
    let mut map = r06_osd_map(crush_data, 16, weights, HashMap::new());
    let mut pool = map.pools.remove(&1).expect("R06 default pool");
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
    map.primary_affinity = primary_affinity;
    map.pg_temp = pg_temp;
    map.primary_temp = primary_temp;
    map
}
