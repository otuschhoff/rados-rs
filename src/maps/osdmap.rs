use std::collections::HashMap;

use crate::protocol::address::EntityAddrVec;
use crate::wire::{Decoder, WireError, crc32c};

use super::pool::{decode_intervals, decode_nested_string_map, decode_pool};
use super::{Fsid, Limits, MapError, Pool, Result, UTime, bounded_count, decode_utime};

const OSDMAP_FLAG_SORT_BITWISE: u32 = 1 << 15;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PG {
    pub(crate) pool: u64,
    pub(crate) seed: u32,
    pub(crate) preferred: i32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OSDRemap {
    pub(crate) from: i32,
    pub(crate) to: i32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Interval {
    pub(crate) start: u64,
    pub(crate) length: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct OSDMap {
    pub(super) fsid: Fsid,
    pub(super) epoch: u32,
    pub(super) created: UTime,
    pub(super) modified: UTime,
    pub(super) pools: HashMap<i64, Pool>,
    pub(super) name_to_id: HashMap<String, i64>,
    pub(super) pool_max: i64,
    pub(super) flags: u32,
    pub(super) max_osd: i32,
    pub(super) osd_state: Vec<u32>,
    pub(super) osd_weight: Vec<u32>,
    pub(super) client_addresses: Vec<EntityAddrVec>,
    pub(super) pg_temp: HashMap<PG, Vec<i32>>,
    pub(super) primary_temp: HashMap<PG, i32>,
    pub(super) primary_affinity: Vec<u32>,
    pub(super) crush_data: Vec<u8>,
    pub(super) erasure_code_profiles: HashMap<String, HashMap<String, String>>,
    pub(super) pg_upmap: HashMap<PG, Vec<i32>>,
    pub(super) pg_upmap_items: HashMap<PG, Vec<OSDRemap>>,
    pub(super) crush_version: u32,
    pub(super) new_removed_snapshots: HashMap<i64, Vec<Interval>>,
    pub(super) new_purged_snapshots: HashMap<i64, Vec<Interval>>,
    pub(super) last_up_change: UTime,
    pub(super) last_in_change: UTime,
    pub(super) pg_upmap_primaries: HashMap<PG, i32>,
    pub(super) crc: u32,
    pub(super) crc_verified: bool,
    pub(super) applied_incremental: bool,
}

impl OSDMap {
    pub(crate) fn fsid(&self) -> Fsid {
        self.fsid
    }
    pub(crate) fn epoch(&self) -> u32 {
        self.epoch
    }
    pub(crate) fn pool_by_id(&self, id: i64) -> Option<&Pool> {
        self.pools.get(&id)
    }
    pub(crate) fn pool_by_name(&self, name: &str) -> Option<&Pool> {
        self.name_to_id.get(name).and_then(|id| self.pools.get(id))
    }
    pub(crate) fn pools(&self) -> impl ExactSizeIterator<Item = &Pool> {
        self.pools.values()
    }
    pub(crate) fn pool_names(&self) -> impl Iterator<Item = &str> {
        self.name_to_id.keys().map(String::as_str)
    }
    pub(crate) fn osd_client_addresses(&self, id: i32) -> Option<&EntityAddrVec> {
        usize::try_from(id)
            .ok()
            .and_then(|id| self.client_addresses.get(id))
            .filter(|a| !a.0.is_empty())
    }
    pub(crate) fn crush_data(&self) -> &[u8] {
        &self.crush_data
    }
    pub(crate) fn sort_bitwise(&self) -> bool {
        self.flags & OSDMAP_FLAG_SORT_BITWISE != 0
    }
    pub(crate) fn crc(&self) -> u32 {
        self.crc
    }
    pub(crate) fn crc_verified(&self) -> bool {
        self.crc_verified
    }
    pub(crate) fn applied_incremental(&self) -> bool {
        self.applied_incremental
    }
}

pub(crate) fn decode_osdmap(data: &[u8], limits: Limits) -> Result<OSDMap> {
    validate_limits(limits)?;
    let mut decoder = Decoder::new(data, limits.max_bytes as usize);
    let (wrapper_version, mut wrapper) = decoder.versioned(8);
    decoder.finish()?;
    if wrapper_version < 8 {
        return Err(WireError::UnsupportedVersion {
            local: 8,
            required: 8,
        }
        .into());
    }
    let (client_version, mut client) = wrapper.versioned(10);
    wrapper.finish()?;
    if client_version < 10 {
        return Err(WireError::UnsupportedVersion {
            local: 10,
            required: 10,
        }
        .into());
    }
    let mut result = decode_client(&mut client, limits)?;
    client.finish()?;
    let (_, extended) = wrapper.versioned(12);
    wrapper.finish()?;
    extended.finish()?;
    result.crc = wrapper.u32();
    wrapper.finish()?;
    decoder.finish()?;
    if decoder.remaining() != 0 {
        return Err(MapError::Malformed("trailing osdmap bytes"));
    }
    if data.len() < 10 {
        return Err(WireError::Malformed.into());
    }
    let crc_offset = data.len() - 4;
    let actual = crc32c(u32::MAX, &data[..crc_offset]);
    if actual != result.crc {
        return Err(MapError::Malformed("osdmap CRC mismatch"));
    }
    result.crc_verified = true;
    Ok(result)
}

pub(super) fn validate_limits(limits: Limits) -> Result<()> {
    if limits.max_bytes == 0
        || limits.max_pools == 0
        || limits.max_osds == 0
        || limits.max_addresses == 0
        || limits.max_pg_mappings == 0
        || limits.max_collection_entries == 0
    {
        Err(WireError::LimitExceeded.into())
    } else {
        Ok(())
    }
}

fn decode_client(decoder: &mut Decoder<'_>, limits: Limits) -> Result<OSDMap> {
    let fsid = Fsid(
        decoder
            .raw(16)
            .try_into()
            .map_err(|_| WireError::Malformed)?,
    );
    let epoch = decoder.u32();
    let created = decode_utime(decoder);
    let modified = decode_utime(decoder);
    let count = bounded_count(decoder, limits.max_pools, 14)?;
    let mut pools = HashMap::with_capacity(count);
    for _ in 0..count {
        let id = decoder.i64();
        let mut pool = decode_pool(decoder, limits)?;
        pool.id = id;
        if pools.insert(id, pool).is_some() {
            return Err(MapError::Malformed("duplicate pool id"));
        }
    }
    let count = bounded_count(decoder, limits.max_pools, 12)?;
    let mut name_to_id = HashMap::with_capacity(count);
    for _ in 0..count {
        let id = decoder.i64();
        let name = decoder.string();
        let pool = pools
            .get_mut(&id)
            .ok_or(MapError::Malformed("name for unknown pool"))?;
        if name_to_id.insert(name.clone(), id).is_some() {
            return Err(MapError::Malformed("duplicate pool name"));
        }
        pool.name = name;
    }
    if name_to_id.len() != pools.len() {
        return Err(MapError::Malformed("missing pool names"));
    }
    let pool_max = i64::from(decoder.i32());
    let flags = decoder.u32();
    let max_osd = decoder.i32();
    let osd_state = decode_u32_vector(decoder, limits.max_osds)?;
    let osd_weight = decode_u32_vector(decoder, limits.max_osds)?;
    let client_addresses = decode_address_vector(decoder, limits)?;
    let pg_temp = decode_pg_vector_map(decoder, limits)?;
    let primary_temp = decode_pg_int_map(decoder, limits)?;
    let primary_affinity = decode_u32_vector(decoder, limits.max_osds)?;
    let Ok(max_osd_unsigned) = u32::try_from(max_osd) else {
        return Err(MapError::Malformed("inconsistent OSD vectors"));
    };
    let max_osd_length = usize::try_from(max_osd_unsigned).map_err(|_| WireError::LimitExceeded)?;
    if max_osd_unsigned > limits.max_osds
        || osd_state.len() != max_osd_length
        || osd_weight.len() != max_osd_length
        || client_addresses.len() != max_osd_length
        || (!primary_affinity.is_empty() && primary_affinity.len() != max_osd_length)
    {
        return Err(MapError::Malformed("inconsistent OSD vectors"));
    }
    let crush_data = decoder.bytes();
    decoder.finish()?;
    let erasure_code_profiles = decode_nested_string_map(decoder, limits.max_collection_entries)?;
    let pg_upmap = decode_pg_vector_map(decoder, limits)?;
    let pg_upmap_items = decode_pg_remap_items(decoder, limits)?;
    let crush_version = decoder.u32();
    let new_removed_snapshots = decode_pool_interval_map(decoder, limits)?;
    let new_purged_snapshots = decode_pool_interval_map(decoder, limits)?;
    let last_up_change = decode_utime(decoder);
    let last_in_change = decode_utime(decoder);
    let pg_upmap_primaries = decode_pg_int_map(decoder, limits)?;
    decoder.finish()?;
    Ok(OSDMap {
        fsid,
        epoch,
        created,
        modified,
        pools,
        name_to_id,
        pool_max,
        flags,
        max_osd,
        osd_state,
        osd_weight,
        client_addresses,
        pg_temp,
        primary_temp,
        primary_affinity,
        crush_data,
        erasure_code_profiles,
        pg_upmap,
        pg_upmap_items,
        crush_version,
        new_removed_snapshots,
        new_purged_snapshots,
        last_up_change,
        last_in_change,
        pg_upmap_primaries,
        crc: 0,
        crc_verified: false,
        applied_incremental: false,
    })
}

pub(super) fn decode_u32_vector(decoder: &mut Decoder<'_>, maximum: u32) -> Result<Vec<u32>> {
    super::decode_u32s(decoder, maximum)
}
fn decode_address_vector(decoder: &mut Decoder<'_>, limits: Limits) -> Result<Vec<EntityAddrVec>> {
    let count = bounded_count(decoder, limits.max_osds, 5)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(EntityAddrVec::decode(decoder, limits.max_addresses)?);
    }
    decoder.finish()?;
    Ok(values)
}
pub(super) fn decode_pg(decoder: &mut Decoder<'_>) -> Result<PG> {
    if decoder.u8() != 1 {
        return Err(WireError::UnsupportedVersion {
            local: 1,
            required: 1,
        }
        .into());
    }
    let pg = PG {
        pool: decoder.u64(),
        seed: decoder.u32(),
        preferred: decoder.i32(),
    };
    decoder.finish()?;
    Ok(pg)
}
pub(super) fn decode_pg_vector_map(
    decoder: &mut Decoder<'_>,
    limits: Limits,
) -> Result<HashMap<PG, Vec<i32>>> {
    let count = bounded_count(decoder, limits.max_pg_mappings, 21)?;
    let mut map = HashMap::with_capacity(count);
    for _ in 0..count {
        let pg = decode_pg(decoder)?;
        let inner = bounded_count(decoder, limits.max_osds, 4)?;
        let mut values = Vec::with_capacity(inner);
        for _ in 0..inner {
            values.push(decoder.i32());
        }
        if map.insert(pg, values).is_some() {
            return Err(MapError::Malformed("duplicate PG mapping"));
        }
    }
    decoder.finish()?;
    Ok(map)
}
pub(super) fn decode_pg_int_map(
    decoder: &mut Decoder<'_>,
    limits: Limits,
) -> Result<HashMap<PG, i32>> {
    let count = bounded_count(decoder, limits.max_pg_mappings, 21)?;
    let mut map = HashMap::with_capacity(count);
    for _ in 0..count {
        let pg = decode_pg(decoder)?;
        let value = decoder.i32();
        if map.insert(pg, value).is_some() {
            return Err(MapError::Malformed("duplicate PG mapping"));
        }
    }
    decoder.finish()?;
    Ok(map)
}
pub(super) fn decode_pg_remap_items(
    decoder: &mut Decoder<'_>,
    limits: Limits,
) -> Result<HashMap<PG, Vec<OSDRemap>>> {
    let count = bounded_count(decoder, limits.max_pg_mappings, 21)?;
    let mut map = HashMap::with_capacity(count);
    for _ in 0..count {
        let pg = decode_pg(decoder)?;
        let inner = bounded_count(decoder, limits.max_osds, 8)?;
        let mut values = Vec::with_capacity(inner);
        for _ in 0..inner {
            values.push(OSDRemap {
                from: decoder.i32(),
                to: decoder.i32(),
            });
        }
        if map.insert(pg, values).is_some() {
            return Err(MapError::Malformed("duplicate PG remap"));
        }
    }
    decoder.finish()?;
    Ok(map)
}
pub(super) fn decode_pool_interval_map(
    decoder: &mut Decoder<'_>,
    limits: Limits,
) -> Result<HashMap<i64, Vec<Interval>>> {
    let count = bounded_count(decoder, limits.max_pools, 12)?;
    let mut map = HashMap::with_capacity(count);
    for _ in 0..count {
        let id = decoder.i64();
        let values = decode_intervals(decoder, limits.max_collection_entries)?;
        if map.insert(id, values).is_some() {
            return Err(MapError::Malformed("duplicate pool interval set"));
        }
    }
    decoder.finish()?;
    Ok(map)
}
