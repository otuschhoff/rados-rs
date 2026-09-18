use std::collections::{HashMap, HashSet};

use crate::protocol::address::EntityAddrVec;
use crate::wire::{Decoder, WireError, crc32c};

use super::osdmap::{
    decode_pg, decode_pg_int_map, decode_pg_remap_items, decode_pg_vector_map,
    decode_pool_interval_map, validate_limits,
};
use super::pool::{decode_nested_string_map, decode_pool};
use super::{
    Fsid, Interval, Limits, MapError, OSDMap, OSDRemap, PG, Pool, Result, UTime, bounded_count,
    decode_strings, decode_utime,
};

const DEFAULT_PRIMARY_AFFINITY: u32 = 0x10000;

#[derive(Clone, Debug)]
pub(crate) struct OSDMapIncremental {
    fsid: Fsid,
    epoch: u32,
    modified: UTime,
    new_pool_max: i64,
    new_flags: i32,
    full_map: Vec<u8>,
    crush_data: Vec<u8>,
    new_max_osd: i32,
    new_pools: HashMap<i64, Pool>,
    new_pool_names: HashMap<i64, String>,
    old_pools: Vec<i64>,
    new_up_client: HashMap<i32, EntityAddrVec>,
    new_state: HashMap<i32, u32>,
    new_weight: HashMap<i32, u32>,
    new_pg_temp: HashMap<PG, Vec<i32>>,
    new_primary_temp: HashMap<PG, i32>,
    new_primary_affinity: HashMap<i32, u32>,
    new_erasure_profiles: HashMap<String, HashMap<String, String>>,
    old_erasure_profiles: Vec<String>,
    new_pg_upmap: HashMap<PG, Vec<i32>>,
    old_pg_upmap: Vec<PG>,
    new_pg_upmap_items: HashMap<PG, Vec<OSDRemap>>,
    old_pg_upmap_items: Vec<PG>,
    new_removed_snapshots: HashMap<i64, Vec<Interval>>,
    new_purged_snapshots: HashMap<i64, Vec<Interval>>,
    new_last_up_change: UTime,
    new_last_in_change: UTime,
    new_pg_upmap_primaries: HashMap<PG, i32>,
    old_pg_upmap_primaries: Vec<PG>,
    incremental_crc: u32,
    full_crc: u32,
}

impl OSDMapIncremental {
    pub(crate) fn fsid(&self) -> Fsid {
        self.fsid
    }
    pub(crate) fn epoch(&self) -> u32 {
        self.epoch
    }
    pub(crate) fn incremental_crc(&self) -> u32 {
        self.incremental_crc
    }
    pub(crate) fn full_crc(&self) -> u32 {
        self.full_crc
    }
}

pub(crate) fn decode_osdmap_incremental(data: &[u8], limits: Limits) -> Result<OSDMapIncremental> {
    validate_limits(limits)?;
    let mut decoder = Decoder::new(data, limits.max_bytes as usize);
    let (version, mut wrapper) = decoder.versioned(8);
    decoder.finish()?;
    if version < 8 {
        return Err(WireError::UnsupportedVersion {
            local: 8,
            required: 8,
        }
        .into());
    }
    let (client_version, mut client) = wrapper.versioned(9);
    wrapper.finish()?;
    if client_version < 9 {
        return Err(WireError::UnsupportedVersion {
            local: 9,
            required: 9,
        }
        .into());
    }
    let mut result = decode_client(&mut client, limits)?;
    client.finish()?;
    let (_, extended) = wrapper.versioned(12);
    wrapper.finish()?;
    extended.finish()?;
    result.incremental_crc = wrapper.u32();
    result.full_crc = wrapper.u32();
    wrapper.finish()?;
    decoder.finish()?;
    if decoder.remaining() != 0 || data.len() < 14 {
        return Err(MapError::Malformed("trailing or short incremental"));
    }
    let offset = data.len() - 8;
    let actual = crc32c(crc32c(u32::MAX, &data[..offset]), &data[offset + 4..]);
    if actual != result.incremental_crc {
        return Err(MapError::Malformed("incremental CRC mismatch"));
    }
    Ok(result)
}

fn decode_client(decoder: &mut Decoder<'_>, limits: Limits) -> Result<OSDMapIncremental> {
    let fsid = Fsid(
        decoder
            .raw(16)
            .try_into()
            .map_err(|_| WireError::Malformed)?,
    );
    let epoch = decoder.u32();
    let modified = decode_utime(decoder);
    let new_pool_max = decoder.i64();
    let new_flags = decoder.i32();
    let full_map = decoder.bytes();
    let crush_data = decoder.bytes();
    let new_max_osd = decoder.i32();
    if u32::try_from(new_max_osd).is_ok_and(|max_osd| max_osd > limits.max_osds) {
        return Err(WireError::LimitExceeded.into());
    }
    let count = bounded_count(decoder, limits.max_pools, 14)?;
    let mut new_pools = HashMap::with_capacity(count);
    for _ in 0..count {
        let id = decoder.i64();
        let mut pool = decode_pool(decoder, limits)?;
        pool.id = id;
        if new_pools.insert(id, pool).is_some() {
            return Err(MapError::Malformed("duplicate new pool"));
        }
    }
    let count = bounded_count(decoder, limits.max_pools, 12)?;
    let mut new_pool_names = HashMap::with_capacity(count);
    for _ in 0..count {
        let id = decoder.i64();
        let name = decoder.string();
        if new_pool_names.insert(id, name).is_some() {
            return Err(MapError::Malformed("duplicate renamed pool"));
        }
    }
    let count = bounded_count(decoder, limits.max_pools, 8)?;
    let mut old_pools = Vec::with_capacity(count);
    let mut seen = HashSet::new();
    for _ in 0..count {
        let id = decoder.i64();
        if !seen.insert(id) {
            return Err(MapError::Malformed("duplicate removed pool"));
        }
        old_pools.push(id);
    }
    let new_up_client = decode_int_address_map(decoder, limits)?;
    let new_state = decode_int_u32_map(decoder, limits.max_osds)?;
    let new_weight = decode_int_u32_map(decoder, limits.max_osds)?;
    let new_pg_temp = decode_pg_vector_map(decoder, limits)?;
    let new_primary_temp = decode_pg_int_map(decoder, limits)?;
    let new_primary_affinity = decode_int_u32_map(decoder, limits.max_osds)?;
    let new_erasure_profiles = decode_nested_string_map(decoder, limits.max_collection_entries)?;
    let old_erasure_profiles = decode_strings(decoder, limits.max_collection_entries)?;
    let new_pg_upmap = decode_pg_vector_map(decoder, limits)?;
    let old_pg_upmap = decode_pg_set(decoder, limits)?;
    let new_pg_upmap_items = decode_pg_remap_items(decoder, limits)?;
    let old_pg_upmap_items = decode_pg_set(decoder, limits)?;
    let new_removed_snapshots = decode_pool_interval_map(decoder, limits)?;
    let new_purged_snapshots = decode_pool_interval_map(decoder, limits)?;
    let new_last_up_change = decode_utime(decoder);
    let new_last_in_change = decode_utime(decoder);
    let new_pg_upmap_primaries = decode_pg_int_map(decoder, limits)?;
    let old_pg_upmap_primaries = decode_pg_set(decoder, limits)?;
    decoder.finish()?;
    Ok(OSDMapIncremental {
        fsid,
        epoch,
        modified,
        new_pool_max,
        new_flags,
        full_map,
        crush_data,
        new_max_osd,
        new_pools,
        new_pool_names,
        old_pools,
        new_up_client,
        new_state,
        new_weight,
        new_pg_temp,
        new_primary_temp,
        new_primary_affinity,
        new_erasure_profiles,
        old_erasure_profiles,
        new_pg_upmap,
        old_pg_upmap,
        new_pg_upmap_items,
        old_pg_upmap_items,
        new_removed_snapshots,
        new_purged_snapshots,
        new_last_up_change,
        new_last_in_change,
        new_pg_upmap_primaries,
        old_pg_upmap_primaries,
        incremental_crc: 0,
        full_crc: 0,
    })
}

#[allow(clippy::too_many_lines)]
pub(crate) fn apply_osdmap_incremental(
    current: &OSDMap,
    incremental: &OSDMapIncremental,
    limits: Limits,
) -> Result<OSDMap> {
    if incremental.fsid != current.fsid {
        return Err(MapError::FsidMismatch);
    }
    if incremental.epoch
        != current
            .epoch
            .checked_add(1)
            .ok_or(MapError::InvalidSequence)?
    {
        return Err(MapError::InvalidSequence);
    }
    if !incremental.full_map.is_empty() {
        let replacement = super::decode_osdmap(&incremental.full_map, limits)?;
        if replacement.fsid != current.fsid
            || replacement.epoch != incremental.epoch
            || replacement.crc != incremental.full_crc
        {
            return Err(MapError::Malformed(
                "replacement full map identity or CRC mismatch",
            ));
        }
        return Ok(replacement);
    }
    let mut next = current.clone();
    next.epoch = incremental.epoch;
    next.modified = incremental.modified;
    next.crc = incremental.full_crc;
    next.crc_verified = false;
    next.applied_incremental = true;
    if incremental.new_pool_max != -1 {
        next.pool_max = incremental.new_pool_max;
    }
    if let Ok(new_flags) = u32::try_from(incremental.new_flags) {
        next.flags = new_flags;
    }
    if let Ok(new_max_osd) = usize::try_from(incremental.new_max_osd) {
        next.max_osd = incremental.new_max_osd;
        resize_osds(&mut next, new_max_osd);
    }
    if !incremental.crush_data.is_empty() {
        next.crush_data.clone_from(&incremental.crush_data);
        next.crush_version = next
            .crush_version
            .checked_add(1)
            .ok_or(MapError::InvalidSequence)?;
    }
    for (id, pool) in &incremental.new_pools {
        let mut pool = pool.clone();
        if let Some(old) = next.pools.get(id) {
            pool.name.clone_from(&old.name);
        }
        next.pools.insert(*id, pool);
    }
    for (id, name) in &incremental.new_pool_names {
        let pool = next
            .pools
            .get_mut(id)
            .ok_or(MapError::Malformed("rename for unknown pool"))?;
        if next.name_to_id.get(name).is_some_and(|old| old != id) {
            return Err(MapError::Malformed("duplicate pool name"));
        }
        next.name_to_id.remove(&pool.name);
        pool.name.clone_from(name);
        next.name_to_id.insert(name.clone(), *id);
    }
    for id in &incremental.old_pools {
        if let Some(pool) = next.pools.remove(id) {
            next.name_to_id.remove(&pool.name);
        }
    }
    for (&osd, &weight) in &incremental.new_weight {
        let id = valid_osd(&next, osd)?;
        next.osd_weight[id] = weight;
        if weight != 0 {
            next.osd_state[id] &= !((1 << 2) | (1 << 3));
        }
    }
    for (&osd, &affinity) in &incremental.new_primary_affinity {
        let id = valid_osd(&next, osd)?;
        ensure_primary_affinity(&mut next);
        next.primary_affinity[id] = affinity;
    }
    for (&osd, &state_value) in &incremental.new_state {
        let id = valid_osd(&next, osd)?;
        let state = if state_value == 0 {
            1 << 1
        } else {
            state_value
        };
        if next.osd_state[id] & 1 != 0 && state & 1 != 0 {
            next.osd_state[id] = 0;
            ensure_primary_affinity(&mut next);
            next.primary_affinity[id] = DEFAULT_PRIMARY_AFFINITY;
            next.client_addresses[id] = EntityAddrVec(Vec::new());
        } else {
            next.osd_state[id] ^= state;
        }
    }
    for (&osd, addresses) in &incremental.new_up_client {
        let id = valid_osd(&next, osd)?;
        next.osd_state[id] |= 3;
        next.osd_state[id] &= !(1 << 12);
        next.client_addresses[id] = addresses.clone();
    }
    apply_pg_vectors(&mut next.pg_temp, &incremental.new_pg_temp, true);
    apply_pg_ints(&mut next.primary_temp, &incremental.new_primary_temp, -1);
    for name in &incremental.old_erasure_profiles {
        next.erasure_code_profiles.remove(name);
    }
    for (name, profile) in &incremental.new_erasure_profiles {
        next.erasure_code_profiles
            .insert(name.clone(), profile.clone());
    }
    apply_pg_vectors(&mut next.pg_upmap, &incremental.new_pg_upmap, false);
    for pg in &incremental.old_pg_upmap {
        next.pg_upmap.remove(pg);
    }
    for (pg, values) in &incremental.new_pg_upmap_items {
        next.pg_upmap_items.insert(*pg, values.clone());
    }
    for pg in &incremental.old_pg_upmap_items {
        next.pg_upmap_items.remove(pg);
    }
    next.new_removed_snapshots
        .clone_from(&incremental.new_removed_snapshots);
    next.new_purged_snapshots
        .clone_from(&incremental.new_purged_snapshots);
    if incremental.new_last_up_change != UTime::default() {
        next.last_up_change = incremental.new_last_up_change;
    }
    if incremental.new_last_in_change != UTime::default() {
        next.last_in_change = incremental.new_last_in_change;
    }
    for (pg, primary) in &incremental.new_pg_upmap_primaries {
        next.pg_upmap_primaries.insert(*pg, *primary);
    }
    for pg in &incremental.old_pg_upmap_primaries {
        next.pg_upmap_primaries.remove(pg);
    }
    if next.pools.values().any(|pool| pool.name.is_empty()) {
        return Err(MapError::Malformed("pool has no name"));
    }
    Ok(next)
}

fn resize_osds(map: &mut OSDMap, size: usize) {
    map.osd_state.resize(size, 0);
    map.osd_weight.resize(size, 0);
    if !map.primary_affinity.is_empty() {
        map.primary_affinity.resize(size, DEFAULT_PRIMARY_AFFINITY);
    }
    map.client_addresses
        .resize_with(size, || EntityAddrVec(Vec::new()));
}

fn ensure_primary_affinity(map: &mut OSDMap) {
    if map.primary_affinity.is_empty() {
        map.primary_affinity
            .resize(map.osd_state.len(), DEFAULT_PRIMARY_AFFINITY);
    }
}
fn valid_osd(map: &OSDMap, osd: i32) -> Result<usize> {
    usize::try_from(osd)
        .ok()
        .filter(|id| *id < map.osd_state.len())
        .ok_or(MapError::Malformed("OSD outside map size"))
}
fn apply_pg_vectors(
    target: &mut HashMap<PG, Vec<i32>>,
    changes: &HashMap<PG, Vec<i32>>,
    empty_deletes: bool,
) {
    for (pg, values) in changes {
        if empty_deletes && values.is_empty() {
            target.remove(pg);
        } else {
            target.insert(*pg, values.clone());
        }
    }
}
fn apply_pg_ints(target: &mut HashMap<PG, i32>, changes: &HashMap<PG, i32>, deleted: i32) {
    for (pg, value) in changes {
        if *value == deleted {
            target.remove(pg);
        } else {
            target.insert(*pg, *value);
        }
    }
}
fn decode_int_address_map(
    decoder: &mut Decoder<'_>,
    limits: Limits,
) -> Result<HashMap<i32, EntityAddrVec>> {
    let count = bounded_count(decoder, limits.max_osds, 9)?;
    let mut map = HashMap::with_capacity(count);
    for _ in 0..count {
        let osd = decoder.i32();
        let addresses = EntityAddrVec::decode(decoder, limits.max_addresses)?;
        if map.insert(osd, addresses).is_some() {
            return Err(MapError::Malformed("duplicate OSD address"));
        }
    }
    decoder.finish()?;
    Ok(map)
}
fn decode_int_u32_map(decoder: &mut Decoder<'_>, maximum: u32) -> Result<HashMap<i32, u32>> {
    let count = bounded_count(decoder, maximum, 8)?;
    let mut map = HashMap::with_capacity(count);
    for _ in 0..count {
        let key = decoder.i32();
        let value = decoder.u32();
        if map.insert(key, value).is_some() {
            return Err(MapError::Malformed("duplicate OSD value"));
        }
    }
    decoder.finish()?;
    Ok(map)
}
fn decode_pg_set(decoder: &mut Decoder<'_>, limits: Limits) -> Result<Vec<PG>> {
    let count = bounded_count(decoder, limits.max_pg_mappings, 17)?;
    let mut values = Vec::with_capacity(count);
    let mut seen = HashSet::new();
    for _ in 0..count {
        let pg = decode_pg(decoder)?;
        if !seen.insert(pg) {
            return Err(MapError::Malformed("duplicate PG set entry"));
        }
        values.push(pg);
    }
    decoder.finish()?;
    Ok(values)
}
