use std::collections::HashSet;

use crate::protocol::address::EntityAddrVec;
use crate::wire::{Decoder, WireError};

use super::pool::decode_string_map;
use super::{
    Limits, MapError, Result, bounded_count, decode_strings, decode_utime, require_timestamp,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MgrMap {
    epoch: u32,
    active_gid: u64,
    available: bool,
    active_name: String,
    active_addresses: EntityAddrVec,
    active_features: u64,
}

impl MgrMap {
    pub(crate) fn epoch(&self) -> u32 {
        self.epoch
    }
    pub(crate) fn active_gid(&self) -> u64 {
        self.active_gid
    }
    pub(crate) fn available(&self) -> bool {
        self.available
    }
    pub(crate) fn active_name(&self) -> &str {
        &self.active_name
    }
    pub(crate) fn active_addresses(&self) -> &EntityAddrVec {
        &self.active_addresses
    }
    pub(crate) fn active_features(&self) -> u64 {
        self.active_features
    }
}

pub(crate) fn decode_mgrmap(data: &[u8], limits: Limits) -> Result<MgrMap> {
    if limits.max_bytes == 0 || limits.max_addresses == 0 || limits.max_collection_entries == 0 {
        return Err(WireError::LimitExceeded.into());
    }
    let mut decoder = Decoder::new(data, limits.max_bytes as usize);
    let (version, mut payload) = decoder.versioned(14);
    decoder.finish()?;
    if version < 6 {
        return Err(WireError::UnsupportedVersion {
            local: 14,
            required: 6,
        }
        .into());
    }
    let epoch = payload.u32();
    let active_addresses = EntityAddrVec::decode(&mut payload, limits.max_addresses)?;
    let active_gid = payload.u64();
    let available = decode_canonical_bool(&mut payload)?;
    let active_name = payload.string();
    consume_standbys(&mut payload, version, limits)?;
    consume_string_set(&mut payload, limits.max_collection_entries)?;
    decode_string_map(&mut payload, limits.max_collection_entries)?;
    consume_module_info_vector(&mut payload, limits)?;
    if version >= 7 {
        require_timestamp(decode_utime(&mut payload))?;
    }
    if version >= 8 {
        consume_always_on_modules(&mut payload, limits.max_collection_entries)?;
    }
    let active_features = if version >= 9 { payload.u64() } else { 0 };
    if version >= 10 {
        payload.u32();
    }
    if version >= 11 {
        let count = bounded_count(&mut payload, limits.max_collection_entries, 1)?;
        for _ in 0..count {
            EntityAddrVec::decode(&mut payload, limits.max_addresses)?;
        }
        if version >= 12
            && decode_strings(&mut payload, limits.max_collection_entries)?.len() != count
        {
            return Err(MapError::Malformed(
                "mgr client name/address count mismatch",
            ));
        }
    }
    if version >= 13 {
        payload.u64();
    }
    if version >= 14 {
        consume_string_set(&mut payload, limits.max_collection_entries)?;
    }
    payload.finish()?;
    decoder.finish()?;
    if decoder.remaining() != 0 {
        return Err(MapError::Malformed("trailing mgrmap bytes"));
    }
    Ok(MgrMap {
        epoch,
        active_gid,
        available,
        active_name,
        active_addresses,
        active_features,
    })
}

fn consume_standbys(decoder: &mut Decoder<'_>, version: u8, limits: Limits) -> Result<()> {
    let count = bounded_count(decoder, limits.max_collection_entries, 14)?;
    let mut seen = HashSet::with_capacity(count);
    for _ in 0..count {
        let key = decoder.u64();
        if !seen.insert(key) {
            return Err(MapError::Malformed("duplicate mgr standby"));
        }
        let gid = consume_standby(decoder, limits)?;
        if key != gid {
            return Err(MapError::Malformed("standby key/GID mismatch"));
        }
    }
    if version < 6 {
        return Err(WireError::UnsupportedVersion {
            local: 14,
            required: 6,
        }
        .into());
    }
    decoder.finish()?;
    Ok(())
}

fn consume_standby(decoder: &mut Decoder<'_>, limits: Limits) -> Result<u64> {
    let (version, mut payload) = decoder.versioned(4);
    decoder.finish()?;
    if version < 1 {
        return Err(WireError::UnsupportedVersion {
            local: 4,
            required: 1,
        }
        .into());
    }
    let gid = payload.u64();
    payload.string();
    if version >= 2 {
        consume_string_set(&mut payload, limits.max_collection_entries)?;
    }
    if version >= 3 {
        consume_module_info_vector(&mut payload, limits)?;
    }
    if version >= 4 {
        payload.u64();
    }
    payload.finish()?;
    Ok(gid)
}
fn consume_module_info_vector(decoder: &mut Decoder<'_>, limits: Limits) -> Result<()> {
    let count = bounded_count(decoder, limits.max_collection_entries, 6)?;
    let mut seen = HashSet::with_capacity(count);
    for _ in 0..count {
        let name = consume_module_info(decoder, limits)?;
        if !seen.insert(name) {
            return Err(MapError::Malformed("duplicate mgr module"));
        }
    }
    decoder.finish()?;
    Ok(())
}
fn consume_module_info(decoder: &mut Decoder<'_>, limits: Limits) -> Result<String> {
    let (version, mut payload) = decoder.versioned(2);
    decoder.finish()?;
    if version < 1 {
        return Err(WireError::UnsupportedVersion {
            local: 2,
            required: 1,
        }
        .into());
    }
    let name = payload.string();
    decode_canonical_bool(&mut payload)?;
    payload.string();
    if version >= 2 {
        consume_module_options(&mut payload, limits)?;
    }
    payload.finish()?;
    Ok(name)
}
fn consume_module_options(decoder: &mut Decoder<'_>, limits: Limits) -> Result<()> {
    let count = bounded_count(decoder, limits.max_collection_entries, 10)?;
    let mut seen = HashSet::with_capacity(count);
    for _ in 0..count {
        let key = decoder.string();
        if !seen.insert(key.clone()) {
            return Err(MapError::Malformed("duplicate mgr module option"));
        }
        if consume_module_option(decoder, limits.max_collection_entries)? != key {
            return Err(MapError::Malformed("module option key/name mismatch"));
        }
    }
    decoder.finish()?;
    Ok(())
}
fn consume_module_option(decoder: &mut Decoder<'_>, maximum: u32) -> Result<String> {
    let (version, mut payload) = decoder.versioned(1);
    decoder.finish()?;
    if version < 1 {
        return Err(WireError::UnsupportedVersion {
            local: 1,
            required: 1,
        }
        .into());
    }
    let name = payload.string();
    payload.u8();
    payload.u8();
    payload.u32();
    for _ in 0..3 {
        payload.string();
    }
    consume_string_set(&mut payload, maximum)?;
    payload.string();
    payload.string();
    consume_string_set(&mut payload, maximum)?;
    consume_string_set(&mut payload, maximum)?;
    payload.finish()?;
    Ok(name)
}
fn consume_string_set(decoder: &mut Decoder<'_>, maximum: u32) -> Result<()> {
    let count = bounded_count(decoder, maximum, 4)?;
    let mut seen = HashSet::with_capacity(count);
    for _ in 0..count {
        if !seen.insert(decoder.string()) {
            return Err(MapError::Malformed("duplicate string set entry"));
        }
    }
    decoder.finish()?;
    Ok(())
}
fn consume_always_on_modules(decoder: &mut Decoder<'_>, maximum: u32) -> Result<()> {
    let count = bounded_count(decoder, maximum, 8)?;
    let mut seen = HashSet::with_capacity(count);
    for _ in 0..count {
        let release = decoder.u32();
        if !seen.insert(release) {
            return Err(MapError::Malformed("duplicate mgr release"));
        }
        consume_string_set(decoder, maximum)?;
    }
    decoder.finish()?;
    Ok(())
}
fn decode_canonical_bool(decoder: &mut Decoder<'_>) -> Result<bool> {
    let value = decoder.u8();
    decoder.finish()?;
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(MapError::Malformed("non-canonical boolean")),
    }
}
