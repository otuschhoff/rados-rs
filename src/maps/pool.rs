use std::collections::{BTreeMap, HashMap, HashSet};

use crate::wire::{Decoder, WireError};

use super::{Limits, MapError, Result, UTime, bounded_count, decode_utime};

const POOL_TYPE_ERASURE: u8 = 3;
const POOL_FLAG_EC_OVERWRITES: u64 = 1 << 2;
const POOL_FLAG_SELF_MANAGED_SNAPSHOTS: u64 = 1 << 13;
const POOL_FLAG_POOL_SNAPSHOTS: u64 = 1 << 14;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PoolOptionType {
    String,
    Integer,
    Double,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum PoolOption {
    String(String),
    Integer(i64),
    Double(f64),
}

impl PoolOption {
    pub(crate) fn option_type(&self) -> PoolOptionType {
        match self {
            Self::String(_) => PoolOptionType::String,
            Self::Integer(_) => PoolOptionType::Integer,
            Self::Double(_) => PoolOptionType::Double,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PoolSnapshot {
    pub(crate) id: u64,
    pub(crate) name: String,
    pub(crate) timestamp: UTime,
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Pool {
    pub(super) id: i64,
    pub(super) name: String,
    pub(super) pool_type: u8,
    pub(super) size: u8,
    pub(super) minimum_size: u8,
    pub(super) crush_rule: u8,
    pub(super) object_hash: u8,
    pub(super) pg_count: u32,
    pub(super) placement_pg_count: u32,
    pub(super) stripe_width: u32,
    pub(super) flags: u64,
    pub(super) snapshot_sequence: u64,
    pub(super) snapshots: BTreeMap<u64, PoolSnapshot>,
    pub(super) erasure_code_profile: String,
    pub(super) application_metadata: HashMap<String, HashMap<String, String>>,
    pub(super) options: HashMap<i32, PoolOption>,
}

impl Pool {
    pub(crate) fn id(&self) -> i64 {
        self.id
    }
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
    pub(crate) fn pool_type(&self) -> u8 {
        self.pool_type
    }
    pub(crate) fn size(&self) -> u8 {
        self.size
    }
    pub(crate) fn minimum_size(&self) -> u8 {
        self.minimum_size
    }
    pub(crate) fn crush_rule(&self) -> u8 {
        self.crush_rule
    }
    pub(crate) fn object_hash(&self) -> u8 {
        self.object_hash
    }
    pub(crate) fn pg_count(&self) -> u32 {
        self.pg_count
    }
    pub(crate) fn placement_pg_count(&self) -> u32 {
        self.placement_pg_count
    }
    pub(crate) fn stripe_width(&self) -> u32 {
        self.stripe_width
    }
    pub(crate) fn flags(&self) -> u64 {
        self.flags
    }
    pub(crate) fn snapshot_sequence(&self) -> u64 {
        self.snapshot_sequence
    }
    pub(crate) fn snapshots(&self) -> impl ExactSizeIterator<Item = &PoolSnapshot> {
        self.snapshots.values()
    }
    pub(crate) fn erasure_code_profile(&self) -> &str {
        &self.erasure_code_profile
    }
    pub(crate) fn application_metadata(&self) -> &HashMap<String, HashMap<String, String>> {
        &self.application_metadata
    }
    pub(crate) fn options(&self) -> &HashMap<i32, PoolOption> {
        &self.options
    }
    pub(crate) fn uses_pool_snapshots(&self) -> bool {
        self.flags & POOL_FLAG_POOL_SNAPSHOTS != 0
    }
    pub(crate) fn uses_self_managed_snapshots(&self) -> bool {
        self.flags & POOL_FLAG_SELF_MANAGED_SNAPSHOTS != 0
    }
    pub(crate) fn is_erasure_coded(&self) -> bool {
        self.pool_type == POOL_TYPE_ERASURE
    }
    pub(crate) fn allows_ec_overwrites(&self) -> bool {
        self.flags & POOL_FLAG_EC_OVERWRITES != 0
    }
    pub(crate) fn requires_alignment(&self) -> bool {
        self.is_erasure_coded() && !self.allows_ec_overwrites()
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn decode_pool(decoder: &mut Decoder<'_>, limits: Limits) -> Result<Pool> {
    let (version, mut payload) = decoder.versioned(32);
    decoder.finish()?;
    if version < 5 {
        return Err(WireError::UnsupportedVersion {
            local: 32,
            required: 5,
        }
        .into());
    }
    let pool_type = payload.u8();
    let size = payload.u8();
    let crush_rule = payload.u8();
    let object_hash = payload.u8();
    let pg_count = payload.u32();
    let placement_pg_count = payload.u32();
    payload.u32();
    payload.u32();
    payload.u32();
    let snapshot_sequence = payload.u64();
    payload.u32();
    let snapshots = decode_pool_snapshots(&mut payload, limits)?;
    decode_intervals(&mut payload, limits.max_collection_entries)?;
    payload.u64();
    let mut flags = 0;
    if version >= 4 {
        flags = payload.u64();
        payload.u32();
    }
    let minimum_size = if version >= 7 {
        payload.u8()
    } else {
        size - size / 2
    };
    if version >= 8 {
        payload.u64();
        payload.u64();
    }
    if version >= 9 {
        consume_u64_set(&mut payload, limits.max_collection_entries)?;
        payload.i64();
        payload.u8();
        payload.i64();
        payload.i64();
    }
    if version >= 10 {
        decode_string_map(&mut payload, limits.max_collection_entries)?;
    }
    if version >= 11 {
        skip_versioned(&mut payload, 1)?;
        payload.u32();
        payload.u32();
    }
    let stripe_width = if version >= 12 { payload.u32() } else { 0 };
    if version >= 13 {
        payload.u64();
        payload.u64();
        for _ in 0..4 {
            payload.u32();
        }
    }
    let erasure_code_profile = if version >= 14 {
        payload.string()
    } else {
        String::new()
    };
    if version >= 15 {
        payload.u32();
    }
    if version >= 16 {
        payload.u32();
    }
    if version >= 17 {
        payload.u64();
    }
    if version >= 19 {
        payload.u32();
    }
    if version >= 20 {
        payload.u32();
    }
    if version >= 21 {
        payload.bool();
    }
    if version >= 22 {
        payload.bool();
    }
    if version >= 23 {
        payload.u32();
        payload.u32();
    }
    let options = if version >= 24 {
        decode_pool_options(&mut payload, limits)?
    } else {
        HashMap::new()
    };
    if version >= 25 {
        payload.u32();
    }
    let application_metadata = if version >= 26 {
        decode_nested_string_map(&mut payload, limits.max_collection_entries)?
    } else {
        HashMap::new()
    };
    if version >= 27 {
        decode_utime(&mut payload);
    }
    if version >= 28 {
        for _ in 0..6 {
            payload.u32();
        }
        payload.u8();
    }
    if version >= 29 {
        skip_versioned(&mut payload, 1)?;
    }
    if version == 30 {
        for _ in 0..3 {
            payload.u32();
        }
        payload.i32();
    }
    if version >= 31 && payload.bool() {
        for _ in 0..4 {
            payload.u32();
        }
    }
    if version >= 32 {
        consume_unsigned_varint(&mut payload)?;
        consume_unsigned_varint(&mut payload)?;
    }
    payload.finish()?;
    Ok(Pool {
        id: 0,
        name: String::new(),
        pool_type,
        size,
        minimum_size,
        crush_rule,
        object_hash,
        pg_count,
        placement_pg_count,
        stripe_width,
        flags,
        snapshot_sequence,
        snapshots,
        erasure_code_profile,
        application_metadata,
        options,
    })
}

fn decode_pool_options(
    decoder: &mut Decoder<'_>,
    limits: Limits,
) -> Result<HashMap<i32, PoolOption>> {
    let (version, mut payload) = decoder.versioned(2);
    decoder.finish()?;
    if version < 1 {
        return Err(WireError::UnsupportedVersion {
            local: 2,
            required: 1,
        }
        .into());
    }
    let count = bounded_count(&mut payload, limits.max_collection_entries, 8)?;
    let mut values = HashMap::with_capacity(count);
    for _ in 0..count {
        let key = payload.i32();
        let option = match payload.i32() {
            0 => PoolOption::String(payload.string()),
            1 => PoolOption::Integer(if version >= 2 {
                payload.i64()
            } else {
                i64::from(payload.i32())
            }),
            2 => PoolOption::Double(f64::from_bits(payload.u64())),
            _ => return Err(MapError::Malformed("unsupported pool option type")),
        };
        if values.insert(key, option).is_some() {
            return Err(MapError::Malformed("duplicate pool option"));
        }
    }
    payload.finish()?;
    Ok(values)
}

fn decode_pool_snapshots(
    decoder: &mut Decoder<'_>,
    limits: Limits,
) -> Result<BTreeMap<u64, PoolSnapshot>> {
    let count = bounded_count(decoder, limits.max_collection_entries, 14)?;
    let mut values = BTreeMap::new();
    let mut names = HashSet::with_capacity(count);
    for _ in 0..count {
        let key = decoder.u64();
        let (version, mut payload) = decoder.versioned(2);
        decoder.finish()?;
        if version < 2 {
            return Err(WireError::UnsupportedVersion {
                local: 2,
                required: 2,
            }
            .into());
        }
        let snapshot = PoolSnapshot {
            id: payload.u64(),
            timestamp: decode_utime(&mut payload),
            name: payload.string(),
        };
        payload.finish()?;
        if key != snapshot.id || values.contains_key(&key) || !names.insert(snapshot.name.clone()) {
            return Err(MapError::Malformed("duplicate or mismatched pool snapshot"));
        }
        values.insert(key, snapshot);
    }
    decoder.finish()?;
    Ok(values)
}

pub(super) fn decode_intervals(
    decoder: &mut Decoder<'_>,
    maximum: u32,
) -> Result<Vec<super::Interval>> {
    let count = bounded_count(decoder, maximum, 16)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(super::Interval {
            start: decoder.u64(),
            length: decoder.u64(),
        });
    }
    decoder.finish()?;
    Ok(values)
}

fn consume_u64_set(decoder: &mut Decoder<'_>, maximum: u32) -> Result<()> {
    let count = bounded_count(decoder, maximum, 8)?;
    for _ in 0..count {
        decoder.u64();
    }
    decoder.finish()?;
    Ok(())
}

pub(super) fn decode_string_map(
    decoder: &mut Decoder<'_>,
    maximum: u32,
) -> Result<HashMap<String, String>> {
    let count = bounded_count(decoder, maximum, 8)?;
    let mut values = HashMap::with_capacity(count);
    for _ in 0..count {
        let key = decoder.string();
        let value = decoder.string();
        if values.insert(key, value).is_some() {
            return Err(MapError::Malformed("duplicate string key"));
        }
    }
    decoder.finish()?;
    Ok(values)
}

pub(super) fn decode_nested_string_map(
    decoder: &mut Decoder<'_>,
    maximum: u32,
) -> Result<HashMap<String, HashMap<String, String>>> {
    let count = bounded_count(decoder, maximum, 8)?;
    let mut values = HashMap::with_capacity(count);
    for _ in 0..count {
        let key = decoder.string();
        let value = decode_string_map(decoder, maximum)?;
        if values.insert(key, value).is_some() {
            return Err(MapError::Malformed("duplicate nested string key"));
        }
    }
    decoder.finish()?;
    Ok(values)
}

pub(super) fn skip_versioned(decoder: &mut Decoder<'_>, local: u8) -> Result<()> {
    let (_, payload) = decoder.versioned(local);
    decoder.finish()?;
    payload.finish()?;
    Ok(())
}

fn consume_unsigned_varint(decoder: &mut Decoder<'_>) -> Result<()> {
    for index in 0..10 {
        let value = decoder.u8();
        decoder.finish()?;
        if value & 0x80 == 0 {
            return if index == 9 && value > 1 {
                Err(WireError::Malformed.into())
            } else {
                Ok(())
            };
        }
    }
    Err(WireError::Malformed.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Encoder;

    #[test]
    fn snapshots_reject_duplicate_names_and_mismatched_ids() {
        for (keys, ids, names) in [
            (vec![2, 2], vec![2, 2], vec!["a", "b"]),
            (vec![2], vec![3], vec!["a"]),
            (vec![2, 3], vec![2, 3], vec!["a", "a"]),
        ] {
            let mut encoder = Encoder::new(1024);
            encoder.u32(u32::try_from(keys.len()).expect("test vector length"));
            for ((key, id), name) in keys.iter().zip(&ids).zip(&names) {
                encoder.u64(*key);
                encoder.versioned(2, 2, |snapshot| {
                    snapshot.u64(*id);
                    snapshot.u32(1);
                    snapshot.u32(2);
                    snapshot.string(name);
                });
            }
            let bytes = encoder.finish().expect("snapshot encoding");
            let mut decoder = Decoder::new(&bytes, 1024);
            assert!(matches!(
                decode_pool_snapshots(
                    &mut decoder,
                    Limits {
                        max_bytes: 1024,
                        max_collection_entries: 8,
                        ..Limits::default()
                    }
                ),
                Err(MapError::Malformed(_))
            ));
        }
    }

    #[test]
    fn unsigned_varints_reject_overflow() {
        let bytes = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 2];
        assert_eq!(
            consume_unsigned_varint(&mut Decoder::new(&bytes, bytes.len())),
            Err(MapError::Wire(WireError::Malformed))
        );
    }
}
