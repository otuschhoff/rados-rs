#![forbid(unsafe_code)]

mod incremental;
mod mgrmap;
mod monmap;
mod osdmap;
mod pool;
mod store;

#[cfg(all(test, not(rados_packaged_source)))]
mod fixture_tests;

use std::fmt;

use crate::wire::{Decoder, WireError};

pub(crate) use incremental::{
    OSDMapIncremental, apply_osdmap_incremental, decode_osdmap_incremental,
};
pub(crate) use mgrmap::{MgrMap, decode_mgrmap};
pub(crate) use monmap::{MonMap, decode_monmap};
pub(crate) use osdmap::{Interval, OSDMap, OSDRemap, PG, decode_osdmap};
pub(crate) use pool::Pool;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MapError {
    Wire(WireError),
    Malformed(&'static str),
    InvalidSequence,
    FsidMismatch,
    LockPoisoned,
}

impl fmt::Display for MapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => write!(formatter, "{error}"),
            Self::Malformed(reason) => write!(formatter, "malformed Ceph map: {reason}"),
            Self::InvalidSequence => formatter.write_str("invalid Ceph map epoch sequence"),
            Self::FsidMismatch => formatter.write_str("Ceph map FSID mismatch"),
            Self::LockPoisoned => formatter.write_str("Ceph map store lock poisoned"),
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

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) struct Fsid(pub(crate) [u8; 16]);

impl fmt::Display for Fsid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0;
        write!(
            formatter,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
            bytes[4],
            bytes[5],
            bytes[6],
            bytes[7],
            bytes[8],
            bytes[9],
            bytes[10],
            bytes[11],
            bytes[12],
            bytes[13],
            bytes[14],
            bytes[15]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fsid_uses_canonical_uuid_format() {
        let fsid = Fsid([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        assert_eq!(fsid.to_string(), "00010203-0405-0607-0809-0a0b0c0d0e0f");
    }

    #[test]
    fn bounded_count_rejects_limits_and_impossible_lengths() {
        let count = 2_u32.to_le_bytes();
        let mut limited = Decoder::new(&count, 4);
        assert_eq!(
            bounded_count(&mut limited, 1, 0),
            Err(MapError::Wire(WireError::LimitExceeded))
        );

        let mut truncated = Decoder::new(&count, 4);
        assert_eq!(
            bounded_count(&mut truncated, 2, 1),
            Err(MapError::Wire(WireError::Malformed))
        );
    }
}
