use std::collections::{HashMap, HashSet};

use crate::protocol::address::EntityAddrVec;
use crate::wire::{Decoder, WireError};

use super::{
    Fsid, Limits, MapError, Result, UTime, bounded_count, decode_strings, decode_u32s,
    decode_utime, require_timestamp,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Monitor {
    pub(crate) name: String,
    pub(crate) addresses: EntityAddrVec,
    pub(crate) priority: u16,
    pub(crate) weight: u16,
    pub(crate) location: HashMap<String, String>,
}

#[derive(Clone, Debug)]
pub(crate) struct MonMap {
    pub(super) fsid: Fsid,
    pub(super) epoch: u32,
    pub(super) last_changed: UTime,
    pub(super) created: UTime,
    pub(super) persistent_features: u64,
    pub(super) optional_features: u64,
    pub(super) monitors: HashMap<String, Monitor>,
    pub(super) ranks: Vec<String>,
    pub(super) minimum_monitor_release: u8,
    pub(super) removed_ranks: Vec<u32>,
    pub(super) election_strategy: u8,
    pub(super) disallowed_leaders: Vec<String>,
    pub(super) stretch_mode: bool,
    pub(super) tiebreaker_monitor: String,
    pub(super) stretch_marked_down: Vec<String>,
}

impl MonMap {
    pub(crate) fn fsid(&self) -> Fsid {
        self.fsid
    }
    pub(crate) fn epoch(&self) -> u32 {
        self.epoch
    }
    pub(crate) fn monitor(&self, name: &str) -> Option<&Monitor> {
        self.monitors.get(name)
    }
    pub(crate) fn monitors(&self) -> impl ExactSizeIterator<Item = (&str, &Monitor)> {
        self.monitors
            .iter()
            .map(|(name, monitor)| (name.as_str(), monitor))
    }
    pub(crate) fn ranks(&self) -> &[String] {
        &self.ranks
    }
    pub(crate) fn last_changed(&self) -> UTime {
        self.last_changed
    }
    pub(crate) fn created(&self) -> UTime {
        self.created
    }
    pub(crate) fn persistent_features(&self) -> u64 {
        self.persistent_features
    }
    pub(crate) fn optional_features(&self) -> u64 {
        self.optional_features
    }
    pub(crate) fn minimum_monitor_release(&self) -> u8 {
        self.minimum_monitor_release
    }
    pub(crate) fn removed_ranks(&self) -> &[u32] {
        &self.removed_ranks
    }
    pub(crate) fn election_strategy(&self) -> u8 {
        self.election_strategy
    }
    pub(crate) fn disallowed_leaders(&self) -> &[String] {
        &self.disallowed_leaders
    }
    pub(crate) fn stretch_mode_enabled(&self) -> bool {
        self.stretch_mode
    }
    pub(crate) fn tiebreaker_monitor(&self) -> &str {
        &self.tiebreaker_monitor
    }
    pub(crate) fn stretch_marked_down(&self) -> &[String] {
        &self.stretch_marked_down
    }
}

pub(crate) fn decode_monmap(data: &[u8], limits: Limits) -> Result<MonMap> {
    if limits.max_bytes == 0
        || limits.max_monitors == 0
        || limits.max_addresses == 0
        || limits.max_locations == 0
    {
        return Err(WireError::LimitExceeded.into());
    }
    let mut decoder = Decoder::new(data, limits.max_bytes as usize);
    let (version, mut payload) = decoder.versioned(9);
    decoder.finish()?;
    if version < 6 {
        return Err(WireError::UnsupportedVersion {
            local: 9,
            required: 6,
        }
        .into());
    }
    let fsid = Fsid(
        payload
            .raw(16)
            .try_into()
            .map_err(|_| WireError::Malformed)?,
    );
    let epoch = payload.u32();
    let last_changed = decode_utime(&mut payload);
    let created = decode_utime(&mut payload);
    let persistent_features = decode_monitor_features(&mut payload)?;
    let optional_features = decode_monitor_features(&mut payload)?;
    let count = bounded_count(&mut payload, limits.max_monitors, 5)?;
    let mut monitors = HashMap::with_capacity(count);
    for _ in 0..count {
        let key = payload.string();
        let monitor = decode_monitor(&mut payload, limits)?;
        if key != monitor.name || monitors.insert(key, monitor).is_some() {
            return Err(MapError::Malformed("duplicate or mismatched monitor"));
        }
    }
    let ranks = decode_strings(&mut payload, limits.max_monitors)?;
    if ranks.len() != monitors.len() {
        return Err(MapError::Malformed("monitor rank count mismatch"));
    }
    let mut seen = HashSet::with_capacity(ranks.len());
    if ranks
        .iter()
        .any(|name| !monitors.contains_key(name) || !seen.insert(name))
    {
        return Err(MapError::Malformed("invalid monitor rank"));
    }
    let minimum_monitor_release = if version >= 7 { payload.u8() } else { 0 };
    let (removed_ranks, election_strategy, disallowed_leaders) = if version >= 8 {
        (
            decode_u32s(&mut payload, limits.max_monitors)?,
            payload.u8(),
            decode_strings(&mut payload, limits.max_monitors)?,
        )
    } else {
        (Vec::new(), 0, Vec::new())
    };
    let (stretch_mode, tiebreaker_monitor, stretch_marked_down) = if version >= 9 {
        (
            payload.bool(),
            payload.string(),
            decode_strings(&mut payload, limits.max_monitors)?,
        )
    } else {
        (false, String::new(), Vec::new())
    };
    payload.finish()?;
    decoder.finish()?;
    if decoder.remaining() != 0 {
        return Err(MapError::Malformed("trailing monmap bytes"));
    }
    Ok(MonMap {
        fsid,
        epoch,
        last_changed: require_timestamp(last_changed)?,
        created: require_timestamp(created)?,
        persistent_features,
        optional_features,
        monitors,
        ranks,
        minimum_monitor_release,
        removed_ranks,
        election_strategy,
        disallowed_leaders,
        stretch_mode,
        tiebreaker_monitor,
        stretch_marked_down,
    })
}

fn decode_monitor(decoder: &mut Decoder<'_>, limits: Limits) -> Result<Monitor> {
    let (version, mut payload) = decoder.versioned(5);
    decoder.finish()?;
    if version < 1 {
        return Err(WireError::UnsupportedVersion {
            local: 5,
            required: 1,
        }
        .into());
    }
    let name = payload.string();
    let addresses = EntityAddrVec::decode(&mut payload, limits.max_addresses)?;
    let priority = if version >= 2 { payload.u16() } else { 0 };
    let weight = if version >= 4 { payload.u16() } else { 0 };
    let mut location = HashMap::new();
    if version >= 5 {
        let count = bounded_count(&mut payload, limits.max_locations, 8)?;
        location.reserve(count);
        for _ in 0..count {
            let key = payload.string();
            let value = payload.string();
            if location.insert(key, value).is_some() {
                return Err(MapError::Malformed("duplicate monitor location"));
            }
        }
    }
    payload.finish()?;
    Ok(Monitor {
        name,
        addresses,
        priority,
        weight,
        location,
    })
}

fn decode_monitor_features(decoder: &mut Decoder<'_>) -> Result<u64> {
    let (_, mut payload) = decoder.versioned(1);
    decoder.finish()?;
    let features = payload.u64();
    payload.finish()?;
    Ok(features)
}
