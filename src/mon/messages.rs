use std::collections::BTreeMap;
use std::fmt;

use crate::maps::{
    Fsid, Limits as MapLimits, MapError, MgrMap, MonMap, OSDMap, OSDMapIncremental, decode_mgrmap,
    decode_monmap, decode_osdmap, decode_osdmap_incremental,
};
use crate::msgr::message::{Message, MessageHeader, MessageLengths};
use crate::wire::{Decoder, Encoder, WireError};

pub(crate) const MESSAGE_MON_MAP: u16 = 4;
pub(crate) const MESSAGE_STATFS: u16 = 13;
pub(crate) const MESSAGE_STATFS_REPLY: u16 = 14;
pub(crate) const MESSAGE_MON_SUBSCRIBE: u16 = 15;
pub(crate) const MESSAGE_MON_SUBSCRIBE_ACK: u16 = 16;
pub(crate) const MESSAGE_OSD_MAP: u16 = 41;
pub(crate) const MESSAGE_POOL_OPERATION_REPLY: u16 = 48;
pub(crate) const MESSAGE_POOL_OPERATION: u16 = 49;
pub(crate) const MESSAGE_MON_COMMAND: u16 = 50;
pub(crate) const MESSAGE_MON_COMMAND_REPLY: u16 = 51;
pub(crate) const MESSAGE_GET_POOL_STATS: u16 = 58;
pub(crate) const MESSAGE_GET_POOL_STATS_REPLY: u16 = 59;
pub(crate) const MESSAGE_MGR_MAP: u16 = 0x704;
pub(crate) const SUBSCRIBE_ONCE: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PoolOperation {
    CreatePool,
    DeletePool,
    CreateSnapshot,
    DeleteSnapshot,
    CreateSelfManaged,
    DeleteSelfManaged,
}

impl PoolOperation {
    const fn code(self) -> u32 {
        match self {
            Self::CreatePool => 0x01,
            Self::DeletePool => 0x02,
            Self::CreateSnapshot => 0x11,
            Self::DeleteSnapshot => 0x12,
            Self::CreateSelfManaged => 0x21,
            Self::DeleteSelfManaged => 0x22,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StatFsReply {
    pub(crate) fsid: Fsid,
    pub(crate) version: u64,
    pub(crate) kib: u64,
    pub(crate) kib_used: u64,
    pub(crate) kib_available: u64,
    pub(crate) objects: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PoolStats {
    pub(crate) bytes_used: u64,
    pub(crate) objects: u64,
    pub(crate) read_bytes: u64,
    pub(crate) write_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PoolStatsReply {
    pub(crate) fsid: Fsid,
    pub(crate) version: u64,
    pub(crate) pools: BTreeMap<String, PoolStats>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PoolOperationReply {
    pub(crate) fsid: Fsid,
    pub(crate) result: i32,
    pub(crate) epoch: u32,
    pub(crate) response_data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CommandReply {
    pub(crate) version: u64,
    pub(crate) result: i32,
    pub(crate) status: String,
    pub(crate) command: Vec<String>,
    pub(crate) data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Subscription {
    pub(crate) start: u64,
    pub(crate) flags: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SubscribeAck {
    pub(crate) interval_seconds: u32,
    pub(crate) fsid: Fsid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MessageLimits {
    pub(crate) max_bytes: u32,
    pub(crate) max_maps: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OSDMapBatch {
    pub(crate) fsid: Fsid,
    pub(crate) incrementals: BTreeMap<u32, Vec<u8>>,
    pub(crate) full_maps: BTreeMap<u32, Vec<u8>>,
    pub(crate) trim_lower_bound: u32,
    pub(crate) newest_map: u32,
}

#[derive(Clone, Debug)]
pub(crate) struct DecodedOSDMapBatch {
    pub(crate) fsid: Fsid,
    pub(crate) incrementals: BTreeMap<u32, OSDMapIncremental>,
    pub(crate) full_maps: BTreeMap<u32, OSDMap>,
    pub(crate) trim_lower_bound: u32,
    pub(crate) newest_map: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MessageError {
    Wire(WireError),
    Map(MapError),
    Malformed(&'static str),
    UnsupportedVersion,
}

impl fmt::Display for MessageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => write!(formatter, "{error}"),
            Self::Map(error) => write!(formatter, "{error}"),
            Self::Malformed(reason) => write!(formatter, "malformed monitor message: {reason}"),
            Self::UnsupportedVersion => formatter.write_str("unsupported monitor message version"),
        }
    }
}

impl std::error::Error for MessageError {}

impl From<WireError> for MessageError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl From<MapError> for MessageError {
    fn from(error: MapError) -> Self {
        Self::Map(error)
    }
}

pub(crate) type Result<T> = std::result::Result<T, MessageError>;

pub(crate) fn encode_subscribe(
    subscriptions: &BTreeMap<String, Subscription>,
    hostname: &str,
    max_bytes: u32,
) -> Result<Message> {
    if max_bytes == 0 {
        return Err(WireError::LimitExceeded.into());
    }
    let count = u32::try_from(subscriptions.len()).map_err(|_| WireError::LimitExceeded)?;
    let mut encoder = Encoder::new(max_bytes as usize);
    encoder.u32(count);
    for (name, subscription) in subscriptions {
        encoder.string(name);
        encoder.u64(subscription.start);
        encoder.u8(subscription.flags);
    }
    encoder.string(hostname);
    front_message(MESSAGE_MON_SUBSCRIBE, 3, 1, encoder.finish()?)
}

pub(crate) fn encode_pool_operation(
    fsid: Fsid,
    have_version: u64,
    pool: u32,
    operation: PoolOperation,
    snapshot: u64,
    name: &str,
    max_bytes: u32,
) -> Result<Message> {
    let valid = match operation {
        PoolOperation::CreatePool => pool == 0 && snapshot == 0 && !name.is_empty(),
        PoolOperation::DeletePool => pool != 0 && snapshot == 0 && name == "delete",
        PoolOperation::CreateSnapshot | PoolOperation::DeleteSnapshot => {
            snapshot == 0 && !name.is_empty()
        }
        PoolOperation::CreateSelfManaged => snapshot == 0 && name.is_empty(),
        PoolOperation::DeleteSelfManaged => snapshot != 0 && name.is_empty(),
    };
    if !valid || max_bytes == 0 {
        return Err(WireError::Malformed.into());
    }
    let mut encoder = Encoder::new(max_bytes as usize);
    encoder.u64(have_version);
    encoder.i16(-1);
    encoder.u64(0);
    encoder.raw(&fsid.0);
    encoder.u32(pool);
    encoder.u32(operation.code());
    encoder.u64(0);
    encoder.u64(snapshot);
    encoder.string(name);
    encoder.u8(0);
    encoder.i16(0);
    front_message(MESSAGE_POOL_OPERATION, 4, 2, encoder.finish()?)
}

pub(crate) fn encode_statfs(fsid: Fsid, have_version: u64, max_bytes: u32) -> Result<Message> {
    if max_bytes == 0 {
        return Err(WireError::LimitExceeded.into());
    }
    let mut encoder = Encoder::new(max_bytes as usize);
    encoder.u64(have_version);
    encoder.i16(-1);
    encoder.u64(0);
    encoder.raw(&fsid.0);
    encoder.u8(0);
    front_message(MESSAGE_STATFS, 2, 1, encoder.finish()?)
}

pub(crate) fn decode_statfs_reply(message: &Message, max_bytes: u32) -> Result<StatFsReply> {
    validate_front_message(message, MESSAGE_STATFS_REPLY, max_bytes)?;
    if message.header.version < 1 || message.header.compat_version > 1 {
        return Err(MessageError::UnsupportedVersion);
    }
    let mut decoder = Decoder::new(&message.front, max_bytes as usize);
    let fsid = decode_fsid(&mut decoder)?;
    let version = decoder.u64();
    let kib = decoder.u64();
    let kib_used = decoder.u64();
    let kib_available = decoder.u64();
    let objects = decoder.u64();
    finish_exact(&decoder, "statfs reply")?;
    Ok(StatFsReply {
        fsid,
        version,
        kib,
        kib_used,
        kib_available,
        objects,
    })
}

pub(crate) fn encode_get_pool_stats(
    fsid: Fsid,
    have_version: u64,
    pools: &[String],
    max_bytes: u32,
) -> Result<Message> {
    if max_bytes == 0 || pools.is_empty() {
        return Err(WireError::LimitExceeded.into());
    }
    let count = u32::try_from(pools.len()).map_err(|_| WireError::LimitExceeded)?;
    let mut encoder = Encoder::new(max_bytes as usize);
    encoder.u64(have_version);
    encoder.i16(-1);
    encoder.u64(0);
    encoder.raw(&fsid.0);
    encoder.u32(count);
    for pool in pools {
        if pool.is_empty() {
            return Err(WireError::Malformed.into());
        }
        encoder.string(pool);
    }
    front_message(MESSAGE_GET_POOL_STATS, 1, 0, encoder.finish()?)
}

pub(crate) fn decode_get_pool_stats_reply(
    message: &Message,
    max_bytes: u32,
    max_pools: u32,
    max_entries: u32,
) -> Result<PoolStatsReply> {
    if max_pools == 0 || max_entries == 0 {
        return Err(WireError::LimitExceeded.into());
    }
    validate_front_message(message, MESSAGE_GET_POOL_STATS_REPLY, max_bytes)?;
    if message.header.version == 0
        || message.header.version > 2
        || message.header.compat_version > 1
    {
        return Err(MessageError::UnsupportedVersion);
    }
    let mut decoder = Decoder::new(&message.front, max_bytes as usize);
    let version = decode_paxos_header(&mut decoder);
    let fsid = decode_fsid(&mut decoder)?;
    let count = decoder.u32();
    if count > max_pools {
        return Err(WireError::LimitExceeded.into());
    }
    let mut raw = BTreeMap::new();
    for _ in 0..count {
        let name = decoder.string();
        if raw.contains_key(&name) {
            return Err(MessageError::Malformed("duplicate pool stats entry"));
        }
        let stats = decode_pool_stats(&mut decoder, max_entries)?;
        raw.insert(name, stats);
    }
    let per_pool = message.header.version >= 2 && decoder.bool();
    finish_exact(&decoder, "get pool stats reply")?;

    let mut pools = BTreeMap::new();
    for (name, stats) in raw {
        let values = [
            stats.num_bytes,
            stats.objects,
            stats.read_kib,
            stats.write_kib,
            stats.hit_set_bytes,
            stats.omap_bytes,
            stats.allocated,
            stats.omap_allocated,
        ];
        if values.iter().any(|value| *value < 0) {
            return Err(MessageError::Malformed("negative pool stats field"));
        }
        let bytes_used = if per_pool {
            add_u64_checked(&[
                stats.allocated.cast_unsigned(),
                stats.omap_allocated.cast_unsigned(),
            ])?
        } else {
            add_u64_checked(&[
                stats.num_bytes.cast_unsigned(),
                stats.hit_set_bytes.cast_unsigned(),
                stats.omap_bytes.cast_unsigned(),
            ])?
        };
        let read_kib = stats.read_kib.cast_unsigned();
        let write_kib = stats.write_kib.cast_unsigned();
        if read_kib > (u64::MAX >> 10) || write_kib > (u64::MAX >> 10) {
            return Err(WireError::LimitExceeded.into());
        }
        pools.insert(
            name,
            PoolStats {
                bytes_used,
                objects: stats.objects.cast_unsigned(),
                read_bytes: read_kib << 10,
                write_bytes: write_kib << 10,
            },
        );
    }
    Ok(PoolStatsReply {
        fsid,
        version,
        pools,
    })
}

pub(crate) fn encode_command(
    fsid: Fsid,
    command: &[String],
    input: &[u8],
    max_bytes: u32,
) -> Result<Message> {
    if max_bytes == 0 || input.len() > max_bytes as usize {
        return Err(WireError::LimitExceeded.into());
    }
    let count = u32::try_from(command.len()).map_err(|_| WireError::LimitExceeded)?;
    let mut encoder = Encoder::new(max_bytes as usize);
    encoder.u64(0);
    encoder.i16(-1);
    encoder.u64(0);
    encoder.raw(&fsid.0);
    encoder.u32(count);
    for value in command {
        encoder.string(value);
    }
    let mut message = front_message(MESSAGE_MON_COMMAND, 1, 0, encoder.finish()?)?;
    message.lengths.data = u32::try_from(input.len()).map_err(|_| WireError::LimitExceeded)?;
    message.data = input.to_vec();
    Ok(message)
}

pub(crate) fn decode_command_reply(
    message: &Message,
    max_bytes: u32,
    max_command_items: u32,
) -> Result<CommandReply> {
    if max_command_items == 0 {
        return Err(WireError::LimitExceeded.into());
    }
    validate_message_payload(message, MESSAGE_MON_COMMAND_REPLY, max_bytes)?;
    let mut decoder = Decoder::new(&message.front, max_bytes as usize);
    let version = decoder.u64();
    decoder.i16();
    decoder.u64();
    let result = decoder.i32();
    let status = decoder.string();
    let count = decoder.u32();
    decoder.finish()?;
    if count > max_command_items || u64::from(count) > decoder.remaining() as u64 / 4 {
        return Err(WireError::LimitExceeded.into());
    }
    let mut command = Vec::with_capacity(count as usize);
    for _ in 0..count {
        command.push(decoder.string());
    }
    finish_exact(&decoder, "monitor command acknowledgement")?;
    Ok(CommandReply {
        version,
        result,
        status,
        command,
        data: message.data.clone(),
    })
}

fn decode_paxos_header(decoder: &mut Decoder<'_>) -> u64 {
    let version = decoder.u64();
    decoder.i16();
    decoder.u64();
    version
}

#[derive(Clone, Copy, Debug)]
struct RawPoolStats {
    num_bytes: i64,
    objects: i64,
    read_kib: i64,
    write_kib: i64,
    hit_set_bytes: i64,
    omap_bytes: i64,
    allocated: i64,
    omap_allocated: i64,
}

fn decode_pool_stats(decoder: &mut Decoder<'_>, max_entries: u32) -> Result<RawPoolStats> {
    let mut result = RawPoolStats {
        num_bytes: 0,
        objects: 0,
        read_kib: 0,
        write_kib: 0,
        hit_set_bytes: 0,
        omap_bytes: 0,
        allocated: 0,
        omap_allocated: 0,
    };

    let (version, mut payload) = decoder.versioned(7);
    if let Err(error) = decoder.finish() {
        return Err(error.into());
    }
    if version != 7 {
        return Err(MessageError::UnsupportedVersion);
    }

    let (collection_version, mut collection) = payload.versioned(2);
    if let Err(error) = payload.finish() {
        return Err(error.into());
    }
    if collection_version != 2 {
        return Err(MessageError::UnsupportedVersion);
    }

    let (sum_version, mut sum) = collection.versioned(20);
    if let Err(error) = collection.finish() {
        return Err(error.into());
    }
    if sum_version != 20 {
        return Err(MessageError::UnsupportedVersion);
    }
    for index in 0..40 {
        let value = if (28..=31).contains(&index) {
            i64::from(sum.i32())
        } else {
            sum.i64()
        };
        match index {
            0 => result.num_bytes = value,
            1 => result.objects = value,
            8 => result.read_kib = value,
            10 => result.write_kib = value,
            22 => result.hit_set_bytes = value,
            37 => result.omap_bytes = value,
            _ => {}
        }
    }
    if sum.finish().is_err() || sum.remaining() != 0 {
        return Err(MessageError::Malformed("pool stats sum"));
    }

    let categories = collection.u32();
    if categories > max_entries {
        return Err(WireError::LimitExceeded.into());
    }
    for _ in 0..categories {
        let _ = collection.string();
        skip_object_stat_sum(&mut collection)?;
    }
    if collection.finish().is_err() || collection.remaining() != 0 {
        return Err(MessageError::Malformed("pool stats categories"));
    }

    payload.i64();
    payload.i64();
    payload.i32();
    payload.i32();

    let (store_version, mut store) = payload.versioned(1);
    if let Err(error) = payload.finish() {
        return Err(error.into());
    }
    if store_version != 1 {
        return Err(MessageError::UnsupportedVersion);
    }
    store.u64();
    store.u64();
    store.u64();
    result.allocated = store.i64();
    store.i64();
    store.i64();
    store.i64();
    store.i64();
    result.omap_allocated = store.i64();
    store.i64();
    if store.finish().is_err() || store.remaining() != 0 {
        return Err(MessageError::Malformed("pool stats store"));
    }

    payload.i32();
    if payload.finish().is_err() || payload.remaining() != 0 {
        return Err(MessageError::Malformed("pool stats payload"));
    }
    Ok(result)
}

fn skip_object_stat_sum(decoder: &mut Decoder<'_>) -> Result<()> {
    let (version, mut payload) = decoder.versioned(20);
    if let Err(error) = decoder.finish() {
        return Err(error.into());
    }
    if version != 20 {
        return Err(MessageError::UnsupportedVersion);
    }
    for index in 0..40 {
        if (28..=31).contains(&index) {
            payload.i32();
        } else {
            payload.i64();
        }
    }
    if payload.finish().is_err() || payload.remaining() != 0 {
        return Err(MessageError::Malformed("object stat sum"));
    }
    Ok(())
}

fn add_u64_checked(values: &[u64]) -> Result<u64> {
    let mut result = 0_u64;
    for value in values {
        result = result.checked_add(*value).ok_or(WireError::LimitExceeded)?;
    }
    Ok(result)
}

pub(crate) fn decode_pool_operation_reply(
    message: &Message,
    max_bytes: u32,
) -> Result<PoolOperationReply> {
    validate_front_message(message, MESSAGE_POOL_OPERATION_REPLY, max_bytes)?;
    if message.header.compat_version > 1 {
        return Err(MessageError::UnsupportedVersion);
    }
    let mut decoder = Decoder::new(&message.front, max_bytes as usize);
    decoder.u64();
    decoder.i16();
    decoder.u64();
    let fsid = decode_fsid(&mut decoder)?;
    let result = decoder.i32();
    let epoch = decoder.u32();
    let has_response_data = decoder.u8();
    let response_data = match has_response_data {
        0 => Vec::new(),
        1 => decoder.bytes(),
        _ => return Err(MessageError::Malformed("pool operation response-data flag")),
    };
    finish_exact(&decoder, "pool operation reply")?;
    Ok(PoolOperationReply {
        fsid,
        result,
        epoch,
        response_data,
    })
}

pub(crate) fn decode_allocated_snapshot_id(data: &[u8], max_bytes: usize) -> Result<u64> {
    let mut decoder = Decoder::new(data, max_bytes);
    let snapshot = decoder.u64();
    finish_exact(&decoder, "allocated snapshot ID")?;
    if snapshot == 0 {
        return Err(MessageError::Malformed("zero allocated snapshot ID"));
    }
    Ok(snapshot)
}

pub(crate) fn decode_subscribe_ack(message: &Message, max_bytes: u32) -> Result<SubscribeAck> {
    validate_front_message(message, MESSAGE_MON_SUBSCRIBE_ACK, max_bytes)?;
    let mut decoder = Decoder::new(&message.front, max_bytes as usize);
    let interval_seconds = decoder.u32();
    let fsid = decode_fsid(&mut decoder)?;
    finish_exact(&decoder, "subscribe acknowledgement")?;
    Ok(SubscribeAck {
        interval_seconds,
        fsid,
    })
}

pub(crate) fn decode_monmap_message(message: &Message, limits: MapLimits) -> Result<MonMap> {
    validate_front_message(message, MESSAGE_MON_MAP, limits.max_bytes)?;
    let mut decoder = Decoder::new(&message.front, limits.max_bytes as usize);
    let encoded = decoder.bytes();
    finish_exact(&decoder, "monmap")?;
    Ok(decode_monmap(&encoded, limits)?)
}

pub(crate) fn decode_mgrmap_message(message: &Message, limits: MapLimits) -> Result<MgrMap> {
    validate_front_message(message, MESSAGE_MGR_MAP, limits.max_bytes)?;
    if message.header.version != 1 || message.header.compat_version != 1 {
        return Err(MessageError::UnsupportedVersion);
    }
    Ok(decode_mgrmap(&message.front, limits)?)
}

pub(crate) fn decode_osdmap_batch(message: &Message, limits: MessageLimits) -> Result<OSDMapBatch> {
    if limits.max_bytes == 0 || limits.max_maps == 0 {
        return Err(WireError::LimitExceeded.into());
    }
    validate_front_message(message, MESSAGE_OSD_MAP, limits.max_bytes)?;
    if message.header.version < 3 || message.header.compat_version > 4 {
        return Err(MessageError::UnsupportedVersion);
    }
    let mut decoder = Decoder::new(&message.front, limits.max_bytes as usize);
    let fsid = decode_fsid(&mut decoder)?;
    let incrementals = decode_map_blobs(&mut decoder, limits.max_maps)?;
    let full_maps = decode_map_blobs(&mut decoder, limits.max_maps)?;
    let trim_lower_bound = decoder.u32();
    let newest_map = decoder.u32();
    if message.header.version >= 4 && decoder.u32() != 0 {
        return Err(MessageError::UnsupportedVersion);
    }
    finish_exact(&decoder, "osdmap")?;
    Ok(OSDMapBatch {
        fsid,
        incrementals,
        full_maps,
        trim_lower_bound,
        newest_map,
    })
}

pub(crate) fn decode_osdmap_batch_maps(
    batch: &OSDMapBatch,
    limits: MapLimits,
) -> Result<DecodedOSDMapBatch> {
    let mut incrementals = BTreeMap::new();
    for (&epoch, encoded) in &batch.incrementals {
        let map = decode_osdmap_incremental(encoded, limits)?;
        validate_map_identity(batch.fsid, epoch, map.fsid(), map.epoch())?;
        incrementals.insert(epoch, map);
    }
    let mut full_maps = BTreeMap::new();
    for (&epoch, encoded) in &batch.full_maps {
        let map = decode_osdmap(encoded, limits)?;
        validate_map_identity(batch.fsid, epoch, map.fsid(), map.epoch())?;
        full_maps.insert(epoch, map);
    }
    Ok(DecodedOSDMapBatch {
        fsid: batch.fsid,
        incrementals,
        full_maps,
        trim_lower_bound: batch.trim_lower_bound,
        newest_map: batch.newest_map,
    })
}

fn decode_map_blobs(decoder: &mut Decoder<'_>, maximum: u32) -> Result<BTreeMap<u32, Vec<u8>>> {
    let count = decoder.u32();
    decoder.finish()?;
    if count > maximum {
        return Err(WireError::LimitExceeded.into());
    }
    let count = usize::try_from(count).map_err(|_| WireError::LimitExceeded)?;
    if count > decoder.remaining() / 8 {
        return Err(WireError::Malformed.into());
    }
    let mut values = BTreeMap::new();
    for _ in 0..count {
        let epoch = decoder.u32();
        let value = decoder.bytes();
        decoder.finish()?;
        if values.insert(epoch, value).is_some() {
            return Err(MessageError::Malformed("duplicate osdmap epoch"));
        }
    }
    Ok(values)
}

fn validate_map_identity(
    expected_fsid: Fsid,
    expected_epoch: u32,
    fsid: Fsid,
    epoch: u32,
) -> Result<()> {
    if fsid != expected_fsid {
        return Err(MapError::FsidMismatch.into());
    }
    if epoch != expected_epoch {
        return Err(MapError::InvalidSequence.into());
    }
    Ok(())
}

fn decode_fsid(decoder: &mut Decoder<'_>) -> Result<Fsid> {
    Ok(Fsid(
        decoder
            .raw(16)
            .try_into()
            .map_err(|_| WireError::Malformed)?,
    ))
}

fn front_message(
    message_type: u16,
    version: u16,
    compat_version: u16,
    front: Vec<u8>,
) -> Result<Message> {
    let front_length = u32::try_from(front.len()).map_err(|_| WireError::LimitExceeded)?;
    Ok(Message {
        header: MessageHeader {
            message_type,
            version,
            compat_version,
            ..MessageHeader::default()
        },
        lengths: MessageLengths {
            front: front_length,
            ..MessageLengths::default()
        },
        front,
        middle: Vec::new(),
        data: Vec::new(),
    })
}

fn validate_front_message(message: &Message, message_type: u16, max_bytes: u32) -> Result<()> {
    if max_bytes == 0 || message.front.len() > max_bytes as usize {
        return Err(WireError::LimitExceeded.into());
    }
    if message.header.message_type != message_type {
        return Err(MessageError::Malformed("message type"));
    }
    let front_length = u32::try_from(message.front.len()).map_err(|_| WireError::LimitExceeded)?;
    if !message.middle.is_empty()
        || !message.data.is_empty()
        || message.lengths
            != (MessageLengths {
                front: front_length,
                ..MessageLengths::default()
            })
    {
        return Err(MessageError::Malformed("segment lengths"));
    }
    Ok(())
}

fn validate_message_payload(message: &Message, message_type: u16, max_bytes: u32) -> Result<()> {
    if max_bytes == 0
        || message.front.len() > max_bytes as usize
        || message.data.len() > max_bytes as usize
    {
        return Err(WireError::LimitExceeded.into());
    }
    if message.header.message_type != message_type {
        return Err(MessageError::Malformed("message type"));
    }
    let front = u32::try_from(message.front.len()).map_err(|_| WireError::LimitExceeded)?;
    let data = u32::try_from(message.data.len()).map_err(|_| WireError::LimitExceeded)?;
    if !message.middle.is_empty()
        || message.lengths
            != (MessageLengths {
                front,
                data,
                ..MessageLengths::default()
            })
    {
        return Err(MessageError::Malformed("segment lengths"));
    }
    Ok(())
}

fn finish_exact(decoder: &Decoder<'_>, name: &'static str) -> Result<()> {
    decoder.finish()?;
    if decoder.remaining() != 0 {
        return Err(MessageError::Malformed(name));
    }
    Ok(())
}

#[cfg(all(test, not(rados_packaged_source)))]
mod tests {
    use std::fs;

    use super::*;

    fn map_limits() -> MapLimits {
        MapLimits {
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
        fs::read(format!("testdata/p04/{name}"))
            .unwrap_or_else(|error| panic!("read required P04 fixture {name}: {error}"))
    }

    fn message(message_type: u16, version: u16, compat: u16, front: Vec<u8>) -> Message {
        front_message(message_type, version, compat, front).expect("test message")
    }

    fn osd_batch(version: u16, compat: u16, entries: &[(u32, &[u8])], gap: u32) -> Message {
        let mut encoder = Encoder::new(1024);
        encoder.raw(&[1; 16]);
        encoder.u32(u32::try_from(entries.len()).expect("test entry count"));
        for (epoch, data) in entries {
            encoder.u32(*epoch);
            encoder.bytes(data);
        }
        encoder.u32(0);
        encoder.u32(0);
        encoder.u32(entries.last().map_or(0, |entry| entry.0));
        if version >= 4 {
            encoder.u32(gap);
        }
        message(MESSAGE_OSD_MAP, version, compat, encoder.finish().unwrap())
    }

    #[test]
    fn subscribe_v3_matches_exact_vector() {
        let subscriptions = BTreeMap::from([
            ("osdmap".to_owned(), Subscription { start: 8, flags: 0 }),
            (
                "monmap".to_owned(),
                Subscription {
                    start: 3,
                    flags: SUBSCRIBE_ONCE,
                },
            ),
        ]);
        let encoded = encode_subscribe(&subscriptions, "client-host", 1024).unwrap();
        assert_eq!(encoded.header.message_type, MESSAGE_MON_SUBSCRIBE);
        assert_eq!(encoded.header.version, 3);
        assert_eq!(encoded.header.compat_version, 1);
        assert_eq!(
            encoded.front,
            [
                2, 0, 0, 0, 6, 0, 0, 0, b'm', b'o', b'n', b'm', b'a', b'p', 3, 0, 0, 0, 0, 0, 0, 0,
                1, 6, 0, 0, 0, b'o', b's', b'd', b'm', b'a', b'p', 8, 0, 0, 0, 0, 0, 0, 0, 0, 11,
                0, 0, 0, b'c', b'l', b'i', b'e', b'n', b't', b'-', b'h', b'o', b's', b't',
            ]
        );
    }

    #[test]
    fn subscribe_ack_decodes_exact_vector_and_rejects_truncation() {
        let mut front = 30_u32.to_le_bytes().to_vec();
        front.extend(0_u8..16);
        let ack =
            decode_subscribe_ack(&message(MESSAGE_MON_SUBSCRIBE_ACK, 0, 0, front.clone()), 20)
                .unwrap();
        assert_eq!(ack.interval_seconds, 30);
        assert_eq!(
            ack.fsid,
            Fsid([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        );
        front.pop();
        assert_eq!(
            decode_subscribe_ack(&message(MESSAGE_MON_SUBSCRIBE_ACK, 0, 0, front), 20),
            Err(MessageError::Wire(WireError::Malformed))
        );
    }

    #[test]
    fn pool_snapshot_operations_match_frozen_layout_and_validate_unions() {
        let request = encode_pool_operation(
            Fsid([1; 16]),
            7,
            3,
            PoolOperation::CreateSnapshot,
            0,
            "snap",
            1024,
        )
        .expect("pool operation");
        assert_eq!(request.header.message_type, MESSAGE_POOL_OPERATION);
        assert_eq!(
            (request.header.version, request.header.compat_version),
            (4, 2)
        );
        let mut decoder = Decoder::new(&request.front, 1024);
        assert_eq!(decoder.u64(), 7);
        assert_eq!(decoder.i16(), -1);
        assert_eq!(decoder.u64(), 0);
        assert_eq!(decoder.raw(16), &[1; 16]);
        assert_eq!(decoder.u32(), 3);
        assert_eq!(decoder.u32(), 0x11);
        assert_eq!(decoder.u64(), 0);
        assert_eq!(decoder.u64(), 0);
        assert_eq!(decoder.string(), "snap");
        assert_eq!(decoder.u8(), 0);
        assert_eq!(decoder.i16(), 0);
        assert_eq!(decoder.remaining(), 0);

        assert!(
            encode_pool_operation(
                Fsid([1; 16]),
                7,
                3,
                PoolOperation::CreateSnapshot,
                1,
                "snap",
                1024,
            )
            .is_err()
        );
        assert!(
            encode_pool_operation(
                Fsid([1; 16]),
                7,
                3,
                PoolOperation::DeleteSelfManaged,
                0,
                "",
                1024,
            )
            .is_err()
        );

        let create_pool = encode_pool_operation(
            Fsid([1; 16]),
            9,
            0,
            PoolOperation::CreatePool,
            0,
            "newpool",
            1024,
        )
        .expect("create pool");
        let mut create_decoder = Decoder::new(&create_pool.front, 1024);
        assert_eq!(create_decoder.u64(), 9);
        assert_eq!(create_decoder.i16(), -1);
        assert_eq!(create_decoder.u64(), 0);
        assert_eq!(create_decoder.raw(16), &[1; 16]);
        assert_eq!(create_decoder.u32(), 0);
        assert_eq!(create_decoder.u32(), 0x01);

        let delete_pool = encode_pool_operation(
            Fsid([1; 16]),
            9,
            3,
            PoolOperation::DeletePool,
            0,
            "delete",
            1024,
        )
        .expect("delete pool");
        let mut delete_decoder = Decoder::new(&delete_pool.front, 1024);
        delete_decoder.u64();
        delete_decoder.i16();
        delete_decoder.u64();
        delete_decoder.raw(16);
        assert_eq!(delete_decoder.u32(), 3);
        assert_eq!(delete_decoder.u32(), 0x02);
        delete_decoder.u64();
        delete_decoder.u64();
        assert_eq!(delete_decoder.string(), "delete");

        assert!(
            encode_pool_operation(Fsid([1; 16]), 9, 1, PoolOperation::DeletePool, 0, "x", 1024)
                .is_err()
        );
        assert!(
            encode_pool_operation(Fsid([1; 16]), 9, 1, PoolOperation::CreatePool, 0, "", 1024,)
                .is_err()
        );
    }

    #[test]
    fn pool_snapshot_reply_and_allocated_id_are_exact() {
        let mut encoder = Encoder::new(128);
        encoder.u64(0);
        encoder.i16(-1);
        encoder.u64(0);
        encoder.raw(&[2; 16]);
        encoder.i32(0);
        encoder.u32(9);
        encoder.u8(1);
        encoder.bytes(&17_u64.to_le_bytes());
        let reply = decode_pool_operation_reply(
            &message(
                MESSAGE_POOL_OPERATION_REPLY,
                1,
                1,
                encoder.finish().expect("reply"),
            ),
            128,
        )
        .expect("decode reply");
        assert_eq!(reply.fsid, Fsid([2; 16]));
        assert_eq!(reply.epoch, 9);
        assert_eq!(
            decode_allocated_snapshot_id(&reply.response_data, 8),
            Ok(17)
        );
        assert!(decode_allocated_snapshot_id(&[0; 8], 8).is_err());
        assert!(decode_allocated_snapshot_id(&[1; 9], 9).is_err());
    }

    #[test]
    fn monitor_command_codecs_match_frozen_layout_and_bounds() {
        let command = vec![r#"{"prefix":"status"}"#.to_owned()];
        let request = encode_command(Fsid([3; 16]), &command, b"input", 128).expect("command");
        assert_eq!(request.header.message_type, MESSAGE_MON_COMMAND);
        assert_eq!(
            (request.header.version, request.header.compat_version),
            (1, 0)
        );
        assert_eq!(request.data, b"input");
        let mut decoder = Decoder::new(&request.front, 128);
        assert_eq!(decoder.u64(), 0);
        assert_eq!(decoder.i16(), -1);
        assert_eq!(decoder.u64(), 0);
        assert_eq!(decoder.raw(16), &[3; 16]);
        assert_eq!(decoder.u32(), 1);
        assert_eq!(decoder.string(), command[0]);
        assert_eq!(decoder.remaining(), 0);

        let mut encoder = Encoder::new(128);
        encoder.u64(7);
        encoder.i16(-1);
        encoder.u64(0);
        encoder.i32(-2);
        encoder.string("missing");
        encoder.u32(1);
        encoder.string(&command[0]);
        let mut reply = message(
            MESSAGE_MON_COMMAND_REPLY,
            1,
            0,
            encoder.finish().expect("reply"),
        );
        reply.data = b"details".to_vec();
        reply.lengths.data = 7;
        let command_reply = decode_command_reply(&reply, 128, 1).expect("decode reply");
        assert_eq!(command_reply.version, 7);
        assert_eq!(command_reply.result, -2);
        assert_eq!(command_reply.status, "missing");
        assert_eq!(command_reply.command, command);
        assert_eq!(command_reply.data, b"details");

        assert!(encode_command(Fsid([0; 16]), &[], &[0; 129], 128).is_err());
        assert_eq!(
            decode_command_reply(&reply, 128, 0),
            Err(MessageError::Wire(WireError::LimitExceeded))
        );
        reply.lengths.data = 6;
        assert_eq!(
            decode_command_reply(&reply, 128, 1),
            Err(MessageError::Malformed("segment lengths"))
        );
    }

    fn encode_test_pool_stats_entry(front: &mut Encoder, name: &str) {
        front.string(name);
        front.versioned(7, 5, |pool| {
            pool.versioned(2, 2, |collection| {
                collection.versioned(20, 14, |sum| {
                    for index in 0..40 {
                        let value = match index {
                            0 => 100_u64,
                            1 => 3,
                            8 => 5,
                            10 => 7,
                            22 => 11,
                            37 => 13,
                            _ => 0,
                        };
                        if (28..=31).contains(&index) {
                            sum.i32(i32::try_from(value).expect("test value"));
                        } else {
                            sum.u64(value);
                        }
                    }
                });
                collection.u32(0);
            });
            pool.i64(0);
            pool.i64(0);
            pool.i32(0);
            pool.i32(0);
            pool.versioned(1, 1, |store| {
                for index in 0..10 {
                    let value = match index {
                        3 => 200_u64,
                        8 => 17,
                        _ => 0,
                    };
                    store.u64(value);
                }
            });
            pool.i32(1);
        });
    }

    fn encode_test_pool_stats(front: &mut Encoder, per_pool: bool) {
        front.u64(9);
        front.i16(-1);
        front.u64(0);
        front.raw(&[1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        front.u32(1);
        encode_test_pool_stats_entry(front, "data");
        front.bool(per_pool);
    }

    #[test]
    fn statfs_and_pool_stats_codecs_match_frozen_layout_and_bounds() {
        let statfs = encode_statfs(Fsid([4; 16]), 42, 128).expect("statfs");
        assert_eq!(statfs.header.message_type, MESSAGE_STATFS);
        assert_eq!(
            (statfs.header.version, statfs.header.compat_version),
            (2, 1)
        );
        let mut request = Decoder::new(&statfs.front, 128);
        assert_eq!(request.u64(), 42);
        assert_eq!(request.i16(), -1);
        assert_eq!(request.u64(), 0);
        assert_eq!(request.raw(16), &[4; 16]);
        assert_eq!(request.u8(), 0);
        assert_eq!(request.remaining(), 0);

        let mut statfs_reply = Encoder::new(128);
        statfs_reply.raw(&[4; 16]);
        statfs_reply.u64(43);
        statfs_reply.u64(100);
        statfs_reply.u64(40);
        statfs_reply.u64(60);
        statfs_reply.u64(7);
        let decoded = decode_statfs_reply(
            &message(
                MESSAGE_STATFS_REPLY,
                1,
                1,
                statfs_reply.finish().expect("statfs reply"),
            ),
            128,
        )
        .expect("decode statfs");
        assert_eq!(decoded.version, 43);
        assert_eq!(decoded.kib, 100);
        assert_eq!(decoded.kib_used, 40);
        assert_eq!(decoded.kib_available, 60);
        assert_eq!(decoded.objects, 7);

        let get = encode_get_pool_stats(Fsid([5; 16]), 11, &["data".to_owned()], 256)
            .expect("get pool stats");
        assert_eq!(get.header.message_type, MESSAGE_GET_POOL_STATS);
        let mut get_decoder = Decoder::new(&get.front, 256);
        assert_eq!(get_decoder.u64(), 11);
        assert_eq!(get_decoder.i16(), -1);
        assert_eq!(get_decoder.u64(), 0);
        assert_eq!(get_decoder.raw(16), &[5; 16]);
        assert_eq!(get_decoder.u32(), 1);
        assert_eq!(get_decoder.string(), "data");

        let mut front = Encoder::new(16 << 10);
        encode_test_pool_stats(&mut front, true);
        let reply = decode_get_pool_stats_reply(
            &message(
                MESSAGE_GET_POOL_STATS_REPLY,
                2,
                1,
                front.finish().expect("pool stats reply"),
            ),
            16 << 10,
            4,
            4,
        )
        .expect("decode pool stats");
        let pool_stats = reply.pools["data"];
        assert_eq!(reply.version, 9);
        assert_eq!(pool_stats.bytes_used, 217);
        assert_eq!(pool_stats.objects, 3);
        assert_eq!(pool_stats.read_bytes, 5 << 10);
        assert_eq!(pool_stats.write_bytes, 7 << 10);

        assert!(encode_get_pool_stats(Fsid([0; 16]), 0, &[], 128).is_err());
        assert!(encode_get_pool_stats(Fsid([0; 16]), 0, &[String::new()], 128).is_err());
    }

    #[test]
    fn pool_stats_decoder_rejects_malformed_negative_and_overflow() {
        let mut negative = Encoder::new(16 << 10);
        encode_test_pool_stats(&mut negative, false);
        let mut negative_message = message(
            MESSAGE_GET_POOL_STATS_REPLY,
            2,
            1,
            negative.finish().expect("negative payload"),
        );
        let pos = negative_message
            .front
            .windows(8)
            .position(|window| window == 100_u64.to_le_bytes())
            .expect("locate num_bytes field");
        negative_message.front[pos..pos + 8].copy_from_slice(&(-1_i64).to_le_bytes());
        assert_eq!(
            decode_get_pool_stats_reply(&negative_message, 16 << 10, 4, 4),
            Err(MessageError::Malformed("negative pool stats field"))
        );

        let mut duplicate = Encoder::new(16 << 10);
        duplicate.u64(9);
        duplicate.i16(-1);
        duplicate.u64(0);
        duplicate.raw(&[1; 16]);
        duplicate.u32(2);
        encode_test_pool_stats_entry(&mut duplicate, "data");
        encode_test_pool_stats_entry(&mut duplicate, "data");
        duplicate.bool(false);
        let duplicate_message = message(
            MESSAGE_GET_POOL_STATS_REPLY,
            2,
            1,
            duplicate.finish().expect("duplicate payload"),
        );
        assert_eq!(
            decode_get_pool_stats_reply(&duplicate_message, 16 << 10, 4, 4),
            Err(MessageError::Malformed("duplicate pool stats entry"))
        );

        let mut overflow = Encoder::new(16 << 10);
        overflow.u64(9);
        overflow.i16(-1);
        overflow.u64(0);
        overflow.raw(&[1; 16]);
        overflow.u32(1);
        overflow.string("data");
        overflow.versioned(7, 5, |pool| {
            pool.versioned(2, 2, |collection| {
                collection.versioned(20, 14, |sum| {
                    for index in 0..40 {
                        let value = if index == 8 { i64::MAX as u64 } else { 0 };
                        if (28..=31).contains(&index) {
                            sum.i32(i32::try_from(value).unwrap_or_default());
                        } else {
                            sum.u64(value);
                        }
                    }
                });
                collection.u32(0);
            });
            pool.i64(0);
            pool.i64(0);
            pool.i32(0);
            pool.i32(0);
            pool.versioned(1, 1, |store| {
                for _ in 0..10 {
                    store.u64(0);
                }
            });
            pool.i32(1);
        });
        overflow.bool(false);
        let overflow_message = message(
            MESSAGE_GET_POOL_STATS_REPLY,
            2,
            1,
            overflow.finish().expect("overflow payload"),
        );
        assert_eq!(
            decode_get_pool_stats_reply(&overflow_message, 16 << 10, 4, 4),
            Err(MessageError::Wire(WireError::LimitExceeded))
        );
    }

    #[test]
    fn monmap_envelope_decodes_and_rejects_truncation() {
        let map_bytes = fixture("monmap-v9.bin");
        let mut encoder = Encoder::new(map_bytes.len() + 4);
        encoder.bytes(&map_bytes);
        let front = encoder.finish().unwrap();
        let decoded =
            decode_monmap_message(&message(MESSAGE_MON_MAP, 0, 0, front.clone()), map_limits())
                .unwrap();
        assert_eq!(decoded.epoch(), 1);

        let mut truncated = front;
        truncated.pop();
        assert!(matches!(
            decode_monmap_message(&message(MESSAGE_MON_MAP, 0, 0, truncated), map_limits()),
            Err(MessageError::Wire(WireError::Malformed))
        ));
    }

    #[test]
    fn osdmap_envelope_enforces_versions_bounds_and_unique_epochs() {
        let decoded = decode_osdmap_batch(
            &osd_batch(4, 3, &[(2, b"inc")], 0),
            MessageLimits {
                max_bytes: 1024,
                max_maps: 1,
            },
        )
        .unwrap();
        assert_eq!(decoded.fsid, Fsid([1; 16]));
        assert_eq!(decoded.incrementals[&2], b"inc");
        assert_eq!(decoded.newest_map, 2);

        assert_eq!(
            decode_osdmap_batch(
                &osd_batch(2, 2, &[], 0),
                MessageLimits {
                    max_bytes: 1024,
                    max_maps: 1
                }
            ),
            Err(MessageError::UnsupportedVersion)
        );
        assert_eq!(
            decode_osdmap_batch(
                &osd_batch(4, 5, &[], 0),
                MessageLimits {
                    max_bytes: 1024,
                    max_maps: 1
                }
            ),
            Err(MessageError::UnsupportedVersion)
        );
        assert_eq!(
            decode_osdmap_batch(
                &osd_batch(4, 3, &[(1, b"a"), (2, b"b")], 0),
                MessageLimits {
                    max_bytes: 1024,
                    max_maps: 1
                }
            ),
            Err(MessageError::Wire(WireError::LimitExceeded))
        );
        assert_eq!(
            decode_osdmap_batch(
                &osd_batch(4, 3, &[], 1),
                MessageLimits {
                    max_bytes: 1024,
                    max_maps: 1
                }
            ),
            Err(MessageError::UnsupportedVersion)
        );
        assert!(matches!(
            decode_osdmap_batch(
                &osd_batch(4, 3, &[(1, b"a"), (1, b"b")], 0),
                MessageLimits {
                    max_bytes: 1024,
                    max_maps: 2
                }
            ),
            Err(MessageError::Malformed("duplicate osdmap epoch"))
        ));
    }

    #[test]
    fn front_message_shape_and_mgr_version_are_strict() {
        let mut wrong_shape = message(MESSAGE_MON_SUBSCRIBE_ACK, 0, 0, vec![0; 20]);
        wrong_shape.middle.push(1);
        assert!(matches!(
            decode_subscribe_ack(&wrong_shape, 20),
            Err(MessageError::Malformed("segment lengths"))
        ));

        let mgr = message(MESSAGE_MGR_MAP, 2, 1, Vec::new());
        assert_eq!(
            decode_mgrmap_message(
                &mgr,
                MapLimits {
                    max_bytes: 1,
                    ..MapLimits::default()
                }
            ),
            Err(MessageError::UnsupportedVersion)
        );
    }

    #[test]
    fn decoded_osdmap_batch_requires_matching_fsid_and_epoch() {
        let full_bytes = fixture("osdmap-v8.bin");
        let incremental_bytes = fixture("osdmap-incremental-v8.bin");
        let limits = map_limits();
        let full = decode_osdmap(&full_bytes, limits).unwrap();
        let incremental = decode_osdmap_incremental(&incremental_bytes, limits).unwrap();
        assert_eq!(full.fsid(), incremental.fsid());
        let batch = OSDMapBatch {
            fsid: full.fsid(),
            incrementals: BTreeMap::from([(incremental.epoch(), incremental_bytes)]),
            full_maps: BTreeMap::from([(full.epoch(), full_bytes)]),
            trim_lower_bound: full.epoch(),
            newest_map: incremental.epoch(),
        };
        let decoded = decode_osdmap_batch_maps(&batch, limits).unwrap();
        assert_eq!(decoded.full_maps[&full.epoch()].epoch(), full.epoch());
        assert_eq!(
            decoded.incrementals[&incremental.epoch()].epoch(),
            incremental.epoch()
        );

        let mut wrong_fsid = batch.clone();
        wrong_fsid.fsid = Fsid([0xff; 16]);
        assert_eq!(
            decode_osdmap_batch_maps(&wrong_fsid, limits).map(|_| ()),
            Err(MessageError::Map(MapError::FsidMismatch))
        );

        let mut wrong_epoch = batch;
        let encoded = wrong_epoch.full_maps.remove(&full.epoch()).unwrap();
        wrong_epoch.full_maps.insert(full.epoch() + 1, encoded);
        assert_eq!(
            decode_osdmap_batch_maps(&wrong_epoch, limits).map(|_| ()),
            Err(MessageError::Map(MapError::InvalidSequence))
        );
    }
}
