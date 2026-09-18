use std::fmt;

use crate::maps::PG;
use crate::msgr::message::{Message, MessageHeader, MessageLengths};
use crate::wire::{Decoder, Encoder, WireError};

const MESSAGE_OSD_OP: u16 = 42;
const MESSAGE_OSD_OP_REPLY: u16 = 43;
const OP_READ: u16 = 0x1201;
const OP_STAT: u16 = 0x1202;
const OP_WRITE: u16 = 0x2201;
const OP_WRITE_FULL: u16 = 0x2202;
const OP_TRUNCATE: u16 = 0x2203;
const OP_ZERO: u16 = 0x2204;
const OP_DELETE: u16 = 0x2205;
const OP_APPEND: u16 = 0x2206;
const OP_CREATE: u16 = 0x220d;
const OP_FLAG_EXCLUSIVE: u32 = 0x0001;
pub(crate) const FLAG_ACK: u32 = 0x0001;
pub(crate) const FLAG_ON_DISK: u32 = 0x0004;
const FLAG_READ: u32 = 0x0010;
pub(crate) const FLAG_WRITE: u32 = 0x0020;
pub(crate) const FLAG_RETRY: u32 = 0x0008;
pub(crate) const FLAG_IGNORE_CACHE: u32 = 0x8000;
pub(crate) const FLAG_IGNORE_OVERLAY: u32 = 0x2_0000;
pub(crate) const FLAG_REDIRECTED: u32 = 0x20_0000;
pub(crate) const NO_SNAP: u64 = u64::MAX - 1;
const OPERATION_DESCRIPTOR_SIZE: usize = 38;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Limits {
    pub(crate) max_bytes: u32,
    pub(crate) max_operations: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    Read { offset: u64, length: u64 },
    Stat,
    Create { exclusive: bool },
    Write { offset: u64, data: Vec<u8> },
    WriteFull(Vec<u8>),
    Append(Vec<u8>),
    Truncate { size: u64 },
    Zero { offset: u64, length: u64 },
    Remove,
}

impl Operation {
    pub(crate) const fn code(&self) -> u16 {
        match self {
            Self::Read { .. } => OP_READ,
            Self::Stat => OP_STAT,
            Self::Create { .. } => OP_CREATE,
            Self::Write { .. } => OP_WRITE,
            Self::WriteFull(_) => OP_WRITE_FULL,
            Self::Append(_) => OP_APPEND,
            Self::Truncate { .. } => OP_TRUNCATE,
            Self::Zero { .. } => OP_ZERO,
            Self::Remove => OP_DELETE,
        }
    }

    pub(crate) const fn is_mutation(&self) -> bool {
        !matches!(self, Self::Read { .. } | Self::Stat)
    }

    pub(crate) fn data(&self) -> &[u8] {
        match self {
            Self::Write { data, .. } | Self::WriteFull(data) | Self::Append(data) => data,
            _ => &[],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Request<'a> {
    pub(crate) map_epoch: u32,
    pub(crate) pg: PG,
    pub(crate) shard: i8,
    pub(crate) sharded: bool,
    pub(crate) object_hash: u32,
    pub(crate) pool_id: i64,
    pub(crate) object: &'a [u8],
    pub(crate) locator: &'a [u8],
    pub(crate) namespace: &'a [u8],
    pub(crate) snapshot: u64,
    pub(crate) transaction_id: u64,
    pub(crate) client_global_id: u64,
    pub(crate) client_incarnation: i32,
    pub(crate) retry: i32,
    pub(crate) flags: u32,
    pub(crate) features: u64,
    pub(crate) operations: &'a [Operation],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OperationResult {
    pub(crate) operation: u16,
    pub(crate) code: i32,
    pub(crate) data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Redirect {
    pub(crate) pool: i64,
    pub(crate) locator: Vec<u8>,
    pub(crate) namespace: Vec<u8>,
    pub(crate) object: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Reply {
    pub(crate) object: Vec<u8>,
    pub(crate) pg: PG,
    pub(crate) flags: i64,
    pub(crate) result: i32,
    pub(crate) map_epoch: u32,
    pub(crate) retry: i32,
    pub(crate) version: u64,
    pub(crate) redirect: Option<Redirect>,
    pub(crate) operations: Vec<OperationResult>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Wire(WireError),
    Malformed,
    UnsupportedVersion,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "OSD message error: {self:?}")
    }
}

impl std::error::Error for Error {}

impl From<WireError> for Error {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

pub(crate) fn encode_request(request: &Request<'_>, limits: Limits) -> Result<Message, Error> {
    if limits.max_bytes == 0
        || limits.max_operations == 0
        || request.pool_id < 0
        || request.operations.is_empty()
        || request.operations.len() > limits.max_operations as usize
        || request.operations.len() > usize::from(u16::MAX)
    {
        return Err(WireError::LimitExceeded.into());
    }
    let mutation = request.operations.iter().any(Operation::is_mutation);
    let data_length = request
        .operations
        .iter()
        .try_fold(0_usize, |total, operation| {
            total
                .checked_add(operation.data().len())
                .ok_or(WireError::LimitExceeded)
        })?;

    let mut front = Encoder::new(limits.max_bytes as usize);
    front.versioned(1, 1, |spg| {
        encode_pg(spg, request.pg);
        spg.i8(if request.sharded { request.shard } else { -1 });
    });
    front.u32(request.object_hash);
    front.u32(request.map_epoch);
    let operation_flags = if mutation {
        FLAG_WRITE | FLAG_ON_DISK
    } else {
        FLAG_READ
    };
    front.u32(operation_flags | request.flags);
    front.versioned(2, 2, |request_id| {
        request_id.u8(8);
        request_id.u64(request.client_global_id);
        request_id.u64(request.transaction_id);
        request_id.i32(request.client_incarnation);
    });
    front.raw(&[0; 24]);
    front.i32(request.client_incarnation);
    front.raw(&[0; 8]);
    encode_locator(
        &mut front,
        request.pool_id,
        request.locator,
        request.namespace,
    );
    front.bytes(request.object);
    front.u16(u16::try_from(request.operations.len()).map_err(|_| WireError::LimitExceeded)?);
    for operation in request.operations {
        encode_operation(&mut front, operation);
    }
    front.u64(request.snapshot);
    front.u64(0);
    front.u32(0);
    front.i32(request.retry);
    front.u64(request.features);
    let front = front.finish()?;
    if front.len().saturating_add(data_length) > limits.max_bytes as usize {
        return Err(WireError::LimitExceeded.into());
    }
    let mut data = Vec::with_capacity(data_length);
    for operation in request.operations {
        data.extend_from_slice(operation.data());
    }
    Ok(Message {
        header: MessageHeader {
            transaction_id: request.transaction_id,
            message_type: MESSAGE_OSD_OP,
            version: 8,
            compat_version: 3,
            ..MessageHeader::default()
        },
        lengths: MessageLengths {
            front: u32::try_from(front.len()).map_err(|_| WireError::LimitExceeded)?,
            data: u32::try_from(data.len()).map_err(|_| WireError::LimitExceeded)?,
            ..MessageLengths::default()
        },
        front,
        data,
        ..Message::default()
    })
}

pub(crate) fn decode_reply(message: &Message, limits: Limits) -> Result<Reply, Error> {
    let total = message
        .front
        .len()
        .checked_add(message.middle.len())
        .and_then(|value| value.checked_add(message.data.len()))
        .ok_or(WireError::LimitExceeded)?;
    if limits.max_bytes == 0
        || limits.max_operations == 0
        || message.header.message_type != MESSAGE_OSD_OP_REPLY
        || message.header.version < 4
        || message.header.compat_version > 8
        || total > limits.max_bytes as usize
    {
        return Err(Error::Malformed);
    }
    let mut decoder = Decoder::new(&message.front, limits.max_bytes as usize);
    let object = decoder.bytes();
    let pg = decode_pg(&mut decoder)?;
    let flags = decoder.i64();
    let result = decoder.i32();
    decoder.raw(12);
    let map_epoch = decoder.u32();
    let count = decoder.u32();
    decoder.finish()?;
    let count = usize::try_from(count).map_err(|_| WireError::LimitExceeded)?;
    if count > limits.max_operations as usize
        || count.saturating_mul(OPERATION_DESCRIPTOR_SIZE) > decoder.remaining()
    {
        return Err(WireError::LimitExceeded.into());
    }
    let mut operations = Vec::with_capacity(count);
    let mut lengths = Vec::with_capacity(count);
    for _ in 0..count {
        let operation = decoder.u16();
        decoder.raw(32);
        let length = decoder.u32();
        operations.push(OperationResult {
            operation,
            code: 0,
            data: Vec::new(),
        });
        lengths.push(length);
    }
    let retry = decoder.i32();
    for operation in &mut operations {
        operation.code = decoder.i32();
    }
    decoder.raw(12);
    let version = decoder.u64();
    if message.header.version == 6 {
        return Err(Error::UnsupportedVersion);
    }
    let redirect = if message.header.version >= 7 && decoder.bool() {
        Some(decode_redirect(&mut decoder)?)
    } else {
        None
    };
    if message.header.version >= 8 {
        decoder.raw(24);
    }
    decoder.finish()?;
    if decoder.remaining() != 0 {
        return Err(Error::Malformed);
    }
    let mut offset = 0_usize;
    for (operation, length) in operations.iter_mut().zip(lengths) {
        let length = usize::try_from(length).map_err(|_| WireError::LimitExceeded)?;
        let end = offset.checked_add(length).ok_or(WireError::LimitExceeded)?;
        let data = message.data.get(offset..end).ok_or(Error::Malformed)?;
        operation.data = data.to_vec();
        offset = end;
    }
    if offset != message.data.len() {
        return Err(Error::Malformed);
    }
    Ok(Reply {
        object,
        pg,
        flags,
        result,
        map_epoch,
        retry,
        version,
        redirect,
        operations,
    })
}

fn encode_pg(encoder: &mut Encoder, pg: PG) {
    encoder.u8(1);
    encoder.u64(pg.pool);
    encoder.u32(pg.seed);
    encoder.i32(pg.preferred);
}

fn decode_pg(decoder: &mut Decoder<'_>) -> Result<PG, Error> {
    if decoder.u8() != 1 {
        return Err(Error::UnsupportedVersion);
    }
    let pg = PG {
        pool: decoder.u64(),
        seed: decoder.u32(),
        preferred: decoder.i32(),
    };
    decoder.finish()?;
    Ok(pg)
}

fn encode_locator(encoder: &mut Encoder, pool: i64, locator: &[u8], namespace: &[u8]) {
    encoder.versioned(6, 3, |payload| {
        payload.i64(pool);
        payload.i32(-1);
        payload.bytes(locator);
        payload.bytes(namespace);
        payload.i64(-1);
    });
}

fn encode_operation(encoder: &mut Encoder, operation: &Operation) {
    encoder.u16(operation.code());
    encoder.u32(match operation {
        Operation::Create { exclusive: true } => OP_FLAG_EXCLUSIVE,
        _ => 0,
    });
    match operation {
        Operation::Read { offset, length } | Operation::Zero { offset, length } => {
            encoder.u64(*offset);
            encoder.u64(*length);
        }
        Operation::Write { offset, data } => {
            encoder.u64(*offset);
            encoder.u64(data.len() as u64);
        }
        Operation::WriteFull(data) | Operation::Append(data) => {
            encoder.u64(0);
            encoder.u64(data.len() as u64);
        }
        Operation::Truncate { size } => {
            encoder.u64(*size);
            encoder.u64(0);
        }
        Operation::Stat | Operation::Create { .. } | Operation::Remove => {
            encoder.u64(0);
            encoder.u64(0);
        }
    }
    encoder.raw(&[0; 12]);
    encoder.u32(u32::try_from(operation.data().len()).unwrap_or(u32::MAX));
}

fn decode_redirect(decoder: &mut Decoder<'_>) -> Result<Redirect, Error> {
    let (version, mut payload) = decoder.versioned(1);
    decoder.finish()?;
    if version != 1 {
        return Err(Error::UnsupportedVersion);
    }
    let (locator_version, mut locator) = payload.versioned(6);
    payload.finish()?;
    if locator_version < 3 {
        return Err(Error::UnsupportedVersion);
    }
    let pool = locator.i64();
    locator.i32();
    let key = locator.bytes();
    let namespace = locator.bytes();
    if locator_version >= 6 {
        locator.i64();
    }
    locator.finish()?;
    if locator.remaining() != 0 {
        return Err(Error::Malformed);
    }
    let object = payload.bytes();
    let legacy_length = payload.u32() as usize;
    if legacy_length > payload.remaining() {
        return Err(Error::Malformed);
    }
    payload.raw(legacy_length);
    payload.finish()?;
    if payload.remaining() != 0 {
        return Err(Error::Malformed);
    }
    Ok(Redirect {
        pool,
        locator: key,
        namespace,
        object,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: Limits = Limits {
        max_bytes: 4096,
        max_operations: 4,
    };

    fn request(operations: &[Operation]) -> Request<'_> {
        Request {
            map_epoch: 9,
            pg: PG {
                pool: 7,
                seed: 3,
                preferred: -1,
            },
            shard: 2,
            sharded: false,
            object_hash: 0x1234_5678,
            pool_id: 7,
            object: b"object",
            locator: b"locator",
            namespace: b"namespace",
            snapshot: NO_SNAP,
            transaction_id: 0,
            client_global_id: 0,
            client_incarnation: 0,
            retry: -1,
            flags: 0,
            features: 0x1122_3344_5566_7788,
            operations,
        }
    }

    #[test]
    fn read_request_matches_pinned_go_layout() {
        assert_eq!(NO_SNAP, 0xffff_ffff_ffff_fffe);
        let message = encode_request(
            &request(&[Operation::Read {
                offset: 11,
                length: 22,
            }]),
            LIMITS,
        )
        .expect("request");
        assert_eq!(message.header.message_type, MESSAGE_OSD_OP);
        assert_eq!(message.header.version, 8);
        assert_eq!(message.header.compat_version, 3);
        let mut decoder = Decoder::new(&message.front, LIMITS.max_bytes as usize);
        let (spg_version, mut spg) = decoder.versioned(1);
        assert_eq!(spg_version, 1);
        assert_eq!(decode_pg(&mut spg).expect("pg"), request(&[]).pg);
        assert_eq!(spg.i8(), -1);
        assert_eq!(spg.remaining(), 0);
        assert_eq!(decoder.u32(), 0x1234_5678);
        assert_eq!(decoder.u32(), 9);
        assert_eq!(decoder.u32(), FLAG_READ);
    }

    #[test]
    fn mutation_request_matches_pinned_go_layout() {
        let message = encode_request(
            &request(&[Operation::Write {
                offset: 11,
                data: b"payload".to_vec(),
            }]),
            LIMITS,
        )
        .expect("request");
        assert_eq!(message.data, b"payload");
        assert_eq!(message.lengths.data, 7);
        let mut decoder = Decoder::new(&message.front, LIMITS.max_bytes as usize);
        let (_, mut spg) = decoder.versioned(1);
        decode_pg(&mut spg).expect("pg");
        spg.i8();
        decoder.u32();
        decoder.u32();
        assert_eq!(decoder.u32(), FLAG_WRITE | FLAG_ON_DISK);
    }

    #[test]
    fn mutation_descriptors_preserve_fields_and_payload_lengths() {
        let operations = [
            Operation::Create { exclusive: true },
            Operation::Write {
                offset: 17,
                data: b"xy".to_vec(),
            },
            Operation::WriteFull(b"full".to_vec()),
            Operation::Append(b"abc".to_vec()),
            Operation::Truncate { size: 23 },
            Operation::Zero {
                offset: 29,
                length: 31,
            },
            Operation::Remove,
        ];
        let mut encoder = Encoder::new(4096);
        for operation in &operations {
            encode_operation(&mut encoder, operation);
        }
        let bytes = encoder.finish().expect("descriptors");
        let mut decoder = Decoder::new(&bytes, bytes.len());
        assert_eq!(decoder.u16(), OP_CREATE);
        assert_eq!(decoder.u32(), OP_FLAG_EXCLUSIVE);
        assert_eq!(decoder.raw(28), vec![0; 28]);
        assert_eq!(decoder.u32(), 0);
        assert_eq!(decoder.u16(), OP_WRITE);
        assert_eq!(decoder.u32(), 0);
        assert_eq!(decoder.u64(), 17);
        assert_eq!(decoder.u64(), 2);
        assert_eq!(decoder.raw(12), vec![0; 12]);
        assert_eq!(decoder.u32(), 2);
        assert_eq!(decoder.u16(), OP_WRITE_FULL);
        assert_eq!(decoder.u32(), 0);
        assert_eq!(decoder.u64(), 0);
        assert_eq!(decoder.u64(), 4);
        assert_eq!(decoder.raw(12), vec![0; 12]);
        assert_eq!(decoder.u32(), 4);
        assert_eq!(decoder.u16(), OP_APPEND);
        assert_eq!(decoder.u32(), 0);
        assert_eq!(decoder.u64(), 0);
        assert_eq!(decoder.u64(), 3);
        assert_eq!(decoder.raw(12), vec![0; 12]);
        assert_eq!(decoder.u32(), 3);
        assert_eq!(decoder.u16(), OP_TRUNCATE);
        assert_eq!(decoder.u32(), 0);
        assert_eq!(decoder.u64(), 23);
        assert_eq!(decoder.raw(20), vec![0; 20]);
        assert_eq!(decoder.u32(), 0);
        assert_eq!(decoder.u16(), OP_ZERO);
        assert_eq!(decoder.u32(), 0);
        assert_eq!(decoder.u64(), 29);
        assert_eq!(decoder.u64(), 31);
        assert_eq!(decoder.raw(12), vec![0; 12]);
        assert_eq!(decoder.u32(), 0);
        assert_eq!(decoder.u16(), OP_DELETE);
        assert_eq!(decoder.u32(), 0);
        assert_eq!(decoder.raw(28), vec![0; 28]);
        assert_eq!(decoder.u32(), 0);
        decoder.finish().expect("descriptor fields");

        let request = encode_request(
            &request(&operations),
            Limits {
                max_operations: 7,
                ..LIMITS
            },
        )
        .expect("mutation request");
        assert_eq!(request.data, b"xyfullabc");
    }

    #[test]
    fn request_preserves_erasure_shard_and_snapshot_zero() {
        let mut value = request(&[Operation::Stat]);
        value.sharded = true;
        value.snapshot = 0;
        let message = encode_request(&value, LIMITS).expect("request");
        let mut decoder = Decoder::new(&message.front, LIMITS.max_bytes as usize);
        let (_, mut spg) = decoder.versioned(1);
        decode_pg(&mut spg).expect("pg");
        assert_eq!(spg.i8(), 2);
        let snapshot = u64::from_le_bytes(
            message.front[message.front.len() - 32..][..8]
                .try_into()
                .expect("snapshot bytes"),
        );
        assert_eq!(snapshot, 0);
    }

    #[test]
    fn request_rejects_empty_operations_and_bounds() {
        assert!(matches!(
            encode_request(&request(&[]), LIMITS),
            Err(Error::Wire(WireError::LimitExceeded))
        ));
        let limits = Limits {
            max_bytes: 32,
            max_operations: 1,
        };
        assert!(matches!(
            encode_request(&request(&[Operation::Stat]), limits),
            Err(Error::Wire(WireError::LimitExceeded))
        ));
    }

    fn reply_message(data: Vec<u8>) -> Message {
        let mut front = Encoder::new(4096);
        front.bytes(b"object");
        encode_pg(
            &mut front,
            PG {
                pool: 7,
                seed: 3,
                preferred: -1,
            },
        );
        front.i64(0);
        front.i32(0);
        front.raw(&[0; 12]);
        front.u32(9);
        front.u32(1);
        front.u16(OP_READ);
        front.raw(&[0; 32]);
        front.u32(u32::try_from(data.len()).expect("data length"));
        front.i32(-1);
        front.i32(0);
        front.raw(&[0; 12]);
        front.u64(44);
        front.bool(false);
        front.raw(&[0; 24]);
        let front = front.finish().expect("reply front");
        Message {
            header: MessageHeader {
                message_type: MESSAGE_OSD_OP_REPLY,
                version: 8,
                compat_version: 3,
                ..MessageHeader::default()
            },
            lengths: MessageLengths {
                front: u32::try_from(front.len()).expect("front length"),
                data: u32::try_from(data.len()).expect("data length"),
                ..MessageLengths::default()
            },
            front,
            data,
            ..Message::default()
        }
    }

    #[test]
    fn reply_decodes_owned_operation_data_and_rejects_mismatch() {
        let message = reply_message(b"payload".to_vec());
        let reply = decode_reply(&message, LIMITS).expect("reply");
        assert_eq!(reply.object, b"object");
        assert_eq!(reply.map_epoch, 9);
        assert_eq!(reply.version, 44);
        assert_eq!(
            reply.operations,
            vec![OperationResult {
                operation: OP_READ,
                code: 0,
                data: b"payload".to_vec(),
            }]
        );
        let mut malformed = message;
        malformed.data.pop();
        assert_eq!(decode_reply(&malformed, LIMITS), Err(Error::Malformed));
    }
}
