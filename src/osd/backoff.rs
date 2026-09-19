use std::cmp::Ordering;

use crate::maps::PG;
use crate::msgr::message::{Message, MessageHeader, MessageLengths};
use crate::wire::{Decoder, Encoder, WireError};

use super::messages::Limits;

pub(crate) const MESSAGE_OSD_BACKOFF: u16 = 61;
pub(crate) const BACKOFF_BLOCK: u8 = 1;
const BACKOFF_ACK_BLOCK: u8 = 2;
pub(crate) const BACKOFF_UNBLOCK: u8 = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HObject {
    pub(crate) key: Vec<u8>,
    pub(crate) object: Vec<u8>,
    pub(crate) snapshot: u64,
    pub(crate) hash: u32,
    pub(crate) max: bool,
    pub(crate) namespace: Vec<u8>,
    pub(crate) pool: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Backoff {
    pub(crate) pg: PG,
    pub(crate) shard: i8,
    pub(crate) map_epoch: u32,
    pub(crate) operation: u8,
    pub(crate) id: u64,
    pub(crate) begin: HObject,
    pub(crate) end: HObject,
}

impl Backoff {
    pub(crate) fn contains(&self, target: &HObject) -> bool {
        if compare_hobject(&self.begin, &self.end) == Ordering::Equal {
            return compare_hobject(target, &self.begin) == Ordering::Equal;
        }
        compare_hobject(&self.begin, target) != Ordering::Greater
            && compare_hobject(target, &self.end) == Ordering::Less
    }
}

pub(crate) fn decode_backoff(message: &Message, limits: Limits) -> Result<Backoff, WireError> {
    if limits.max_bytes == 0
        || message.header.message_type != MESSAGE_OSD_BACKOFF
        || message.header.version != 1
        || message.header.compat_version > 1
        || !message.middle.is_empty()
        || !message.data.is_empty()
        || message.front.len() > limits.max_bytes as usize
    {
        return Err(WireError::Malformed);
    }
    let mut decoder = Decoder::new(&message.front, limits.max_bytes as usize);
    let (pg, shard) = decode_spg(&mut decoder)?;
    let map_epoch = decoder.u32();
    let operation = decoder.u8();
    if !matches!(operation, BACKOFF_BLOCK | BACKOFF_UNBLOCK) {
        return Err(WireError::UnsupportedVersion {
            local: BACKOFF_UNBLOCK,
            required: operation,
        });
    }
    let id = decoder.u64();
    let begin = decode_hobject(&mut decoder)?;
    let end = decode_hobject(&mut decoder)?;
    decoder.finish()?;
    if decoder.remaining() != 0 {
        return Err(WireError::Malformed);
    }
    Ok(Backoff {
        pg,
        shard,
        map_epoch,
        operation,
        id,
        begin,
        end,
    })
}

pub(crate) fn encode_acknowledgment(
    backoff: &Backoff,
    limits: Limits,
) -> Result<Message, WireError> {
    if limits.max_bytes == 0 || backoff.operation != BACKOFF_BLOCK {
        return Err(WireError::Malformed);
    }
    encode(backoff, BACKOFF_ACK_BLOCK, limits)
}

#[cfg(test)]
pub(crate) fn encode_for_test(backoff: &Backoff, limits: Limits) -> Result<Message, WireError> {
    if !matches!(backoff.operation, BACKOFF_BLOCK | BACKOFF_UNBLOCK) {
        return Err(WireError::Malformed);
    }
    encode(backoff, backoff.operation, limits)
}

fn encode(backoff: &Backoff, operation: u8, limits: Limits) -> Result<Message, WireError> {
    let mut front = Encoder::new(limits.max_bytes as usize);
    encode_spg(&mut front, backoff.pg, backoff.shard);
    front.u32(backoff.map_epoch);
    front.u8(operation);
    front.u64(backoff.id);
    encode_hobject(&mut front, &backoff.begin);
    encode_hobject(&mut front, &backoff.end);
    let front = front.finish()?;
    Ok(Message {
        header: MessageHeader {
            message_type: MESSAGE_OSD_BACKOFF,
            version: 1,
            compat_version: 1,
            ..MessageHeader::default()
        },
        lengths: MessageLengths {
            front: u32::try_from(front.len()).map_err(|_| WireError::LimitExceeded)?,
            ..MessageLengths::default()
        },
        front,
        ..Message::default()
    })
}

fn decode_spg(decoder: &mut Decoder<'_>) -> Result<(PG, i8), WireError> {
    let (version, mut payload) = decoder.versioned(1);
    decoder.finish()?;
    if version != 1 || payload.u8() != 1 {
        return Err(WireError::UnsupportedVersion {
            local: 1,
            required: version,
        });
    }
    let pg = PG {
        pool: payload.u64(),
        seed: payload.u32(),
        preferred: payload.i32(),
    };
    let shard = payload.i8();
    payload.finish()?;
    if payload.remaining() != 0 {
        return Err(WireError::Malformed);
    }
    Ok((pg, shard))
}

fn encode_spg(encoder: &mut Encoder, pg: PG, shard: i8) {
    encoder.versioned(1, 1, |payload| {
        payload.u8(1);
        payload.u64(pg.pool);
        payload.u32(pg.seed);
        payload.i32(pg.preferred);
        payload.i8(shard);
    });
}

pub(crate) fn decode_hobject(decoder: &mut Decoder<'_>) -> Result<HObject, WireError> {
    let (version, mut payload) = decoder.versioned(4);
    decoder.finish()?;
    if !(3..=4).contains(&version) {
        return Err(WireError::UnsupportedVersion {
            local: 4,
            required: version,
        });
    }
    let key = payload.bytes();
    let object = payload.bytes();
    let snapshot = payload.u64();
    let hash = payload.u32();
    let max = payload.bool();
    let (namespace, pool) = if version >= 4 {
        (payload.bytes(), payload.i64())
    } else {
        (Vec::new(), i64::MIN)
    };
    payload.finish()?;
    if payload.remaining() != 0 {
        return Err(WireError::Malformed);
    }
    Ok(HObject {
        key,
        object,
        snapshot,
        hash,
        max,
        namespace,
        pool,
    })
}

pub(crate) fn encode_hobject(encoder: &mut Encoder, object: &HObject) {
    encoder.versioned(4, 3, |payload| {
        payload.bytes(&object.key);
        payload.bytes(&object.object);
        payload.u64(object.snapshot);
        payload.u32(object.hash);
        payload.bool(object.max);
        payload.bytes(&object.namespace);
        payload.i64(object.pool);
    });
}

pub(crate) fn compare_hobject(left: &HObject, right: &HObject) -> Ordering {
    if left.max && right.max {
        return Ordering::Equal;
    }
    left.max
        .cmp(&right.max)
        .then_with(|| left.pool.cmp(&right.pool))
        .then_with(|| left.hash.reverse_bits().cmp(&right.hash.reverse_bits()))
        .then_with(|| left.namespace.cmp(&right.namespace))
        .then_with(|| {
            if left.key.is_empty() && right.key.is_empty() {
                Ordering::Equal
            } else {
                effective_key(left).cmp(effective_key(right))
            }
        })
        .then_with(|| left.object.cmp(&right.object))
        .then_with(|| left.snapshot.cmp(&right.snapshot))
}

fn effective_key(object: &HObject) -> &[u8] {
    if object.key.is_empty() {
        &object.object
    } else {
        &object.key
    }
}

#[cfg(test)]
mod tests {
    use super::super::messages::NO_SNAP;
    use super::*;

    const LIMITS: Limits = Limits {
        max_bytes: 4096,
        max_operations: 4,
    };

    fn object(name: &[u8]) -> HObject {
        HObject {
            key: Vec::new(),
            object: name.to_vec(),
            snapshot: NO_SNAP,
            hash: 0x8000_0000,
            max: false,
            namespace: b"space".to_vec(),
            pool: 7,
        }
    }

    fn backoff() -> Backoff {
        Backoff {
            pg: PG {
                pool: 7,
                seed: 3,
                preferred: -1,
            },
            shard: -1,
            map_epoch: 9,
            operation: BACKOFF_BLOCK,
            id: 42,
            begin: object(b"a"),
            end: object(b"z"),
        }
    }

    #[test]
    fn backoff_round_trips_through_acknowledgment_layout() {
        let value = backoff();
        let mut message = encode_acknowledgment(&value, LIMITS).expect("ack");
        message.front[28] = BACKOFF_BLOCK;
        let decoded = decode_backoff(&message, LIMITS).expect("backoff");
        assert_eq!(decoded, value);
        let acknowledgment = encode_acknowledgment(&decoded, LIMITS).expect("ack");
        assert_eq!(acknowledgment.front[28], BACKOFF_ACK_BLOCK);
    }

    #[test]
    fn backoff_ranges_are_half_open_and_bit_reversed() {
        let value = backoff();
        assert!(value.contains(&object(b"a")));
        assert!(value.contains(&object(b"m")));
        assert!(!value.contains(&object(b"z")));
        assert_eq!(
            compare_hobject(
                &HObject {
                    hash: 1,
                    ..object(b"")
                },
                &HObject {
                    hash: 2,
                    ..object(b"")
                },
            ),
            Ordering::Greater
        );
    }

    #[test]
    fn malformed_backoff_is_rejected() {
        let value = backoff();
        let mut message = encode_acknowledgment(&value, LIMITS).expect("ack");
        message.front.pop();
        assert!(decode_backoff(&message, LIMITS).is_err());
        let mut message = encode_acknowledgment(&value, LIMITS).expect("ack");
        message.data.push(1);
        assert!(decode_backoff(&message, LIMITS).is_err());
    }
}
