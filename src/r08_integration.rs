//! Hidden qualification adapters for R08 mutation fuzzing.

use crate::maps::PG;
use crate::msgr::message::{Message, MessageHeader, MessageLengths};
use crate::osd::backoff::{MESSAGE_OSD_BACKOFF, decode_backoff};
use crate::osd::fuzz_mutation_lifecycle as fuzz_lifecycle;
use crate::osd::messages::{Limits, Operation, Request, decode_reply, encode_request};

const MAX_FUZZ_BYTES: usize = 65_536;
const MAX_FUZZ_BYTES_U32: u32 = 65_536;
const LIMITS: Limits = Limits {
    max_bytes: MAX_FUZZ_BYTES_U32,
    max_operations: 64,
};

/// Feeds bounded arbitrary mutation fields and payloads to the production request encoder.
pub fn fuzz_mutation_request(data: &[u8]) {
    if data.len() < 18 || data.len() > MAX_FUZZ_BYTES {
        return;
    }
    let offset = u64::from_le_bytes(data[1..9].try_into().expect("slice length"));
    let length = u64::from_le_bytes(data[9..17].try_into().expect("slice length"));
    let payload = &data[17..];
    let operation = match data[0] % 7 {
        0 => Operation::Create {
            exclusive: data[0] & 0x80 != 0,
        },
        1 => Operation::Write {
            offset,
            data: payload.to_vec(),
        },
        2 => Operation::WriteFull(payload.to_vec()),
        3 => Operation::Append(payload.to_vec()),
        4 => Operation::Truncate { size: offset },
        5 => Operation::Zero { offset, length },
        _ => Operation::Remove,
    };
    drop(encode_request(
        &Request {
            map_epoch: 1,
            pg: PG {
                pool: 1,
                seed: 1,
                preferred: -1,
            },
            shard: -1,
            sharded: false,
            object_hash: 1,
            pool_id: 1,
            object: b"r08-fuzz",
            locator: b"",
            namespace: b"",
            snapshot: u64::MAX - 1,
            transaction_id: 1,
            client_global_id: 1,
            client_incarnation: 1,
            retry: -1,
            flags: 0,
            features: u64::MAX,
            operations: &[operation],
        },
        LIMITS,
    ));
}

/// Feeds bounded arbitrary segmented mutation replies to the production decoder.
pub fn fuzz_mutation_reply(data: &[u8]) {
    if let Some(message) = segmented_message(data, 43, 8, 3) {
        drop(decode_reply(&message, LIMITS));
    }
}

/// Feeds mixed reply/backoff inputs through the production recovery parsers.
pub fn fuzz_mutation_recovery(data: &[u8]) {
    let Some((&selector, payload)) = data.split_first() else {
        return;
    };
    if selector & 1 == 0 {
        fuzz_mutation_reply(payload);
    } else if let Some(message) = segmented_message(payload, MESSAGE_OSD_BACKOFF, 1, 1) {
        drop(decode_backoff(&message, LIMITS));
    }
    fuzz_lifecycle(payload);
}

fn segmented_message(
    data: &[u8],
    message_type: u16,
    version: u16,
    compat_version: u16,
) -> Option<Message> {
    if data.len() > MAX_FUZZ_BYTES {
        return None;
    }
    let (control, payload) = data.split_at_checked(4)?;
    let front_length = usize::from(u16::from_le_bytes([control[0], control[1]])).min(payload.len());
    let remaining = &payload[front_length..];
    let middle_length =
        usize::from(u16::from_le_bytes([control[2], control[3]])).min(remaining.len());
    let (middle, body) = remaining.split_at(middle_length);
    let front = &payload[..front_length];
    Some(Message {
        header: MessageHeader {
            message_type,
            version,
            compat_version,
            ..MessageHeader::default()
        },
        lengths: MessageLengths {
            front: u32::try_from(front.len()).ok()?,
            middle: u32::try_from(middle.len()).ok()?,
            data: u32::try_from(body.len()).ok()?,
        },
        front: front.to_vec(),
        middle: middle.to_vec(),
        data: body.to_vec(),
    })
}
