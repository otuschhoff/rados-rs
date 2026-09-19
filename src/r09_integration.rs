//! Hidden qualification adapters for R09 metadata and enumeration fuzzing.

use crate::maps::PG;
use crate::msgr::message::{Message, MessageHeader, MessageLengths};
use crate::osd::enumeration;
use crate::osd::messages::{Limits, Operation, Request, decode_reply, encode_request};
use crate::osd::metadata;

const MAX_FUZZ_BYTES: usize = 65_536;
const LIMITS: Limits = Limits {
    max_bytes: 65_536,
    max_operations: 16,
};

/// Feeds arbitrary bounded metadata containers to the production decoders.
pub fn fuzz_metadata(data: &[u8]) {
    if data.len() > MAX_FUZZ_BYTES {
        return;
    }
    drop(metadata::decode_map(data, MAX_FUZZ_BYTES, 1024));
    drop(metadata::decode_page(data, MAX_FUZZ_BYTES, 1024));
}

/// Feeds arbitrary bounded PGNLS pages and cursors to the production decoders.
pub fn fuzz_enumeration(data: &[u8]) {
    if data.len() > MAX_FUZZ_BYTES {
        return;
    }
    drop(enumeration::decode_page(data, MAX_FUZZ_BYTES, 1024));
    drop(enumeration::unmarshal_cursor(data));
}

/// Feeds bounded compound requests and replies through production codecs.
pub fn fuzz_compound(data: &[u8]) {
    if data.len() > MAX_FUZZ_BYTES {
        return;
    }
    let split = data.len() / 2;
    let operations = [
        Operation::WithFlags {
            operation: Box::new(Operation::GetXattr(data[..split].to_vec())),
            flags: 2,
        },
        Operation::SetXattr {
            name: data[..split].to_vec(),
            value: data[split..].to_vec(),
        },
    ];
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
            object: b"r09-fuzz",
            locator: b"",
            namespace: b"",
            snapshot: u64::MAX - 1,
            transaction_id: 1,
            client_global_id: 1,
            client_incarnation: 1,
            retry: -1,
            flags: 0x0400_0000,
            features: u64::MAX,
            operations: &operations,
        },
        LIMITS,
    ));
    if data.len() >= 4 {
        let front_length = usize::from(u16::from_le_bytes([data[0], data[1]])).min(data.len() - 4);
        let remaining = data.len() - 4 - front_length;
        let middle_length = usize::from(u16::from_le_bytes([data[2], data[3]])).min(remaining);
        let front_start = 4;
        let middle_start = front_start + front_length;
        let body_start = middle_start + middle_length;
        let message = Message {
            header: MessageHeader {
                message_type: 43,
                version: 8,
                compat_version: 3,
                ..MessageHeader::default()
            },
            lengths: MessageLengths {
                front: u32::try_from(front_length).unwrap_or_default(),
                middle: u32::try_from(middle_length).unwrap_or_default(),
                data: u32::try_from(data.len() - body_start).unwrap_or_default(),
            },
            front: data[front_start..middle_start].to_vec(),
            middle: data[middle_start..body_start].to_vec(),
            data: data[body_start..].to_vec(),
        };
        drop(decode_reply(&message, LIMITS));
    }
}
