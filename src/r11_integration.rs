//! Hidden qualification adapters for R11 snapshot and specialized-I/O fuzzing.

use crate::maps::PG;
use crate::mon::messages::{decode_allocated_snapshot_id, decode_pool_operation_reply};
use crate::msgr::message::{Message, MessageHeader, MessageLengths};
use crate::osd::messages::{Limits, Operation, Request, decode_reply, encode_request};
use crate::osd::special::{decode_sparse_read, validate_checksum};

const MAX_FUZZ_BYTES: usize = 65_536;
const LIMITS: Limits = Limits {
    max_bytes: 65_536,
    max_operations: 16,
};

/// Feeds bounded monitor snapshot replies to the production decoders.
pub fn fuzz_snapshot(data: &[u8]) {
    if data.len() > MAX_FUZZ_BYTES {
        return;
    }
    let _ = decode_allocated_snapshot_id(data, MAX_FUZZ_BYTES);
    let message = Message {
        header: MessageHeader {
            message_type: 48,
            version: 1,
            compat_version: 1,
            ..MessageHeader::default()
        },
        lengths: MessageLengths {
            front: u32::try_from(data.len()).unwrap_or_default(),
            ..MessageLengths::default()
        },
        front: data.to_vec(),
        ..Message::default()
    };
    let max_bytes = u32::try_from(MAX_FUZZ_BYTES).expect("fuzz byte limit fits u32");
    drop(decode_pool_operation_reply(&message, max_bytes));
}

/// Feeds arbitrary bounded sparse-read and checksum results to production decoders.
pub fn fuzz_sparse(data: &[u8]) {
    if data.len() <= MAX_FUZZ_BYTES {
        drop(decode_sparse_read(data, 0, u64::MAX, MAX_FUZZ_BYTES, 1024));
        for width in [1, 4, 8, 16] {
            let _ = validate_checksum(data, width, MAX_FUZZ_BYTES);
        }
    }
}

/// Feeds specialized requests and arbitrary `MOSDOp` replies through production codecs.
pub fn fuzz_special(data: &[u8]) {
    if data.len() > MAX_FUZZ_BYTES {
        return;
    }
    let split = data.len() / 2;
    let operations = [
        Operation::WriteSame {
            offset: 0,
            length: data.len() as u64,
            pattern: data[..split].to_vec(),
        },
        Operation::AllocationHint {
            expected_object_size: data.len() as u64,
            expected_write_size: split as u64,
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
            object: b"r11-fuzz",
            locator: b"",
            namespace: b"",
            snapshot: u64::MAX - 1,
            snapshot_sequence: 0,
            write_snapshots: &[],
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
    if let Some(message) = split_message(data) {
        drop(decode_reply(&message, LIMITS));
    }
}

fn split_message(data: &[u8]) -> Option<Message> {
    if data.len() < 4 {
        return None;
    }
    let front_length = usize::from(u16::from_le_bytes([data[0], data[1]])).min(data.len() - 4);
    let remaining = data.len() - 4 - front_length;
    let middle_length = usize::from(u16::from_le_bytes([data[2], data[3]])).min(remaining);
    let front_start = 4;
    let middle_start = front_start + front_length;
    let body_start = middle_start + middle_length;
    Some(Message {
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
    })
}
