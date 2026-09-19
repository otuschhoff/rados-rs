//! Hidden qualification adapters for R10 class, lock, and watch fuzzing.

use crate::maps::PG;
use crate::msgr::message::{Message, MessageHeader, MessageLengths};
use crate::osd::lock;
use crate::osd::messages::{Limits, Operation, Request, decode_reply, encode_request};
use crate::osd::watch;

const MAX_FUZZ_BYTES: usize = 65_536;
const LIMITS: Limits = Limits {
    max_bytes: 65_536,
    max_operations: 16,
};

/// Feeds bounded class calls and arbitrary `MOSDOp` replies through production codecs.
pub fn fuzz_class(data: &[u8]) {
    if data.len() > MAX_FUZZ_BYTES {
        return;
    }
    let class_length = u8::try_from(data.len().min(255)).unwrap_or_default();
    let operation = Operation::Call {
        class_length,
        method_length: 0,
        input_length: 0,
        data: data[..usize::from(class_length)].to_vec(),
        mutation: false,
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
            object: b"r10-fuzz",
            locator: b"",
            namespace: b"",
            snapshot: u64::MAX - 1,
            transaction_id: 1,
            client_global_id: 1,
            client_incarnation: 1,
            retry: -1,
            flags: 0x0400_0000,
            features: u64::MAX,
            operations: &[operation],
        },
        LIMITS,
    ));
    if let Some(message) = split_message(data, 43, 8, 3) {
        drop(decode_reply(&message, LIMITS));
    }
}

/// Feeds arbitrary bounded lock-info replies to the production decoder.
pub fn fuzz_lock(data: &[u8]) {
    if data.len() <= MAX_FUZZ_BYTES {
        drop(lock::decode_info(data, MAX_FUZZ_BYTES, 1024));
    }
}

/// Feeds arbitrary bounded watch notifications and result containers to production decoders.
pub fn fuzz_watch(data: &[u8]) {
    if data.len() > MAX_FUZZ_BYTES {
        return;
    }
    drop(watch::decode_notify_result(data, MAX_FUZZ_BYTES, 1024));
    drop(watch::decode_watchers(data, MAX_FUZZ_BYTES, 1024));
    if let Some(message) = split_message(data, watch::MESSAGE_WATCH_NOTIFY, 3, 1) {
        drop(watch::decode_notification(&message, MAX_FUZZ_BYTES));
    }
}

fn split_message(
    data: &[u8],
    message_type: u16,
    version: u16,
    compat_version: u16,
) -> Option<Message> {
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
            message_type,
            version,
            compat_version,
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
