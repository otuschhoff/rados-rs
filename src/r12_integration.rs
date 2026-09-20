//! Hidden qualification adapters for R12 administration decoder fuzzing.

use crate::client::decode_inconsistent_pgs;
use crate::mgr::messages::{
    MESSAGE_MGR_COMMAND_REPLY, decode_command_reply as decode_manager_command_reply,
};
use crate::mon::messages::{
    MESSAGE_GET_POOL_STATS_REPLY, MESSAGE_MON_COMMAND_REPLY, MESSAGE_STATFS_REPLY,
    decode_command_reply as decode_monitor_command_reply, decode_get_pool_stats_reply,
    decode_statfs_reply,
};
use crate::msgr::message::{Message, MessageHeader, MessageLengths};
use crate::osd::command::decode_command_reply as decode_osd_command_reply;
use crate::osd::inconsistent::decode_scrub_list;

const MAX_FUZZ_BYTES: usize = 65_536;
const MAX_FUZZ_BYTES_U32: u32 = 65_536;
const MAX_ENTRIES: u32 = 1_024;

const OSD_COMMAND_REPLY: u16 = 98;

/// Feeds arbitrary bounded command replies through the monitor, manager, and OSD decoders.
pub fn fuzz_command(data: &[u8]) {
    if data.len() > MAX_FUZZ_BYTES {
        return;
    }
    let monitor = build_payload_message(data, MESSAGE_MON_COMMAND_REPLY, 1, 0);
    let _ = decode_monitor_command_reply(&monitor, MAX_FUZZ_BYTES_U32, MAX_ENTRIES);
    let manager = build_payload_message(data, MESSAGE_MGR_COMMAND_REPLY, 1, 1);
    let _ = decode_manager_command_reply(&manager, MAX_FUZZ_BYTES_U32);
    let osd = build_payload_message(data, OSD_COMMAND_REPLY, 1, 0);
    let _ = decode_osd_command_reply(&osd, MAX_FUZZ_BYTES_U32);
}

/// Feeds arbitrary bounded statfs and pool-stat replies to production monitor decoders.
pub fn fuzz_stats(data: &[u8]) {
    if data.len() > MAX_FUZZ_BYTES {
        return;
    }
    let statfs = build_front_message(data, MESSAGE_STATFS_REPLY, 1, 1);
    let _ = decode_statfs_reply(&statfs, MAX_FUZZ_BYTES_U32);
    let pool_stats_v1 = build_front_message(data, MESSAGE_GET_POOL_STATS_REPLY, 1, 0);
    let _ =
        decode_get_pool_stats_reply(&pool_stats_v1, MAX_FUZZ_BYTES_U32, MAX_ENTRIES, MAX_ENTRIES);
    let pool_stats_v2 = build_front_message(data, MESSAGE_GET_POOL_STATS_REPLY, 2, 1);
    let _ =
        decode_get_pool_stats_reply(&pool_stats_v2, MAX_FUZZ_BYTES_U32, MAX_ENTRIES, MAX_ENTRIES);
}

/// Feeds arbitrary bounded scrub-list wire buffers and inconsistent-PG JSON to production decoders.
pub fn fuzz_inconsistent(data: &[u8]) {
    if data.len() > MAX_FUZZ_BYTES {
        return;
    }
    let _ = decode_scrub_list(data, MAX_FUZZ_BYTES_U32, MAX_ENTRIES);
    let _ = decode_inconsistent_pgs(data, "r12_integration::fuzz_inconsistent");
}

fn build_front_message(
    data: &[u8],
    message_type: u16,
    version: u16,
    compat_version: u16,
) -> Message {
    let front = data.to_vec();
    let front_length = u32::try_from(front.len()).unwrap_or_default();
    Message {
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
    }
}

fn build_payload_message(
    data: &[u8],
    message_type: u16,
    version: u16,
    compat_version: u16,
) -> Message {
    let split = data.len().min(usize::from(u16::from_le_bytes([
        *data.first().unwrap_or(&0),
        *data.get(1).unwrap_or(&0),
    ])));
    let front = data.get(..split).unwrap_or_default().to_vec();
    let body = data.get(split..).unwrap_or_default().to_vec();
    let front_length = u32::try_from(front.len()).unwrap_or_default();
    let data_length = u32::try_from(body.len()).unwrap_or_default();
    Message {
        header: MessageHeader {
            message_type,
            version,
            compat_version,
            ..MessageHeader::default()
        },
        lengths: MessageLengths {
            front: front_length,
            middle: 0,
            data: data_length,
        },
        front,
        middle: Vec::new(),
        data: body,
    }
}
