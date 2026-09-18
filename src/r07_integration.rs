//! Hidden qualification adapters for R07 parser fuzzing.

use crate::msgr::message::{Message, MessageHeader, MessageLengths};
use crate::osd::backoff::{MESSAGE_OSD_BACKOFF, decode_backoff};
use crate::osd::messages::{Limits, decode_reply};

const MAX_FUZZ_BYTES: usize = 65_536;
const MAX_FUZZ_BYTES_U32: u32 = 65_536;
const MESSAGE_OSD_OP_REPLY: u16 = 43;
const LIMITS: Limits = Limits {
    max_bytes: MAX_FUZZ_BYTES_U32,
    max_operations: 64,
};

/// Feeds bounded arbitrary segment contents to the production `MOSDOp` reply decoder.
pub fn fuzz_osd_reply(data: &[u8]) {
    if let Some(message) = segmented_message(data, MESSAGE_OSD_OP_REPLY, 8, 3) {
        drop(decode_reply(&message, LIMITS));
    }
}

/// Feeds bounded arbitrary segment contents to the production `MOSDBackoff` decoder.
pub fn fuzz_osd_backoff(data: &[u8]) {
    if let Some(message) = segmented_message(data, MESSAGE_OSD_BACKOFF, 1, 1) {
        drop(decode_backoff(&message, LIMITS));
    }
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
