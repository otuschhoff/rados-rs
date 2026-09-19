use crate::msgr::message::Message;
use crate::protocol::address::EntityAddr;
use crate::wire::{Decoder, Encoder, WireError};

pub(crate) const MESSAGE_WATCH_NOTIFY: u16 = 44;
pub(crate) const OPERATION_UNWATCH: u8 = 0;
pub(crate) const OPERATION_REGISTER: u8 = 3;
pub(crate) const OPERATION_RECONNECT: u8 = 5;
pub(crate) const OPERATION_PING: u8 = 7;
pub(crate) const EVENT_NOTIFY: u8 = 1;
pub(crate) const EVENT_COMPLETE: u8 = 2;
pub(crate) const EVENT_DISCONNECT: u8 = 3;
const ENTITY_CLIENT: u8 = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Notification {
    pub(crate) cookie: u64,
    pub(crate) version: u64,
    pub(crate) notify_id: u64,
    pub(crate) opcode: u8,
    pub(crate) data: Vec<u8>,
    pub(crate) result: i32,
    pub(crate) notifier: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Acknowledgment {
    pub(crate) client: u64,
    pub(crate) cookie: u64,
    pub(crate) data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Timeout {
    pub(crate) client: u64,
    pub(crate) cookie: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WatcherInfo {
    pub(crate) client: u64,
    pub(crate) cookie: u64,
    pub(crate) timeout_seconds: u32,
    pub(crate) address: String,
}

pub(crate) fn encode_notify(
    timeout_seconds: u32,
    data: &[u8],
    max_bytes: usize,
) -> Result<Vec<u8>, WireError> {
    let mut encoder = Encoder::new(max_bytes);
    encoder.u32(1);
    encoder.u32(timeout_seconds);
    encoder.bytes(data);
    encoder.finish()
}

pub(crate) fn encode_ack(
    notify_id: u64,
    cookie: u64,
    data: &[u8],
    max_bytes: usize,
) -> Result<Vec<u8>, WireError> {
    if notify_id == 0 || cookie == 0 {
        return Err(WireError::Malformed);
    }
    let mut encoder = Encoder::new(max_bytes);
    encoder.u64(notify_id);
    encoder.u64(cookie);
    encoder.bytes(data);
    encoder.finish()
}

pub(crate) fn decode_notification(
    message: &Message,
    max_bytes: usize,
) -> Result<Notification, WireError> {
    let total = message
        .front
        .len()
        .checked_add(message.data.len())
        .ok_or(WireError::LimitExceeded)?;
    if max_bytes == 0
        || message.header.message_type != MESSAGE_WATCH_NOTIFY
        || !(1..=3).contains(&message.header.version)
        || message.header.compat_version > 1
        || !message.middle.is_empty()
        || total > max_bytes
    {
        return Err(WireError::Malformed);
    }
    let mut decoder = Decoder::new(&message.front, max_bytes);
    let message_version = decoder.u8();
    let opcode = decoder.u8();
    let cookie = decoder.u64();
    let version = decoder.u64();
    let notify_id = decoder.u64();
    if message_version == 0
        || cookie == 0
        || !matches!(opcode, EVENT_NOTIFY | EVENT_COMPLETE | EVENT_DISCONNECT)
    {
        return Err(WireError::Malformed);
    }
    let front_data = decoder.bytes();
    if !front_data.is_empty() && !message.data.is_empty() {
        return Err(WireError::Malformed);
    }
    let result = if message.header.version >= 2 {
        decoder.i32()
    } else {
        0
    };
    let notifier = if message.header.version >= 3 {
        decoder.u64()
    } else {
        0
    };
    decoder.finish()?;
    if decoder.remaining() != 0 {
        return Err(WireError::Malformed);
    }
    Ok(Notification {
        cookie,
        version,
        notify_id,
        opcode,
        data: if message.data.is_empty() {
            front_data
        } else {
            message.data.clone()
        },
        result,
        notifier,
    })
}

pub(crate) fn decode_notify_result(
    data: &[u8],
    max_bytes: usize,
    max_entries: usize,
) -> Result<(Vec<Acknowledgment>, Vec<Timeout>), WireError> {
    let mut decoder = Decoder::new(data, max_bytes);
    let acknowledged_count = decoder.u32() as usize;
    decoder.finish()?;
    if acknowledged_count > max_entries
        || acknowledged_count.saturating_mul(20) > decoder.remaining()
    {
        return Err(WireError::LimitExceeded);
    }
    let mut acknowledged = Vec::with_capacity(acknowledged_count);
    for _ in 0..acknowledged_count {
        acknowledged.push(Acknowledgment {
            client: decoder.u64(),
            cookie: decoder.u64(),
            data: decoder.bytes(),
        });
        decoder.finish()?;
    }
    let timeout_count = decoder.u32() as usize;
    decoder.finish()?;
    if timeout_count > max_entries.saturating_sub(acknowledged.len())
        || timeout_count.saturating_mul(16) > decoder.remaining()
    {
        return Err(WireError::LimitExceeded);
    }
    let mut timed_out = Vec::with_capacity(timeout_count);
    for _ in 0..timeout_count {
        timed_out.push(Timeout {
            client: decoder.u64(),
            cookie: decoder.u64(),
        });
    }
    decoder.finish()?;
    if decoder.remaining() != 0 {
        return Err(WireError::Malformed);
    }
    Ok((acknowledged, timed_out))
}

pub(crate) fn decode_watchers(
    data: &[u8],
    max_bytes: usize,
    max_watchers: usize,
) -> Result<Vec<WatcherInfo>, WireError> {
    let mut decoder = Decoder::new(data, max_bytes);
    let (version, mut payload) = decoder.versioned(1);
    decoder.finish()?;
    if version != 1 {
        return Err(WireError::Malformed);
    }
    let count = payload.u32() as usize;
    payload.finish()?;
    if count > max_watchers || count.saturating_mul(17) > payload.remaining() {
        return Err(WireError::LimitExceeded);
    }
    let mut watchers = Vec::with_capacity(count);
    for _ in 0..count {
        let (item_version, mut item) = payload.versioned(2);
        payload.finish()?;
        if !(1..=2).contains(&item_version) || item.u8() != ENTITY_CLIENT {
            return Err(WireError::Malformed);
        }
        let client = item.i64();
        let cookie = item.u64();
        let timeout_seconds = item.u32();
        if client < 0 || cookie == 0 {
            return Err(WireError::Malformed);
        }
        let address = if item_version >= 2 {
            EntityAddr::decode(&mut item)?
                .endpoint()
                .map_or_else(String::new, |value| value.to_string())
        } else {
            String::new()
        };
        item.finish()?;
        if item.remaining() != 0 {
            return Err(WireError::Malformed);
        }
        watchers.push(WatcherInfo {
            client: u64::try_from(client).map_err(|_| WireError::Malformed)?,
            cookie,
            timeout_seconds,
            address,
        });
    }
    payload.finish()?;
    if payload.remaining() != 0 {
        return Err(WireError::Malformed);
    }
    Ok(watchers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgr::message::{MessageHeader, MessageLengths};

    #[test]
    fn watch_notification_and_notify_result_match_frozen_go_vectors() {
        let mut encoder = Encoder::new(4096);
        encoder.u8(1);
        encoder.u8(EVENT_NOTIFY);
        encoder.u64(8);
        encoder.u64(9);
        encoder.u64(10);
        encoder.bytes(b"payload");
        encoder.i32(0);
        encoder.u64(11);
        let front = encoder.finish().expect("front");
        let notification = decode_notification(
            &Message {
                header: MessageHeader {
                    message_type: MESSAGE_WATCH_NOTIFY,
                    version: 3,
                    compat_version: 1,
                    ..MessageHeader::default()
                },
                lengths: MessageLengths {
                    front: u32::try_from(front.len()).expect("front length"),
                    ..MessageLengths::default()
                },
                front,
                ..Message::default()
            },
            4096,
        )
        .expect("notification");
        assert_eq!(notification.cookie, 8);
        assert_eq!(notification.notify_id, 10);
        assert_eq!(notification.notifier, 11);
        assert_eq!(notification.data, b"payload");

        let mut result = Encoder::new(4096);
        result.u32(1);
        result.u64(12);
        result.u64(13);
        result.bytes(b"ack");
        result.u32(1);
        result.u64(14);
        result.u64(15);
        let result = result.finish().expect("result");
        let (acknowledged, timed_out) =
            decode_notify_result(&result, 4096, 2).expect("decode result");
        assert_eq!(acknowledged[0].client, 12);
        assert_eq!(acknowledged[0].data, b"ack");
        assert_eq!(timed_out[0].cookie, 15);
        assert_eq!(
            decode_notify_result(&result, 4096, 1),
            Err(WireError::LimitExceeded)
        );
    }
}
