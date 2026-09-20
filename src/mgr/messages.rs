use std::fmt;

use crate::maps::Fsid;
use crate::msgr::message::{Message, MessageHeader, MessageLengths};
use crate::wire::{Decoder, Encoder, WireError};

pub(crate) const MESSAGE_MGR_COMMAND: u16 = 0x709;
pub(crate) const MESSAGE_MGR_COMMAND_REPLY: u16 = 0x70a;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CommandReply {
    pub(crate) result: i32,
    pub(crate) status: String,
    pub(crate) data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MessageError {
    Wire(WireError),
    Malformed(&'static str),
}

impl fmt::Display for MessageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wire(error) => write!(formatter, "{error}"),
            Self::Malformed(reason) => write!(formatter, "malformed manager message: {reason}"),
        }
    }
}

impl std::error::Error for MessageError {}

impl From<WireError> for MessageError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

pub(crate) type Result<T> = std::result::Result<T, MessageError>;

pub(crate) fn encode_command(
    fsid: Fsid,
    command: &[String],
    input: &[u8],
    max_bytes: u32,
) -> Result<Message> {
    if max_bytes == 0 || command.is_empty() {
        return Err(WireError::LimitExceeded.into());
    }
    if input.len() > max_bytes as usize {
        return Err(WireError::LimitExceeded.into());
    }
    let mut encoder = Encoder::new(max_bytes as usize);
    encoder.raw(&fsid.0);
    encoder.u32(u32::try_from(command.len()).map_err(|_| WireError::LimitExceeded)?);
    for item in command {
        encoder.string(item);
    }
    let front = encoder.finish()?;
    if front.len().saturating_add(input.len()) > max_bytes as usize {
        return Err(WireError::LimitExceeded.into());
    }
    let data = input.to_vec();
    Ok(Message {
        header: MessageHeader {
            message_type: MESSAGE_MGR_COMMAND,
            version: 1,
            compat_version: 0,
            ..MessageHeader::default()
        },
        lengths: MessageLengths {
            front: u32::try_from(front.len()).map_err(|_| WireError::LimitExceeded)?,
            middle: 0,
            data: u32::try_from(data.len()).map_err(|_| WireError::LimitExceeded)?,
        },
        front,
        middle: Vec::new(),
        data,
    })
}

pub(crate) fn decode_command_reply(message: &Message, max_bytes: u32) -> Result<CommandReply> {
    validate_message_payload(message, MESSAGE_MGR_COMMAND_REPLY, 1, 1, max_bytes)?;
    let mut decoder = Decoder::new(&message.front, max_bytes as usize);
    let result = decoder.i32();
    let status = decoder.string();
    finish_exact(&decoder, "manager command reply")?;
    Ok(CommandReply {
        result,
        status,
        data: message.data.clone(),
    })
}

fn validate_message_payload(
    message: &Message,
    message_type: u16,
    version: u16,
    compat: u16,
    max_bytes: u32,
) -> Result<()> {
    let total = message
        .front
        .len()
        .checked_add(message.data.len())
        .ok_or(WireError::LimitExceeded)?;
    if max_bytes == 0 || total > max_bytes as usize {
        return Err(WireError::LimitExceeded.into());
    }
    if message.header.message_type != message_type
        || message.header.version != version
        || message.header.compat_version != compat
        || !message.middle.is_empty()
        || message.lengths
            != (MessageLengths {
                front: u32::try_from(message.front.len()).map_err(|_| WireError::LimitExceeded)?,
                middle: 0,
                data: u32::try_from(message.data.len()).map_err(|_| WireError::LimitExceeded)?,
            })
    {
        return Err(MessageError::Malformed("message payload"));
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
    use super::*;

    #[test]
    fn manager_command_codecs_match_frozen_layout_and_bounds() {
        let fsid = Fsid([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let command = vec![
            "{\"prefix\":\"dashboard get\",\"format\":\"json\"}".to_owned(),
            "{\"target\":\"mgr.active\"}".to_owned(),
        ];
        let request = encode_command(fsid, &command, b"input", 1024).expect("command");
        assert_eq!(request.header.message_type, MESSAGE_MGR_COMMAND);
        assert_eq!(
            (request.header.version, request.header.compat_version),
            (1, 0)
        );
        assert_eq!(request.data, b"input");

        let mut decoder = Decoder::new(&request.front, 1024);
        assert_eq!(decoder.raw(16), &fsid.0);
        assert_eq!(decoder.u32(), 2);
        assert_eq!(decoder.string(), command[0]);
        assert_eq!(decoder.string(), command[1]);
        assert_eq!(decoder.remaining(), 0);

        let mut encoder = Encoder::new(256);
        encoder.i32(-13);
        encoder.string("permission denied");
        let mut reply = Message {
            header: MessageHeader {
                message_type: MESSAGE_MGR_COMMAND_REPLY,
                version: 1,
                compat_version: 1,
                ..MessageHeader::default()
            },
            lengths: MessageLengths::default(),
            front: encoder.finish().expect("front"),
            middle: Vec::new(),
            data: b"details".to_vec(),
        };
        reply.lengths.front = u32::try_from(reply.front.len()).expect("front length");
        reply.lengths.data = u32::try_from(reply.data.len()).expect("data length");
        let decoded_reply = decode_command_reply(&reply, 256).expect("decode reply");
        assert_eq!(decoded_reply.result, -13);
        assert_eq!(decoded_reply.status, "permission denied");
        assert_eq!(decoded_reply.data, b"details");

        assert!(encode_command(fsid, &command, &[0; 65], 64).is_err());
        reply.lengths.data += 1;
        assert!(matches!(
            decode_command_reply(&reply, 256),
            Err(MessageError::Malformed("message payload"))
        ));
    }
}
