use std::fmt;

use crate::maps::{Fsid, PG};
use crate::msgr::message::{Message, MessageHeader, MessageLengths};
use crate::wire::{Decoder, Encoder, WireError};

const MESSAGE_COMMAND: u16 = 97;
const MESSAGE_COMMAND_REPLY: u16 = 98;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CommandRequest<'a> {
    pub(crate) fsid: Fsid,
    pub(crate) transaction_id: u64,
    pub(crate) command: &'a [String],
    pub(crate) input: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CommandReply {
    pub(crate) transaction_id: u64,
    pub(crate) result: i32,
    pub(crate) status: String,
    pub(crate) output: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Wire(WireError),
    MalformedReply,
    UnsupportedVersion,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "OSD command error: {self:?}")
    }
}

impl std::error::Error for Error {}

impl From<WireError> for Error {
    fn from(value: WireError) -> Self {
        Self::Wire(value)
    }
}

pub(crate) fn encode_command_request(
    request: &CommandRequest<'_>,
    max_bytes: u32,
) -> Result<Message, Error> {
    if max_bytes == 0 || request.command.is_empty() || request.input.len() > max_bytes as usize {
        return Err(WireError::LimitExceeded.into());
    }
    if request
        .command
        .iter()
        .any(|argument| argument.len() > u32::MAX as usize)
    {
        return Err(WireError::LimitExceeded.into());
    }
    let mut encoder = Encoder::new(max_bytes as usize);
    encoder.raw(&request.fsid.0);
    encoder.u32(u32::try_from(request.command.len()).map_err(|_| WireError::LimitExceeded)?);
    for argument in request.command {
        encoder.string(argument);
    }
    let front = encoder.finish()?;
    if front.len().saturating_add(request.input.len()) > max_bytes as usize {
        return Err(WireError::LimitExceeded.into());
    }
    let data = request.input.to_vec();
    Ok(Message {
        header: MessageHeader {
            transaction_id: request.transaction_id,
            message_type: MESSAGE_COMMAND,
            version: 1,
            compat_version: 0,
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

pub(crate) fn decode_command_reply(
    message: &Message,
    max_bytes: u32,
) -> Result<CommandReply, Error> {
    if max_bytes == 0 {
        return Err(WireError::LimitExceeded.into());
    }
    if message.header.message_type != MESSAGE_COMMAND_REPLY {
        return Err(Error::MalformedReply);
    }
    if message.header.version < 1 || message.header.compat_version > 1 {
        return Err(Error::UnsupportedVersion);
    }
    if !message.middle.is_empty() {
        return Err(Error::MalformedReply);
    }
    if message.front.len().saturating_add(message.data.len()) > max_bytes as usize {
        return Err(WireError::LimitExceeded.into());
    }
    let front_len = u32::try_from(message.front.len()).map_err(|_| WireError::LimitExceeded)?;
    let data_len = u32::try_from(message.data.len()).map_err(|_| WireError::LimitExceeded)?;
    if message.lengths.front != front_len || message.lengths.data != data_len {
        return Err(Error::MalformedReply);
    }
    let mut decoder = Decoder::new(&message.front, max_bytes as usize);
    let result = decoder.i32();
    let status = decoder.string();
    if decoder.finish().is_err() || decoder.remaining() != 0 {
        return Err(Error::MalformedReply);
    }
    Ok(CommandReply {
        transaction_id: message.header.transaction_id,
        result,
        status,
        output: message.data.clone(),
    })
}

pub(crate) fn parse_pg(text: &str) -> Result<PG, WireError> {
    let Some(dot) = text.as_bytes().iter().position(|byte| *byte == b'.') else {
        return Err(WireError::Malformed);
    };
    if dot == 0 || dot >= text.len().saturating_sub(1) {
        return Err(WireError::Malformed);
    }
    let pool_text = &text[..dot];
    let seed_text = &text[dot + 1..];
    if seed_text.contains(['s', 'S', 'p', 'P', '_']) {
        return Err(WireError::Malformed);
    }
    let pool = pool_text
        .parse::<i64>()
        .map_err(|_| WireError::Malformed)
        .and_then(|value| u64::try_from(value).map_err(|_| WireError::Malformed))?;
    let seed = u32::from_str_radix(seed_text, 16).map_err(|_| WireError::Malformed)?;
    Ok(PG {
        pool,
        seed,
        preferred: -1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply_front(result: i32, status: &str) -> Vec<u8> {
        let mut encoder = Encoder::new(1024);
        encoder.i32(result);
        encoder.string(status);
        encoder.finish().expect("reply front")
    }

    #[test]
    fn encode_command_request_exact_bytes() {
        let request = CommandRequest {
            fsid: Fsid([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
            transaction_id: 0x0102_0304_0506_0708,
            command: &["ping".to_owned(), "osd.5".to_owned()],
            input: b"data",
        };
        let message = encode_command_request(&request, 128).expect("request");
        assert_eq!(message.header.message_type, MESSAGE_COMMAND);
        assert_eq!(message.header.version, 1);
        assert_eq!(message.header.compat_version, 0);
        assert_eq!(message.header.transaction_id, request.transaction_id);

        let mut expected = Vec::new();
        expected.extend_from_slice(&request.fsid.0);
        expected.extend_from_slice(&2_u32.to_le_bytes());
        expected.extend_from_slice(&4_u32.to_le_bytes());
        expected.extend_from_slice(b"ping");
        expected.extend_from_slice(&5_u32.to_le_bytes());
        expected.extend_from_slice(b"osd.5");
        assert_eq!(message.front, expected);
        assert_eq!(message.data, b"data");
        assert_eq!(
            message.lengths.front,
            u32::try_from(message.front.len()).expect("front length")
        );
        assert_eq!(message.lengths.data, 4);
        assert_eq!(message.lengths.middle, 0);
    }

    #[test]
    fn encode_command_request_rejects_empty_or_oversized_payloads() {
        let request = CommandRequest {
            fsid: Fsid([0; 16]),
            transaction_id: 1,
            command: &[],
            input: &[],
        };
        assert_eq!(
            encode_command_request(&request, 16),
            Err(Error::Wire(WireError::LimitExceeded))
        );

        let oversized_input = CommandRequest {
            fsid: Fsid([0; 16]),
            transaction_id: 1,
            command: &["x".to_owned()],
            input: &[0; 32],
        };
        assert_eq!(
            encode_command_request(&oversized_input, 16),
            Err(Error::Wire(WireError::LimitExceeded))
        );

        let oversized_front = CommandRequest {
            fsid: Fsid([0; 16]),
            transaction_id: 1,
            command: &["01234567890123456789".to_owned()],
            input: &[],
        };
        assert_eq!(
            encode_command_request(&oversized_front, 20),
            Err(Error::Wire(WireError::LimitExceeded))
        );
    }

    #[test]
    fn decode_command_reply_exact_bytes() {
        let message = Message {
            header: MessageHeader {
                message_type: MESSAGE_COMMAND_REPLY,
                version: 1,
                compat_version: 1,
                transaction_id: 42,
                ..MessageHeader::default()
            },
            lengths: MessageLengths {
                front: 14,
                data: 6,
                ..MessageLengths::default()
            },
            front: reply_front(-13, "denied"),
            data: b"output".to_vec(),
            ..Message::default()
        };
        let reply = decode_command_reply(&message, 4096).expect("reply");
        assert_eq!(reply.transaction_id, 42);
        assert_eq!(reply.result, -13);
        assert_eq!(reply.status, "denied");
        assert_eq!(reply.output, b"output");
    }

    #[test]
    fn decode_command_reply_rejects_malformed_payloads() {
        let good = Message {
            header: MessageHeader {
                message_type: MESSAGE_COMMAND_REPLY,
                version: 1,
                compat_version: 1,
                ..MessageHeader::default()
            },
            lengths: MessageLengths {
                front: 10,
                ..MessageLengths::default()
            },
            front: reply_front(0, "ok"),
            ..Message::default()
        };

        let mut wrong_type = good.clone();
        wrong_type.header.message_type = MESSAGE_COMMAND;
        assert_eq!(
            decode_command_reply(&wrong_type, 4096),
            Err(Error::MalformedReply)
        );

        let mut wrong_compat = good.clone();
        wrong_compat.header.compat_version = 2;
        assert_eq!(
            decode_command_reply(&wrong_compat, 4096),
            Err(Error::UnsupportedVersion)
        );

        let mut unexpected_middle = good.clone();
        unexpected_middle.middle = vec![1];
        assert_eq!(
            decode_command_reply(&unexpected_middle, 4096),
            Err(Error::MalformedReply)
        );

        let mut mismatch = good.clone();
        mismatch.lengths.front = mismatch.lengths.front.saturating_add(1);
        assert_eq!(
            decode_command_reply(&mismatch, 4096),
            Err(Error::MalformedReply)
        );

        let mut trailing = good.clone();
        trailing.front.push(0);
        trailing.lengths.front = u32::try_from(trailing.front.len()).expect("front length");
        assert_eq!(
            decode_command_reply(&trailing, 4096),
            Err(Error::MalformedReply)
        );

        let mut truncated = good.clone();
        truncated.front.pop();
        truncated.lengths.front = u32::try_from(truncated.front.len()).expect("front length");
        assert_eq!(
            decode_command_reply(&truncated, 4096),
            Err(Error::MalformedReply)
        );

        assert_eq!(
            decode_command_reply(&good, 0),
            Err(Error::Wire(WireError::LimitExceeded))
        );

        let mut over_limit = good;
        over_limit.data = vec![0; 5000];
        over_limit.lengths.data = 5000;
        assert_eq!(
            decode_command_reply(&over_limit, 4096),
            Err(Error::Wire(WireError::LimitExceeded))
        );
    }

    #[test]
    fn parse_pg_accepts_canonical_form_and_rejects_suffixes() {
        assert_eq!(
            parse_pg("7.1a"),
            Ok(PG {
                pool: 7,
                seed: 0x1a,
                preferred: -1
            })
        );
        assert_eq!(
            parse_pg("0.0"),
            Ok(PG {
                pool: 0,
                seed: 0,
                preferred: -1
            })
        );
        for value in [
            "", "7", "7.", ".1", "-1.1", "7.g", "7.1s0", "7.1p0", "7.1_head", "abc.1",
        ] {
            assert_eq!(parse_pg(value), Err(WireError::Malformed));
        }
    }
}
