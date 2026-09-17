use super::frame::{DEFAULT_ALIGNMENT, Frame, FrameError, Limits, Segment, Tag};
use crate::protocol::address::{EntityAddr, EntityAddrVec};
use crate::protocol::features::GlobalFeatures;
use crate::wire::{Decoder, Encoder};

pub(crate) const CONNECTION_FLAG_LOSSY: u64 = 1;
const CONTROL_FEATURES: GlobalFeatures =
    GlobalFeatures(GlobalFeatures::MESSAGE_ADDRESS_V2.0 | GlobalFeatures::SERVER_NAUTILUS_MASK.0);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Hello {
    pub(crate) entity_type: u8,
    pub(crate) peer_address: EntityAddr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClientIdent {
    pub(crate) addresses: EntityAddrVec,
    pub(crate) target_address: EntityAddr,
    pub(crate) global_id: i64,
    pub(crate) global_sequence: u64,
    pub(crate) supported_features: u64,
    pub(crate) required_features: u64,
    pub(crate) flags: u64,
    pub(crate) cookie: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServerIdent {
    pub(crate) addresses: EntityAddrVec,
    pub(crate) global_id: i64,
    pub(crate) global_sequence: u64,
    pub(crate) supported_features: u64,
    pub(crate) required_features: u64,
    pub(crate) flags: u64,
    pub(crate) cookie: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IdentMissingFeatures {
    pub(crate) features: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SessionReconnect {
    pub(crate) addresses: EntityAddrVec,
    pub(crate) client_cookie: u64,
    pub(crate) server_cookie: u64,
    pub(crate) global_sequence: u64,
    pub(crate) connect_sequence: u64,
    pub(crate) message_sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SessionReset {
    pub(crate) full: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SessionRetry {
    pub(crate) connect_sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SessionRetryGlobal {
    pub(crate) global_sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SessionReconnectOk {
    pub(crate) message_sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Timestamp {
    pub(crate) seconds: u32,
    pub(crate) nanoseconds: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthRequest {
    pub(crate) method: u32,
    pub(crate) preferred_modes: Vec<u32>,
    pub(crate) auth_payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthBadMethod {
    pub(crate) method: u32,
    pub(crate) result: i32,
    pub(crate) allowed_methods: Vec<u32>,
    pub(crate) allowed_modes: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthDone {
    pub(crate) global_id: u64,
    pub(crate) connection_mode: u32,
    pub(crate) auth_payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Control {
    Hello(Hello),
    ClientIdent(ClientIdent),
    ServerIdent(ServerIdent),
    IdentMissingFeatures(IdentMissingFeatures),
    SessionReconnect(SessionReconnect),
    SessionReset(SessionReset),
    SessionRetry(SessionRetry),
    SessionRetryGlobal(SessionRetryGlobal),
    SessionReconnectOk(SessionReconnectOk),
    Wait,
    Keepalive2(Timestamp),
    Keepalive2Ack(Timestamp),
    Ack(u64),
    AuthRequest(AuthRequest),
    AuthBadMethod(AuthBadMethod),
    AuthReplyMore(Vec<u8>),
    AuthRequestMore(Vec<u8>),
    AuthDone(AuthDone),
    AuthSignature([u8; 32]),
    AuthPayload { tag: Tag, payload: Vec<u8> },
}

impl Control {
    pub(crate) fn encode(self, limits: Limits) -> Result<Frame, FrameError> {
        let tag = self.tag()?;
        let max_segment_bytes =
            usize::try_from(limits.max_segment_bytes).map_err(|_| FrameError::LimitExceeded)?;
        let mut encoder = Encoder::new(max_segment_bytes);
        match self {
            Self::Hello(value) => {
                encoder.u8(value.entity_type);
                value.peer_address.encode(&mut encoder, CONTROL_FEATURES)?;
            }
            Self::ClientIdent(value) => {
                check_addresses(&value.addresses, limits)?;
                value.addresses.encode(&mut encoder, CONTROL_FEATURES)?;
                value
                    .target_address
                    .encode(&mut encoder, CONTROL_FEATURES)?;
                encoder.i64(value.global_id);
                encoder.u64(value.global_sequence);
                encoder.u64(value.supported_features);
                encoder.u64(value.required_features);
                encoder.u64(value.flags);
                encoder.u64(value.cookie);
            }
            Self::ServerIdent(value) => {
                check_addresses(&value.addresses, limits)?;
                value.addresses.encode(&mut encoder, CONTROL_FEATURES)?;
                encoder.i64(value.global_id);
                encoder.u64(value.global_sequence);
                encoder.u64(value.supported_features);
                encoder.u64(value.required_features);
                encoder.u64(value.flags);
                encoder.u64(value.cookie);
            }
            Self::IdentMissingFeatures(value) => encoder.u64(value.features),
            Self::SessionReconnect(value) => {
                check_addresses(&value.addresses, limits)?;
                value.addresses.encode(&mut encoder, CONTROL_FEATURES)?;
                encoder.u64(value.client_cookie);
                encoder.u64(value.server_cookie);
                encoder.u64(value.global_sequence);
                encoder.u64(value.connect_sequence);
                encoder.u64(value.message_sequence);
            }
            Self::SessionReset(value) => encoder.bool(value.full),
            Self::SessionRetry(value) => encoder.u64(value.connect_sequence),
            Self::SessionRetryGlobal(value) => encoder.u64(value.global_sequence),
            Self::SessionReconnectOk(value) => encoder.u64(value.message_sequence),
            Self::Wait => {}
            Self::Keepalive2(value) | Self::Keepalive2Ack(value) => {
                encoder.u32(value.seconds);
                encoder.u32(value.nanoseconds);
            }
            Self::Ack(sequence) => encoder.u64(sequence),
            Self::AuthRequest(value) => {
                check_auth_bytes(&value.auth_payload, limits)?;
                encoder.u32(value.method);
                encode_u32_slice(&mut encoder, &value.preferred_modes, limits.max_auth_bytes)?;
                encoder.bytes(&value.auth_payload);
            }
            Self::AuthBadMethod(value) => {
                encoder.u32(value.method);
                encoder.i32(value.result);
                encode_u32_slice(&mut encoder, &value.allowed_methods, limits.max_auth_bytes)?;
                encode_u32_slice(&mut encoder, &value.allowed_modes, limits.max_auth_bytes)?;
            }
            Self::AuthReplyMore(payload) | Self::AuthRequestMore(payload) => {
                check_auth_bytes(&payload, limits)?;
                encoder.bytes(&payload);
            }
            Self::AuthDone(value) => {
                check_auth_bytes(&value.auth_payload, limits)?;
                encoder.u64(value.global_id);
                encoder.u32(value.connection_mode);
                encoder.bytes(&value.auth_payload);
            }
            Self::AuthSignature(signature) => encoder.raw(&signature),
            Self::AuthPayload { payload, .. } => {
                check_auth_bytes(&payload, limits)?;
                encoder.raw(&payload);
            }
        }
        Ok(Frame {
            tag,
            segments: vec![Segment {
                alignment: DEFAULT_ALIGNMENT,
                data: encoder.finish()?,
            }],
        })
    }

    pub(crate) fn decode(frame: &Frame, limits: Limits) -> Result<Self, FrameError> {
        if matches!(frame.tag, Tag::CompressionRequest | Tag::CompressionDone) {
            return Err(FrameError::UnsupportedPayload);
        }
        if frame.tag == Tag::Message
            || (frame.tag as u8) < Tag::Hello as u8
            || (frame.tag as u8) > Tag::Ack as u8
            || frame.segments.len() != 1
            || frame.segments[0].alignment != DEFAULT_ALIGNMENT
        {
            return Err(FrameError::Malformed);
        }
        let data = &frame.segments[0].data;
        if data.len() > limits.max_segment_bytes as usize {
            return Err(FrameError::LimitExceeded);
        }
        let mut decoder = Decoder::new(data, limits.max_segment_bytes as usize);
        let payload = decode_payload(frame.tag, &mut decoder, limits)?;
        decoder.finish()?;
        if decoder.remaining() != 0 {
            return Err(FrameError::Malformed);
        }
        Ok(payload)
    }

    fn tag(&self) -> Result<Tag, FrameError> {
        Ok(match self {
            Self::Hello(_) => Tag::Hello,
            Self::ClientIdent(_) => Tag::ClientIdent,
            Self::ServerIdent(_) => Tag::ServerIdent,
            Self::IdentMissingFeatures(_) => Tag::IdentMissingFeatures,
            Self::SessionReconnect(_) => Tag::SessionReconnect,
            Self::SessionReset(_) => Tag::SessionReset,
            Self::SessionRetry(_) => Tag::SessionRetry,
            Self::SessionRetryGlobal(_) => Tag::SessionRetryGlobal,
            Self::SessionReconnectOk(_) => Tag::SessionReconnectOk,
            Self::Wait => Tag::Wait,
            Self::Keepalive2(_) => Tag::Keepalive2,
            Self::Keepalive2Ack(_) => Tag::Keepalive2Ack,
            Self::Ack(_) => Tag::Ack,
            Self::AuthRequest(_) => Tag::AuthRequest,
            Self::AuthBadMethod(_) => Tag::AuthBadMethod,
            Self::AuthReplyMore(_) => Tag::AuthReplyMore,
            Self::AuthRequestMore(_) => Tag::AuthRequestMore,
            Self::AuthDone(_) => Tag::AuthDone,
            Self::AuthSignature(_) => Tag::AuthSignature,
            Self::AuthPayload { tag, .. }
                if (*tag as u8) >= Tag::AuthRequest as u8
                    && (*tag as u8) <= Tag::AuthSignature as u8 =>
            {
                *tag
            }
            Self::AuthPayload { .. } => return Err(FrameError::Malformed),
        })
    }
}

fn decode_payload(
    tag: Tag,
    decoder: &mut Decoder<'_>,
    limits: Limits,
) -> Result<Control, FrameError> {
    Ok(match tag {
        Tag::Hello => Control::Hello(Hello {
            entity_type: decoder.u8(),
            peer_address: EntityAddr::decode(decoder)?,
        }),
        Tag::ClientIdent => Control::ClientIdent(ClientIdent {
            addresses: EntityAddrVec::decode(decoder, limits.max_addresses)?,
            target_address: EntityAddr::decode(decoder)?,
            global_id: decoder.i64(),
            global_sequence: decoder.u64(),
            supported_features: decoder.u64(),
            required_features: decoder.u64(),
            flags: decoder.u64(),
            cookie: decoder.u64(),
        }),
        Tag::ServerIdent => Control::ServerIdent(ServerIdent {
            addresses: EntityAddrVec::decode(decoder, limits.max_addresses)?,
            global_id: decoder.i64(),
            global_sequence: decoder.u64(),
            supported_features: decoder.u64(),
            required_features: decoder.u64(),
            flags: decoder.u64(),
            cookie: decoder.u64(),
        }),
        Tag::IdentMissingFeatures => Control::IdentMissingFeatures(IdentMissingFeatures {
            features: decoder.u64(),
        }),
        Tag::SessionReconnect => Control::SessionReconnect(SessionReconnect {
            addresses: EntityAddrVec::decode(decoder, limits.max_addresses)?,
            client_cookie: decoder.u64(),
            server_cookie: decoder.u64(),
            global_sequence: decoder.u64(),
            connect_sequence: decoder.u64(),
            message_sequence: decoder.u64(),
        }),
        Tag::SessionReset => {
            let encoded = decoder.u8();
            if encoded > 1 {
                return Err(FrameError::Malformed);
            }
            Control::SessionReset(SessionReset { full: encoded == 1 })
        }
        Tag::SessionRetry => Control::SessionRetry(SessionRetry {
            connect_sequence: decoder.u64(),
        }),
        Tag::SessionRetryGlobal => Control::SessionRetryGlobal(SessionRetryGlobal {
            global_sequence: decoder.u64(),
        }),
        Tag::SessionReconnectOk => Control::SessionReconnectOk(SessionReconnectOk {
            message_sequence: decoder.u64(),
        }),
        Tag::Wait => Control::Wait,
        Tag::Keepalive2 => Control::Keepalive2(decode_timestamp(decoder)?),
        Tag::Keepalive2Ack => Control::Keepalive2Ack(decode_timestamp(decoder)?),
        Tag::Ack => Control::Ack(decoder.u64()),
        Tag::AuthRequest => Control::AuthRequest(AuthRequest {
            method: decoder.u32(),
            preferred_modes: decode_u32_slice(decoder, limits.max_auth_bytes)?,
            auth_payload: decode_auth_bytes(decoder, limits)?,
        }),
        Tag::AuthBadMethod => Control::AuthBadMethod(AuthBadMethod {
            method: decoder.u32(),
            result: decoder.i32(),
            allowed_methods: decode_u32_slice(decoder, limits.max_auth_bytes)?,
            allowed_modes: decode_u32_slice(decoder, limits.max_auth_bytes)?,
        }),
        Tag::AuthReplyMore => Control::AuthReplyMore(decode_auth_bytes(decoder, limits)?),
        Tag::AuthRequestMore => Control::AuthRequestMore(decode_auth_bytes(decoder, limits)?),
        Tag::AuthDone => Control::AuthDone(AuthDone {
            global_id: decoder.u64(),
            connection_mode: decoder.u32(),
            auth_payload: decode_auth_bytes(decoder, limits)?,
        }),
        Tag::AuthSignature => {
            let signature: [u8; 32] = decoder
                .raw(32)
                .try_into()
                .map_err(|_| FrameError::Malformed)?;
            Control::AuthSignature(signature)
        }
        Tag::Message | Tag::CompressionRequest | Tag::CompressionDone => {
            return Err(FrameError::Malformed);
        }
    })
}

fn check_addresses(addresses: &EntityAddrVec, limits: Limits) -> Result<(), FrameError> {
    if addresses.0.len() > limits.max_addresses as usize {
        return Err(FrameError::LimitExceeded);
    }
    Ok(())
}

fn check_auth_bytes(payload: &[u8], limits: Limits) -> Result<(), FrameError> {
    if payload.len() > limits.max_auth_bytes as usize {
        return Err(FrameError::LimitExceeded);
    }
    Ok(())
}

fn encode_u32_slice(
    encoder: &mut Encoder,
    values: &[u32],
    max_bytes: u32,
) -> Result<(), FrameError> {
    let count = u32::try_from(values.len()).map_err(|_| FrameError::LimitExceeded)?;
    if count.checked_mul(4).ok_or(FrameError::LimitExceeded)? > max_bytes {
        return Err(FrameError::LimitExceeded);
    }
    encoder.u32(count);
    for value in values {
        encoder.u32(*value);
    }
    Ok(())
}

fn decode_u32_slice(decoder: &mut Decoder<'_>, max_bytes: u32) -> Result<Vec<u32>, FrameError> {
    let count = decoder.u32();
    let encoded_bytes = count.checked_mul(4).ok_or(FrameError::LimitExceeded)?;
    if encoded_bytes > max_bytes {
        return Err(FrameError::LimitExceeded);
    }
    let count = usize::try_from(count).map_err(|_| FrameError::LimitExceeded)?;
    if count.checked_mul(4).ok_or(FrameError::LimitExceeded)? > decoder.remaining() {
        return Err(FrameError::Malformed);
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(decoder.u32());
    }
    Ok(values)
}

fn decode_auth_bytes(decoder: &mut Decoder<'_>, limits: Limits) -> Result<Vec<u8>, FrameError> {
    let length = decoder.u32();
    if length > limits.max_auth_bytes {
        return Err(FrameError::LimitExceeded);
    }
    let length = usize::try_from(length).map_err(|_| FrameError::LimitExceeded)?;
    if length > decoder.remaining() {
        return Err(FrameError::Malformed);
    }
    Ok(decoder.raw(length))
}

fn decode_timestamp(decoder: &mut Decoder<'_>) -> Result<Timestamp, FrameError> {
    let value = Timestamp {
        seconds: decoder.u32(),
        nanoseconds: decoder.u32(),
    };
    decoder.finish()?;
    if value.nanoseconds >= 1_000_000_000 {
        return Err(FrameError::Malformed);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_LIMITS: Limits = Limits {
        max_segment_bytes: 4096,
        max_frame_bytes: 8192,
        max_addresses: 4,
        max_auth_bytes: 64,
    };

    fn test_address() -> EntityAddr {
        let encoded = [
            0x01, 0x01, 0x01, 0x1c, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
            0x04, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0c, 0xe4, 0xc0, 0x00, 0x02, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut decoder = Decoder::new(&encoded, encoded.len());
        EntityAddr::decode(&mut decoder).expect("valid test address")
    }

    #[test]
    fn hello_matches_exact_go_vector() {
        let expected = vec![
            0x08, 0x01, 0x01, 0x01, 0x1c, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x02,
            0x03, 0x04, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0c, 0xe4, 0xc0, 0x00, 0x02, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let payload = Control::Hello(Hello {
            entity_type: 8,
            peer_address: test_address(),
        });
        let frame = payload.clone().encode(TEST_LIMITS).expect("valid hello");
        assert_eq!(frame.tag, Tag::Hello);
        assert_eq!(frame.segments[0].data, expected);
        assert_eq!(Control::decode(&frame, TEST_LIMITS), Ok(payload));
    }

    #[test]
    fn all_control_payloads_round_trip() {
        let address = test_address();
        let addresses = EntityAddrVec(vec![address.clone()]);
        let payloads = vec![
            Control::ClientIdent(ClientIdent {
                addresses: addresses.clone(),
                target_address: address.clone(),
                global_id: -1,
                global_sequence: 2,
                supported_features: 3,
                required_features: 4,
                flags: 5,
                cookie: 6,
            }),
            Control::ServerIdent(ServerIdent {
                addresses: addresses.clone(),
                global_id: 1,
                global_sequence: 2,
                supported_features: 3,
                required_features: 4,
                flags: 5,
                cookie: 6,
            }),
            Control::IdentMissingFeatures(IdentMissingFeatures { features: 9 }),
            Control::SessionReconnect(SessionReconnect {
                addresses,
                client_cookie: 1,
                server_cookie: 2,
                global_sequence: 3,
                connect_sequence: 4,
                message_sequence: 5,
            }),
            Control::SessionReset(SessionReset { full: true }),
            Control::SessionRetry(SessionRetry {
                connect_sequence: 11,
            }),
            Control::SessionRetryGlobal(SessionRetryGlobal {
                global_sequence: 12,
            }),
            Control::SessionReconnectOk(SessionReconnectOk {
                message_sequence: 13,
            }),
            Control::Wait,
            Control::Keepalive2(Timestamp {
                seconds: 14,
                nanoseconds: 15,
            }),
            Control::Keepalive2Ack(Timestamp {
                seconds: 16,
                nanoseconds: 17,
            }),
            Control::Ack(18),
            Control::AuthRequest(AuthRequest {
                method: 2,
                preferred_modes: vec![2, 1],
                auth_payload: vec![1, 2, 3],
            }),
            Control::AuthBadMethod(AuthBadMethod {
                method: 2,
                result: -13,
                allowed_methods: vec![2],
                allowed_modes: vec![2, 1],
            }),
            Control::AuthReplyMore(vec![4, 5]),
            Control::AuthRequestMore(vec![6, 7]),
            Control::AuthDone(AuthDone {
                global_id: 42,
                connection_mode: 2,
                auth_payload: vec![8, 9],
            }),
            Control::AuthSignature([
                1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
        ];
        for payload in payloads {
            let frame = payload.clone().encode(TEST_LIMITS).expect("encode control");
            assert_eq!(Control::decode(&frame, TEST_LIMITS), Ok(payload));
        }
    }

    #[test]
    fn raw_auth_tags_are_bounded_and_classified() {
        for tag in [
            Tag::AuthRequest,
            Tag::AuthBadMethod,
            Tag::AuthReplyMore,
            Tag::AuthRequestMore,
            Tag::AuthDone,
            Tag::AuthSignature,
        ] {
            let frame = Control::AuthPayload {
                tag,
                payload: vec![1, 2, 3],
            }
            .encode(TEST_LIMITS)
            .expect("valid raw auth payload");
            assert_eq!(frame.tag, tag);
        }
        assert_eq!(
            Control::AuthPayload {
                tag: Tag::Ack,
                payload: Vec::new()
            }
            .encode(TEST_LIMITS),
            Err(FrameError::Malformed)
        );
        assert_eq!(
            Control::AuthReplyMore(vec![0; 65]).encode(TEST_LIMITS),
            Err(FrameError::LimitExceeded)
        );
        assert_eq!(
            Control::AuthRequest(AuthRequest {
                method: 2,
                preferred_modes: vec![0; 17],
                auth_payload: Vec::new(),
            })
            .encode(TEST_LIMITS),
            Err(FrameError::LimitExceeded)
        );
        assert_eq!(
            Control::AuthBadMethod(AuthBadMethod {
                method: 2,
                result: -13,
                allowed_methods: vec![0; 17],
                allowed_modes: Vec::new(),
            })
            .encode(TEST_LIMITS),
            Err(FrameError::LimitExceeded)
        );
    }

    #[test]
    fn rejects_malformed_truncated_and_limited_payloads() {
        let cases = [
            Frame {
                tag: Tag::Ack,
                segments: vec![Segment {
                    alignment: 8,
                    data: vec![0; 9],
                }],
            },
            Frame {
                tag: Tag::SessionReset,
                segments: vec![Segment {
                    alignment: 8,
                    data: vec![2],
                }],
            },
            Frame {
                tag: Tag::Wait,
                segments: vec![Segment {
                    alignment: 16,
                    data: Vec::new(),
                }],
            },
            Frame {
                tag: Tag::Wait,
                segments: vec![
                    Segment {
                        alignment: 8,
                        data: Vec::new(),
                    },
                    Segment {
                        alignment: 8,
                        data: Vec::new(),
                    },
                ],
            },
            Frame {
                tag: Tag::AuthSignature,
                segments: vec![Segment {
                    alignment: 8,
                    data: vec![0; 31],
                }],
            },
        ];
        for frame in cases {
            assert_eq!(
                Control::decode(&frame, TEST_LIMITS),
                Err(FrameError::Malformed)
            );
        }
        assert_eq!(
            Control::decode(
                &Frame {
                    tag: Tag::CompressionRequest,
                    segments: vec![Segment {
                        alignment: 8,
                        data: Vec::new()
                    }]
                },
                TEST_LIMITS
            ),
            Err(FrameError::UnsupportedPayload)
        );
        assert_eq!(
            Control::decode(
                &Frame {
                    tag: Tag::ServerIdent,
                    segments: vec![Segment {
                        alignment: 8,
                        data: vec![2, 5, 0, 0, 0]
                    }]
                },
                TEST_LIMITS
            ),
            Err(FrameError::LimitExceeded)
        );
    }
}
