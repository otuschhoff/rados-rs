mod wire {
    pub(crate) mod codec {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../src/wire/codec.rs"));
    }
    pub(crate) mod crc {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../src/wire/crc.rs"));
    }
    pub(crate) use codec::{Decoder, Encoder, WireError};
    pub(crate) use crc::crc32c;
}

mod protocol {
    pub(crate) mod features {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../src/protocol/features.rs"
        ));
    }
    pub(crate) mod address {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../src/protocol/address.rs"
        ));
    }
}

mod msgr {
    pub(crate) mod banner {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../src/msgr/banner.rs"
        ));
    }
    pub(crate) mod control {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../src/msgr/control.rs"
        ));
    }
    pub(crate) mod frame {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../src/msgr/frame.rs"));
    }
    pub(crate) mod message {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../src/msgr/message.rs"
        ));
    }
    pub(crate) mod secure {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../src/msgr/secure.rs"
        ));
    }
    pub(crate) mod session {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../src/msgr/session.rs"
        ));
    }
}

use msgr::control::{ClientIdent, Control, Timestamp};
use msgr::frame::{CrcCodec, DEFAULT_ALIGNMENT, Frame, FrameError, Limits, Segment, Tag};
use msgr::message::{Message, MessageLengths};
use msgr::secure::SecureCodec;
use msgr::session::{Config, Effect, Input, Machine, ReconnectPolicy, SessionError};
use protocol::address::{EntityAddr, EntityAddrVec};
use std::io::Cursor;

const FUZZ_LIMITS: Limits = Limits {
    max_segment_bytes: 256,
    max_frame_bytes: 1024,
    max_addresses: 2,
    max_auth_bytes: 64,
};
const MAX_FUZZ_WIRE_BYTES: usize = 2048;
const MAX_SESSION_SCRIPT_BYTES: usize = 24;

pub fn primitive_decoder(data: &[u8]) {
    let mut decoder = wire::Decoder::new(data, 4_096);
    let _ = decoder.u8();
    let _ = decoder.u16();
    let _ = decoder.u32();
    let _ = decoder.u64();
    let _ = decoder.i8();
    let _ = decoder.i16();
    let _ = decoder.i32();
    let _ = decoder.i64();
    let _ = decoder.bool();
    let _ = decoder.bytes();
    let _ = decoder.string();
    let _ = decoder.finish();
}

pub fn versioned_envelope(data: &[u8]) {
    let mut decoder = wire::Decoder::new(data, 4_096);
    let (_, mut payload) = decoder.versioned(3);
    let _ = payload.u64();
    let _ = payload.bytes();
    let _ = payload.finish();
    let _ = decoder.finish();
}

pub fn entity_address(data: &[u8]) {
    let mut decoder = wire::Decoder::new(data, 4_096);
    if let Ok(address) = protocol::address::EntityAddr::decode(&mut decoder) {
        if decoder.finish().is_err() || decoder.remaining() != 0 {
            return;
        }
        let mut encoder = wire::Encoder::new(4_096);
        let _ = address.encode(&mut encoder, address.encoding_features());
        if let Ok(encoded) = encoder.finish() {
            let mut round_trip = wire::Decoder::new(&encoded, 4_096);
            let decoded = protocol::address::EntityAddr::decode(&mut round_trip)
                .expect("encoded address must decode");
            assert!(round_trip.finish().is_ok());
            assert_eq!(round_trip.remaining(), 0);
            let mut second_encoder = wire::Encoder::new(4_096);
            decoded
                .encode(&mut second_encoder, decoded.encoding_features())
                .expect("decoded address must encode");
            assert_eq!(second_encoder.finish().expect("canonical address"), encoded);
        }
    }
}

pub fn entity_address_vector(data: &[u8]) {
    let mut decoder = wire::Decoder::new(data, 4_096);
    if let Ok(addresses) = protocol::address::EntityAddrVec::decode(&mut decoder, 64) {
        if decoder.finish().is_err() || decoder.remaining() != 0 {
            return;
        }
        let mut encoder = wire::Encoder::new(4_096);
        let _ = addresses.encode(
            &mut encoder,
            protocol::features::GlobalFeatures::MESSAGE_ADDRESS_V2,
        );
        if let Ok(encoded) = encoder.finish() {
            let mut round_trip = wire::Decoder::new(&encoded, 4_096);
            let decoded = protocol::address::EntityAddrVec::decode(&mut round_trip, 64)
                .expect("encoded address vector must decode");
            assert!(round_trip.finish().is_ok());
            assert_eq!(round_trip.remaining(), 0);
            let mut second_encoder = wire::Encoder::new(4_096);
            decoded
                .encode(
                    &mut second_encoder,
                    protocol::features::GlobalFeatures::MESSAGE_ADDRESS_V2,
                )
                .expect("decoded address vector must encode");
            assert_eq!(
                second_encoder.finish().expect("canonical address vector"),
                encoded
            );
        }
    }
}

pub fn banner(data: &[u8]) {
    if data.len() > MAX_FUZZ_WIRE_BYTES {
        return;
    }
    let mut cursor = Cursor::new(data);
    let Ok(value) = msgr::banner::Banner::read(&mut cursor, 64) else {
        return;
    };
    if cursor.position() != data.len() as u64 {
        return;
    }
    let encoded = value.encode();
    let mut canonical = Cursor::new(&encoded);
    let decoded =
        msgr::banner::Banner::read(&mut canonical, 64).expect("encoded banner must decode");
    assert_eq!(canonical.position(), encoded.len() as u64);
    assert_eq!(decoded, value);
    assert_eq!(decoded.encode(), encoded);
}

pub fn crc_frame(data: &[u8]) {
    let Some((&mode, wire)) = data.split_first() else {
        return;
    };
    if wire.len() > MAX_FUZZ_WIRE_BYTES {
        return;
    }
    let codec = CrcCodec {
        with_data_crc: mode & 1 != 0,
    };
    let mut cursor = Cursor::new(wire);
    let Ok(frame) = codec.read(&mut cursor, FUZZ_LIMITS) else {
        return;
    };
    if cursor.position() != wire.len() as u64 {
        return;
    }
    let encoded = codec
        .encode(&frame, FUZZ_LIMITS)
        .expect("decoded CRC frame must encode");
    let mut canonical = Cursor::new(&encoded);
    let decoded = codec
        .read(&mut canonical, FUZZ_LIMITS)
        .expect("encoded CRC frame must decode");
    assert_eq!(canonical.position(), encoded.len() as u64);
    assert_eq!(decoded, frame);
    assert_eq!(codec.encode(&decoded, FUZZ_LIMITS), Ok(encoded));
}

pub fn secure_frame(data: &[u8]) {
    if data.len() > MAX_FUZZ_WIRE_BYTES {
        return;
    }
    let secret: Vec<u8> = (0..64).collect();
    let mut raw_reader = SecureCodec::new(&secret, true).expect("synthetic secret is valid");
    let mut raw_cursor = Cursor::new(data);
    if let Ok(frame) = raw_reader.read(&mut raw_cursor, FUZZ_LIMITS)
        && raw_cursor.position() == data.len() as u64
    {
        let mut writer = SecureCodec::new(&secret, false).expect("synthetic secret is valid");
        assert_eq!(writer.encode(&frame, FUZZ_LIMITS), Ok(data.to_vec()));
    }

    let Some((&mutation, wire)) = data.split_first() else {
        return;
    };
    let crc = CrcCodec {
        with_data_crc: true,
    };
    let mut cursor = Cursor::new(wire);
    let Ok(frame) = crc.read(&mut cursor, FUZZ_LIMITS) else {
        return;
    };
    if cursor.position() != wire.len() as u64 {
        return;
    }

    let mut writer = SecureCodec::new(&secret, false).expect("synthetic secret is valid");
    let encoded = writer
        .encode(&frame, FUZZ_LIMITS)
        .expect("bounded frame must encode securely");
    let mut reader = SecureCodec::new(&secret, true).expect("synthetic secret is valid");
    let mut canonical = Cursor::new(&encoded);
    let decoded = reader
        .read(&mut canonical, FUZZ_LIMITS)
        .expect("encoded secure frame must authenticate");
    assert_eq!(canonical.position(), encoded.len() as u64);
    assert_eq!(decoded, frame);

    let mut canonical_writer = SecureCodec::new(&secret, false).expect("synthetic secret is valid");
    assert_eq!(
        canonical_writer.encode(&decoded, FUZZ_LIMITS),
        Ok(encoded.clone())
    );

    let mut corrupt = encoded;
    let offset = usize::from(mutation) % corrupt.len();
    corrupt[offset] ^= 1 << (mutation % 8);
    let mut rejecting_reader = SecureCodec::new(&secret, true).expect("synthetic secret is valid");
    assert_eq!(
        rejecting_reader.read(&mut Cursor::new(corrupt), FUZZ_LIMITS),
        Err(FrameError::Integrity)
    );

    let mut authenticated_writer =
        SecureCodec::new(&secret, false).expect("synthetic secret is valid");
    let authenticated_mutation = authenticated_writer
        .encode_with_authenticated_mutation(
            &frame,
            FUZZ_LIMITS,
            usize::from(mutation),
            mutation,
        )
        .expect("bounded frame must encode with an authenticated mutation");
    let mut authenticated_reader =
        SecureCodec::new(&secret, true).expect("synthetic secret is valid");
    if let Ok(mutated_frame) = authenticated_reader.read(
        &mut Cursor::new(authenticated_mutation),
        FUZZ_LIMITS,
    ) {
        match mutated_frame.tag {
            Tag::Message => {
                let _ = Message::decode(&mutated_frame, FUZZ_LIMITS);
            }
            _ => {
                let _ = Control::decode(&mutated_frame, FUZZ_LIMITS);
            }
        }
    }

    match decoded.tag {
        Tag::Message => {
            let _ = Message::decode(&decoded, FUZZ_LIMITS);
        }
        _ => {
            let _ = Control::decode(&decoded, FUZZ_LIMITS);
        }
    }
}

pub fn controls(data: &[u8]) {
    let Some((&tag, payload)) = data.split_first() else {
        return;
    };
    if payload.len() > FUZZ_LIMITS.max_segment_bytes as usize {
        return;
    }
    let Ok(tag) = Tag::try_from(tag) else {
        return;
    };
    let frame = Frame {
        tag,
        segments: vec![Segment {
            alignment: DEFAULT_ALIGNMENT,
            data: payload.to_vec(),
        }],
    };
    let Ok(control) = Control::decode(&frame, FUZZ_LIMITS) else {
        return;
    };
    let encoded = control
        .clone()
        .encode(FUZZ_LIMITS)
        .expect("decoded control must encode");
    let decoded = Control::decode(&encoded, FUZZ_LIMITS).expect("encoded control must decode");
    assert_eq!(decoded, control);
    assert_eq!(decoded.encode(FUZZ_LIMITS), Ok(encoded));
}

pub fn messages(data: &[u8]) {
    if data.len() > MAX_FUZZ_WIRE_BYTES {
        return;
    }
    let codec = CrcCodec {
        with_data_crc: true,
    };
    let mut cursor = Cursor::new(data);
    let Ok(frame) = codec.read(&mut cursor, FUZZ_LIMITS) else {
        return;
    };
    if cursor.position() != data.len() as u64 {
        return;
    }
    let Ok(message) = Message::decode(&frame, FUZZ_LIMITS) else {
        return;
    };
    let encoded_frame = message
        .clone()
        .encode(FUZZ_LIMITS)
        .expect("decoded message must encode");
    let decoded =
        Message::decode(&encoded_frame, FUZZ_LIMITS).expect("encoded message must decode");
    assert_eq!(decoded, message);
    assert_eq!(decoded.encode(FUZZ_LIMITS), Ok(encoded_frame.clone()));
    let encoded = codec
        .encode(&encoded_frame, FUZZ_LIMITS)
        .expect("message frame must encode");
    let mut canonical = Cursor::new(&encoded);
    let round_trip = codec
        .read(&mut canonical, FUZZ_LIMITS)
        .expect("encoded message frame must decode");
    assert_eq!(canonical.position(), encoded.len() as u64);
    assert_eq!(round_trip, encoded_frame);
}

pub fn bounded_session_scripts(script: &[u8]) {
    if script.len() > MAX_SESSION_SCRIPT_BYTES {
        return;
    }
    let Ok(mut machine) = Machine::new(session_config()) else {
        return;
    };
    let _ = machine.step(Input::Start { ready: true });
    for (index, instruction) in script.iter().copied().enumerate() {
        let operand = u64::from(instruction >> 4);
        let generation = machine.snapshot().generation;
        let input = match instruction & 0x0f {
            0 => Input::Admit {
                request_id: index as u64 + 1,
                message: session_message(&[operand as u8, machine.snapshot().queued as u8]),
                one_way: false,
            },
            1 => Input::Cancel {
                request_id: operand + 1,
            },
            2 => Input::Control {
                generation,
                control: Control::Ack(operand),
            },
            3 => Input::Control {
                generation,
                control: Control::Keepalive2(Timestamp {
                    seconds: operand as u32,
                    nanoseconds: 0,
                }),
            },
            4 => Input::Message {
                generation,
                message: Message {
                    header: msgr::message::MessageHeader {
                        sequence: operand + 1,
                        transaction_id: operand,
                        ..msgr::message::MessageHeader::default()
                    },
                    ..Message::default()
                },
            },
            5 => Input::Dispatch,
            6 => Input::Fault {
                generation,
                error: SessionError::Disconnected,
            },
            7 => Input::ConnectFailed { generation },
            8 => Input::ConsumeIncoming,
            _ => continue,
        };
        let effects = machine.step(input);
        for effect in effects {
            if let Effect::SendMessage {
                generation,
                request_id,
                ..
            } = effect
            {
                let _ = machine.step(Input::WriteComplete {
                    generation,
                    request_id: Some(request_id),
                    result: Ok(()),
                });
            }
        }
        let snapshot = machine.snapshot();
        assert!(snapshot.queued + snapshot.in_flight <= machine.queue_limit());
        assert!(snapshot.in_flight <= 4);
        assert!(snapshot.retained_bytes <= 2048);
        assert!(snapshot.handshake_transitions <= 8);
    }
}

fn session_message(payload: &[u8]) -> Message {
    Message {
        lengths: MessageLengths {
            front: payload.len() as u32,
            ..MessageLengths::default()
        },
        front: payload.to_vec(),
        ..Message::default()
    }
}

fn session_config() -> Config {
    let encoded = [
        0x01, 0x01, 0x01, 0x1c, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0c, 0xe4, 0xc0, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut decoder = wire::Decoder::new(&encoded, encoded.len());
    let address = EntityAddr::decode(&mut decoder).expect("fixed address must decode");
    Config {
        limits: FUZZ_LIMITS,
        max_queued_messages: 8,
        max_retained_bytes: 2048,
        max_in_flight_transactions: 4,
        max_reconnect_attempts: 2,
        max_handshake_transitions: 8,
        reconnect_policy: ReconnectPolicy::ReplayPending,
        client_ident: ClientIdent {
            addresses: EntityAddrVec(vec![address.clone()]),
            target_address: address,
            global_id: 0,
            global_sequence: 3,
            supported_features: 0x0f,
            required_features: 0x01,
            flags: 0,
            cookie: 0,
        },
        client_cookie: 11,
        server_cookie: 22,
        global_sequence: 3,
        connect_sequence: 0,
        replacement_cookies: vec![41, 42, 43],
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn retained_go_session_seed_regresses() {
        // Extracted from internal/msgr/testdata/fuzz/FuzzSessionScript/938f779fb2101a93.
        // Go container SHA-256: 938f779fb2101a931328ed6fb6810d6454ee91ebcad1c79cbbbceb27f156bb14.
        // Raw input SHA-256: a4f61a6bb886a378045132f942db5e025dd8ebf34b3ebc86f97ade8707a40de8.
        let seed = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/corpus/bounded_session_scripts/go-session-938f779fb2101a93.raw"
        ));
        assert_eq!(seed, b"08&0");
        super::bounded_session_scripts(seed);
    }
}
