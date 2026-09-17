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

mod cephx {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../src/cephx/mod.rs"));
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
use std::time::Duration;

const FUZZ_LIMITS: Limits = Limits {
    max_segment_bytes: 256,
    max_frame_bytes: 1024,
    max_addresses: 2,
    max_auth_bytes: 64,
};
const MAX_FUZZ_WIRE_BYTES: usize = 2048;
const MAX_SESSION_SCRIPT_BYTES: usize = 24;
const MAX_CEPHX_FUZZ_BYTES: usize = 4096;
const AES_KEY: &str = "AQB7AAAAyAEAABAAMTIzNDU2Nzg5MDEyMzQ1Ng==";
const AES256_KEY: &str = "AgBm8qdqnvU7HiAAg6prN8XJ47FG9AprWpB72EwKyLfFC7UgnMYvcnFI29M=";

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

pub fn cephx_credentials(data: &[u8]) {
    let Some((&operation, input)) = data.split_first() else {
        return;
    };
    if input.len() > MAX_CEPHX_FUZZ_BYTES {
        return;
    }
    if operation & 1 == 0 {
        if let Ok(encoded) = std::str::from_utf8(input) {
            let _ = cephx::parse_key("client.fuzz", encoded, MAX_CEPHX_FUZZ_BYTES);
        }
    } else {
        let _ = cephx::parse_keyring(input, "client.fuzz", MAX_CEPHX_FUZZ_BYTES);
    }
}

pub fn cephx_server_challenge(data: &[u8]) {
    if data.len() <= MAX_CEPHX_FUZZ_BYTES {
        let _ = cephx::core::parse_server_challenge(data, cephx_limits());
    }
}

pub fn cephx_auth_session_reply(data: &[u8]) {
    if data.len() > MAX_CEPHX_FUZZ_BYTES {
        return;
    }
    let limits = cephx_limits();
    let raw_key = cephx_key(data.first().copied().unwrap_or_default());
    let raw_mode = if data.get(1).copied().unwrap_or_default() & 1 == 0 {
        cephx::core::CONNECTION_MODE_CRC
    } else {
        cephx::core::CONNECTION_MODE_SECURE
    };
    let _ = cephx::core::parse_auth_session_reply(
        data,
        &raw_key,
        None,
        raw_mode,
        Duration::from_secs(100),
        limits,
    );

    let [key_selector, mode_selector, path_selector, mutation @ ..] = data else {
        return;
    };
    let principal = cephx_key(*key_selector);
    let session = cephx_key(*key_selector >> 1);
    let mode = if mode_selector & 1 == 0 {
        cephx::core::CONNECTION_MODE_CRC
    } else {
        cephx::core::CONNECTION_MODE_SECURE
    };
    let mut service_plaintext = service_ticket_plaintext(&session, limits);
    let mut connection_plaintext = connection_secret_plaintext(limits);
    match path_selector % 3 {
        0 => service_plaintext = mutate_plaintext(&service_plaintext, mutation),
        1 => connection_plaintext = mutate_plaintext(&connection_plaintext, mutation),
        _ => return,
    }
    let Some(payload) = auth_session_payload(
        &principal,
        &session,
        &service_plaintext,
        if path_selector % 3 == 1 {
            Some(&connection_plaintext)
        } else {
            None
        },
        limits,
    ) else {
        return;
    };
    let parsed = cephx::core::parse_auth_session_reply(
        &payload,
        &principal,
        None,
        mode,
        Duration::from_secs(100),
        limits,
    );
    if mutation.is_empty() && (path_selector % 3 == 0 || mode == cephx::core::CONNECTION_MODE_SECURE)
    {
        parsed.expect("constructed authenticated session reply must parse");
    }
}

pub fn cephx_authorizer(data: &[u8]) {
    if data.len() > MAX_CEPHX_FUZZ_BYTES {
        return;
    }
    let limits = cephx_limits();
    let key = cephx_key(data.first().copied().unwrap_or_default());
    let authorizer = cephx::core::Authorizer {
        base: vec![1, 2, 3],
        payload: vec![4, 5],
        nonce: 1,
        service_id: cephx::core::SERVICE_MONITOR,
    };
    let _ = cephx::core::verify_authorizer_reply(data, &key, authorizer.nonce, limits);
    let _ = cephx::core::add_authorizer_challenge(
        &authorizer,
        data,
        &key,
        Some(&[0x41; 16]),
        limits,
    );

    let [key_selector, operation, mutation @ ..] = data else {
        return;
    };
    let key = cephx_key(*key_selector);
    if operation & 1 == 0 {
        let mut plaintext = wire::Encoder::new(limits.max_auth_bytes);
        plaintext.u8(2);
        plaintext.u64(authorizer.nonce.wrapping_add(1));
        plaintext.bytes(&[0x5a; cephx::core::CONNECTION_SECRET_SIZE_SECURE]);
        let plaintext = mutate_plaintext(
            &plaintext.finish().expect("bounded authorizer reply"),
            mutation,
        );
        let Ok(encrypted) = cephx::crypto::encrypt_with_magic(
            &key,
            &plaintext,
            cephx::crypto::KEY_USAGE_AUTHORIZE_REPLY,
            Some(&[0x42; 16]),
            limits,
        ) else {
            return;
        };
        let mut payload = wire::Encoder::new(limits.max_auth_bytes);
        payload.bytes(&encrypted);
        let Ok(payload) = payload.finish() else {
            return;
        };
        let verified = cephx::core::verify_authorizer_reply(
            &payload,
            &key,
            authorizer.nonce,
            limits,
        );
        if mutation.is_empty() {
            verified.expect("constructed authenticated authorizer reply must parse");
        }
    } else {
        let mut plaintext = wire::Encoder::new(limits.max_auth_bytes);
        plaintext.u8(1);
        plaintext.u64(0x1122_3344_5566_7788);
        let plaintext = mutate_plaintext(
            &plaintext.finish().expect("bounded authorizer challenge"),
            mutation,
        );
        let Ok(challenge) = cephx::crypto::encrypt_with_magic(
            &key,
            &plaintext,
            cephx::crypto::KEY_USAGE_AUTHORIZE_CHALLENGE,
            Some(&[0x43; 16]),
            limits,
        ) else {
            return;
        };
        let challenged = cephx::core::add_authorizer_challenge(
            &authorizer,
            &challenge,
            &key,
            Some(&[0x44; 16]),
            limits,
        );
        if mutation.is_empty() {
            challenged.expect("constructed authenticated authorizer challenge must parse");
        }
    }
}

fn cephx_limits() -> cephx::crypto::Limits {
    cephx::crypto::Limits {
        max_auth_bytes: MAX_CEPHX_FUZZ_BYTES,
        max_ticket_blob_bytes: 256,
        max_decrypt_bytes: MAX_CEPHX_FUZZ_BYTES,
        max_encrypt_bytes: MAX_CEPHX_FUZZ_BYTES,
        max_connection_secret_bytes: cephx::core::CONNECTION_SECRET_SIZE_SECURE,
        max_tickets: 4,
    }
}

fn cephx_key(selector: u8) -> cephx::CryptoKey {
    cephx::parse_key(
        "client.fuzz",
        if selector & 1 == 0 { AES_KEY } else { AES256_KEY },
        64,
    )
    .expect("fixed CephX key must parse")
    .secret()
    .clone()
}

fn mutate_plaintext(seed: &[u8], mutation: &[u8]) -> Vec<u8> {
    let Some((&strategy, bytes)) = mutation.split_first() else {
        return seed.to_vec();
    };
    match strategy % 3 {
        0 => bytes.to_vec(),
        1 => {
            let mut value = seed.to_vec();
            value.extend_from_slice(bytes);
            value
        }
        _ => {
            let mut value = seed.to_vec();
            for (index, byte) in bytes.iter().copied().enumerate() {
                if value.is_empty() {
                    value.push(byte);
                } else {
                    let offset = index % value.len();
                    value[offset] ^= byte;
                }
            }
            value
        }
    }
}

fn encrypted_envelope(
    key: &cephx::CryptoKey,
    plaintext: &[u8],
    usage: u32,
    limits: cephx::crypto::Limits,
) -> Option<Vec<u8>> {
    let encrypted = cephx::crypto::encrypt_with_magic(
        key,
        plaintext,
        usage,
        Some(&[u8::try_from(usage).expect("CephX key usage fits u8"); 16]),
        limits,
    )
    .ok()?;
    let mut envelope = wire::Encoder::new(limits.max_auth_bytes);
    envelope.bytes(&encrypted);
    envelope.finish().ok()
}

fn service_ticket_plaintext(
    session: &cephx::CryptoKey,
    limits: cephx::crypto::Limits,
) -> Vec<u8> {
    let mut plaintext = wire::Encoder::new(limits.max_auth_bytes);
    plaintext.u8(1);
    plaintext.u16(session.type_id());
    plaintext.u32(0);
    plaintext.u32(0);
    plaintext.u16(u16::try_from(session.bytes().len()).expect("fixed key length"));
    plaintext.raw(session.bytes());
    plaintext.u32(60);
    plaintext.u32(0);
    plaintext.finish().expect("bounded service ticket")
}

fn connection_secret_plaintext(limits: cephx::crypto::Limits) -> Vec<u8> {
    let mut plaintext = wire::Encoder::new(limits.max_auth_bytes);
    plaintext.bytes(&[0x33; cephx::core::CONNECTION_SECRET_SIZE_SECURE]);
    plaintext.finish().expect("bounded connection secret")
}

fn auth_session_payload(
    principal: &cephx::CryptoKey,
    session: &cephx::CryptoKey,
    service_plaintext: &[u8],
    connection_plaintext: Option<&[u8]>,
    limits: cephx::crypto::Limits,
) -> Option<Vec<u8>> {
    let service = encrypted_envelope(
        principal,
        service_plaintext,
        cephx::crypto::KEY_USAGE_TICKET_SESSION_KEY,
        limits,
    )?;
    let mut ticket = wire::Encoder::new(limits.max_auth_bytes);
    ticket.u8(1);
    ticket.u64(7);
    ticket.bytes(b"fuzz-ticket");

    let mut reply = wire::Encoder::new(limits.max_auth_bytes);
    reply.u16(0x0100);
    reply.i32(0);
    reply.u8(1);
    reply.u32(1);
    reply.u32(cephx::core::SERVICE_AUTH);
    reply.u8(1);
    reply.raw(&service);
    reply.u8(0);
    reply.bytes(&ticket.finish().expect("bounded ticket blob"));
    if let Some(plaintext) = connection_plaintext {
        let connection = encrypted_envelope(
            session,
            plaintext,
            cephx::crypto::KEY_USAGE_AUTH_CONNECTION_SECRET,
            limits,
        )?;
        reply.bytes(&connection);
        reply.bytes(&[]);
    }
    reply.finish().ok()
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
    fn cephx_harnesses_reach_all_key_and_mode_variants() {
        super::cephx_credentials(format!("\0{}", super::AES_KEY).as_bytes());
        super::cephx_credentials(
            format!("\x01[client.fuzz]\nkey = {}\n", super::AES256_KEY).as_bytes(),
        );
        super::cephx_server_challenge(&[1, 1, 0, 0, 0, 0, 0, 0, 0]);
        for principal_key in 0..=1 {
            for session_key in 0..=1 {
                let key_selector = principal_key | (session_key << 1);
                for mode in 0..=1 {
                    super::cephx_auth_session_reply(&[key_selector, mode, 0]);
                    super::cephx_auth_session_reply(&[key_selector, mode, 1]);
                }
            }
            super::cephx_authorizer(&[principal_key, 0]);
            super::cephx_authorizer(&[principal_key, 1]);
        }
    }

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
