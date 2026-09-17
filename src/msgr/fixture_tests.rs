use super::banner::{Banner, REVISION_1_FEATURES};
use super::control::Control;
use super::frame::{CrcCodec, DEFAULT_ALIGNMENT, Frame, Limits, PAGE_ALIGNMENT, Segment, Tag};
use super::message::{Message, MessageHeader, MessageLengths};
use super::secure::SecureCodec;
use std::io::Cursor;

const TEST_LIMITS: Limits = Limits {
    max_segment_bytes: 4096,
    max_frame_bytes: 8192,
    max_addresses: 4,
    max_auth_bytes: 4096,
};

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/testdata/p02/{path}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("P02 fixture must be readable")
}

fn sequence(length: usize) -> Vec<u8> {
    (0..length)
        .map(|value| u8::try_from(value).expect("fixture sequence value must fit in u8"))
        .collect()
}

fn assert_crc_fixture(path: &str, codec: CrcCodec, expected: &Frame) {
    let wire = fixture(path);
    assert_eq!(codec.encode(expected, TEST_LIMITS), Ok(wire.clone()));
    let mut cursor = Cursor::new(&wire);
    let decoded = codec
        .read(&mut cursor, TEST_LIMITS)
        .expect("valid CRC fixture");
    assert_eq!(cursor.position(), wire.len() as u64);
    assert_eq!(&decoded, expected);
    assert_eq!(codec.encode(&decoded, TEST_LIMITS), Ok(wire));
}

fn assert_secure_fixture(path: &str, expected: &Frame) {
    let wire = fixture(path);
    let secret = sequence(64);
    let mut encoder = SecureCodec::new(&secret, false).expect("valid client codec");
    assert_eq!(encoder.encode(expected, TEST_LIMITS), Ok(wire.clone()));
    let mut decoder = SecureCodec::new(&secret, true).expect("valid server codec");
    let mut cursor = Cursor::new(&wire);
    let decoded_frame = decoder
        .read(&mut cursor, TEST_LIMITS)
        .expect("authenticated secure fixture");
    assert_eq!(cursor.position(), wire.len() as u64);
    assert_eq!(&decoded_frame, expected);
}

#[test]
fn p02_banner_fixture_is_exact_and_semantic() {
    let wire = fixture("banner-rev1.bin");
    assert_eq!(Banner::client().encode(), wire);
    let mut cursor = Cursor::new(&wire);
    let banner = Banner::read(&mut cursor, 16).expect("valid banner fixture");
    assert_eq!(cursor.position(), wire.len() as u64);
    assert_eq!(banner.supported, REVISION_1_FEATURES);
    assert_eq!(banner.required, REVISION_1_FEATURES);
    assert_eq!(banner.encode(), wire);
}

#[test]
fn p02_crc_fixtures_are_exact_and_semantic() {
    let one_segment = Frame {
        tag: Tag::Ack,
        segments: vec![Segment {
            alignment: DEFAULT_ALIGNMENT,
            data: b"ceph".to_vec(),
        }],
    };
    let four_segments = Frame {
        tag: Tag::Message,
        segments: vec![
            Segment {
                alignment: DEFAULT_ALIGNMENT,
                data: b"header".to_vec(),
            },
            Segment {
                alignment: DEFAULT_ALIGNMENT,
                data: Vec::new(),
            },
            Segment {
                alignment: DEFAULT_ALIGNMENT,
                data: b"middle".to_vec(),
            },
            Segment {
                alignment: PAGE_ALIGNMENT,
                data: vec![0, 1, 2, 3],
            },
        ],
    };
    let enabled = CrcCodec {
        with_data_crc: true,
    };
    let disabled = CrcCodec {
        with_data_crc: false,
    };
    assert_crc_fixture("crc-one-segment.bin", enabled, &one_segment);
    assert_crc_fixture("crc-four-segment.bin", enabled, &four_segments);
    assert_crc_fixture(
        "upstream/upstream-crc-one-segment.bin",
        enabled,
        &one_segment,
    );
    assert_crc_fixture(
        "upstream/upstream-crc-disabled-one-segment.bin",
        disabled,
        &one_segment,
    );
    assert_crc_fixture(
        "upstream/upstream-crc-four-segment.bin",
        enabled,
        &four_segments,
    );
}

#[test]
fn p02_ack_and_message_fixtures_are_exact_and_semantic() {
    let ack_wire = fixture("upstream/upstream-ack-control.bin");
    let codec = CrcCodec {
        with_data_crc: true,
    };
    let mut cursor = Cursor::new(&ack_wire);
    let ack_frame = codec
        .read(&mut cursor, TEST_LIMITS)
        .expect("valid ACK fixture");
    assert_eq!(cursor.position(), ack_wire.len() as u64);
    assert_eq!(
        Control::decode(&ack_frame, TEST_LIMITS),
        Ok(Control::Ack(0x0102_0304_0506_0708))
    );
    assert_eq!(codec.encode(&ack_frame, TEST_LIMITS), Ok(ack_wire));

    let message_wire = fixture("upstream/upstream-message-frame.bin");
    let mut cursor = Cursor::new(&message_wire);
    let message_frame = codec
        .read(&mut cursor, TEST_LIMITS)
        .expect("valid message fixture");
    assert_eq!(cursor.position(), message_wire.len() as u64);
    let message = Message::decode(&message_frame, TEST_LIMITS).expect("valid message payload");
    assert_eq!(
        message.header,
        MessageHeader {
            sequence: 0x0102_0304_0506_0708,
            transaction_id: 0x1112_1314_1516_1718,
            message_type: 0x2122,
            priority: 0x3132,
            version: 0x4142,
            data_pre_padding_length: 2,
            data_offset: 0x5152,
            ack_sequence: 0x6162_6364_6566_6768,
            flags: 0x71,
            compat_version: 0x8182,
            reserved: 0,
        }
    );
    assert_eq!(
        message.lengths,
        MessageLengths {
            front: 5,
            middle: 3,
            data: 2
        }
    );
    assert_eq!(message.front, b"front");
    assert_eq!(message.middle, b"mid");
    assert_eq!(message.data, [0, 1]);
    let canonical = message.encode(TEST_LIMITS).expect("message must re-encode");
    assert_eq!(codec.encode(&canonical, TEST_LIMITS), Ok(message_wire));
}

#[test]
fn p02_secure_fixtures_are_exact_authenticated_and_semantic() {
    let one_segment = Frame {
        tag: Tag::Ack,
        segments: vec![Segment {
            alignment: DEFAULT_ALIGNMENT,
            data: b"ceph".to_vec(),
        }],
    };
    let multi_record = Frame {
        tag: Tag::Message,
        segments: vec![
            Segment {
                alignment: DEFAULT_ALIGNMENT,
                data: sequence(63),
            },
            Segment {
                alignment: DEFAULT_ALIGNMENT,
                data: Vec::new(),
            },
            Segment {
                alignment: DEFAULT_ALIGNMENT,
                data: b"middle".to_vec(),
            },
            Segment {
                alignment: PAGE_ALIGNMENT,
                data: sequence(32),
            },
        ],
    };
    assert_secure_fixture("secure-one-segment.bin", &one_segment);
    assert_secure_fixture("secure-multi-record.bin", &multi_record);
    assert_secure_fixture("upstream/upstream-secure-one-segment.bin", &one_segment);
    assert_secure_fixture("upstream/upstream-secure-multi-record.bin", &multi_record);
}
