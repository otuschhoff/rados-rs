use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use super::core::parse_server_challenge;
use super::crypto::{Limits, calculate_challenge, decrypt_payload, encrypt_payload};
use super::{CRYPTO_AES, CRYPTO_AES256_KRB5, CryptoKey, parse_key};
use crate::wire::Decoder;

const ENCODING_FIXTURE: &str = include_str!("../../testdata/p03/cephx-encoding-vectors.json");
const CRYPTO_FIXTURE: &str = include_str!("../../testdata/p03/crypto-vectors.json");

const EXPECTED_ENCODING_FIXTURE: &str = r#"{
  "schema_version": 1,
  "vectors": [
    {"type": "CephXServerChallenge", "test_instance": 0, "hex": "010100000000000000"},
    {"type": "CephXResponseHeader", "test_instance": 0, "hex": "010000000000"},
    {"type": "CephXTicketBlob", "test_instance": 0, "hex": "017b000000000000000e00000074686973206973206120626c6f62"},
    {"type": "CryptoKey", "test_instance": 0, "hex": "01007b000000c8010000100031323334353637383930313233343536"}
  ]
}
"#;

const EXPECTED_CRYPTO_FIXTURE: &str = r#"{
  "schema_version": 1,
  "vectors": {
    "ceph_aes_cbc": {
      "key_hex": "31323334353637383930313233343536",
      "plaintext_hex": "616263",
      "ciphertext_hex": "0ba3d1290cc47bb370aa355b24a7d152"
    },
    "rfc8009_aes256": {
      "key_usage": 2,
      "key_hex": "6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52",
      "ciphertext_hex": "4ed7b37c2bcac8f74f23c1cf07e62bc7b75fb3f637b9f559c7f664f69eab7b6092237526ea0d1f61cb20d69d10f2",
      "plaintext_hex": "000102030405"
    },
    "aes256_challenge": {
      "key_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "server_challenge": 1234605616436508552,
      "client_challenge": 72623859790382856,
      "result_hex_le": "044bebe5403060ff"
    }
  }
}
"#;

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("valid fixture hex")
        })
        .collect()
}

fn key(type_id: u16, value: &str) -> CryptoKey {
    CryptoKey {
        type_id,
        secret: decode_hex(value),
    }
}

#[test]
fn p03_ceph_dencoder_fixture_parity() {
    assert_eq!(ENCODING_FIXTURE, EXPECTED_ENCODING_FIXTURE);
    let limits = Limits::default();
    let challenge = decode_hex("010100000000000000");
    assert_eq!(parse_server_challenge(&challenge, limits).unwrap(), 1);
    let encoded_key = STANDARD.encode(decode_hex(
        "01007b000000c8010000100031323334353637383930313233343536",
    ));
    let credential = parse_key("client.fixture", &encoded_key, 64).unwrap();
    assert_eq!(credential.secret.type_id, CRYPTO_AES);
    assert_eq!(credential.secret.secret, b"1234567890123456");

    let ticket_bytes = decode_hex("017b000000000000000e00000074686973206973206120626c6f62");
    let mut ticket = Decoder::new(&ticket_bytes, limits.max_auth_bytes);
    assert_eq!(ticket.u8(), 1);
    assert_eq!(ticket.u64(), 123);
    assert_eq!(ticket.bytes(), b"this is a blob");
    assert_eq!(ticket.remaining(), 0);
    ticket.finish().unwrap();

    let response_bytes = decode_hex("010000000000");
    let mut response = Decoder::new(&response_bytes, limits.max_auth_bytes);
    assert_eq!(response.u16(), 1);
    assert_eq!(response.i32(), 0);
    assert_eq!(response.remaining(), 0);
    response.finish().unwrap();
}

#[test]
fn p03_crypto_fixture_parity() {
    assert_eq!(CRYPTO_FIXTURE, EXPECTED_CRYPTO_FIXTURE);
    let limits = Limits::default();
    assert_eq!(
        encrypt_payload(
            &key(CRYPTO_AES, "31323334353637383930313233343536"),
            &decode_hex("616263"),
            0,
            limits,
        )
        .unwrap(),
        decode_hex("0ba3d1290cc47bb370aa355b24a7d152")
    );
    assert_eq!(
        decrypt_payload(
            &key(
                CRYPTO_AES256_KRB5,
                "6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52",
            ),
            &decode_hex("4ed7b37c2bcac8f74f23c1cf07e62bc7b75fb3f637b9f559c7f664f69eab7b6092237526ea0d1f61cb20d69d10f2"),
            2,
            limits,
        )
        .unwrap(),
        decode_hex("000102030405")
    );
    assert_eq!(
        calculate_challenge(
            &key(
                CRYPTO_AES256_KRB5,
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            ),
            1_234_605_616_436_508_552,
            72_623_859_790_382_856,
            limits,
        )
        .unwrap(),
        u64::from_le_bytes([0x04, 0x4b, 0xeb, 0xe5, 0x40, 0x30, 0x60, 0xff])
    );
}
