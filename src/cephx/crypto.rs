use aes::cipher::{
    BlockCipherDecrypt, BlockCipherEncrypt, BlockModeDecrypt, BlockModeEncrypt, KeyInit, KeyIvInit,
    block_padding::Pkcs7,
};
use aes::{Aes128, Aes256, Block};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha384};
use zeroize::Zeroize;

use super::{CRYPTO_AES, CRYPTO_AES256_KRB5, CryptoKey, Error};

const AES_BLOCK_SIZE: usize = 16;
const AES256_KEY_SIZE: usize = 32;
const RFC8009_CHECKSUM_SIZE: usize = 24;
const CEPH_AES_IV: &[u8; AES_BLOCK_SIZE] = b"cephsageyudagreg";
const AUTH_ENC_MAGIC: u64 = 0xff00_9cad_8826_aa55;

pub(crate) const KEY_USAGE_AUTH_CONNECTION_SECRET: u32 = 0x03;
pub(crate) const KEY_USAGE_TICKET_SESSION_KEY: u32 = 0x04;
pub(crate) const KEY_USAGE_TICKET_BLOB: u32 = 0x05;
pub(crate) const KEY_USAGE_AUTHORIZE: u32 = 0x10;
pub(crate) const KEY_USAGE_AUTHORIZE_CHALLENGE: u32 = 0x11;
pub(crate) const KEY_USAGE_AUTHORIZE_REPLY: u32 = 0x12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::struct_field_names)]
pub(crate) struct Limits {
    pub(crate) max_auth_bytes: usize,
    pub(crate) max_ticket_blob_bytes: usize,
    pub(crate) max_decrypt_bytes: usize,
    pub(crate) max_encrypt_bytes: usize,
    pub(crate) max_connection_secret_bytes: usize,
    pub(crate) max_tickets: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_auth_bytes: 1 << 20,
            max_ticket_blob_bytes: 1 << 20,
            max_decrypt_bytes: 1 << 20,
            max_encrypt_bytes: 1 << 20,
            max_connection_secret_bytes: 64,
            max_tickets: 64,
        }
    }
}

pub(crate) fn encrypt_payload(
    secret: &CryptoKey,
    plaintext: &[u8],
    usage: u32,
    limits: Limits,
) -> Result<Vec<u8>, Error> {
    if plaintext.len() > limits.max_encrypt_bytes {
        return Err(Error::LimitExceeded);
    }
    match secret.type_id {
        CRYPTO_AES => encrypt_cbc(secret, plaintext, limits),
        CRYPTO_AES256_KRB5 => {
            let _ = usage;
            Err(Error::MalformedPayload)
        }
        _ => Err(Error::UnsupportedType),
    }
}

pub(crate) fn encrypt_rfc8009_with_confounder(
    secret: &CryptoKey,
    plaintext: &[u8],
    usage: u32,
    confounder: &[u8; AES_BLOCK_SIZE],
    limits: Limits,
) -> Result<Vec<u8>, Error> {
    if secret.type_id != CRYPTO_AES256_KRB5 || secret.secret.len() != AES256_KEY_SIZE {
        return Err(Error::UnsupportedType);
    }
    if plaintext.len() > limits.max_encrypt_bytes {
        return Err(Error::LimitExceeded);
    }
    let mut data = Vec::with_capacity(AES_BLOCK_SIZE.saturating_add(plaintext.len()));
    data.extend_from_slice(confounder);
    data.extend_from_slice(plaintext);
    let mut encryption_key = rfc8009_derive_key(&secret.secret, usage, 0xaa, 256)?;
    let mut ciphertext = cts_encrypt(&encryption_key, &data)?;
    encryption_key.zeroize();
    let mut integrity_key = rfc8009_derive_key(&secret.secret, usage, 0x55, 192)?;
    let mut mac = <Hmac<Sha384> as KeyInit>::new_from_slice(&integrity_key)
        .map_err(|_| Error::UnsupportedType)?;
    mac.update(&[0; AES_BLOCK_SIZE]);
    mac.update(&ciphertext);
    ciphertext.extend_from_slice(&mac.finalize().into_bytes()[..RFC8009_CHECKSUM_SIZE]);
    integrity_key.zeroize();
    data.zeroize();
    Ok(ciphertext)
}

pub(crate) fn decrypt_payload(
    secret: &CryptoKey,
    ciphertext: &[u8],
    usage: u32,
    limits: Limits,
) -> Result<Vec<u8>, Error> {
    match secret.type_id {
        CRYPTO_AES => decrypt_cbc(secret, ciphertext, limits),
        CRYPTO_AES256_KRB5 => decrypt_rfc8009(secret, ciphertext, usage, limits),
        _ => Err(Error::UnsupportedType),
    }
}

fn encrypt_cbc(secret: &CryptoKey, plaintext: &[u8], limits: Limits) -> Result<Vec<u8>, Error> {
    if secret.type_id != CRYPTO_AES || secret.secret.len() != AES_BLOCK_SIZE {
        return Err(Error::UnsupportedType);
    }
    if plaintext.len() > limits.max_encrypt_bytes {
        return Err(Error::LimitExceeded);
    }
    let padded_length = plaintext
        .len()
        .checked_add(AES_BLOCK_SIZE - plaintext.len() % AES_BLOCK_SIZE)
        .ok_or(Error::LimitExceeded)?;
    if padded_length > limits.max_encrypt_bytes.saturating_add(AES_BLOCK_SIZE) {
        return Err(Error::LimitExceeded);
    }
    let mut output = vec![0; padded_length];
    cbc::Encryptor::<Aes128>::new_from_slices(&secret.secret, CEPH_AES_IV)
        .map_err(|_| Error::UnsupportedType)?
        .encrypt_padded_b2b::<Pkcs7>(plaintext, &mut output)
        .map_err(|_| Error::MalformedPayload)?;
    Ok(output)
}

fn decrypt_cbc(secret: &CryptoKey, ciphertext: &[u8], limits: Limits) -> Result<Vec<u8>, Error> {
    if secret.type_id != CRYPTO_AES || secret.secret.len() != AES_BLOCK_SIZE {
        return Err(Error::UnsupportedType);
    }
    if ciphertext.len() < AES_BLOCK_SIZE || !ciphertext.len().is_multiple_of(AES_BLOCK_SIZE) {
        return Err(Error::MalformedPayload);
    }
    if ciphertext.len() > limits.max_decrypt_bytes.saturating_add(AES_BLOCK_SIZE) {
        return Err(Error::LimitExceeded);
    }
    let mut output = vec![0; ciphertext.len()];
    let plaintext = cbc::Decryptor::<Aes128>::new_from_slices(&secret.secret, CEPH_AES_IV)
        .map_err(|_| Error::UnsupportedType)?
        .decrypt_padded_b2b::<Pkcs7>(ciphertext, &mut output)
        .map_err(|_| Error::MalformedPayload)?;
    let length = plaintext.len();
    output.truncate(length);
    Ok(output)
}

fn decrypt_rfc8009(
    secret: &CryptoKey,
    ciphertext: &[u8],
    usage: u32,
    limits: Limits,
) -> Result<Vec<u8>, Error> {
    if secret.secret.len() != AES256_KEY_SIZE {
        return Err(Error::UnsupportedType);
    }
    if ciphertext.len() < AES_BLOCK_SIZE + RFC8009_CHECKSUM_SIZE {
        return Err(Error::MalformedPayload);
    }
    if ciphertext.len()
        > limits
            .max_decrypt_bytes
            .saturating_add(AES_BLOCK_SIZE + RFC8009_CHECKSUM_SIZE)
    {
        return Err(Error::LimitExceeded);
    }
    let split = ciphertext.len() - RFC8009_CHECKSUM_SIZE;
    let (encrypted, checksum) = ciphertext.split_at(split);
    let mut integrity_key = rfc8009_derive_key(&secret.secret, usage, 0x55, 192)?;
    let mut mac = <Hmac<Sha384> as KeyInit>::new_from_slice(&integrity_key)
        .map_err(|_| Error::UnsupportedType)?;
    mac.update(&[0; AES_BLOCK_SIZE]);
    mac.update(encrypted);
    let valid = mac.verify_truncated_left(checksum).is_ok();
    integrity_key.zeroize();
    if !valid {
        return Err(Error::MalformedPayload);
    }
    let mut encryption_key = rfc8009_derive_key(&secret.secret, usage, 0xaa, 256)?;
    let mut plaintext = cts_decrypt(&encryption_key, encrypted)?;
    encryption_key.zeroize();
    plaintext.drain(..AES_BLOCK_SIZE);
    Ok(plaintext)
}

fn rfc8009_derive_key(key: &[u8], usage: u32, constant: u8, bits: u32) -> Result<Vec<u8>, Error> {
    let mut mac =
        <Hmac<Sha384> as KeyInit>::new_from_slice(key).map_err(|_| Error::UnsupportedType)?;
    mac.update(&1_u32.to_be_bytes());
    mac.update(&usage.to_be_bytes());
    mac.update(&[constant, 0]);
    mac.update(&bits.to_be_bytes());
    let bytes = usize::try_from(bits / 8).map_err(|_| Error::LimitExceeded)?;
    Ok(mac.finalize().into_bytes()[..bytes].to_vec())
}

fn cts_encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    if plaintext.len() < AES_BLOCK_SIZE {
        return Err(Error::MalformedPayload);
    }
    let cipher = Aes256::new_from_slice(key).map_err(|_| Error::UnsupportedType)?;
    let mut padded = plaintext.to_vec();
    let remainder = padded.len() % AES_BLOCK_SIZE;
    if remainder != 0 {
        padded.resize(padded.len() + AES_BLOCK_SIZE - remainder, 0);
    }
    let mut previous = [0_u8; AES_BLOCK_SIZE];
    let mut blocks = Vec::with_capacity(padded.len());
    for chunk in padded.as_chunks::<AES_BLOCK_SIZE>().0 {
        let mut block = Block::default();
        for (output, (input, iv)) in block.iter_mut().zip(chunk.iter().zip(previous)) {
            *output = input ^ iv;
        }
        cipher.encrypt_block(&mut block);
        previous.copy_from_slice(&block);
        blocks.extend_from_slice(&block);
    }
    if blocks.len() > AES_BLOCK_SIZE {
        let penultimate = blocks.len() - 2 * AES_BLOCK_SIZE;
        for index in 0..AES_BLOCK_SIZE {
            blocks.swap(penultimate + index, penultimate + AES_BLOCK_SIZE + index);
        }
    }
    blocks.truncate(plaintext.len());
    Ok(blocks)
}

fn cts_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < AES_BLOCK_SIZE {
        return Err(Error::MalformedPayload);
    }
    let cipher = Aes256::new_from_slice(key).map_err(|_| Error::UnsupportedType)?;
    let remainder = ciphertext.len() % AES_BLOCK_SIZE;
    if remainder == 0 {
        let mut swapped = ciphertext.to_vec();
        if swapped.len() > AES_BLOCK_SIZE {
            let offset = swapped.len() - 2 * AES_BLOCK_SIZE;
            for index in 0..AES_BLOCK_SIZE {
                swapped.swap(offset + index, offset + AES_BLOCK_SIZE + index);
            }
        }
        return cbc_decrypt_no_padding(&cipher, &swapped, &[0; AES_BLOCK_SIZE]);
    }
    let tail_start = ciphertext.len() - remainder - AES_BLOCK_SIZE;
    let (prefix, tail) = ciphertext.split_at(tail_start);
    let (penultimate, last_partial) = tail.split_at(AES_BLOCK_SIZE);
    let mut plaintext = cbc_decrypt_no_padding(&cipher, prefix, &[0; AES_BLOCK_SIZE])?;
    let previous: [u8; AES_BLOCK_SIZE] = if prefix.is_empty() {
        [0; AES_BLOCK_SIZE]
    } else {
        prefix[prefix.len() - AES_BLOCK_SIZE..]
            .try_into()
            .map_err(|_| Error::MalformedPayload)?
    };
    let mut intermediate = Block::try_from(penultimate).map_err(|_| Error::MalformedPayload)?;
    cipher.decrypt_block(&mut intermediate);
    let mut reconstructed_last = [0_u8; AES_BLOCK_SIZE];
    reconstructed_last[..remainder].copy_from_slice(last_partial);
    reconstructed_last[remainder..].copy_from_slice(&intermediate[remainder..]);
    let mut last_plain = Block::from(reconstructed_last);
    cipher.decrypt_block(&mut last_plain);
    for (value, prior) in last_plain.iter_mut().zip(previous) {
        *value ^= prior;
    }
    let mut penultimate_plain =
        Block::try_from(penultimate).map_err(|_| Error::MalformedPayload)?;
    cipher.decrypt_block(&mut penultimate_plain);
    for (value, prior) in penultimate_plain.iter_mut().zip(reconstructed_last) {
        *value ^= prior;
    }
    plaintext.extend_from_slice(&last_plain);
    plaintext.extend_from_slice(&penultimate_plain[..remainder]);
    Ok(plaintext)
}

fn cbc_decrypt_no_padding(
    cipher: &Aes256,
    ciphertext: &[u8],
    iv: &[u8; AES_BLOCK_SIZE],
) -> Result<Vec<u8>, Error> {
    if !ciphertext.len().is_multiple_of(AES_BLOCK_SIZE) {
        return Err(Error::MalformedPayload);
    }
    let mut output = Vec::with_capacity(ciphertext.len());
    let mut previous = *iv;
    for chunk in ciphertext.as_chunks::<AES_BLOCK_SIZE>().0 {
        let mut block = Block::from(*chunk);
        cipher.decrypt_block(&mut block);
        for (value, prior) in block.iter_mut().zip(previous) {
            *value ^= prior;
        }
        output.extend_from_slice(&block);
        previous.copy_from_slice(chunk);
    }
    Ok(output)
}

pub(crate) fn encrypt_with_magic(
    secret: &CryptoKey,
    payload: &[u8],
    usage: u32,
    confounder: Option<&[u8; AES_BLOCK_SIZE]>,
    limits: Limits,
) -> Result<Vec<u8>, Error> {
    let mut plaintext = Vec::with_capacity(9_usize.saturating_add(payload.len()));
    plaintext.push(1);
    plaintext.extend_from_slice(&AUTH_ENC_MAGIC.to_le_bytes());
    plaintext.extend_from_slice(payload);
    let result = match secret.type_id {
        CRYPTO_AES => encrypt_payload(secret, &plaintext, usage, limits),
        CRYPTO_AES256_KRB5 => encrypt_rfc8009_with_confounder(
            secret,
            &plaintext,
            usage,
            confounder.ok_or(Error::MalformedPayload)?,
            limits,
        ),
        _ => Err(Error::UnsupportedType),
    };
    plaintext.zeroize();
    result
}

pub(crate) fn decrypt_with_magic(
    secret: &CryptoKey,
    ciphertext: &[u8],
    usage: u32,
    limits: Limits,
) -> Result<Vec<u8>, Error> {
    let mut plaintext = decrypt_payload(secret, ciphertext, usage, limits)?;
    if plaintext.len() < 9 {
        plaintext.zeroize();
        return Err(Error::MalformedPayload);
    }
    if plaintext[0] != 1 {
        plaintext.zeroize();
        return Err(Error::InvalidVersion);
    }
    let magic = u64::from_le_bytes(
        plaintext[1..9]
            .try_into()
            .map_err(|_| Error::MalformedPayload)?,
    );
    if magic != AUTH_ENC_MAGIC {
        plaintext.zeroize();
        return Err(Error::InvalidMagic);
    }
    Ok(plaintext.split_off(9))
}

pub(crate) fn calculate_challenge(
    secret: &CryptoKey,
    server_challenge: u64,
    client_challenge: u64,
    limits: Limits,
) -> Result<u64, Error> {
    let mut challenge = [0_u8; 16];
    challenge[..8].copy_from_slice(&server_challenge.to_le_bytes());
    challenge[8..].copy_from_slice(&client_challenge.to_le_bytes());
    let folded = match secret.type_id {
        CRYPTO_AES => {
            let encrypted = encrypt_with_magic(secret, &challenge, 0, None, limits)?;
            let mut envelope = Vec::with_capacity(4 + encrypted.len());
            envelope.extend_from_slice(
                &u32::try_from(encrypted.len())
                    .map_err(|_| Error::LimitExceeded)?
                    .to_le_bytes(),
            );
            envelope.extend_from_slice(&encrypted);
            envelope
        }
        CRYPTO_AES256_KRB5 => {
            let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&secret.secret)
                .map_err(|_| Error::UnsupportedType)?;
            mac.update(&challenge);
            mac.finalize().into_bytes().to_vec()
        }
        _ => return Err(Error::UnsupportedType),
    };
    Ok(folded
        .as_chunks::<8>()
        .0
        .iter()
        .fold(0, |value, word| value ^ u64::from_le_bytes(*word)))
}

pub(crate) fn transcript_signature(secret: &CryptoKey, transcript: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&secret.secret)
        .expect("validated CephX key length");
    mac.update(transcript);
    mac.finalize().into_bytes().into()
}

pub(crate) fn verify_transcript_signature(
    secret: &CryptoKey,
    transcript: &[u8],
    signature: &[u8; 32],
) -> bool {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&secret.secret)
        .expect("validated CephX key length");
    mac.update(transcript);
    mac.verify_slice(signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(type_id: u16, bytes: &[u8]) -> CryptoKey {
        CryptoKey {
            type_id,
            secret: bytes.to_vec(),
        }
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("ASCII hex");
                u8::from_str_radix(text, 16).expect("valid hex")
            })
            .collect()
    }

    #[test]
    fn matches_p03_crypto_vectors() {
        let limits = Limits::default();
        let aes = key(CRYPTO_AES, b"1234567890123456");
        assert_eq!(
            encrypt_payload(&aes, b"abc", 0, limits).unwrap(),
            decode_hex("0ba3d1290cc47bb370aa355b24a7d152")
        );
        let aes256 = key(
            CRYPTO_AES256_KRB5,
            &decode_hex("6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52"),
        );
        let ciphertext = decode_hex(
            "4ed7b37c2bcac8f74f23c1cf07e62bc7b75fb3f637b9f559c7f664f69eab7b6092237526ea0d1f61cb20d69d10f2",
        );
        assert_eq!(
            decrypt_payload(&aes256, &ciphertext, 2, limits).unwrap(),
            [0, 1, 2, 3, 4, 5]
        );
        let challenge_key = key(CRYPTO_AES256_KRB5, &(0_u8..32).collect::<Vec<_>>());
        assert_eq!(
            calculate_challenge(
                &challenge_key,
                0x1122_3344_5566_7788,
                0x0102_0304_0506_0708,
                limits,
            )
            .unwrap(),
            0xff60_3040_e5eb_4b04
        );
    }

    #[test]
    fn rfc8009_round_trip_and_integrity() {
        let secret = key(CRYPTO_AES256_KRB5, &(0_u8..32).collect::<Vec<_>>());
        let limits = Limits::default();
        let ciphertext = encrypt_rfc8009_with_confounder(
            &secret,
            b"deterministic payload",
            KEY_USAGE_AUTHORIZE,
            &[0x5a; AES_BLOCK_SIZE],
            limits,
        )
        .unwrap();
        assert_eq!(
            decrypt_payload(&secret, &ciphertext, KEY_USAGE_AUTHORIZE, limits).unwrap(),
            b"deterministic payload"
        );
        let mut tampered = ciphertext;
        tampered[0] ^= 1;
        assert_eq!(
            decrypt_payload(&secret, &tampered, KEY_USAGE_AUTHORIZE, limits),
            Err(Error::MalformedPayload)
        );
    }

    #[test]
    fn transcript_signatures_are_verified() {
        let secret = key(CRYPTO_AES, b"1234567890123456");
        let signature = transcript_signature(&secret, b"transcript");
        assert!(verify_transcript_signature(
            &secret,
            b"transcript",
            &signature
        ));
        assert!(!verify_transcript_signature(
            &secret, b"changed", &signature
        ));
    }
}
