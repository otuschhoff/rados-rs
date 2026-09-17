use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use zeroize::{Zeroize, Zeroizing};

#[cfg(not(any(fuzzing, feature = "fuzzing")))]
pub(crate) mod connector;
pub(crate) mod core;
pub(crate) mod crypto;
#[cfg(test)]
mod fixture_tests;

pub(crate) const CRYPTO_AES: u16 = 1;
pub(crate) const CRYPTO_AES256_KRB5: u16 = 2;
const AES_KEY_SIZE: usize = 16;
const AES256_KEY_SIZE: usize = 32;
const DEFAULT_MAX_KEY_BYTES: usize = 256;
const DEFAULT_MAX_KEYRING_BYTES: usize = 1 << 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    CredentialNotFound,
    InvalidCredential,
    InvalidKeyring,
    InvalidMagic,
    InvalidMode,
    InvalidNonce,
    InvalidStatus,
    InvalidVersion,
    LimitExceeded,
    MalformedPayload,
    MissingTicket,
    ExpiredTicket,
    UnsupportedType,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct CryptoKey {
    type_id: u16,
    secret: Vec<u8>,
}

impl Drop for CryptoKey {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl CryptoKey {
    pub(crate) const fn type_id(&self) -> u16 {
        self.type_id
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.secret
    }
}

impl fmt::Debug for CryptoKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "CephX crypto key type {} (redacted)",
            self.type_id
        )
    }
}

impl fmt::Display for CryptoKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, formatter)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct Credential {
    entity: String,
    created_seconds: u32,
    created_nanoseconds: u32,
    secret: CryptoKey,
}

impl Credential {
    pub(crate) fn entity(&self) -> &str {
        &self.entity
    }

    pub(crate) const fn created(&self) -> (u32, u32) {
        (self.created_seconds, self.created_nanoseconds)
    }

    pub(crate) const fn secret(&self) -> &CryptoKey {
        &self.secret
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "CephX credential for {}", self.entity)
    }
}

impl fmt::Display for Credential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, formatter)
    }
}

pub(crate) fn parse_key(
    entity: &str,
    encoded: &str,
    max_bytes: usize,
) -> Result<Credential, Error> {
    if !valid_client_entity(entity) {
        return Err(Error::InvalidCredential);
    }
    let maximum = if max_bytes == 0 {
        DEFAULT_MAX_KEY_BYTES
    } else {
        max_bytes
    };
    let encoded = encoded.trim();
    if encoded.is_empty() || encoded.len() > maximum.saturating_mul(2) {
        return Err(Error::InvalidCredential);
    }
    let data = Zeroizing::new(
        STANDARD
            .decode(encoded)
            .map_err(|_| Error::InvalidCredential)?,
    );
    if data.len() > maximum || data.len() < 12 {
        return Err(Error::InvalidCredential);
    }
    let type_id = u16::from_le_bytes([data[0], data[1]]);
    let created_seconds = u32::from_le_bytes(data[2..6].try_into().expect("fixed slice"));
    let created_nanoseconds = u32::from_le_bytes(data[6..10].try_into().expect("fixed slice"));
    let secret_length = usize::from(u16::from_le_bytes([data[10], data[11]]));
    if !valid_key_parameters(type_id, secret_length)
        || created_nanoseconds >= 1_000_000_000
        || data.len() != 12 + secret_length
    {
        return Err(Error::InvalidCredential);
    }
    Ok(Credential {
        entity: entity.to_owned(),
        created_seconds,
        created_nanoseconds,
        secret: CryptoKey {
            type_id,
            secret: data[12..].to_vec(),
        },
    })
}

pub(crate) fn parse_keyring(
    data: &[u8],
    entity: &str,
    max_bytes: usize,
) -> Result<Credential, Error> {
    if !valid_client_entity(entity) {
        return Err(Error::InvalidKeyring);
    }
    let maximum = if max_bytes == 0 {
        DEFAULT_MAX_KEYRING_BYTES
    } else {
        max_bytes
    };
    if data.len() > maximum {
        return Err(Error::InvalidKeyring);
    }
    let text = std::str::from_utf8(data).map_err(|_| Error::InvalidKeyring)?;
    let mut section = "";
    let mut key = None;
    let mut found_section = false;
    for raw_line in text.lines() {
        if raw_line.len() > maximum {
            return Err(Error::InvalidKeyring);
        }
        let line = strip_comment(raw_line.trim());
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            if !line.ends_with(']')
                || line.matches('[').count() != 1
                || line.matches(']').count() != 1
            {
                return Err(Error::InvalidKeyring);
            }
            section = line[1..line.len() - 1].trim();
            if section == entity {
                if found_section {
                    return Err(Error::InvalidKeyring);
                }
                found_section = true;
            }
            continue;
        }
        let (name, value) = line.split_once('=').ok_or(Error::InvalidKeyring)?;
        if name.trim().is_empty() || section.is_empty() {
            return Err(Error::InvalidKeyring);
        }
        if section != entity {
            continue;
        }
        let property = name.trim();
        if property == "auid" || property.starts_with("caps ") || property.starts_with("caps_") {
            continue;
        }
        if property != "key" || key.is_some() {
            return Err(Error::InvalidKeyring);
        }
        let value = value.trim();
        key = Some(
            if value.len() >= 2
                && ((value.starts_with('"') && value.ends_with('"'))
                    || (value.starts_with('\'') && value.ends_with('\'')))
            {
                &value[1..value.len() - 1]
            } else {
                value
            },
        );
    }
    if !found_section {
        return Err(Error::CredentialNotFound);
    }
    parse_key(
        entity,
        key.ok_or(Error::CredentialNotFound)?,
        DEFAULT_MAX_KEY_BYTES,
    )
    .map_err(|_| Error::InvalidKeyring)
}

fn valid_key_parameters(type_id: u16, secret_length: usize) -> bool {
    matches!(
        (type_id, secret_length),
        (CRYPTO_AES, AES_KEY_SIZE) | (CRYPTO_AES256_KRB5, AES256_KEY_SIZE)
    )
}

fn valid_client_entity(entity: &str) -> bool {
    entity.strip_prefix("client.").is_some_and(|id| {
        !id.is_empty()
            && !id
                .bytes()
                .any(|byte| matches!(byte, b'[' | b']' | b'\r' | b'\n' | 0))
    })
}

fn strip_comment(line: &str) -> &str {
    let mut quote = None;
    for (index, byte) in line.bytes().enumerate() {
        match byte {
            b'\'' | b'"' if quote.is_none() => quote = Some(byte),
            b'\'' | b'"' if quote == Some(byte) => quote = None,
            b'#' | b';' if quote.is_none() => return line[..index].trim(),
            _ => {}
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    const AES_KEY: &str = "AQB7AAAAyAEAABAAMTIzNDU2Nzg5MDEyMzQ1Ng==";
    const AES256_KEY: &str = "AgBm8qdqnvU7HiAAg6prN8XJ47FG9AprWpB72EwKyLfFC7UgnMYvcnFI29M=";

    #[test]
    fn parses_canonical_keys_without_exposing_secrets() {
        let credential = parse_key("client.test", AES_KEY, 64).unwrap();
        assert_eq!(credential.entity(), "client.test");
        assert_eq!(credential.created(), (123, 456));
        assert_eq!(credential.secret().type_id(), CRYPTO_AES);
        assert_eq!(credential.secret().bytes(), b"1234567890123456");
        assert!(!format!("{credential:?} {:?}", credential.secret()).contains("123456"));

        let credential = parse_key("client.p03", AES256_KEY, 64).unwrap();
        assert_eq!(credential.secret().type_id(), CRYPTO_AES256_KRB5);
        assert_eq!(credential.secret().bytes().len(), AES256_KEY_SIZE);
    }

    #[test]
    fn rejects_malformed_keys() {
        assert_eq!(
            parse_key("osd.1", AES_KEY, 64),
            Err(Error::InvalidCredential)
        );
        assert_eq!(
            parse_key("client.test", "%%%", 64),
            Err(Error::InvalidCredential)
        );
        assert_eq!(
            parse_key("client.test", &"A".repeat(130), 64),
            Err(Error::InvalidCredential)
        );
    }

    #[test]
    fn parses_supported_keyring_subset() {
        let data = format!(
            "# generated\n[client.other]\n key = bad\n\n[client.test]\n key = '{AES_KEY}' ; comment\n caps mon = allow r\n caps_osd = allow rw pool=test\n auid = 0\n"
        );
        let credential = parse_keyring(data.as_bytes(), "client.test", 4096).unwrap();
        assert_eq!(credential.secret().bytes(), b"1234567890123456");
    }

    #[test]
    fn rejects_unsupported_keyring_input() {
        assert_eq!(
            parse_keyring(b"[client.other]\nkey = x\n", "client.test", 64),
            Err(Error::CredentialNotFound)
        );
        assert_eq!(
            parse_keyring(b"[client.test]\nunknown = value\n", "client.test", 64),
            Err(Error::InvalidKeyring)
        );
        assert_eq!(
            parse_keyring(&[b'x'; 65], "client.test", 64),
            Err(Error::InvalidKeyring)
        );
    }
}
