use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use zeroize::{Zeroize, Zeroizing};

use super::crypto::{
    KEY_USAGE_AUTH_CONNECTION_SECRET, KEY_USAGE_AUTHORIZE, KEY_USAGE_AUTHORIZE_CHALLENGE,
    KEY_USAGE_AUTHORIZE_REPLY, KEY_USAGE_TICKET_BLOB, KEY_USAGE_TICKET_SESSION_KEY, Limits,
    calculate_challenge, decrypt_with_magic, encrypt_with_magic,
};
use super::{CRYPTO_AES, CRYPTO_AES256_KRB5, Credential, CryptoKey, Error};
use crate::wire::{Decoder, Encoder, WireError};

pub(crate) const AUTH_MODE_MON: u8 = 10;
pub(crate) const CONNECTION_MODE_CRC: u32 = 1;
pub(crate) const CONNECTION_MODE_SECURE: u32 = 2;
pub(crate) const CONNECTION_SECRET_SIZE_SECURE: usize = 64;
pub(crate) const SERVICE_MONITOR: u32 = 0x01;
pub(crate) const SERVICE_OSD: u32 = 0x04;
pub(crate) const SERVICE_MANAGER: u32 = 0x10;
pub(crate) const SERVICE_AUTH: u32 = 0x20;

const ENTITY_CLIENT: u32 = 0x08;
const GET_AUTH_SESSION_KEY: u16 = 0x0100;
const GET_PRINCIPAL_SESSION_KEY: u16 = 0x0200;

impl From<WireError> for Error {
    fn from(value: WireError) -> Self {
        match value {
            WireError::LimitExceeded => Self::LimitExceeded,
            WireError::Malformed | WireError::UnsupportedVersion { .. } => Self::MalformedPayload,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct TicketBlob {
    pub(crate) secret_id: u64,
    pub(crate) blob: Vec<u8>,
}

impl fmt::Debug for TicketBlob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "CephX ticket secret_id={} (redacted)",
            self.secret_id
        )
    }
}

impl fmt::Display for TicketBlob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, formatter)
    }
}

impl Drop for TicketBlob {
    fn drop(&mut self) {
        self.blob.zeroize();
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ServiceTicket {
    pub(crate) service_id: u32,
    pub(crate) ticket: TicketBlob,
    pub(crate) session_key: CryptoKey,
    pub(crate) expires_at: Duration,
    pub(crate) renew_after: Duration,
}

impl fmt::Debug for ServiceTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "CephX service ticket service={} expires_at={:?} (redacted)",
            self.service_id, self.expires_at
        )
    }
}

impl fmt::Display for ServiceTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, formatter)
    }
}

pub(crate) struct AuthSessionReply {
    pub(crate) request_type: u16,
    pub(crate) auth_session_key: CryptoKey,
    pub(crate) connection_secret: Vec<u8>,
    pub(crate) tickets: BTreeMap<u32, ServiceTicket>,
}

impl fmt::Debug for AuthSessionReply {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "CephX auth reply type={} tickets={} (redacted)",
            self.request_type,
            self.tickets.len()
        )
    }
}

impl fmt::Display for AuthSessionReply {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, formatter)
    }
}

impl Drop for AuthSessionReply {
    fn drop(&mut self) {
        self.connection_secret.zeroize();
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct Authorizer {
    pub(crate) base: Vec<u8>,
    pub(crate) payload: Vec<u8>,
    pub(crate) nonce: u64,
    pub(crate) service_id: u32,
}

impl fmt::Debug for Authorizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "CephX authorizer service={} (redacted)",
            self.service_id
        )
    }
}

impl fmt::Display for Authorizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, formatter)
    }
}

impl Drop for Authorizer {
    fn drop(&mut self) {
        self.base.zeroize();
        self.payload.zeroize();
    }
}

pub(crate) fn build_initial_payload(
    credential: &Credential,
    global_id: u64,
    limits: Limits,
) -> Result<Vec<u8>, Error> {
    let id = credential
        .entity
        .strip_prefix("client.")
        .ok_or(Error::InvalidCredential)?;
    let mut encoder = Encoder::new(limits.max_auth_bytes);
    encoder.u8(AUTH_MODE_MON);
    encoder.u32(ENTITY_CLIENT);
    encoder.string(id);
    encoder.u64(global_id);
    encoder.finish().map_err(Into::into)
}

pub(crate) fn parse_server_challenge(payload: &[u8], limits: Limits) -> Result<u64, Error> {
    if payload.len() > limits.max_auth_bytes {
        return Err(Error::LimitExceeded);
    }
    let mut decoder = Decoder::new(payload, limits.max_auth_bytes);
    let version = decoder.u8();
    let challenge = decoder.u64();
    finish_exact(&decoder)?;
    if version != 1 {
        return Err(Error::InvalidVersion);
    }
    Ok(challenge)
}

pub(crate) fn build_challenge_request(
    credential: &Credential,
    server_challenge: u64,
    client_challenge: u64,
    old_ticket: &TicketBlob,
    requested_keys: u32,
    limits: Limits,
) -> Result<Vec<u8>, Error> {
    if old_ticket.blob.len() > limits.max_ticket_blob_bytes {
        return Err(Error::LimitExceeded);
    }
    let challenge_key = calculate_challenge(
        &credential.secret,
        server_challenge,
        client_challenge,
        limits,
    )?;
    let mut encoder = Encoder::new(limits.max_auth_bytes);
    encoder.u16(GET_AUTH_SESSION_KEY);
    encoder.u8(3);
    encoder.u64(client_challenge);
    encoder.u64(challenge_key);
    encode_ticket_blob(&mut encoder, old_ticket);
    encoder.u32(requested_keys);
    encoder.finish().map_err(Into::into)
}

pub(crate) fn build_service_ticket_request(
    authorizer: &[u8],
    requested_keys: u32,
    limits: Limits,
) -> Result<Vec<u8>, Error> {
    if authorizer.len() > limits.max_auth_bytes {
        return Err(Error::LimitExceeded);
    }
    let mut encoder = Encoder::new(limits.max_auth_bytes);
    encoder.u16(GET_PRINCIPAL_SESSION_KEY);
    encoder.raw(authorizer);
    encoder.u8(1);
    encoder.u32(requested_keys);
    encoder.finish().map_err(Into::into)
}

pub(crate) fn parse_auth_session_reply(
    payload: &[u8],
    principal_secret: &CryptoKey,
    existing_auth_key: Option<&CryptoKey>,
    connection_mode: u32,
    now: Duration,
    limits: Limits,
) -> Result<AuthSessionReply, Error> {
    if !matches!(
        connection_mode,
        CONNECTION_MODE_CRC | CONNECTION_MODE_SECURE
    ) {
        return Err(Error::InvalidMode);
    }
    if payload.len() > limits.max_auth_bytes {
        return Err(Error::LimitExceeded);
    }
    let mut decoder = Decoder::new(payload, limits.max_auth_bytes);
    let request_type = decoder.u16();
    let status = decoder.i32();
    decoder.finish()?;
    if status != 0 {
        return Err(Error::InvalidStatus);
    }
    if request_type != GET_AUTH_SESSION_KEY {
        return Err(Error::UnsupportedType);
    }
    let mut tickets = parse_service_ticket_reply(
        &mut decoder,
        principal_secret,
        existing_auth_key,
        now,
        limits,
        limits.max_tickets,
    )?;
    let auth_session_key = tickets
        .get(&SERVICE_AUTH)
        .ok_or(Error::MissingTicket)?
        .session_key
        .clone();
    let mut connection_secret = Vec::new();
    if decoder.remaining() != 0 {
        let connection_blob = decoder.bytes();
        let extra_tickets_blob = decoder.bytes();
        finish_exact(&decoder)?;
        if !connection_blob.is_empty() {
            if connection_mode != CONNECTION_MODE_SECURE {
                return Err(Error::InvalidMode);
            }
            let plaintext = Zeroizing::new(decrypt_envelope(
                &auth_session_key,
                &connection_blob,
                KEY_USAGE_AUTH_CONNECTION_SECRET,
                limits,
            )?);
            let mut secret_decoder = Decoder::new(&plaintext, limits.max_connection_secret_bytes);
            connection_secret = secret_decoder.bytes();
            finish_exact(&secret_decoder)?;
            if connection_secret.len() != CONNECTION_SECRET_SIZE_SECURE {
                return Err(Error::MalformedPayload);
            }
        }
        if !extra_tickets_blob.is_empty() {
            let mut extra_decoder = Decoder::new(&extra_tickets_blob, limits.max_auth_bytes);
            let remaining = limits.max_tickets.saturating_sub(tickets.len());
            let extra = parse_service_ticket_reply(
                &mut extra_decoder,
                &auth_session_key,
                None,
                now,
                limits,
                remaining,
            )?;
            finish_exact(&extra_decoder)?;
            for (service_id, ticket) in extra {
                if tickets.insert(service_id, ticket).is_some() {
                    return Err(Error::MalformedPayload);
                }
            }
        }
    }
    Ok(AuthSessionReply {
        request_type,
        auth_session_key,
        connection_secret,
        tickets,
    })
}

pub(crate) fn build_authorizer(
    service_id: u32,
    global_id: u64,
    ticket: &ServiceTicket,
    now: Duration,
    nonce: u64,
    confounder: Option<&[u8; 16]>,
    limits: Limits,
) -> Result<Authorizer, Error> {
    if ticket.service_id != service_id {
        return Err(Error::MalformedPayload);
    }
    if ticket.expires_at.is_zero() || now >= ticket.expires_at {
        return Err(Error::ExpiredTicket);
    }
    let mut base_encoder = Encoder::new(limits.max_auth_bytes);
    base_encoder.u8(1);
    base_encoder.u64(global_id);
    base_encoder.u32(service_id);
    encode_ticket_blob(&mut base_encoder, &ticket.ticket);
    let base = base_encoder.finish()?;
    let encrypted = encrypt_authorize(&ticket.session_key, nonce, None, confounder, limits)?;
    let mut payload = base.clone();
    payload.extend_from_slice(&encrypted);
    if payload.len() > limits.max_auth_bytes {
        return Err(Error::LimitExceeded);
    }
    Ok(Authorizer {
        base,
        payload,
        nonce,
        service_id,
    })
}

pub(crate) fn add_authorizer_challenge(
    authorizer: &Authorizer,
    challenge: &[u8],
    session_key: &CryptoKey,
    confounder: Option<&[u8; 16]>,
    limits: Limits,
) -> Result<Authorizer, Error> {
    let plaintext = Zeroizing::new(decrypt_with_magic(
        session_key,
        challenge,
        KEY_USAGE_AUTHORIZE_CHALLENGE,
        limits,
    )?);
    let mut decoder = Decoder::new(&plaintext, limits.max_auth_bytes);
    let version = decoder.u8();
    let server_challenge = decoder.u64();
    finish_exact(&decoder)?;
    if version != 1 {
        return Err(Error::InvalidVersion);
    }
    let encrypted = encrypt_authorize(
        session_key,
        authorizer.nonce,
        Some(server_challenge.wrapping_add(1)),
        confounder,
        limits,
    )?;
    let mut payload = authorizer.base.clone();
    payload.extend_from_slice(&encrypted);
    if payload.len() > limits.max_auth_bytes {
        return Err(Error::LimitExceeded);
    }
    Ok(Authorizer {
        base: authorizer.base.clone(),
        payload,
        nonce: authorizer.nonce,
        service_id: authorizer.service_id,
    })
}

pub(crate) fn verify_authorizer_reply(
    payload: &[u8],
    session_key: &CryptoKey,
    nonce: u64,
    limits: Limits,
) -> Result<Vec<u8>, Error> {
    let mut outer = Decoder::new(payload, limits.max_auth_bytes);
    let encrypted = outer.bytes();
    finish_exact(&outer)?;
    let plaintext = Zeroizing::new(decrypt_with_magic(
        session_key,
        &encrypted,
        KEY_USAGE_AUTHORIZE_REPLY,
        limits,
    )?);
    let mut reply = Decoder::new(&plaintext, limits.max_auth_bytes);
    let version = reply.u8();
    let nonce_plus_one = reply.u64();
    let secret = if version >= 2 {
        reply.bytes()
    } else {
        Vec::new()
    };
    finish_exact(&reply)?;
    if version < 1 {
        return Err(Error::InvalidVersion);
    }
    if nonce_plus_one != nonce.wrapping_add(1) {
        return Err(Error::InvalidNonce);
    }
    if secret.len() > limits.max_connection_secret_bytes {
        return Err(Error::LimitExceeded);
    }
    Ok(secret)
}

fn encrypt_authorize(
    session_key: &CryptoKey,
    nonce: u64,
    challenge_plus_one: Option<u64>,
    confounder: Option<&[u8; 16]>,
    limits: Limits,
) -> Result<Vec<u8>, Error> {
    let mut encoder = Encoder::new(limits.max_auth_bytes);
    encoder.u8(2);
    encoder.u64(nonce);
    encoder.bool(challenge_plus_one.is_some());
    encoder.u64(challenge_plus_one.unwrap_or_default());
    let plaintext = Zeroizing::new(encoder.finish()?);
    let encrypted = encrypt_with_magic(
        session_key,
        &plaintext,
        KEY_USAGE_AUTHORIZE,
        confounder,
        limits,
    )?;
    let mut outer = Encoder::new(limits.max_auth_bytes);
    outer.bytes(&encrypted);
    outer.finish().map_err(Into::into)
}

fn parse_service_ticket_reply(
    decoder: &mut Decoder<'_>,
    decrypt_key: &CryptoKey,
    existing_auth_key: Option<&CryptoKey>,
    now: Duration,
    limits: Limits,
    max_tickets: usize,
) -> Result<BTreeMap<u32, ServiceTicket>, Error> {
    let version = decoder.u8();
    let count = decoder.u32() as usize;
    if version != 1 {
        return Err(Error::InvalidVersion);
    }
    if count > max_tickets {
        return Err(Error::LimitExceeded);
    }
    let mut tickets = BTreeMap::new();
    for _ in 0..count {
        let service_id = decoder.u32();
        if tickets.contains_key(&service_id) {
            return Err(Error::MalformedPayload);
        }
        if decoder.u8() != 1 {
            return Err(Error::InvalidVersion);
        }
        let service_payload = Zeroizing::new(decode_envelope(
            decoder,
            decrypt_key,
            KEY_USAGE_TICKET_SESSION_KEY,
            limits,
        )?);
        let mut service_decoder = Decoder::new(&service_payload, limits.max_auth_bytes);
        if service_decoder.u8() != 1 {
            return Err(Error::InvalidVersion);
        }
        let session_key = decode_secret_key(&mut service_decoder, limits)?;
        let validity = decode_utime(&mut service_decoder)?;
        finish_exact(&service_decoder)?;
        if validity.is_zero() {
            return Err(Error::ExpiredTicket);
        }
        let ticket_payload = Zeroizing::new(match decoder.u8() {
            0 => decoder.bytes(),
            1 => {
                let key = existing_auth_key.ok_or(Error::MissingTicket)?;
                let encrypted = decode_envelope(decoder, key, KEY_USAGE_TICKET_BLOB, limits)?;
                let mut inner = Decoder::new(&encrypted, limits.max_auth_bytes);
                let value = inner.bytes();
                finish_exact(&inner)?;
                value
            }
            _ => return Err(Error::MalformedPayload),
        });
        let mut ticket_decoder = Decoder::new(&ticket_payload, limits.max_auth_bytes);
        let ticket = decode_ticket_blob(&mut ticket_decoder, limits)?;
        finish_exact(&ticket_decoder)?;
        let expires_at = now.checked_add(validity).ok_or(Error::LimitExceeded)?;
        let renew_after = expires_at
            .checked_sub(validity / 4)
            .ok_or(Error::MalformedPayload)?;
        tickets.insert(
            service_id,
            ServiceTicket {
                service_id,
                ticket,
                session_key,
                expires_at,
                renew_after,
            },
        );
    }
    Ok(tickets)
}

fn decode_envelope(
    decoder: &mut Decoder<'_>,
    key: &CryptoKey,
    usage: u32,
    limits: Limits,
) -> Result<Vec<u8>, Error> {
    let encrypted = decoder.bytes();
    decoder.finish()?;
    decrypt_with_magic(key, &encrypted, usage, limits)
}

fn decrypt_envelope(
    key: &CryptoKey,
    encoded: &[u8],
    usage: u32,
    limits: Limits,
) -> Result<Vec<u8>, Error> {
    let mut decoder = Decoder::new(encoded, limits.max_auth_bytes);
    let value = decode_envelope(&mut decoder, key, usage, limits)?;
    finish_exact(&decoder)?;
    Ok(value)
}

fn decode_secret_key(decoder: &mut Decoder<'_>, limits: Limits) -> Result<CryptoKey, Error> {
    let type_id = decoder.u16();
    let _created = decode_utime(decoder)?;
    let length = decoder.u16() as usize;
    if !matches!(
        (type_id, length),
        (CRYPTO_AES, 16) | (CRYPTO_AES256_KRB5, 32)
    ) {
        return Err(Error::UnsupportedType);
    }
    if length > limits.max_decrypt_bytes {
        return Err(Error::LimitExceeded);
    }
    Ok(CryptoKey {
        type_id,
        secret: decoder.raw(length),
    })
}

fn decode_utime(decoder: &mut Decoder<'_>) -> Result<Duration, Error> {
    let seconds = u64::from(decoder.u32());
    let nanoseconds = decoder.u32();
    if nanoseconds >= 1_000_000_000 {
        return Err(Error::MalformedPayload);
    }
    Ok(Duration::new(seconds, nanoseconds))
}

fn encode_ticket_blob(encoder: &mut Encoder, ticket: &TicketBlob) {
    encoder.u8(1);
    encoder.u64(ticket.secret_id);
    encoder.bytes(&ticket.blob);
}

fn decode_ticket_blob(decoder: &mut Decoder<'_>, limits: Limits) -> Result<TicketBlob, Error> {
    let version = decoder.u8();
    let secret_id = decoder.u64();
    let blob = decoder.bytes();
    if version != 1 {
        return Err(Error::InvalidVersion);
    }
    if blob.len() > limits.max_ticket_blob_bytes {
        return Err(Error::LimitExceeded);
    }
    Ok(TicketBlob { secret_id, blob })
}

fn finish_exact(decoder: &Decoder<'_>) -> Result<(), Error> {
    decoder.finish()?;
    if decoder.remaining() != 0 {
        return Err(Error::MalformedPayload);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cephx::{CRYPTO_AES256_KRB5, parse_key};

    const AES_KEY: &str = "AQB7AAAAyAEAABAAMTIzNDU2Nzg5MDEyMzQ1Ng==";

    fn credential() -> Credential {
        parse_key("client.test", AES_KEY, 64).unwrap()
    }

    fn aes256_key(start: u8) -> CryptoKey {
        CryptoKey {
            type_id: CRYPTO_AES256_KRB5,
            secret: (start..start + 32).collect(),
        }
    }

    fn encode_envelope(key: &CryptoKey, plaintext: &[u8], usage: u32, limits: Limits) -> Vec<u8> {
        let confounder = [u8::try_from(usage).unwrap(); 16];
        let encrypted =
            encrypt_with_magic(key, plaintext, usage, Some(&confounder), limits).unwrap();
        let mut encoder = Encoder::new(limits.max_auth_bytes);
        encoder.bytes(&encrypted);
        encoder.finish().unwrap()
    }

    fn encode_auth_reply(
        principal: &CryptoKey,
        session_key: &CryptoKey,
        limits: Limits,
    ) -> Vec<u8> {
        let mut secret = Encoder::new(limits.max_auth_bytes);
        secret.u8(1);
        secret.u16(session_key.type_id);
        secret.u32(0);
        secret.u32(0);
        secret.u16(u16::try_from(session_key.secret.len()).unwrap());
        secret.raw(&session_key.secret);
        secret.u32(60);
        secret.u32(0);
        let encrypted_secret = encode_envelope(
            principal,
            &secret.finish().unwrap(),
            KEY_USAGE_TICKET_SESSION_KEY,
            limits,
        );
        let mut ticket = Encoder::new(limits.max_auth_bytes);
        encode_ticket_blob(
            &mut ticket,
            &TicketBlob {
                secret_id: 7,
                blob: b"auth-ticket".to_vec(),
            },
        );
        let mut reply = Encoder::new(limits.max_auth_bytes);
        reply.u16(GET_AUTH_SESSION_KEY);
        reply.i32(0);
        reply.u8(1);
        reply.u32(1);
        reply.u32(SERVICE_AUTH);
        reply.u8(1);
        reply.raw(&encrypted_secret);
        reply.u8(0);
        reply.bytes(&ticket.finish().unwrap());
        reply.finish().unwrap()
    }

    #[test]
    fn builds_initial_and_challenge_requests() {
        let limits = Limits::default();
        let credential = credential();
        assert_eq!(
            build_initial_payload(&credential, 42, limits).unwrap(),
            [
                10, 8, 0, 0, 0, 4, 0, 0, 0, b't', b'e', b's', b't', 42, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
        assert_eq!(
            parse_server_challenge(&[1, 1, 0, 0, 0, 0, 0, 0, 0], limits).unwrap(),
            1
        );
        let request = build_challenge_request(
            &credential,
            0x1122_3344_5566_7788,
            0x0102_0304_0506_0708,
            &TicketBlob {
                secret_id: 7,
                blob: vec![1, 2, 3],
            },
            SERVICE_AUTH,
            limits,
        )
        .unwrap();
        assert_eq!(&request[..3], &[0, 1, 3]);
        assert_eq!(&request[3..11], &0x0102_0304_0506_0708_u64.to_le_bytes());
        assert_eq!(&request[request.len() - 4..], &SERVICE_AUTH.to_le_bytes());
    }

    #[test]
    fn authorizer_round_trip_is_redacted() {
        let limits = Limits::default();
        let credential = credential();
        let ticket = ServiceTicket {
            service_id: SERVICE_MONITOR,
            ticket: TicketBlob {
                secret_id: 9,
                blob: b"ticket-secret".to_vec(),
            },
            session_key: credential.secret.clone(),
            expires_at: Duration::from_secs(200),
            renew_after: Duration::from_secs(150),
        };
        let authorizer = build_authorizer(
            SERVICE_MONITOR,
            77,
            &ticket,
            Duration::from_secs(100),
            0x0807_0605_0403_0201,
            None,
            limits,
        )
        .unwrap();
        assert_eq!(authorizer.payload[0], 1);
        let formatted = format!("{authorizer:?} {ticket:?}");
        assert!(!formatted.contains("ticket-secret"));
        assert_eq!(
            build_authorizer(
                SERVICE_MONITOR,
                77,
                &ticket,
                ticket.expires_at,
                1,
                None,
                limits,
            ),
            Err(Error::ExpiredTicket)
        );
    }

    #[test]
    fn parses_nested_session_tickets_for_both_key_types() {
        let limits = Limits::default();
        let aes = credential().secret.clone();
        let keys = [(aes.clone(), aes), (aes256_key(0), aes256_key(32))];
        for (principal, session_key) in keys {
            let payload = encode_auth_reply(&principal, &session_key, limits);
            let reply = parse_auth_session_reply(
                &payload,
                &principal,
                None,
                CONNECTION_MODE_CRC,
                Duration::from_secs(100),
                limits,
            )
            .unwrap();
            assert_eq!(reply.auth_session_key, session_key);
            assert_eq!(reply.tickets[&SERVICE_AUTH].ticket.blob, b"auth-ticket");
            assert_eq!(
                reply.tickets[&SERVICE_AUTH].expires_at,
                Duration::from_secs(160)
            );
            assert_eq!(
                reply.tickets[&SERVICE_AUTH].renew_after,
                Duration::from_secs(145)
            );
        }
    }

    #[test]
    fn authorizer_challenge_and_reply_use_distinct_contexts() {
        let limits = Limits::default();
        for session_key in [credential().secret.clone(), aes256_key(64)] {
            let ticket = ServiceTicket {
                service_id: SERVICE_MONITOR,
                ticket: TicketBlob {
                    secret_id: 9,
                    blob: b"monitor-ticket".to_vec(),
                },
                session_key: session_key.clone(),
                expires_at: Duration::from_secs(200),
                renew_after: Duration::from_secs(150),
            };
            let authorizer = build_authorizer(
                SERVICE_MONITOR,
                77,
                &ticket,
                Duration::from_secs(100),
                0x0807_0605_0403_0201,
                Some(&[0x10; 16]),
                limits,
            )
            .unwrap();
            let mut challenge_plaintext = Encoder::new(limits.max_auth_bytes);
            challenge_plaintext.u8(1);
            challenge_plaintext.u64(0x1122_3344_5566_7788);
            let challenge = encrypt_with_magic(
                &session_key,
                &challenge_plaintext.finish().unwrap(),
                KEY_USAGE_AUTHORIZE_CHALLENGE,
                Some(&[0x11; 16]),
                limits,
            )
            .unwrap();
            let updated = add_authorizer_challenge(
                &authorizer,
                &challenge,
                &session_key,
                Some(&[0x12; 16]),
                limits,
            )
            .unwrap();
            assert_ne!(updated.payload, authorizer.payload);

            let connection_secret = [0x5a; CONNECTION_SECRET_SIZE_SECURE];
            let mut reply_plaintext = Encoder::new(limits.max_auth_bytes);
            reply_plaintext.u8(2);
            reply_plaintext.u64(authorizer.nonce.wrapping_add(1));
            reply_plaintext.bytes(&connection_secret);
            let encrypted_reply = encrypt_with_magic(
                &session_key,
                &reply_plaintext.finish().unwrap(),
                KEY_USAGE_AUTHORIZE_REPLY,
                Some(&[0x13; 16]),
                limits,
            )
            .unwrap();
            let mut reply = Encoder::new(limits.max_auth_bytes);
            reply.bytes(&encrypted_reply);
            assert_eq!(
                verify_authorizer_reply(
                    &reply.finish().unwrap(),
                    &session_key,
                    authorizer.nonce,
                    limits,
                )
                .unwrap(),
                connection_secret
            );
        }
    }
}
