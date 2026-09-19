use crate::protocol::address::EntityAddr;
use crate::wire::{Decoder, Encoder, WireError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const ENTITY_CLIENT: u8 = 8;
pub(crate) const LOCK_EXCLUSIVE: u8 = 1;
pub(crate) const LOCK_SHARED: u8 = 2;
const LOCK_MAY_RENEW: u8 = 1;

pub(crate) struct Request<'a> {
    pub(crate) name: &'a str,
    pub(crate) lock_type: u8,
    pub(crate) cookie: &'a str,
    pub(crate) tag: &'a str,
    pub(crate) description: &'a str,
    pub(crate) duration: Duration,
    pub(crate) renew: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Holder {
    pub(crate) client: u64,
    pub(crate) cookie: String,
    pub(crate) address: String,
    pub(crate) description: String,
    pub(crate) expiration: SystemTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Info {
    pub(crate) holders: Vec<Holder>,
    pub(crate) lock_type: u8,
    pub(crate) tag: String,
}

pub(crate) fn encode_lock(request: &Request<'_>, max_bytes: usize) -> Result<Vec<u8>, WireError> {
    if request.name.is_empty()
        || request.cookie.is_empty()
        || !matches!(request.lock_type, LOCK_EXCLUSIVE | LOCK_SHARED)
        || request.duration.as_secs() > u64::from(u32::MAX)
    {
        return Err(WireError::Malformed);
    }
    let seconds = u32::try_from(request.duration.as_secs()).map_err(|_| WireError::Malformed)?;
    let mut encoder = Encoder::new(max_bytes);
    encoder.versioned(1, 1, |payload| {
        payload.string(request.name);
        payload.u8(request.lock_type);
        payload.string(request.cookie);
        payload.string(request.tag);
        payload.string(request.description);
        payload.u32(seconds);
        payload.u32(request.duration.subsec_nanos());
        payload.u8(if request.renew { LOCK_MAY_RENEW } else { 0 });
    });
    encoder.finish()
}

pub(crate) fn encode_unlock(
    name: &str,
    cookie: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, WireError> {
    if name.is_empty() || cookie.is_empty() {
        return Err(WireError::Malformed);
    }
    let mut encoder = Encoder::new(max_bytes);
    encoder.versioned(1, 1, |payload| {
        payload.string(name);
        payload.string(cookie);
    });
    encoder.finish()
}

pub(crate) fn encode_break(
    name: &str,
    client: u64,
    cookie: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, WireError> {
    if name.is_empty() || cookie.is_empty() || client > i64::MAX as u64 {
        return Err(WireError::Malformed);
    }
    let mut encoder = Encoder::new(max_bytes);
    let client = i64::try_from(client).map_err(|_| WireError::Malformed)?;
    encoder.versioned(1, 1, |payload| {
        payload.string(name);
        payload.u8(ENTITY_CLIENT);
        payload.i64(client);
        payload.string(cookie);
    });
    encoder.finish()
}

pub(crate) fn encode_get_info(name: &str, max_bytes: usize) -> Result<Vec<u8>, WireError> {
    if name.is_empty() {
        return Err(WireError::Malformed);
    }
    let mut encoder = Encoder::new(max_bytes);
    encoder.versioned(1, 1, |payload| payload.string(name));
    encoder.finish()
}

pub(crate) fn decode_info(
    data: &[u8],
    max_bytes: usize,
    max_holders: usize,
) -> Result<Info, WireError> {
    let mut decoder = Decoder::new(data, max_bytes);
    let (version, mut payload) = decoder.versioned(1);
    decoder.finish()?;
    if version != 1 {
        return Err(WireError::UnsupportedVersion {
            local: 1,
            required: version,
        });
    }
    let count = payload.u32() as usize;
    payload.finish()?;
    if count > max_holders || count.saturating_mul(13) > payload.remaining() {
        return Err(WireError::LimitExceeded);
    }
    let mut holders = Vec::with_capacity(count);
    for _ in 0..count {
        holders.push(decode_holder(&mut payload)?);
    }
    let lock_type = payload.u8();
    let tag = strict_string(&mut payload)?;
    payload.finish()?;
    if payload.remaining() != 0
        || !matches!(lock_type, 0 | LOCK_EXCLUSIVE | LOCK_SHARED)
        || lock_type == 0 && !holders.is_empty()
    {
        return Err(WireError::Malformed);
    }
    Ok(Info {
        holders,
        lock_type,
        tag,
    })
}

fn decode_holder(decoder: &mut Decoder<'_>) -> Result<Holder, WireError> {
    let (identity_version, mut identity) = decoder.versioned(1);
    decoder.finish()?;
    if identity_version != 1 || identity.u8() != ENTITY_CLIENT {
        return Err(WireError::Malformed);
    }
    let client = identity.i64();
    let cookie = strict_string(&mut identity)?;
    identity.finish()?;
    if client < 0 || identity.remaining() != 0 {
        return Err(WireError::Malformed);
    }

    let (info_version, mut info) = decoder.versioned(1);
    decoder.finish()?;
    if info_version != 1 {
        return Err(WireError::Malformed);
    }
    let seconds = info.u32();
    let nanoseconds = info.u32();
    if nanoseconds >= 1_000_000_000 {
        return Err(WireError::Malformed);
    }
    let address = EntityAddr::decode(&mut info)?;
    let description = strict_string(&mut info)?;
    info.finish()?;
    if info.remaining() != 0 {
        return Err(WireError::Malformed);
    }
    let expiration = if seconds == 0 && nanoseconds == 0 {
        UNIX_EPOCH
    } else {
        UNIX_EPOCH + Duration::new(u64::from(seconds), nanoseconds)
    };
    Ok(Holder {
        client: u64::try_from(client).map_err(|_| WireError::Malformed)?,
        cookie,
        address: address
            .endpoint()
            .map_or_else(String::new, |value| value.to_string()),
        description,
        expiration,
    })
}

fn strict_string(decoder: &mut Decoder<'_>) -> Result<String, WireError> {
    String::from_utf8(decoder.bytes()).map_err(|_| WireError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::features::GlobalFeatures;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    #[test]
    fn lock_request_matches_frozen_go_fields() {
        let bytes = encode_lock(
            &Request {
                name: "name",
                lock_type: LOCK_SHARED,
                cookie: "cookie",
                tag: "tag",
                description: "description",
                duration: Duration::new(3, 4),
                renew: true,
            },
            4096,
        )
        .expect("lock");
        let mut decoder = Decoder::new(&bytes, 4096);
        let (version, mut payload) = decoder.versioned(1);
        assert_eq!(version, 1);
        assert_eq!(payload.string(), "name");
        assert_eq!(payload.u8(), LOCK_SHARED);
        assert_eq!(payload.string(), "cookie");
        assert_eq!(payload.string(), "tag");
        assert_eq!(payload.string(), "description");
        assert_eq!(payload.u32(), 3);
        assert_eq!(payload.u32(), 4);
        assert_eq!(payload.u8(), LOCK_MAY_RENEW);
        assert_eq!(payload.remaining(), 0);
        assert!(
            encode_lock(
                &Request {
                    name: "",
                    lock_type: LOCK_EXCLUSIVE,
                    cookie: "cookie",
                    tag: "",
                    description: "",
                    duration: Duration::ZERO,
                    renew: false,
                },
                64
            )
            .is_err()
        );
    }

    #[test]
    fn lock_info_decodes_owned_holder_and_rejects_bounds_and_modes() {
        let address = EntityAddr::ipv4_v2(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(192, 0, 2, 8),
            6800,
        )))
        .expect("address");
        let mut encoder = Encoder::new(4096);
        encoder.versioned(1, 1, |reply| {
            reply.u32(1);
            reply.versioned(1, 1, |identity| {
                identity.u8(ENTITY_CLIENT);
                identity.i64(42);
                identity.string("cookie");
            });
            reply.versioned(1, 1, |info| {
                info.u32(9);
                info.u32(10);
                address
                    .encode(info, GlobalFeatures::MESSAGE_ADDRESS_V2)
                    .expect("encode address");
                info.string("description");
            });
            reply.u8(LOCK_EXCLUSIVE);
            reply.string("tag");
        });
        let data = encoder.finish().expect("reply");
        let decoded = decode_info(&data, 4096, 2).expect("lock info");
        assert_eq!(decoded.lock_type, LOCK_EXCLUSIVE);
        assert_eq!(decoded.tag, "tag");
        assert_eq!(decoded.holders[0].client, 42);
        assert_eq!(decoded.holders[0].cookie, "cookie");
        assert_eq!(decoded.holders[0].address, "192.0.2.8:6800");
        assert_eq!(decoded.holders[0].description, "description");
        assert_eq!(
            decoded.holders[0].expiration,
            UNIX_EPOCH + Duration::new(9, 10)
        );
        assert_eq!(decode_info(&data, 4096, 0), Err(WireError::LimitExceeded));

        let mut invalid = data.clone();
        let mode = invalid.len() - 8;
        invalid[mode] = 3;
        assert_eq!(decode_info(&invalid, 4096, 2), Err(WireError::Malformed));
    }
}
