use crate::protocol::features::GlobalFeatures;
use crate::wire::{Decoder, Encoder, WireError};

const AF_UNSPEC: u16 = 0;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const LEGACY_SOCKADDR_SIZE: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AddressType(u32);

impl AddressType {
    const NONE: Self = Self(0);
    const LEGACY: Self = Self(1);
    const V2: Self = Self(2);
    const ANY: Self = Self(3);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EntityAddr {
    address_type: AddressType,
    nonce: u32,
    family: u16,
    socket_data: Vec<u8>,
    legacy_encoding: bool,
}

impl EntityAddr {
    pub(crate) fn decode(decoder: &mut Decoder<'_>) -> Result<Self, WireError> {
        let marker = decoder.u8();
        decoder.finish()?;
        Self::decode_after_marker(decoder, marker)
    }

    fn decode_after_marker(decoder: &mut Decoder<'_>, marker: u8) -> Result<Self, WireError> {
        match marker {
            0 => {
                decoder.raw(3);
                let nonce = decoder.u32();
                let socket = decoder.raw(LEGACY_SOCKADDR_SIZE);
                decoder.finish()?;
                let family = u16::from_be_bytes([socket[0], socket[1]]);
                let length = socket_data_length(family)?;
                Ok(Self {
                    address_type: if family == AF_UNSPEC {
                        AddressType::NONE
                    } else {
                        AddressType::LEGACY
                    },
                    nonce,
                    family,
                    socket_data: socket[2..2 + length].to_vec(),
                    legacy_encoding: true,
                })
            }
            1 => {
                let (_, mut payload) = decoder.versioned(1);
                let address_type = AddressType(payload.u32());
                let nonce = payload.u32();
                let encoded_length = payload.u32() as usize;
                if encoded_length == 0 {
                    payload.finish()?;
                    decoder.finish()?;
                    return Ok(Self {
                        address_type,
                        nonce,
                        family: AF_UNSPEC,
                        socket_data: vec![0; 26],
                        legacy_encoding: false,
                    });
                }
                if encoded_length < 2 {
                    return Err(WireError::Malformed);
                }
                let family = payload.u16();
                let maximum = socket_data_length(family)?;
                let data_length = encoded_length - 2;
                if data_length > maximum {
                    return Err(WireError::Malformed);
                }
                let mut socket_data = vec![0; maximum];
                let encoded = payload.raw(data_length);
                socket_data[..encoded.len()].copy_from_slice(&encoded);
                payload.finish()?;
                decoder.finish()?;
                Ok(Self {
                    address_type,
                    nonce,
                    family,
                    socket_data,
                    legacy_encoding: false,
                })
            }
            _ => Err(WireError::Malformed),
        }
    }

    pub(crate) fn encode(
        &self,
        encoder: &mut Encoder,
        features: GlobalFeatures,
    ) -> Result<(), WireError> {
        if self.socket_data.len() != socket_data_length(self.family)? {
            return Err(WireError::Malformed);
        }
        if !features.contains(GlobalFeatures::MESSAGE_ADDRESS_V2) {
            encoder.u32(0);
            encoder.u32(self.nonce);
            let mut socket = [0; LEGACY_SOCKADDR_SIZE];
            socket[..2].copy_from_slice(&self.family.to_be_bytes());
            socket[2..2 + self.socket_data.len()].copy_from_slice(&self.socket_data);
            encoder.raw(&socket);
            return Ok(());
        }
        let address_type = if self.address_type == AddressType::ANY
            && !features.contains(GlobalFeatures::SERVER_NAUTILUS_MASK)
        {
            AddressType::LEGACY
        } else {
            self.address_type
        };
        encoder.u8(1);
        encoder.versioned(1, 1, |payload| {
            payload.u32(address_type.0);
            payload.u32(self.nonce);
            payload.u32(u32::try_from(2 + self.socket_data.len()).expect("bounded sockaddr"));
            payload.u16(self.family);
            payload.raw(&self.socket_data);
        });
        Ok(())
    }

    pub(crate) const fn encoding_features(&self) -> GlobalFeatures {
        if self.legacy_encoding {
            GlobalFeatures(0)
        } else {
            GlobalFeatures(
                GlobalFeatures::MESSAGE_ADDRESS_V2.0 | GlobalFeatures::SERVER_NAUTILUS_MASK.0,
            )
        }
    }
}

fn socket_data_length(family: u16) -> Result<usize, WireError> {
    match family {
        AF_INET => Ok(14),
        AF_UNSPEC | AF_INET6 => Ok(26),
        _ => Err(WireError::Malformed),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EntityAddrVec(pub(crate) Vec<EntityAddr>);

impl EntityAddrVec {
    pub(crate) fn decode(decoder: &mut Decoder<'_>, max_addresses: u32) -> Result<Self, WireError> {
        let marker = decoder.u8();
        decoder.finish()?;
        if marker < 2 {
            return Ok(Self(vec![EntityAddr::decode_after_marker(
                decoder, marker,
            )?]));
        }
        if marker != 2 {
            return Err(WireError::Malformed);
        }
        let count = decoder.u32();
        if count > max_addresses {
            return Err(WireError::LimitExceeded);
        }
        let count = usize::try_from(count).map_err(|_| WireError::LimitExceeded)?;
        if count > decoder.remaining() {
            return Err(WireError::Malformed);
        }
        let mut addresses = Vec::with_capacity(count);
        for _ in 0..count {
            addresses.push(EntityAddr::decode(decoder)?);
        }
        decoder.finish()?;
        Ok(Self(addresses))
    }

    pub(crate) fn encode(
        &self,
        encoder: &mut Encoder,
        features: GlobalFeatures,
    ) -> Result<(), WireError> {
        if !features.contains(GlobalFeatures::MESSAGE_ADDRESS_V2) {
            if let Some(address) = self
                .0
                .iter()
                .find(|address| address.address_type == AddressType::LEGACY)
            {
                return address.encode(encoder, GlobalFeatures(0));
            }
            return EntityAddr {
                address_type: AddressType::NONE,
                nonce: 0,
                family: AF_UNSPEC,
                socket_data: vec![0; 26],
                legacy_encoding: true,
            }
            .encode(encoder, GlobalFeatures(0));
        }
        encoder.u8(2);
        encoder.u32(u32::try_from(self.0.len()).map_err(|_| WireError::LimitExceeded)?);
        for address in &self.0 {
            address.encode(encoder, features)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    fn endpoint(address: &EntityAddr) -> Option<SocketAddr> {
        let port = u16::from_be_bytes([address.socket_data[0], address.socket_data[1]]);
        match address.family {
            AF_INET => Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(
                    address.socket_data[2],
                    address.socket_data[3],
                    address.socket_data[4],
                    address.socket_data[5],
                )),
                port,
            )),
            AF_INET6 => {
                let bytes: [u8; 16] = address.socket_data[6..22].try_into().ok()?;
                Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(bytes)), port))
            }
            _ => None,
        }
    }

    #[test]
    fn native_fixtures_have_independent_expected_fields() {
        let cases = [
            (
                include_bytes!("../../testdata/p01/entity-addr-ipv4-legacy.bin").as_slice(),
                AddressType::LEGACY,
                5,
                "127.0.1.2:2",
            ),
            (
                include_bytes!("../../testdata/p01/entity-addr-ipv4-modern.bin").as_slice(),
                AddressType::LEGACY,
                5,
                "127.0.1.2:2",
            ),
            (
                include_bytes!("../../testdata/p01/entity-addr-ipv6-modern.bin").as_slice(),
                AddressType::V2,
                7,
                "[2001:db8::1234]:3300",
            ),
        ];
        for (fixture, address_type, nonce, expected_endpoint) in cases {
            let address = EntityAddr::decode(&mut Decoder::new(fixture, 256)).expect("address");
            assert_eq!(address.address_type, address_type);
            assert_eq!(address.nonce, nonce);
            assert_eq!(
                endpoint(&address).expect("endpoint").to_string(),
                expected_endpoint
            );
        }
        let ipv6 = EntityAddr::decode(&mut Decoder::new(
            include_bytes!("../../testdata/p01/entity-addr-ipv6-modern.bin"),
            256,
        ))
        .expect("IPv6 address");
        assert_eq!(
            u32::from_le_bytes(ipv6.socket_data[2..6].try_into().expect("flow")),
            0x0102_0304
        );
        assert_eq!(
            u32::from_le_bytes(ipv6.socket_data[22..26].try_into().expect("scope")),
            0x0506_0708
        );
    }

    #[test]
    fn rejects_invalid_markers_lengths_families_and_counts() {
        for data in [
            vec![3],
            vec![1, 1, 1, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0],
            vec![1, 1, 1, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 99, 0],
        ] {
            assert!(EntityAddr::decode(&mut Decoder::new(&data, 64)).is_err());
        }
        assert_eq!(
            EntityAddrVec::decode(&mut Decoder::new(&[2, 2, 0, 0, 0], 64), 1),
            Err(WireError::LimitExceeded)
        );
        assert_eq!(
            EntityAddrVec::decode(
                &mut Decoder::new(&[2, 0xff, 0xff, 0xff, 0xff], 64),
                u32::MAX,
            ),
            Err(WireError::Malformed)
        );
    }
}
