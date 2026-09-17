mod address;
mod errno;
mod features;

#[cfg(test)]
mod tests {
    use super::address::{EntityAddr, EntityAddrVec};
    use super::features::GlobalFeatures;
    use crate::wire::{Decoder, Encoder};

    #[test]
    fn all_native_p01_addresses_round_trip() {
        for fixture in [
            include_bytes!("../../testdata/p01/entity-addr-ipv4-legacy.bin").as_slice(),
            include_bytes!("../../testdata/p01/entity-addr-ipv4-modern.bin").as_slice(),
            include_bytes!("../../testdata/p01/entity-addr-ipv6-modern.bin").as_slice(),
        ] {
            let mut decoder = Decoder::new(fixture, 256);
            let address = EntityAddr::decode(&mut decoder).expect("fixture address");
            assert_eq!(decoder.remaining(), 0);
            let mut encoder = Encoder::new(256);
            address
                .encode(&mut encoder, address.encoding_features())
                .expect("encode fixture address");
            assert_eq!(encoder.finish().expect("encoded address"), fixture);
        }

        let fixture = include_bytes!("../../testdata/p01/entity-addrvec-modern.bin");
        let mut decoder = Decoder::new(fixture, 256);
        let addresses = EntityAddrVec::decode(&mut decoder, 2).expect("fixture address vector");
        assert_eq!(addresses.0.len(), 2);
        let mut encoder = Encoder::new(256);
        addresses
            .encode(&mut encoder, GlobalFeatures::MESSAGE_ADDRESS_V2)
            .expect("encode address vector");
        assert_eq!(encoder.finish().expect("encoded vector"), fixture);
    }
}
