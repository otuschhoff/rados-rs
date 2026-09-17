mod wire {
    pub(crate) mod codec {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../src/wire/codec.rs"));
    }
    pub(crate) use codec::{Decoder, Encoder, WireError};
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
