//! Hidden qualification adapters for R06 fuzzing.

use std::collections::HashMap;

use crate::crush::{self, DecodeLimits, Map};
use crate::maps::{self, OSDRemap, PG};

const MAX_CRUSH_BYTES: u32 = 1 << 20;
const MAX_OSDS: usize = 64;

const DECODE_LIMITS: DecodeLimits = DecodeLimits {
    max_bytes: MAX_CRUSH_BYTES,
    max_buckets: 1_024,
    max_rules: 256,
    max_items: 65_536,
    max_names: 65_536,
};

/// Feeds bounded arbitrary bytes to the production CRUSH map decoder.
pub fn fuzz_crush_decode(data: &[u8]) {
    if data.len() > MAX_CRUSH_BYTES as usize {
        return;
    }
    drop(Map::decode(data, DECODE_LIMITS));
}

/// Decodes a CRUSH map and places arbitrary seeds, replicas, rules, and weights.
pub fn fuzz_crush_place(data: &[u8]) {
    if data.len() > MAX_CRUSH_BYTES as usize {
        return;
    }
    let Some((control, map_data)) = data.split_at_checked(10) else {
        return;
    };
    let rule = u32::from_le_bytes(control[0..4].try_into().expect("fixed control"));
    let seed = u32::from_le_bytes(control[4..8].try_into().expect("fixed control"));
    let replicas = usize::from(control[8] % 64) + 1;
    let weight_count = usize::from(control[9] % u8::try_from(MAX_OSDS).expect("bound fits")) + 1;
    let Some((weight_bytes, map_data)) = map_data.split_at_checked(weight_count * 2) else {
        return;
    };
    let weights = weight_bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|bytes| u32::from(u16::from_le_bytes([bytes[0], bytes[1]])) * 2)
        .collect::<Vec<_>>();
    let Ok(map) = Map::decode(map_data, DECODE_LIMITS) else {
        return;
    };
    drop(map.place(rule, seed, replicas, &weights));
}

/// Hashes arbitrary object identity bytes and maps the hash to a stable PG.
pub fn fuzz_object_mapping(data: &[u8]) {
    if data.len() > MAX_CRUSH_BYTES as usize {
        return;
    }
    let Some((control, identity)) = data.split_at_checked(10) else {
        return;
    };
    let object_length = usize::from(u16::from_le_bytes([control[0], control[1]]));
    let namespace_length = usize::from(u16::from_le_bytes([control[2], control[3]]));
    let locator_length = usize::from(u16::from_le_bytes([control[4], control[5]]));
    let pg_count = u32::from_le_bytes(control[6..10].try_into().expect("fixed control"));
    let Some((object, remainder)) = identity.split_at_checked(object_length.min(identity.len()))
    else {
        return;
    };
    let Some((namespace, remainder)) =
        remainder.split_at_checked(namespace_length.min(remainder.len()))
    else {
        return;
    };
    let locator = &remainder[..locator_length.min(remainder.len())];
    let hash = crush::object_hash(object, locator, namespace);
    let _ = crush::stable_mod(hash, pg_count);
}

/// Exercises production object placement and PG override handling on a decoded CRUSH map.
pub fn fuzz_osdmap_place_object(data: &[u8]) {
    if data.len() > MAX_CRUSH_BYTES as usize {
        return;
    }
    let Some((control, map_data)) = data.split_at_checked(32) else {
        return;
    };
    let pg_count = u32::from_le_bytes(control[0..4].try_into().expect("fixed control"));
    if pg_count == 0 {
        return;
    }
    let weights = control[4..12]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|bytes| u32::from(u16::from_le_bytes([bytes[0], bytes[1]])) * 2)
        .collect::<Vec<_>>();
    let object_length = usize::from(control[12]);
    let namespace_length = usize::from(control[13]);
    let locator_length = usize::from(control[14]);
    let identity_length = object_length
        .saturating_add(namespace_length)
        .saturating_add(locator_length)
        .min(17);
    let identity = &control[15..15 + identity_length];
    let object_end = object_length.min(identity.len());
    let namespace_end = object_end
        .saturating_add(namespace_length)
        .min(identity.len());
    let locator_end = namespace_end
        .saturating_add(locator_length)
        .min(identity.len());
    let object = &identity[..object_end];
    let namespace = &identity[object_end..namespace_end];
    let locator = &identity[namespace_end..locator_end];

    let hash = crush::object_hash(object, locator, namespace);
    let pg = PG {
        pool: 1,
        seed: crush::stable_mod(hash, pg_count),
        preferred: -1,
    };
    let remaps = HashMap::from([(
        pg,
        vec![OSDRemap {
            from: i32::from(control[30] % 4),
            to: i32::from(control[31] % 4),
        }],
    )]);
    let osd_map = maps::r06_osd_map(
        map_data.to_vec(),
        control[29] % 3,
        pg_count,
        weights,
        remaps,
    );
    drop(osd_map.place_object(1, object, locator, namespace));
}
