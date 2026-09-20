use std::fmt::Write;

use crate::wire::{Decoder, Encoder, WireError};

use super::messages::Operation;

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub(crate) struct InconsistentObject {
    pub(crate) object: Vec<u8>,
    pub(crate) namespace: Vec<u8>,
    pub(crate) locator: Vec<u8>,
    pub(crate) snapshot: u64,
    pub(crate) shards: Vec<i32>,
    pub(crate) errors: Vec<String>,
}

pub(crate) fn encode_scrub_list(
    interval: u32,
    start: &InconsistentObject,
    maximum: u64,
    max_bytes: u32,
) -> Result<Operation, WireError> {
    if maximum == 0 || max_bytes == 0 {
        return Err(WireError::LimitExceeded);
    }
    let mut encoder = Encoder::new(max_bytes as usize);
    encoder.versioned(1, 1, |payload| {
        payload.u32(interval);
        payload.u32(0);
        payload.bytes(&start.object);
        payload.bytes(&start.namespace);
        payload.u64(start.snapshot);
        payload.u64(maximum);
    });
    Ok(Operation::ScrubList(encoder.finish()?))
}

pub(crate) fn decode_scrub_list(
    data: &[u8],
    max_bytes: u32,
    max_entries: u32,
) -> Result<(u32, Vec<InconsistentObject>), WireError> {
    if max_bytes == 0 || max_entries == 0 {
        return Err(WireError::LimitExceeded);
    }
    let mut decoder = Decoder::new(data, max_bytes as usize);
    let (version, mut payload) = decoder.versioned(1);
    decoder.finish()?;
    if version != 1 {
        return Err(WireError::UnsupportedVersion {
            local: 1,
            required: version,
        });
    }
    let interval = payload.u32();
    let count = payload.u32();
    if count > max_entries {
        return Err(WireError::LimitExceeded);
    }
    let mut objects = Vec::with_capacity(count as usize);
    for _ in 0..count {
        objects.push(decode_inconsistent_object(
            &payload.bytes(),
            max_bytes,
            max_entries,
        )?);
    }
    payload.finish()?;
    if payload.remaining() != 0 || decoder.remaining() != 0 {
        return Err(WireError::Malformed);
    }
    Ok((interval, objects))
}

#[allow(clippy::too_many_lines)]
fn decode_inconsistent_object(
    data: &[u8],
    max_bytes: u32,
    max_entries: u32,
) -> Result<InconsistentObject, WireError> {
    let mut decoder = Decoder::new(data, max_bytes as usize);
    let (version, mut payload) = decoder.versioned(2);
    decoder.finish()?;
    if version != 2 {
        return Err(WireError::UnsupportedVersion {
            local: 2,
            required: version,
        });
    }
    let object_errors = payload.u64();
    let (object_version, mut object) = payload.versioned(1);
    payload.finish()?;
    if object_version != 1 {
        return Err(WireError::UnsupportedVersion {
            local: 1,
            required: object_version,
        });
    }
    let mut result = InconsistentObject {
        object: object.bytes(),
        namespace: object.bytes(),
        locator: object.bytes(),
        snapshot: object.u64(),
        ..InconsistentObject::default()
    };
    object.finish()?;
    if object.remaining() != 0 {
        return Err(WireError::Malformed);
    }
    payload.u64();
    let shard_count = payload.u32();
    if shard_count > max_entries {
        return Err(WireError::LimitExceeded);
    }
    let mut shard_errors = 0_u64;
    for _ in 0..shard_count {
        let (shard_version, mut shard) = payload.versioned(1);
        payload.finish()?;
        if shard_version != 1 {
            return Err(WireError::UnsupportedVersion {
                local: 1,
                required: shard_version,
            });
        }
        let osd_id = shard.i32();
        shard.i8();
        shard.finish()?;
        if shard.remaining() != 0 {
            return Err(WireError::Malformed);
        }

        let (info_version, mut info) = payload.versioned(3);
        payload.finish()?;
        if info_version != 3 {
            return Err(WireError::UnsupportedVersion {
                local: 3,
                required: info_version,
            });
        }
        let errors = info.u64();
        shard_errors |= errors;
        info.bool();
        if errors & (1 << 1) == 0 {
            let attributes = info.u32();
            if attributes > max_entries {
                return Err(WireError::LimitExceeded);
            }
            for _ in 0..attributes {
                info.bytes();
                info.bytes();
            }
            info.u64();
            info.bool();
            info.u32();
            info.bool();
            info.u32();
            info.bool();
        }
        info.finish()?;
        if info.remaining() != 0 {
            return Err(WireError::Malformed);
        }
        result.shards.push(osd_id);
    }
    shard_errors |= payload.u64();
    payload.finish()?;
    if payload.remaining() != 0 {
        return Err(WireError::Malformed);
    }
    result
        .errors
        .extend(error_names(object_errors, OBJECT_ERROR_NAMES));
    result
        .errors
        .extend(error_names(shard_errors, SHARD_ERROR_NAMES));
    result.shards.sort_unstable();
    result.errors.sort();
    Ok(result)
}

const OBJECT_ERROR_NAMES: &[(u64, &str)] = &[
    (1 << 1, "object_info_inconsistency"),
    (1 << 4, "data_digest_mismatch"),
    (1 << 5, "omap_digest_mismatch"),
    (1 << 6, "size_mismatch"),
    (1 << 7, "attr_value_mismatch"),
    (1 << 8, "attr_name_mismatch"),
    (1 << 9, "snapset_inconsistency"),
    (1 << 10, "hinfo_inconsistency"),
    (1 << 11, "size_too_large"),
];

const SHARD_ERROR_NAMES: &[(u64, &str)] = &[
    (1 << 1, "shard_missing"),
    (1 << 2, "shard_stat_error"),
    (1 << 3, "shard_read_error"),
    (1 << 9, "data_digest_mismatch_info"),
    (1 << 10, "omap_digest_mismatch_info"),
    (1 << 11, "size_mismatch_info"),
    (1 << 12, "shard_ec_hash_mismatch"),
    (1 << 13, "shard_ec_size_mismatch"),
    (1 << 14, "info_missing"),
    (1 << 15, "info_corrupted"),
    (1 << 16, "snapset_missing"),
    (1 << 17, "snapset_corrupted"),
    (1 << 18, "object_size_info_mismatch"),
    (1 << 19, "hinfo_missing"),
    (1 << 20, "hinfo_corrupted"),
];

fn error_names(bits: u64, names: &[(u64, &str)]) -> Vec<String> {
    let mut known = 0_u64;
    let mut result = Vec::with_capacity(names.len());
    for (bit, name) in names {
        known |= *bit;
        if bits & *bit != 0 {
            result.push((*name).to_owned());
        }
    }
    let unknown = bits & !known;
    if unknown != 0 {
        let mut value = String::from("unknown_0x");
        let _ = write!(&mut value, "{unknown:x}");
        result.push(value);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_list_request_and_result_match_frozen_layout() {
        let start = InconsistentObject {
            object: b"before".to_vec(),
            namespace: b"ns".to_vec(),
            snapshot: 9,
            ..InconsistentObject::default()
        };
        let operation = encode_scrub_list(17, &start, 25, 4096).expect("operation");
        let Operation::ScrubList(data) = operation else {
            panic!("scrub list operation");
        };
        let mut request = Decoder::new(&data, 4096);
        let (version, mut payload) = request.versioned(1);
        assert_eq!(version, 1);
        assert_eq!(payload.u32(), 17);
        assert_eq!(payload.u32(), 0);
        assert_eq!(payload.bytes(), b"before");
        assert_eq!(payload.bytes(), b"ns");
        assert_eq!(payload.u64(), 9);
        assert_eq!(payload.u64(), 25);
        payload.finish().expect("request payload");

        let mut item = Encoder::new(4096);
        item.versioned(2, 2, |entry| {
            entry.u64(1 << 4);
            entry.versioned(1, 1, |object| {
                object.bytes(b"broken");
                object.bytes(b"ns");
                object.bytes(b"key");
                object.u64(3);
            });
            entry.u64(8);
            entry.u32(1);
            entry.versioned(1, 1, |shard| {
                shard.i32(4);
                shard.i8(1);
            });
            entry.versioned(3, 3, |info| {
                info.u64(1 << 1);
                info.bool(true);
            });
            entry.u64(1 << 3);
        });
        let encoded_item = item.finish().expect("item");

        let mut result = Encoder::new(4096);
        result.versioned(1, 1, |page| {
            page.u32(18);
            page.u32(1);
            page.bytes(&encoded_item);
        });
        let result = result.finish().expect("result");
        let (interval, objects) = decode_scrub_list(&result, 4096, 8).expect("decode");
        assert_eq!(interval, 18);
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].object, b"broken");
        assert_eq!(objects[0].namespace, b"ns");
        assert_eq!(objects[0].locator, b"key");
        assert_eq!(objects[0].snapshot, 3);
        assert_eq!(objects[0].shards, vec![4]);
        assert_eq!(
            objects[0].errors,
            vec![
                "data_digest_mismatch".to_owned(),
                "shard_missing".to_owned(),
                "shard_read_error".to_owned()
            ]
        );
    }

    #[test]
    fn scrub_list_decode_rejects_malformed_and_overbound_payloads() {
        assert_eq!(decode_scrub_list(&[], 0, 1), Err(WireError::LimitExceeded));
        assert_eq!(decode_scrub_list(&[], 1, 0), Err(WireError::LimitExceeded));

        let mut wrong_version = Encoder::new(128);
        wrong_version.versioned(2, 2, |payload| {
            payload.u32(0);
            payload.u32(0);
        });
        assert!(matches!(
            decode_scrub_list(&wrong_version.finish().expect("bytes"), 128, 4),
            Err(WireError::UnsupportedVersion {
                local: 1,
                required: 2
            })
        ));

        let mut excessive = Encoder::new(128);
        excessive.versioned(1, 1, |payload| {
            payload.u32(0);
            payload.u32(5);
        });
        assert_eq!(
            decode_scrub_list(&excessive.finish().expect("bytes"), 128, 4),
            Err(WireError::LimitExceeded)
        );
    }
}
