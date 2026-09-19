use crate::wire::{Decoder, Encoder, WireError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Entry {
    pub(crate) key: Vec<u8>,
    pub(crate) value: Vec<u8>,
}

pub(crate) fn encode_list_request(
    after: &[u8],
    limit: u64,
    max_bytes: usize,
) -> Result<Vec<u8>, WireError> {
    let mut encoder = Encoder::new(max_bytes);
    encoder.bytes(after);
    encoder.u64(limit);
    encoder.bytes(&[]);
    encoder.finish()
}

pub(crate) fn encode_map(
    entries: impl IntoIterator<Item = Entry>,
    max_bytes: usize,
) -> Result<Vec<u8>, WireError> {
    let mut entries = entries.into_iter().collect::<Vec<_>>();
    entries.sort_unstable_by(|left, right| left.key.cmp(&right.key));
    if entries.len() > u32::MAX as usize
        || entries.windows(2).any(|pair| pair[0].key == pair[1].key)
    {
        return Err(WireError::Malformed);
    }
    let mut encoder = Encoder::new(max_bytes);
    encoder.u32(u32::try_from(entries.len()).map_err(|_| WireError::LimitExceeded)?);
    for entry in entries {
        encoder.bytes(&entry.key);
        encoder.bytes(&entry.value);
    }
    encoder.finish()
}

pub(crate) fn encode_keys(
    keys: impl IntoIterator<Item = Vec<u8>>,
    max_bytes: usize,
) -> Result<Vec<u8>, WireError> {
    let mut keys = keys.into_iter().collect::<Vec<_>>();
    keys.sort_unstable();
    if keys.len() > u32::MAX as usize || keys.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(WireError::Malformed);
    }
    let mut encoder = Encoder::new(max_bytes);
    encoder.u32(u32::try_from(keys.len()).map_err(|_| WireError::LimitExceeded)?);
    for key in keys {
        encoder.bytes(&key);
    }
    encoder.finish()
}

pub(crate) fn encode_range(
    begin: &[u8],
    end: &[u8],
    max_bytes: usize,
) -> Result<Vec<u8>, WireError> {
    if begin >= end {
        return Err(WireError::Malformed);
    }
    let mut encoder = Encoder::new(max_bytes);
    encoder.bytes(begin);
    encoder.bytes(end);
    encoder.finish()
}

pub(crate) fn encode_compare(
    key: &[u8],
    value: &[u8],
    comparison: i32,
    max_bytes: usize,
) -> Result<Vec<u8>, WireError> {
    let mut encoder = Encoder::new(max_bytes);
    encoder.u32(1);
    encoder.bytes(key);
    encoder.bytes(value);
    encoder.i32(comparison);
    encoder.finish()
}

pub(crate) fn decode_map(
    data: &[u8],
    max_bytes: usize,
    max_entries: usize,
) -> Result<Vec<Entry>, WireError> {
    let mut decoder = Decoder::new(data, max_bytes);
    let entries = decode_entries(&mut decoder, max_entries)?;
    decoder.finish()?;
    if decoder.remaining() != 0 {
        return Err(WireError::Malformed);
    }
    Ok(entries)
}

pub(crate) fn decode_page(
    data: &[u8],
    max_bytes: usize,
    max_entries: usize,
) -> Result<(Vec<Entry>, bool), WireError> {
    let mut decoder = Decoder::new(data, max_bytes);
    let entries = decode_entries(&mut decoder, max_entries)?;
    let more = decoder.bool();
    decoder.finish()?;
    if decoder.remaining() != 0 {
        return Err(WireError::Malformed);
    }
    Ok((entries, more))
}

fn decode_entries(decoder: &mut Decoder<'_>, max_entries: usize) -> Result<Vec<Entry>, WireError> {
    let count = decoder.u32() as usize;
    decoder.finish()?;
    if count > max_entries || count.saturating_mul(8) > decoder.remaining() {
        return Err(WireError::LimitExceeded);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let entry = Entry {
            key: decoder.bytes(),
            value: decoder.bytes(),
        };
        decoder.finish()?;
        if entries
            .last()
            .is_some_and(|previous: &Entry| previous.key >= entry.key)
        {
            return Err(WireError::Malformed);
        }
        entries.push(entry);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_map_is_binary_sorted_and_owned() {
        let encoded = encode_map(
            [
                Entry {
                    key: vec![0xff],
                    value: vec![3],
                },
                Entry {
                    key: vec![0, b'a'],
                    value: vec![0, 1],
                },
                Entry {
                    key: vec![b'b'],
                    value: vec![2],
                },
            ],
            128,
        )
        .expect("map");
        assert_eq!(
            decode_map(&encoded, 128, 3).expect("decode"),
            vec![
                Entry {
                    key: vec![0, b'a'],
                    value: vec![0, 1]
                },
                Entry {
                    key: vec![b'b'],
                    value: vec![2]
                },
                Entry {
                    key: vec![0xff],
                    value: vec![3]
                },
            ]
        );
    }

    #[test]
    fn duplicate_unordered_and_trailing_metadata_are_rejected() {
        assert_eq!(
            encode_keys([b"same".to_vec(), b"same".to_vec()], 64),
            Err(WireError::Malformed)
        );
        let mut unordered = Encoder::new(64);
        unordered.u32(2);
        unordered.bytes(b"b");
        unordered.bytes(b"1");
        unordered.bytes(b"a");
        unordered.bytes(b"2");
        assert_eq!(
            decode_map(&unordered.finish().expect("bytes"), 64, 2),
            Err(WireError::Malformed)
        );
        let mut trailing = encode_map([], 64).expect("map");
        trailing.push(0);
        assert_eq!(decode_map(&trailing, 64, 1), Err(WireError::Malformed));
    }

    #[test]
    fn list_page_range_compare_and_limits_match_oracle() {
        assert_eq!(
            encode_list_request(b"after", 3, 64).expect("list"),
            b"\x05\0\0\0after\x03\0\0\0\0\0\0\0\0\0\0\0"
        );
        assert_eq!(encode_range(b"z", b"a", 64), Err(WireError::Malformed));
        assert_eq!(
            encode_compare(b"key", b"value", -2, 64).expect("compare"),
            b"\x01\0\0\0\x03\0\0\0key\x05\0\0\0value\xfe\xff\xff\xff"
        );

        let mut page = encode_map(
            [Entry {
                key: b"key".to_vec(),
                value: b"value".to_vec(),
            }],
            64,
        )
        .expect("page");
        page.push(1);
        assert!(decode_page(&page, 64, 1).expect("decode").1);
        assert_eq!(decode_page(&page, 64, 0), Err(WireError::LimitExceeded));
    }
}
