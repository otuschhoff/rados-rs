use crate::SparseExtent;
use crate::wire::{Decoder, Encoder, WireError};

pub(crate) struct CopySource<'a> {
    pub(crate) object: &'a [u8],
    pub(crate) pool: i64,
    pub(crate) locator: &'a [u8],
    pub(crate) namespace: &'a [u8],
}

pub(crate) fn encode_copy_source(
    source: &CopySource<'_>,
    truncate: Option<(u32, u64)>,
    max_bytes: usize,
) -> Result<Vec<u8>, WireError> {
    if source.object.is_empty() || source.pool < 0 {
        return Err(WireError::Malformed);
    }
    let mut encoder = Encoder::new(max_bytes);
    encoder.bytes(source.object);
    encoder.versioned(6, 3, |locator| {
        locator.i64(source.pool);
        locator.i32(-1);
        locator.bytes(source.locator);
        locator.bytes(source.namespace);
        locator.i64(-1);
    });
    if let Some((sequence, size)) = truncate {
        encoder.u32(sequence);
        encoder.u64(size);
    }
    encoder.finish()
}

pub(crate) fn decode_sparse_read(
    data: &[u8],
    request_offset: u64,
    request_length: u64,
    max_bytes: usize,
    max_extents: usize,
) -> Result<Vec<SparseExtent>, WireError> {
    let request_end = request_offset
        .checked_add(request_length)
        .ok_or(WireError::Malformed)?;
    let mut decoder = Decoder::new(data, max_bytes);
    let count = decoder.u32() as usize;
    decoder.finish()?;
    if count > max_extents || count.saturating_mul(16) > decoder.remaining() {
        return Err(WireError::LimitExceeded);
    }
    let mut ranges = Vec::with_capacity(count);
    let mut total = 0_usize;
    let mut previous_end = request_offset;
    for _ in 0..count {
        let offset = decoder.u64();
        let length = decoder.u64();
        let end = offset.checked_add(length).ok_or(WireError::Malformed)?;
        let length = usize::try_from(length).map_err(|_| WireError::LimitExceeded)?;
        if length == 0 || offset < request_offset || offset < previous_end || end > request_end {
            return Err(WireError::Malformed);
        }
        total = total.checked_add(length).ok_or(WireError::LimitExceeded)?;
        previous_end = end;
        ranges.push((offset, length));
    }
    let bytes = decoder.bytes();
    decoder.finish()?;
    if decoder.remaining() != 0 || bytes.len() != total {
        return Err(WireError::Malformed);
    }
    let mut cursor = 0;
    Ok(ranges
        .into_iter()
        .map(|(offset, length)| {
            let end = cursor + length;
            let extent = SparseExtent {
                offset,
                data: bytes[cursor..end].to_vec(),
            };
            cursor = end;
            extent
        })
        .collect())
}

pub(crate) fn validate_checksum(
    data: &[u8],
    checksum_bytes: usize,
    max_bytes: usize,
) -> Result<(), WireError> {
    let mut decoder = Decoder::new(data, max_bytes);
    let count = decoder.u32() as usize;
    decoder.finish()?;
    let expected = count
        .checked_mul(checksum_bytes)
        .ok_or(WireError::LimitExceeded)?;
    if decoder.remaining() != expected {
        return Err(WireError::Malformed);
    }
    decoder.raw(expected);
    decoder.finish()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_read_is_owned_bounded_and_exact() {
        let mut encoder = Encoder::new(128);
        encoder.u32(2);
        encoder.u64(10);
        encoder.u64(2);
        encoder.u64(15);
        encoder.u64(3);
        encoder.bytes(b"abcde");
        let wire = encoder.finish().expect("sparse result");
        assert_eq!(
            decode_sparse_read(&wire, 10, 10, 128, 2).expect("decode"),
            vec![
                SparseExtent {
                    offset: 10,
                    data: b"ab".to_vec(),
                },
                SparseExtent {
                    offset: 15,
                    data: b"cde".to_vec(),
                },
            ]
        );
        assert_eq!(
            decode_sparse_read(&wire, 10, 10, 128, 1),
            Err(WireError::LimitExceeded)
        );
    }

    #[test]
    fn checksum_count_controls_exact_width() {
        let mut encoder = Encoder::new(32);
        encoder.u32(2);
        encoder.raw(&[1; 8]);
        let wire = encoder.finish().expect("checksum");
        validate_checksum(&wire, 4, 32).expect("checksum");
        assert_eq!(validate_checksum(&wire, 8, 32), Err(WireError::Malformed));
    }
}
