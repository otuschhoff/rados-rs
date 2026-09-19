use crate::wire::{Decoder, Encoder, WireError};

use super::backoff::{HObject, decode_hobject, encode_hobject};
use super::messages::Operation;

pub(crate) const CURSOR_MAX_BYTES: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ListEntry {
    pub(crate) namespace: Vec<u8>,
    pub(crate) object: Vec<u8>,
    pub(crate) locator: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ListPage {
    pub(crate) next: HObject,
    pub(crate) entries: Vec<ListEntry>,
}

pub(crate) fn encode_operation(
    cursor: &HObject,
    count: u64,
    start_epoch: u32,
    max_bytes: usize,
) -> Result<Operation, WireError> {
    if count == 0 {
        return Err(WireError::Malformed);
    }
    let mut encoder = Encoder::new(max_bytes);
    encode_hobject(&mut encoder, cursor);
    Ok(Operation::PGNList {
        cursor: encoder.finish()?,
        cursor_hash: cursor.hash,
        count,
        start_epoch,
    })
}

pub(crate) fn decode_page(
    data: &[u8],
    max_bytes: usize,
    max_entries: usize,
) -> Result<ListPage, WireError> {
    let mut decoder = Decoder::new(data, max_bytes);
    let (version, mut payload) = decoder.versioned(1);
    decoder.finish()?;
    if version != 1 {
        return Err(WireError::UnsupportedVersion {
            local: 1,
            required: version,
        });
    }
    let next = decode_hobject(&mut payload)?;
    let count = payload.u32() as usize;
    payload.finish()?;
    if count > max_entries || count.saturating_mul(12) > payload.remaining() {
        return Err(WireError::LimitExceeded);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        entries.push(ListEntry {
            namespace: payload.bytes(),
            object: payload.bytes(),
            locator: payload.bytes(),
        });
        payload.finish()?;
    }
    if payload.remaining() != 0 || decoder.remaining() != 0 {
        return Err(WireError::Malformed);
    }
    Ok(ListPage { next, entries })
}

pub(crate) fn marshal_cursor(cursor: &HObject) -> Result<Vec<u8>, WireError> {
    let mut encoder = Encoder::new(CURSOR_MAX_BYTES);
    encode_hobject(&mut encoder, cursor);
    encoder.finish()
}

pub(crate) fn unmarshal_cursor(data: &[u8]) -> Result<HObject, WireError> {
    let mut decoder = Decoder::new(data, CURSOR_MAX_BYTES);
    let cursor = decode_hobject(&mut decoder)?;
    if decoder.remaining() != 0 {
        return Err(WireError::Malformed);
    }
    Ok(cursor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osd::messages::NO_SNAP;

    fn cursor() -> HObject {
        HObject {
            key: vec![0, 0xff],
            object: b"object".to_vec(),
            snapshot: NO_SNAP,
            hash: 0x1234_5678,
            max: false,
            namespace: vec![b'n', 0],
            pool: 7,
        }
    }

    #[test]
    fn pgnls_operation_preserves_cursor_and_union_fields() {
        let operation = encode_operation(&cursor(), 19, 23, 4096).expect("operation");
        let Operation::PGNList {
            cursor: data,
            cursor_hash,
            count,
            start_epoch,
        } = operation
        else {
            panic!("PGNLS operation");
        };
        assert_eq!(cursor_hash, 0x1234_5678);
        assert_eq!((count, start_epoch), (19, 23));
        let mut decoder = Decoder::new(&data, 4096);
        assert_eq!(decode_hobject(&mut decoder).expect("cursor"), cursor());
        assert_eq!(decoder.remaining(), 0);
        assert!(encode_operation(&cursor(), 0, 23, 4096).is_err());
    }

    #[test]
    fn pgnls_page_is_binary_safe_bounded_and_exact() {
        let mut encoder = Encoder::new(4096);
        encoder.versioned(1, 1, |payload| {
            encode_hobject(payload, &cursor());
            payload.u32(2);
            payload.bytes(&[]);
            payload.bytes(&[0, 0xff]);
            payload.bytes(&[]);
            payload.bytes(&[b'n', 0]);
            payload.bytes(b"two");
            payload.bytes(&[0x80]);
        });
        let data = encoder.finish().expect("page");
        let page = decode_page(&data, 4096, 2).expect("decode");
        assert_eq!(page.next, cursor());
        assert_eq!(page.entries[0].object, [0, 0xff]);
        assert_eq!(page.entries[1].namespace, [b'n', 0]);
        assert_eq!(decode_page(&data, 4096, 1), Err(WireError::LimitExceeded));

        let mut trailing = data;
        trailing.push(0);
        assert_eq!(decode_page(&trailing, 4096, 2), Err(WireError::Malformed));
    }
}
