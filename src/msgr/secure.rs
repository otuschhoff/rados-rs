use super::frame::{
    Descriptor, Frame, FrameError, LATE_STATUS_ABORTED, LATE_STATUS_COMPLETE, Limits,
    PREAMBLE_SIZE, Segment, Tag, decode_preamble, encode_preamble, normalized_segments,
    valid_alignment,
};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use std::io::{self, Read};
use tokio::io::{AsyncRead, AsyncReadExt};

const SECRET_SIZE: usize = 64;
const KEY_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: u64 = 16;
const BLOCK_SIZE: u64 = 16;
const BLOCK_SIZE_USIZE: usize = 16;
const INLINE_SIZE: u64 = 48;
const INLINE_SIZE_USIZE: usize = 48;
const SECURE_PREAMBLE_SIZE: u64 = PREAMBLE_SIZE as u64 + INLINE_SIZE + TAG_SIZE;
const SECURE_PREAMBLE_SIZE_USIZE: usize = PREAMBLE_SIZE + INLINE_SIZE_USIZE + 16;

#[derive(Clone)]
pub(crate) struct SecureCodec {
    tx: Direction,
    rx: Direction,
}

pub(crate) struct SecureEncoder(SecureCodec);

pub(crate) struct SecureDecoder(SecureCodec);

#[derive(Clone)]
struct Direction {
    cipher: Aes128Gcm,
    fixed: u32,
    counter: u64,
    exhausted: bool,
}

impl SecureCodec {
    pub(crate) fn new(secret: &[u8], server: bool) -> Result<Self, FrameError> {
        if secret.len() != SECRET_SIZE {
            return Err(FrameError::InvalidSecret);
        }
        let client_rx = &secret[16..28];
        let client_tx = &secret[28..40];
        let (rx_seed, tx_seed) = if server {
            (client_tx, client_rx)
        } else {
            (client_rx, client_tx)
        };
        Ok(Self {
            tx: Direction::new(&secret[..KEY_SIZE], tx_seed)?,
            rx: Direction::new(&secret[..KEY_SIZE], rx_seed)?,
        })
    }

    pub(crate) fn split(self) -> (SecureEncoder, SecureDecoder) {
        let decoder = Self {
            tx: self.tx.clone(),
            rx: self.rx,
        };
        let encoder = Self {
            tx: self.tx,
            rx: decoder.rx.clone(),
        };
        (SecureEncoder(encoder), SecureDecoder(decoder))
    }

    pub(crate) fn encode(&mut self, frame: &Frame, limits: Limits) -> Result<Vec<u8>, FrameError> {
        let prepared = PreparedFrame::new(frame, limits)?;
        if !self.tx.available(prepared.records) {
            return Err(FrameError::CounterExhausted);
        }
        let capacity =
            usize::try_from(prepared.wire_size).map_err(|_| FrameError::LimitExceeded)?;
        let mut output = Vec::with_capacity(capacity);
        for plaintext in prepared.plaintext_records(frame.tag)? {
            output.extend_from_slice(&self.tx.seal(&plaintext)?);
        }
        Ok(output)
    }

    pub(crate) fn encode_with_authenticated_mutation(
        &mut self,
        frame: &Frame,
        limits: Limits,
        offset: usize,
        bit: u8,
    ) -> Result<Vec<u8>, FrameError> {
        let prepared = PreparedFrame::new(frame, limits)?;
        let mut records = prepared.plaintext_records(frame.tag)?;
        let plaintext_size = records.iter().map(Vec::len).sum::<usize>();
        let mut remaining_offset = offset % plaintext_size;
        for record in &mut records {
            if remaining_offset < record.len() {
                record[remaining_offset] ^= 1 << (bit % 8);
                break;
            }
            remaining_offset -= record.len();
        }
        let mut output = Vec::with_capacity(
            usize::try_from(prepared.wire_size).map_err(|_| FrameError::LimitExceeded)?,
        );
        for plaintext in records {
            output.extend_from_slice(&self.tx.seal(&plaintext)?);
        }
        Ok(output)
    }

    pub(crate) fn read(
        &mut self,
        reader: &mut impl Read,
        limits: Limits,
    ) -> Result<Frame, FrameError> {
        if !self.rx.available(1) {
            return Err(FrameError::CounterExhausted);
        }
        if limits.max_frame_bytes < SECURE_PREAMBLE_SIZE {
            return Err(FrameError::LimitExceeded);
        }

        let mut first_ciphertext = vec![0; SECURE_PREAMBLE_SIZE_USIZE];
        read_exact(reader, &mut first_ciphertext)?;
        let first = self.rx.open(&first_ciphertext)?;
        let preamble: [u8; PREAMBLE_SIZE] = first[..PREAMBLE_SIZE]
            .try_into()
            .map_err(|_| FrameError::Malformed)?;
        let (tag, descriptors) = decode_preamble(&preamble)?;
        let (wire_size, records) = validate_descriptors(&descriptors, limits)?;
        if !self.rx.available(records - 1) {
            return Err(FrameError::CounterExhausted);
        }

        let first_padded = padded_length(u64::from(descriptors[0].length))?;
        let first_padded_size =
            usize::try_from(first_padded).map_err(|_| FrameError::LimitExceeded)?;
        let mut first_data = if first_padded > INLINE_SIZE {
            let ciphertext_size = usize::try_from(first_padded - INLINE_SIZE + TAG_SIZE)
                .map_err(|_| FrameError::LimitExceeded)?;
            let mut ciphertext = vec![0; ciphertext_size];
            read_exact(reader, &mut ciphertext)?;
            let remainder = self.rx.open(&ciphertext)?;
            let mut data = vec![0; first_padded_size];
            data[..INLINE_SIZE_USIZE].copy_from_slice(&first[PREAMBLE_SIZE..]);
            data[INLINE_SIZE_USIZE..].copy_from_slice(&remainder);
            data
        } else {
            first[PREAMBLE_SIZE..].to_vec()
        };
        let first_length = descriptors[0].length as usize;
        if !all_zero(&first_data[first_length..]) {
            return Err(FrameError::Malformed);
        }
        first_data.truncate(first_length);
        let mut segments = vec![Segment {
            alignment: descriptors[0].alignment,
            data: first_data,
        }];
        if descriptors.len() == 1 {
            return Ok(Frame { tag, segments });
        }

        let mut remaining_size = wire_size
            .checked_sub(SECURE_PREAMBLE_SIZE)
            .ok_or(FrameError::LimitExceeded)?;
        if first_padded > INLINE_SIZE {
            remaining_size = remaining_size
                .checked_sub(first_padded - INLINE_SIZE + TAG_SIZE)
                .ok_or(FrameError::LimitExceeded)?;
        }
        let mut ciphertext =
            vec![0; usize::try_from(remaining_size).map_err(|_| FrameError::LimitExceeded)?];
        read_exact(reader, &mut ciphertext)?;
        let remaining = self.rx.open(&ciphertext)?;
        let mut offset = 0;
        for descriptor in &descriptors[1..] {
            let logical = descriptor.length as usize;
            let padded = usize::try_from(padded_length(u64::from(descriptor.length))?)
                .map_err(|_| FrameError::LimitExceeded)?;
            if !all_zero(&remaining[offset + logical..offset + padded]) {
                return Err(FrameError::Malformed);
            }
            segments.push(Segment {
                alignment: descriptor.alignment,
                data: remaining[offset..offset + logical].to_vec(),
            });
            offset += padded;
        }
        let epilogue = &remaining[offset..];
        if epilogue.len() != BLOCK_SIZE_USIZE || !all_zero(&epilogue[1..]) {
            return Err(FrameError::Malformed);
        }
        match epilogue[0] & 0x0f {
            LATE_STATUS_COMPLETE => Ok(Frame { tag, segments }),
            LATE_STATUS_ABORTED => Err(FrameError::Aborted),
            _ => Err(FrameError::Malformed),
        }
    }

    pub(crate) async fn read_async(
        &mut self,
        reader: &mut (impl AsyncRead + Unpin),
        limits: Limits,
    ) -> Result<Frame, FrameError> {
        if !self.rx.available(1) {
            return Err(FrameError::CounterExhausted);
        }
        if limits.max_frame_bytes < SECURE_PREAMBLE_SIZE {
            return Err(FrameError::LimitExceeded);
        }

        let mut first_ciphertext = vec![0; SECURE_PREAMBLE_SIZE_USIZE];
        read_exact_async(reader, &mut first_ciphertext).await?;
        let first = self.rx.open(&first_ciphertext)?;
        let preamble: [u8; PREAMBLE_SIZE] = first[..PREAMBLE_SIZE]
            .try_into()
            .map_err(|_| FrameError::Malformed)?;
        let (tag, descriptors) = decode_preamble(&preamble)?;
        let (wire_size, records) = validate_descriptors(&descriptors, limits)?;
        if !self.rx.available(records - 1) {
            return Err(FrameError::CounterExhausted);
        }

        let first_padded = padded_length(u64::from(descriptors[0].length))?;
        let first_padded_size =
            usize::try_from(first_padded).map_err(|_| FrameError::LimitExceeded)?;
        let mut first_data = if first_padded > INLINE_SIZE {
            let ciphertext_size = usize::try_from(first_padded - INLINE_SIZE + TAG_SIZE)
                .map_err(|_| FrameError::LimitExceeded)?;
            let mut ciphertext = vec![0; ciphertext_size];
            read_exact_async(reader, &mut ciphertext).await?;
            let remainder = self.rx.open(&ciphertext)?;
            let mut data = vec![0; first_padded_size];
            data[..INLINE_SIZE_USIZE].copy_from_slice(&first[PREAMBLE_SIZE..]);
            data[INLINE_SIZE_USIZE..].copy_from_slice(&remainder);
            data
        } else {
            first[PREAMBLE_SIZE..].to_vec()
        };
        let first_length = descriptors[0].length as usize;
        if !all_zero(&first_data[first_length..]) {
            return Err(FrameError::Malformed);
        }
        first_data.truncate(first_length);
        let mut segments = vec![Segment {
            alignment: descriptors[0].alignment,
            data: first_data,
        }];
        if descriptors.len() == 1 {
            return Ok(Frame { tag, segments });
        }

        let mut remaining_size = wire_size
            .checked_sub(SECURE_PREAMBLE_SIZE)
            .ok_or(FrameError::LimitExceeded)?;
        if first_padded > INLINE_SIZE {
            remaining_size = remaining_size
                .checked_sub(first_padded - INLINE_SIZE + TAG_SIZE)
                .ok_or(FrameError::LimitExceeded)?;
        }
        let mut ciphertext =
            vec![0; usize::try_from(remaining_size).map_err(|_| FrameError::LimitExceeded)?];
        read_exact_async(reader, &mut ciphertext).await?;
        let remaining = self.rx.open(&ciphertext)?;
        let mut offset = 0;
        for descriptor in &descriptors[1..] {
            let logical = descriptor.length as usize;
            let padded = usize::try_from(padded_length(u64::from(descriptor.length))?)
                .map_err(|_| FrameError::LimitExceeded)?;
            if !all_zero(&remaining[offset + logical..offset + padded]) {
                return Err(FrameError::Malformed);
            }
            segments.push(Segment {
                alignment: descriptor.alignment,
                data: remaining[offset..offset + logical].to_vec(),
            });
            offset += padded;
        }
        let epilogue = &remaining[offset..];
        if epilogue.len() != BLOCK_SIZE_USIZE || !all_zero(&epilogue[1..]) {
            return Err(FrameError::Malformed);
        }
        match epilogue[0] & 0x0f {
            LATE_STATUS_COMPLETE => Ok(Frame { tag, segments }),
            LATE_STATUS_ABORTED => Err(FrameError::Aborted),
            _ => Err(FrameError::Malformed),
        }
    }
}

pub(crate) fn validate_frame_size(frame: &Frame, limits: Limits) -> Result<(), FrameError> {
    PreparedFrame::new(frame, limits).map(|_| ())
}

impl SecureEncoder {
    pub(crate) fn encode(&mut self, frame: &Frame, limits: Limits) -> Result<Vec<u8>, FrameError> {
        self.0.encode(frame, limits)
    }
}

impl SecureDecoder {
    pub(crate) async fn read(
        &mut self,
        reader: &mut (impl AsyncRead + Unpin),
        limits: Limits,
    ) -> Result<Frame, FrameError> {
        self.0.read_async(reader, limits).await
    }
}

impl Direction {
    fn new(key: &[u8], seed: &[u8]) -> Result<Self, FrameError> {
        let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| FrameError::InvalidSecret)?;
        let fixed = u32::from_le_bytes(
            seed[..4]
                .try_into()
                .map_err(|_| FrameError::InvalidSecret)?,
        );
        let counter = u64::from_le_bytes(
            seed[4..]
                .try_into()
                .map_err(|_| FrameError::InvalidSecret)?,
        );
        Ok(Self {
            cipher,
            fixed,
            counter,
            exhausted: false,
        })
    }

    fn available(&self, count: u64) -> bool {
        count == 0 || (!self.exhausted && count - 1 <= u64::MAX.saturating_sub(self.counter))
    }

    fn nonce(&mut self) -> Result<[u8; NONCE_SIZE], FrameError> {
        if !self.available(1) {
            return Err(FrameError::CounterExhausted);
        }
        let mut nonce = [0; NONCE_SIZE];
        nonce[..4].copy_from_slice(&self.fixed.to_le_bytes());
        nonce[4..].copy_from_slice(&self.counter.to_le_bytes());
        if self.counter == u64::MAX {
            self.exhausted = true;
        } else {
            self.counter += 1;
        }
        Ok(nonce)
    }

    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, FrameError> {
        let nonce = self.nonce()?;
        let nonce = Nonce::try_from(nonce.as_slice()).map_err(|_| FrameError::Malformed)?;
        self.cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| FrameError::LimitExceeded)
    }

    fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, FrameError> {
        let nonce = self.nonce()?;
        let nonce = Nonce::try_from(nonce.as_slice()).map_err(|_| FrameError::Malformed)?;
        self.cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| FrameError::Integrity)
    }
}

struct PreparedFrame<'a> {
    descriptors: Vec<Descriptor>,
    segments: &'a [Segment],
    wire_size: u64,
    records: u64,
}

impl<'a> PreparedFrame<'a> {
    fn new(frame: &'a Frame, limits: Limits) -> Result<Self, FrameError> {
        let segments = normalized_segments(&frame.segments)?;
        if frame.tag as u8 > Tag::Ack as u8 {
            return Err(FrameError::Malformed);
        }
        let descriptors = segments
            .iter()
            .map(|segment| {
                if !valid_alignment(segment.alignment) {
                    return Err(FrameError::Malformed);
                }
                Ok(Descriptor {
                    length: u32::try_from(segment.data.len())
                        .map_err(|_| FrameError::LimitExceeded)?,
                    alignment: segment.alignment,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let (wire_size, records) = validate_descriptors(&descriptors, limits)?;
        Ok(Self {
            descriptors,
            segments,
            wire_size,
            records,
        })
    }

    fn plaintext_records(&self, tag: Tag) -> Result<Vec<Vec<u8>>, FrameError> {
        let preamble = encode_preamble(tag, &self.descriptors);
        let mut first = vec![0; PREAMBLE_SIZE + INLINE_SIZE_USIZE];
        first[..PREAMBLE_SIZE].copy_from_slice(&preamble);
        let inline = self.segments[0].data.len().min(INLINE_SIZE_USIZE);
        first[PREAMBLE_SIZE..PREAMBLE_SIZE + inline]
            .copy_from_slice(&self.segments[0].data[..inline]);
        let mut records = vec![first];

        let first_padded = padded_length(self.segments[0].data.len() as u64)?;
        if first_padded > INLINE_SIZE {
            let remainder_size = usize::try_from(first_padded - INLINE_SIZE)
                .map_err(|_| FrameError::LimitExceeded)?;
            let mut remainder = vec![0; remainder_size];
            remainder[..self.segments[0].data.len() - INLINE_SIZE_USIZE]
                .copy_from_slice(&self.segments[0].data[INLINE_SIZE_USIZE..]);
            records.push(remainder);
        }
        if self.segments.len() == 1 {
            return Ok(records);
        }

        let remaining_size = self.segments[1..]
            .iter()
            .try_fold(BLOCK_SIZE, |total, segment| {
                total
                    .checked_add(padded_length(segment.data.len() as u64)?)
                    .ok_or(FrameError::LimitExceeded)
            })?;
        let mut remaining =
            vec![0; usize::try_from(remaining_size).map_err(|_| FrameError::LimitExceeded)?];
        let mut offset = 0;
        for segment in &self.segments[1..] {
            remaining[offset..offset + segment.data.len()].copy_from_slice(&segment.data);
            offset += usize::try_from(padded_length(segment.data.len() as u64)?)
                .map_err(|_| FrameError::LimitExceeded)?;
        }
        remaining[offset] = LATE_STATUS_COMPLETE;
        records.push(remaining);
        Ok(records)
    }
}

fn validate_descriptors(
    descriptors: &[Descriptor],
    limits: Limits,
) -> Result<(u64, u64), FrameError> {
    let mut wire_size = SECURE_PREAMBLE_SIZE;
    let mut records = 1;
    for descriptor in descriptors {
        if !valid_alignment(descriptor.alignment) {
            return Err(FrameError::Malformed);
        }
        if descriptor.length > limits.max_segment_bytes {
            return Err(FrameError::LimitExceeded);
        }
    }
    let first_padded = padded_length(u64::from(descriptors[0].length))?;
    if first_padded > INLINE_SIZE {
        wire_size = wire_size
            .checked_add(first_padded - INLINE_SIZE + TAG_SIZE)
            .ok_or(FrameError::LimitExceeded)?;
        records += 1;
    }
    if descriptors.len() > 1 {
        wire_size = wire_size
            .checked_add(BLOCK_SIZE + TAG_SIZE)
            .ok_or(FrameError::LimitExceeded)?;
        for descriptor in &descriptors[1..] {
            wire_size = wire_size
                .checked_add(padded_length(u64::from(descriptor.length))?)
                .ok_or(FrameError::LimitExceeded)?;
        }
        records += 1;
    }
    if wire_size > limits.max_frame_bytes || usize::try_from(wire_size).is_err() {
        return Err(FrameError::LimitExceeded);
    }
    Ok((wire_size, records))
}

fn padded_length(length: u64) -> Result<u64, FrameError> {
    length
        .checked_add(BLOCK_SIZE - 1)
        .map(|value| value & !(BLOCK_SIZE - 1))
        .ok_or(FrameError::LimitExceeded)
}

fn all_zero(data: &[u8]) -> bool {
    data.iter().all(|value| *value == 0)
}

fn read_exact(reader: &mut impl Read, output: &mut [u8]) -> Result<(), FrameError> {
    reader
        .read_exact(output)
        .map_err(|error| match error.kind() {
            io::ErrorKind::OutOfMemory => FrameError::LimitExceeded,
            _ => FrameError::Malformed,
        })
}

async fn read_exact_async(
    reader: &mut (impl AsyncRead + Unpin),
    output: &mut [u8],
) -> Result<(), FrameError> {
    reader
        .read_exact(output)
        .await
        .map(|_| ())
        .map_err(|error| match error.kind() {
            io::ErrorKind::OutOfMemory => FrameError::LimitExceeded,
            _ => FrameError::Malformed,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgr::frame::{DEFAULT_ALIGNMENT, PAGE_ALIGNMENT};
    use std::io::Cursor;

    const TEST_LIMITS: Limits = Limits {
        max_segment_bytes: 4096,
        max_frame_bytes: 8192,
        max_addresses: 64,
        max_auth_bytes: 4096,
    };

    #[test]
    fn deterministic_vector_matches_go() {
        let mut codec = SecureCodec::new(&test_secret(), false).expect("valid codec");
        let frame = Frame {
            tag: Tag::Ack,
            segments: vec![Segment {
                alignment: DEFAULT_ALIGNMENT,
                data: b"ceph".to_vec(),
            }],
        };
        let expected = hex_bytes(
            "4de81a477793cc7cbb381480b30cc69431dabdf879b50b483d403cfd7520cf9d25a34695d34ff7965036a3b4f02908ecd7f8cc4f2688a28ab01f761aeee6fdba01654a9d4a848c689172d4521fcf810804495e6587c7f08a8c5bc025ec8d1369",
        );
        assert_eq!(codec.encode(&frame, TEST_LIMITS), Ok(expected));
    }

    #[test]
    fn round_trip_uses_crossed_directions() {
        let secret = test_secret();
        let mut client = SecureCodec::new(&secret, false).expect("client codec");
        let mut server = SecureCodec::new(&secret, true).expect("server codec");
        let frame = Frame {
            tag: Tag::Message,
            segments: vec![
                Segment {
                    alignment: DEFAULT_ALIGNMENT,
                    data: vec![0x5a; 63],
                },
                Segment {
                    alignment: PAGE_ALIGNMENT,
                    data: Vec::new(),
                },
                Segment {
                    alignment: DEFAULT_ALIGNMENT,
                    data: b"middle".to_vec(),
                },
            ],
        };
        let wire = client.encode(&frame, TEST_LIMITS).expect("encode request");
        assert_eq!(wire.len(), 176);
        assert_eq!(
            server.read(&mut OneByteReader(wire), TEST_LIMITS),
            Ok(frame)
        );

        let reply = Frame {
            tag: Tag::Keepalive2Ack,
            segments: vec![Segment {
                alignment: DEFAULT_ALIGNMENT,
                data: b"reply".to_vec(),
            }],
        };
        let wire = server.encode(&reply, TEST_LIMITS).expect("encode reply");
        assert_eq!(client.read(&mut Cursor::new(wire), TEST_LIMITS), Ok(reply));
    }

    #[test]
    fn corrupt_authentication_tags_are_rejected() {
        let secret = test_secret();
        let frame = Frame {
            tag: Tag::Message,
            segments: vec![
                Segment {
                    alignment: DEFAULT_ALIGNMENT,
                    data: vec![1; 49],
                },
                Segment {
                    alignment: DEFAULT_ALIGNMENT,
                    data: b"tail".to_vec(),
                },
            ],
        };
        let mut client = SecureCodec::new(&secret, false).expect("client codec");
        let wire = client.encode(&frame, TEST_LIMITS).expect("encode");
        for offset in [
            SECURE_PREAMBLE_SIZE_USIZE - 1,
            SECURE_PREAMBLE_SIZE_USIZE + 31,
            wire.len() - 1,
        ] {
            let mut corrupt = wire.clone();
            corrupt[offset] ^= 0x80;
            let mut server = SecureCodec::new(&secret, true).expect("server codec");
            assert_eq!(
                server.read(&mut Cursor::new(corrupt), TEST_LIMITS),
                Err(FrameError::Integrity)
            );
        }
    }

    #[test]
    fn authentication_failure_consumes_rx_nonce() {
        let mut secret = test_secret();
        secret[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        let frame = empty_ack();
        let mut client = SecureCodec::new(&secret, false).expect("client codec");
        let mut wire = client.encode(&frame, TEST_LIMITS).expect("encode");
        *wire.last_mut().expect("authentication tag") ^= 0x80;
        let mut server = SecureCodec::new(&secret, true).expect("server codec");
        assert_eq!(
            server.read(&mut Cursor::new(wire), TEST_LIMITS),
            Err(FrameError::Integrity)
        );
        assert_eq!(
            server.read(&mut Cursor::new([]), TEST_LIMITS),
            Err(FrameError::CounterExhausted)
        );
    }

    #[test]
    fn authenticated_padding_and_status_are_checked() {
        let secret = test_secret();
        for (tag, descriptor) in [
            (
                Tag::CompressionRequest,
                Descriptor {
                    length: 0,
                    alignment: DEFAULT_ALIGNMENT,
                },
            ),
            (
                Tag::CompressionDone,
                Descriptor {
                    length: 0,
                    alignment: DEFAULT_ALIGNMENT,
                },
            ),
            (
                Tag::Ack,
                Descriptor {
                    length: 0,
                    alignment: 3,
                },
            ),
        ] {
            let mut first = vec![0; PREAMBLE_SIZE + INLINE_SIZE_USIZE];
            first[..PREAMBLE_SIZE].copy_from_slice(&encode_preamble(tag, &[descriptor]));
            let mut client = SecureCodec::new(&secret, false).expect("client codec");
            let wire = client.tx.seal(&first).expect("seal");
            let mut server = SecureCodec::new(&secret, true).expect("server codec");
            assert_eq!(
                server.read(&mut Cursor::new(wire), TEST_LIMITS),
                Err(FrameError::Malformed)
            );
        }

        let descriptor = Descriptor {
            length: 1,
            alignment: DEFAULT_ALIGNMENT,
        };
        let mut first = vec![0; PREAMBLE_SIZE + INLINE_SIZE_USIZE];
        first[..PREAMBLE_SIZE].copy_from_slice(&encode_preamble(Tag::Ack, &[descriptor]));
        first[PREAMBLE_SIZE + 1] = 1;
        let mut client = SecureCodec::new(&secret, false).expect("client codec");
        let wire = client.tx.seal(&first).expect("seal");
        let mut server = SecureCodec::new(&secret, true).expect("server codec");
        assert_eq!(
            server.read(&mut Cursor::new(wire), TEST_LIMITS),
            Err(FrameError::Malformed)
        );

        for (status, nonzero_padding) in [(0x02, false), (LATE_STATUS_COMPLETE, true)] {
            let mut client = SecureCodec::new(&secret, false).expect("client codec");
            let descriptors = [
                Descriptor {
                    length: 0,
                    alignment: DEFAULT_ALIGNMENT,
                },
                Descriptor {
                    length: 1,
                    alignment: DEFAULT_ALIGNMENT,
                },
            ];
            let mut first = vec![0; PREAMBLE_SIZE + INLINE_SIZE_USIZE];
            first[..PREAMBLE_SIZE].copy_from_slice(&encode_preamble(Tag::Message, &descriptors));
            let mut wire = client.tx.seal(&first).expect("seal preamble");
            let mut remaining = vec![0; 2 * BLOCK_SIZE_USIZE];
            remaining[0] = 7;
            remaining[BLOCK_SIZE_USIZE] = status;
            if nonzero_padding {
                remaining[BLOCK_SIZE_USIZE + 1] = 1;
            }
            wire.extend_from_slice(&client.tx.seal(&remaining).expect("seal remaining"));
            let mut server = SecureCodec::new(&secret, true).expect("server codec");
            assert_eq!(
                server.read(&mut Cursor::new(wire), TEST_LIMITS),
                Err(FrameError::Malformed)
            );
        }

        let mut client = SecureCodec::new(&secret, false).expect("client codec");
        let descriptors = [
            Descriptor {
                length: 0,
                alignment: DEFAULT_ALIGNMENT,
            },
            Descriptor {
                length: 1,
                alignment: DEFAULT_ALIGNMENT,
            },
        ];
        let mut first = vec![0; PREAMBLE_SIZE + INLINE_SIZE_USIZE];
        first[..PREAMBLE_SIZE].copy_from_slice(&encode_preamble(Tag::Message, &descriptors));
        let mut wire = client.tx.seal(&first).expect("seal preamble");
        let mut remaining = vec![0; 2 * BLOCK_SIZE_USIZE];
        remaining[0] = 7;
        remaining[1] = 1;
        remaining[BLOCK_SIZE_USIZE] = LATE_STATUS_COMPLETE;
        wire.extend_from_slice(&client.tx.seal(&remaining).expect("seal remaining"));
        let mut server = SecureCodec::new(&secret, true).expect("server codec");
        assert_eq!(
            server.read(&mut Cursor::new(wire), TEST_LIMITS),
            Err(FrameError::Malformed)
        );
    }

    #[test]
    fn limits_are_checked_before_variable_payload() {
        let secret = test_secret();
        let descriptor = Descriptor {
            length: 2048,
            alignment: DEFAULT_ALIGNMENT,
        };
        let mut first = vec![0; PREAMBLE_SIZE + INLINE_SIZE_USIZE];
        first[..PREAMBLE_SIZE].copy_from_slice(&encode_preamble(Tag::Message, &[descriptor]));
        let mut client = SecureCodec::new(&secret, false).expect("client codec");
        let wire = client.tx.seal(&first).expect("seal");
        for limits in [
            Limits {
                max_segment_bytes: 1024,
                ..TEST_LIMITS
            },
            Limits {
                max_frame_bytes: 100,
                ..TEST_LIMITS
            },
        ] {
            let mut server = SecureCodec::new(&secret, true).expect("server codec");
            assert_eq!(
                server.read(&mut Cursor::new(&wire), limits),
                Err(FrameError::LimitExceeded)
            );
        }
    }

    #[test]
    fn tx_and_rx_counters_exhaust_without_partial_tx() {
        let mut secret = test_secret();
        secret[32..40].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
        let mut client = SecureCodec::new(&secret, false).expect("client codec");
        let mut server = SecureCodec::new(&secret, true).expect("server codec");
        let frame = empty_ack();
        for _ in 0..2 {
            let wire = client.encode(&frame, TEST_LIMITS).expect("encode");
            assert_eq!(
                server.read(&mut Cursor::new(wire), TEST_LIMITS),
                Ok(frame.clone())
            );
        }
        assert_eq!(
            client.encode(&frame, TEST_LIMITS),
            Err(FrameError::CounterExhausted)
        );
        assert_eq!(
            server.read(&mut Cursor::new([]), TEST_LIMITS),
            Err(FrameError::CounterExhausted)
        );

        let mut client = SecureCodec::new(&secret, false).expect("client codec");
        let multi_record = Frame {
            tag: Tag::Message,
            segments: vec![
                Segment {
                    alignment: DEFAULT_ALIGNMENT,
                    data: vec![1; 49],
                },
                Segment {
                    alignment: DEFAULT_ALIGNMENT,
                    data: vec![2],
                },
            ],
        };
        assert_eq!(
            client.encode(&multi_record, TEST_LIMITS),
            Err(FrameError::CounterExhausted)
        );
        assert!(client.encode(&frame, TEST_LIMITS).is_ok());
    }

    #[test]
    fn secret_must_be_exactly_64_bytes() {
        assert!(matches!(
            SecureCodec::new(&[0; 63], false),
            Err(FrameError::InvalidSecret)
        ));
        assert!(matches!(
            SecureCodec::new(&[0; 65], false),
            Err(FrameError::InvalidSecret)
        ));
    }

    fn empty_ack() -> Frame {
        Frame {
            tag: Tag::Ack,
            segments: vec![Segment {
                alignment: DEFAULT_ALIGNMENT,
                data: Vec::new(),
            }],
        }
    }

    fn test_secret() -> [u8; SECRET_SIZE] {
        std::array::from_fn(|index| u8::try_from(index).expect("64-byte secret index"))
    }

    fn hex_bytes(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("hex text");
                u8::from_str_radix(text, 16).expect("hex byte")
            })
            .collect()
    }

    struct OneByteReader(Vec<u8>);

    impl Read for OneByteReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            if self.0.is_empty() {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "end"));
            }
            output[0] = self.0.remove(0);
            Ok(1)
        }
    }
}
