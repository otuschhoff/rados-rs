use crate::wire::WireError;
use crate::wire::crc32c;
use std::fmt;
use std::io::{self, Read};
use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) const PREAMBLE_SIZE: usize = 32;
pub(crate) const MAX_SEGMENTS: usize = 4;
pub(crate) const DEFAULT_ALIGNMENT: u16 = 8;
pub(crate) const PAGE_ALIGNMENT: u16 = 4096;
pub(super) const LATE_STATUS_ABORTED: u8 = 0x01;
pub(super) const LATE_STATUS_COMPLETE: u8 = 0x0e;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum Tag {
    Hello = 1,
    AuthRequest = 2,
    AuthBadMethod = 3,
    AuthReplyMore = 4,
    AuthRequestMore = 5,
    AuthDone = 6,
    AuthSignature = 7,
    ClientIdent = 8,
    ServerIdent = 9,
    IdentMissingFeatures = 10,
    SessionReconnect = 11,
    SessionReset = 12,
    SessionRetry = 13,
    SessionRetryGlobal = 14,
    SessionReconnectOk = 15,
    Wait = 16,
    Message = 17,
    Keepalive2 = 18,
    Keepalive2Ack = 19,
    Ack = 20,
    CompressionRequest = 21,
    CompressionDone = 22,
}

impl TryFrom<u8> for Tag {
    type Error = FrameError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Hello),
            2 => Ok(Self::AuthRequest),
            3 => Ok(Self::AuthBadMethod),
            4 => Ok(Self::AuthReplyMore),
            5 => Ok(Self::AuthRequestMore),
            6 => Ok(Self::AuthDone),
            7 => Ok(Self::AuthSignature),
            8 => Ok(Self::ClientIdent),
            9 => Ok(Self::ServerIdent),
            10 => Ok(Self::IdentMissingFeatures),
            11 => Ok(Self::SessionReconnect),
            12 => Ok(Self::SessionReset),
            13 => Ok(Self::SessionRetry),
            14 => Ok(Self::SessionRetryGlobal),
            15 => Ok(Self::SessionReconnectOk),
            16 => Ok(Self::Wait),
            17 => Ok(Self::Message),
            18 => Ok(Self::Keepalive2),
            19 => Ok(Self::Keepalive2Ack),
            20 => Ok(Self::Ack),
            21 => Ok(Self::CompressionRequest),
            22 => Ok(Self::CompressionDone),
            _ => Err(FrameError::Malformed),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::struct_field_names)]
pub(crate) struct Limits {
    pub(crate) max_segment_bytes: u32,
    pub(crate) max_frame_bytes: u64,
    pub(crate) max_addresses: u32,
    pub(crate) max_auth_bytes: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Segment {
    pub(crate) alignment: u16,
    pub(crate) data: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Frame {
    pub(crate) tag: Tag,
    pub(crate) segments: Vec<Segment>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameError {
    Aborted,
    CounterExhausted,
    Integrity,
    InvalidSecret,
    LimitExceeded,
    Malformed,
    UnsupportedFeature,
    UnsupportedPayload,
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Aborted => "messenger frame aborted",
            Self::CounterExhausted => "messenger secure counter exhausted",
            Self::Integrity => "messenger integrity check failed",
            Self::InvalidSecret => "invalid messenger secure secret",
            Self::LimitExceeded => "messenger limit exceeded",
            Self::Malformed => "malformed messenger data",
            Self::UnsupportedFeature => "unsupported messenger feature",
            Self::UnsupportedPayload => "unsupported messenger payload",
        })
    }
}

impl std::error::Error for FrameError {}

impl From<WireError> for FrameError {
    fn from(error: WireError) -> Self {
        match error {
            WireError::LimitExceeded => Self::LimitExceeded,
            WireError::Malformed | WireError::UnsupportedVersion { .. } => Self::Malformed,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Descriptor {
    pub(super) length: u32,
    pub(super) alignment: u16,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CrcCodec {
    pub(crate) with_data_crc: bool,
}

impl CrcCodec {
    pub(crate) fn encode(self, frame: &Frame, limits: Limits) -> Result<Vec<u8>, FrameError> {
        let segments = normalized_segments(&frame.segments)?;
        if frame.tag as u8 > Tag::Ack as u8 {
            return Err(FrameError::Malformed);
        }
        let (descriptors, total) = descriptors_and_crc_size(segments, limits)?;
        let mut output = Vec::with_capacity(total);
        output.extend_from_slice(&encode_preamble(frame.tag, &descriptors));
        for (index, segment) in segments.iter().enumerate() {
            output.extend_from_slice(&segment.data);
            if index == 0 && !segment.data.is_empty() {
                let checksum = if self.with_data_crc {
                    crc32c(u32::MAX, &segment.data)
                } else {
                    0
                };
                output.extend_from_slice(&checksum.to_le_bytes());
            }
        }
        if segments.len() > 1 {
            output.push(LATE_STATUS_COMPLETE);
            for index in 1..MAX_SEGMENTS {
                let checksum = if self.with_data_crc && index < segments.len() {
                    crc32c(u32::MAX, &segments[index].data)
                } else {
                    0
                };
                output.extend_from_slice(&checksum.to_le_bytes());
            }
        }
        Ok(output)
    }

    pub(crate) fn read(self, reader: &mut impl Read, limits: Limits) -> Result<Frame, FrameError> {
        let mut preamble = [0_u8; PREAMBLE_SIZE];
        read_exact(reader, &mut preamble)?;
        let (tag, descriptors) = decode_preamble(&preamble)?;
        descriptors_and_crc_size_from_descriptors(&descriptors, limits)?;

        let mut segments = Vec::with_capacity(descriptors.len());
        for (index, descriptor) in descriptors.iter().enumerate() {
            let length =
                usize::try_from(descriptor.length).map_err(|_| FrameError::LimitExceeded)?;
            let mut data = vec![0; length];
            read_exact(reader, &mut data)?;
            if index == 0 && length > 0 {
                let mut encoded = [0; 4];
                read_exact(reader, &mut encoded)?;
                if self.with_data_crc && crc32c(u32::MAX, &data) != u32::from_le_bytes(encoded) {
                    return Err(FrameError::Integrity);
                }
            }
            segments.push(Segment {
                alignment: descriptor.alignment,
                data,
            });
        }
        if descriptors.len() > 1 {
            let mut epilogue = [0; 13];
            read_exact(reader, &mut epilogue)?;
            match epilogue[0] & 0x0f {
                LATE_STATUS_COMPLETE => {}
                LATE_STATUS_ABORTED => return Err(FrameError::Aborted),
                _ => return Err(FrameError::Malformed),
            }
            for (index, segment) in segments.iter().enumerate().take(descriptors.len()).skip(1) {
                let offset = 1 + (index - 1) * 4;
                let encoded = u32::from_le_bytes(
                    epilogue[offset..offset + 4]
                        .try_into()
                        .map_err(|_| FrameError::Malformed)?,
                );
                if self.with_data_crc && crc32c(u32::MAX, &segment.data) != encoded {
                    return Err(FrameError::Integrity);
                }
            }
        }
        Ok(Frame { tag, segments })
    }

    pub(crate) async fn read_async(
        self,
        reader: &mut (impl AsyncRead + Unpin),
        limits: Limits,
    ) -> Result<Frame, FrameError> {
        let mut preamble = [0_u8; PREAMBLE_SIZE];
        read_exact_async(reader, &mut preamble).await?;
        let (tag, descriptors) = decode_preamble(&preamble)?;
        descriptors_and_crc_size_from_descriptors(&descriptors, limits)?;

        let mut segments = Vec::with_capacity(descriptors.len());
        for (index, descriptor) in descriptors.iter().enumerate() {
            let length =
                usize::try_from(descriptor.length).map_err(|_| FrameError::LimitExceeded)?;
            let mut data = vec![0; length];
            read_exact_async(reader, &mut data).await?;
            if index == 0 && length > 0 {
                let mut encoded = [0; 4];
                read_exact_async(reader, &mut encoded).await?;
                if self.with_data_crc && crc32c(u32::MAX, &data) != u32::from_le_bytes(encoded) {
                    return Err(FrameError::Integrity);
                }
            }
            segments.push(Segment {
                alignment: descriptor.alignment,
                data,
            });
        }
        if descriptors.len() > 1 {
            let mut epilogue = [0; 13];
            read_exact_async(reader, &mut epilogue).await?;
            match epilogue[0] & 0x0f {
                LATE_STATUS_COMPLETE => {}
                LATE_STATUS_ABORTED => return Err(FrameError::Aborted),
                _ => return Err(FrameError::Malformed),
            }
            for (index, segment) in segments.iter().enumerate().take(descriptors.len()).skip(1) {
                let offset = 1 + (index - 1) * 4;
                let encoded = u32::from_le_bytes(
                    epilogue[offset..offset + 4]
                        .try_into()
                        .map_err(|_| FrameError::Malformed)?,
                );
                if self.with_data_crc && crc32c(u32::MAX, &segment.data) != encoded {
                    return Err(FrameError::Integrity);
                }
            }
        }
        Ok(Frame { tag, segments })
    }
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

fn read_exact(reader: &mut impl Read, output: &mut [u8]) -> Result<(), FrameError> {
    reader
        .read_exact(output)
        .map_err(|error| match error.kind() {
            io::ErrorKind::OutOfMemory => FrameError::LimitExceeded,
            _ => FrameError::Malformed,
        })
}

pub(super) fn normalized_segments(segments: &[Segment]) -> Result<&[Segment], FrameError> {
    if segments.is_empty() || segments.len() > MAX_SEGMENTS {
        return Err(FrameError::Malformed);
    }
    let mut end = segments.len();
    while end > 1 && segments[end - 1].data.is_empty() {
        end -= 1;
    }
    Ok(&segments[..end])
}

fn descriptors_and_crc_size(
    segments: &[Segment],
    limits: Limits,
) -> Result<(Vec<Descriptor>, usize), FrameError> {
    let descriptors = segments
        .iter()
        .map(|segment| {
            Ok(Descriptor {
                length: u32::try_from(segment.data.len()).map_err(|_| FrameError::LimitExceeded)?,
                alignment: segment.alignment,
            })
        })
        .collect::<Result<Vec<_>, FrameError>>()?;
    let total = descriptors_and_crc_size_from_descriptors(&descriptors, limits)?;
    Ok((descriptors, total))
}

fn descriptors_and_crc_size_from_descriptors(
    descriptors: &[Descriptor],
    limits: Limits,
) -> Result<usize, FrameError> {
    let mut total = u64::try_from(PREAMBLE_SIZE).map_err(|_| FrameError::LimitExceeded)?;
    for (index, descriptor) in descriptors.iter().enumerate() {
        if descriptor.length > limits.max_segment_bytes {
            return Err(FrameError::LimitExceeded);
        }
        if !valid_alignment(descriptor.alignment) {
            return Err(FrameError::Malformed);
        }
        let crc = u64::from(index == 0 && descriptor.length > 0) * 4;
        total = total
            .checked_add(u64::from(descriptor.length))
            .and_then(|value| value.checked_add(crc))
            .ok_or(FrameError::LimitExceeded)?;
    }
    if descriptors.len() > 1 {
        total = total.checked_add(13).ok_or(FrameError::LimitExceeded)?;
    }
    if total > limits.max_frame_bytes {
        return Err(FrameError::LimitExceeded);
    }
    usize::try_from(total).map_err(|_| FrameError::LimitExceeded)
}

pub(super) fn encode_preamble(tag: Tag, descriptors: &[Descriptor]) -> [u8; PREAMBLE_SIZE] {
    let mut preamble = [0; PREAMBLE_SIZE];
    preamble[0] = tag as u8;
    preamble[1] = u8::try_from(descriptors.len()).expect("at most four descriptors");
    for (index, descriptor) in descriptors.iter().enumerate() {
        let offset = 2 + index * 6;
        preamble[offset..offset + 4].copy_from_slice(&descriptor.length.to_le_bytes());
        preamble[offset + 4..offset + 6].copy_from_slice(&descriptor.alignment.to_le_bytes());
    }
    let checksum = crc32c(0, &preamble[..28]);
    preamble[28..].copy_from_slice(&checksum.to_le_bytes());
    preamble
}

pub(super) fn decode_preamble(
    preamble: &[u8; PREAMBLE_SIZE],
) -> Result<(Tag, Vec<Descriptor>), FrameError> {
    let expected = u32::from_le_bytes(
        preamble[28..]
            .try_into()
            .map_err(|_| FrameError::Malformed)?,
    );
    if crc32c(0, &preamble[..28]) != expected {
        return Err(FrameError::Integrity);
    }
    let tag = Tag::try_from(preamble[0])?;
    if tag as u8 > Tag::Ack as u8 {
        return Err(FrameError::Malformed);
    }
    let count = usize::from(preamble[1]);
    if !(1..=MAX_SEGMENTS).contains(&count) || preamble[26] != 0 || preamble[27] != 0 {
        return Err(FrameError::Malformed);
    }
    let mut descriptors = Vec::with_capacity(count);
    for index in 0..MAX_SEGMENTS {
        let offset = 2 + index * 6;
        let descriptor = Descriptor {
            length: u32::from_le_bytes(
                preamble[offset..offset + 4]
                    .try_into()
                    .map_err(|_| FrameError::Malformed)?,
            ),
            alignment: u16::from_le_bytes(
                preamble[offset + 4..offset + 6]
                    .try_into()
                    .map_err(|_| FrameError::Malformed)?,
            ),
        };
        if index < count {
            descriptors.push(descriptor);
        } else if descriptor.length != 0 || descriptor.alignment != 0 {
            return Err(FrameError::Malformed);
        }
    }
    if count > 1 && descriptors[count - 1].length == 0 {
        return Err(FrameError::Malformed);
    }
    Ok((tag, descriptors))
}

pub(super) fn valid_alignment(alignment: u16) -> bool {
    alignment != 0 && alignment.is_power_of_two()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const TEST_LIMITS: Limits = Limits {
        max_segment_bytes: 4096,
        max_frame_bytes: 8192,
        max_addresses: 64,
        max_auth_bytes: 4096,
    };

    #[test]
    fn crc_codec_matches_go_one_segment_vector() {
        let frame = Frame {
            tag: Tag::Ack,
            segments: vec![Segment {
                alignment: DEFAULT_ALIGNMENT,
                data: b"ceph".to_vec(),
            }],
        };
        let expected = hex_bytes(
            "14010400000008000000000000000000000000000000000000000000c6329e8563657068ee24c1e0",
        );
        let codec = CrcCodec {
            with_data_crc: true,
        };
        assert_eq!(codec.encode(&frame, TEST_LIMITS), Ok(expected.clone()));
        assert_eq!(
            codec.read(&mut Cursor::new(expected), TEST_LIMITS),
            Ok(frame)
        );
    }

    #[test]
    fn crc_codec_rejects_corrupt_preamble_before_lengths() {
        let mut wire = hex_bytes(
            "14010400000008000000000000000000000000000000000000000000c6329e8563657068ee24c1e0",
        );
        wire[2] = 0xff;
        assert_eq!(
            CrcCodec {
                with_data_crc: true
            }
            .read(&mut Cursor::new(wire), TEST_LIMITS),
            Err(FrameError::Integrity)
        );
    }

    #[test]
    fn crc_codec_matches_all_go_deterministic_vectors() {
        let one_segment = Frame {
            tag: Tag::Ack,
            segments: vec![Segment {
                alignment: DEFAULT_ALIGNMENT,
                data: b"ceph".to_vec(),
            }],
        };
        let multi_segment = Frame {
            tag: Tag::Message,
            segments: vec![
                Segment {
                    alignment: DEFAULT_ALIGNMENT,
                    data: b"header".to_vec(),
                },
                Segment {
                    alignment: DEFAULT_ALIGNMENT,
                    data: Vec::new(),
                },
                Segment {
                    alignment: DEFAULT_ALIGNMENT,
                    data: b"middle".to_vec(),
                },
                Segment {
                    alignment: PAGE_ALIGNMENT,
                    data: vec![0, 1, 2, 3],
                },
            ],
        };
        let vectors = [
            (
                true,
                &one_segment,
                "14010400000008000000000000000000000000000000000000000000c6329e8563657068ee24c1e0",
            ),
            (
                false,
                &one_segment,
                "14010400000008000000000000000000000000000000000000000000c6329e856365706800000000",
            ),
            (
                true,
                &multi_segment,
                "11040600000008000000000008000600000008000400000000100000a46c0fbf686561646572bd1ea0e36d6964646c65000102030efffffffff29402775ce5cc26",
            ),
            (
                false,
                &multi_segment,
                "11040600000008000000000008000600000008000400000000100000a46c0fbf686561646572000000006d6964646c65000102030e000000000000000000000000",
            ),
        ];
        for (with_data_crc, frame, encoded) in vectors {
            let codec = CrcCodec { with_data_crc };
            let expected = hex_bytes(encoded);
            assert_eq!(codec.encode(frame, TEST_LIMITS), Ok(expected.clone()));
            assert_eq!(
                codec.read(&mut OneByteReader(expected), TEST_LIMITS),
                Ok(frame.clone())
            );
        }
    }

    #[test]
    fn crc_codec_rejects_limits_aborts_and_invalid_shapes() {
        let frame = Frame {
            tag: Tag::Message,
            segments: vec![
                Segment {
                    alignment: DEFAULT_ALIGNMENT,
                    data: Vec::new(),
                },
                Segment {
                    alignment: DEFAULT_ALIGNMENT,
                    data: b"front".to_vec(),
                },
            ],
        };
        let codec = CrcCodec {
            with_data_crc: true,
        };
        let mut wire = codec.encode(&frame, TEST_LIMITS).expect("valid frame");
        assert_eq!(
            codec.read(
                &mut Cursor::new(&wire),
                Limits {
                    max_segment_bytes: 4,
                    ..TEST_LIMITS
                }
            ),
            Err(FrameError::LimitExceeded)
        );
        let status = wire.len() - 13;
        wire[status] = LATE_STATUS_ABORTED;
        assert_eq!(
            codec.read(&mut Cursor::new(wire), TEST_LIMITS),
            Err(FrameError::Aborted)
        );
        assert_eq!(
            codec.encode(
                &Frame {
                    tag: Tag::Ack,
                    segments: vec![Segment {
                        alignment: 0,
                        data: Vec::new()
                    }]
                },
                TEST_LIMITS
            ),
            Err(FrameError::Malformed)
        );
    }

    #[test]
    fn data_crc_compatibility_and_late_status_match_go() {
        let frame = Frame {
            tag: Tag::Message,
            segments: vec![
                Segment {
                    alignment: DEFAULT_ALIGNMENT,
                    data: b"header".to_vec(),
                },
                Segment {
                    alignment: DEFAULT_ALIGNMENT,
                    data: Vec::new(),
                },
                Segment {
                    alignment: DEFAULT_ALIGNMENT,
                    data: b"middle".to_vec(),
                },
            ],
        };
        let enabled = CrcCodec {
            with_data_crc: true,
        };
        let disabled = CrcCodec {
            with_data_crc: false,
        };
        for offset in [PREAMBLE_SIZE, PREAMBLE_SIZE + b"header".len() + 4] {
            let mut wire = enabled.encode(&frame, TEST_LIMITS).expect("valid frame");
            wire[offset] ^= 1;
            assert_eq!(
                enabled.read(&mut Cursor::new(wire), TEST_LIMITS),
                Err(FrameError::Integrity)
            );

            let mut wire = disabled.encode(&frame, TEST_LIMITS).expect("valid frame");
            wire[offset] ^= 1;
            assert!(disabled.read(&mut Cursor::new(wire), TEST_LIMITS).is_ok());
        }

        let mut wire = disabled.encode(&frame, TEST_LIMITS).expect("valid frame");
        let status = wire.len() - 13;
        wire[status] |= 0xf0;
        assert!(disabled.read(&mut Cursor::new(wire), TEST_LIMITS).is_ok());
    }

    #[test]
    fn rejects_every_truncation_and_compression_tags_on_wire() {
        let codec = CrcCodec {
            with_data_crc: true,
        };
        let frame = Frame {
            tag: Tag::Message,
            segments: vec![
                Segment {
                    alignment: DEFAULT_ALIGNMENT,
                    data: b"header".to_vec(),
                },
                Segment {
                    alignment: DEFAULT_ALIGNMENT,
                    data: b"front".to_vec(),
                },
            ],
        };
        let wire = codec.encode(&frame, TEST_LIMITS).expect("valid frame");
        for length in 0..wire.len() {
            assert_eq!(
                codec.read(&mut Cursor::new(&wire[..length]), TEST_LIMITS),
                Err(FrameError::Malformed),
                "truncation at {length} bytes"
            );
        }

        let mut compression = wire;
        compression[0] = Tag::CompressionRequest as u8;
        let checksum = crc32c(0, &compression[..28]);
        compression[28..32].copy_from_slice(&checksum.to_le_bytes());
        assert_eq!(
            codec.read(&mut Cursor::new(compression), TEST_LIMITS),
            Err(FrameError::Malformed)
        );
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
