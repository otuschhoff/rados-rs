use super::frame::{DEFAULT_ALIGNMENT, Frame, FrameError, Limits, PAGE_ALIGNMENT, Segment, Tag};
use crate::wire::{Decoder, Encoder};

pub(crate) const MESSAGE_HEADER_SIZE: usize = 41;
const MESSAGE_ALIGNMENTS: [u16; 4] = [
    DEFAULT_ALIGNMENT,
    DEFAULT_ALIGNMENT,
    DEFAULT_ALIGNMENT,
    PAGE_ALIGNMENT,
];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct MessageHeader {
    pub(crate) sequence: u64,
    pub(crate) transaction_id: u64,
    pub(crate) message_type: u16,
    pub(crate) priority: u16,
    pub(crate) version: u16,
    pub(crate) data_pre_padding_length: u32,
    pub(crate) data_offset: u16,
    pub(crate) ack_sequence: u64,
    pub(crate) flags: u8,
    pub(crate) compat_version: u16,
    pub(crate) reserved: u16,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct MessageLengths {
    pub(crate) front: u32,
    pub(crate) middle: u32,
    pub(crate) data: u32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Message {
    pub(crate) header: MessageHeader,
    pub(crate) lengths: MessageLengths,
    pub(crate) front: Vec<u8>,
    pub(crate) middle: Vec<u8>,
    pub(crate) data: Vec<u8>,
}

impl MessageHeader {
    pub(crate) fn encode(self) -> [u8; MESSAGE_HEADER_SIZE] {
        let mut encoder = Encoder::new(MESSAGE_HEADER_SIZE);
        encoder.u64(self.sequence);
        encoder.u64(self.transaction_id);
        encoder.u16(self.message_type);
        encoder.u16(self.priority);
        encoder.u16(self.version);
        encoder.u32(self.data_pre_padding_length);
        encoder.u16(self.data_offset);
        encoder.u64(self.ack_sequence);
        encoder.u8(self.flags);
        encoder.u16(self.compat_version);
        encoder.u16(self.reserved);
        encoder
            .finish()
            .expect("fixed message header must fit")
            .try_into()
            .expect("fixed message header has exact size")
    }

    pub(crate) fn decode(data: &[u8]) -> Result<Self, FrameError> {
        if data.len() != MESSAGE_HEADER_SIZE {
            return Err(FrameError::Malformed);
        }
        let mut decoder = Decoder::new(data, MESSAGE_HEADER_SIZE);
        let header = Self {
            sequence: decoder.u64(),
            transaction_id: decoder.u64(),
            message_type: decoder.u16(),
            priority: decoder.u16(),
            version: decoder.u16(),
            data_pre_padding_length: decoder.u32(),
            data_offset: decoder.u16(),
            ack_sequence: decoder.u64(),
            flags: decoder.u8(),
            compat_version: decoder.u16(),
            reserved: decoder.u16(),
        };
        decoder.finish()?;
        if decoder.remaining() != 0 {
            return Err(FrameError::Malformed);
        }
        Ok(header)
    }
}

impl Message {
    pub(crate) fn encode(self, limits: Limits) -> Result<Frame, FrameError> {
        let actual = MessageLengths {
            front: checked_length(self.front.len())?,
            middle: checked_length(self.middle.len())?,
            data: checked_length(self.data.len())?,
        };
        if self.lengths != actual || self.header.data_pre_padding_length > actual.data {
            return Err(FrameError::Malformed);
        }
        let segments = vec![
            Segment {
                alignment: MESSAGE_ALIGNMENTS[0],
                data: self.header.encode().to_vec(),
            },
            Segment {
                alignment: MESSAGE_ALIGNMENTS[1],
                data: self.front,
            },
            Segment {
                alignment: MESSAGE_ALIGNMENTS[2],
                data: self.middle,
            },
            Segment {
                alignment: MESSAGE_ALIGNMENTS[3],
                data: self.data,
            },
        ];
        validate_segments(&segments, limits)?;
        Ok(Frame {
            tag: Tag::Message,
            segments,
        })
    }

    pub(crate) fn decode(frame: &Frame, limits: Limits) -> Result<Self, FrameError> {
        if frame.tag != Tag::Message
            || !(1..=MESSAGE_ALIGNMENTS.len()).contains(&frame.segments.len())
        {
            return Err(FrameError::Malformed);
        }
        validate_segments(&frame.segments, limits)?;
        let header = MessageHeader::decode(&frame.segments[0].data)?;
        let data_length = frame
            .segments
            .get(3)
            .map_or(0, |segment| segment.data.len());
        if usize::try_from(header.data_pre_padding_length).map_err(|_| FrameError::LimitExceeded)?
            > data_length
        {
            return Err(FrameError::Malformed);
        }
        let front = frame
            .segments
            .get(1)
            .map_or_else(Vec::new, |segment| segment.data.clone());
        let middle = frame
            .segments
            .get(2)
            .map_or_else(Vec::new, |segment| segment.data.clone());
        let data = frame
            .segments
            .get(3)
            .map_or_else(Vec::new, |segment| segment.data.clone());
        Ok(Self {
            header,
            lengths: MessageLengths {
                front: checked_length(front.len())?,
                middle: checked_length(middle.len())?,
                data: checked_length(data.len())?,
            },
            front,
            middle,
            data,
        })
    }
}

fn checked_length(length: usize) -> Result<u32, FrameError> {
    u32::try_from(length).map_err(|_| FrameError::LimitExceeded)
}

fn validate_segments(segments: &[Segment], limits: Limits) -> Result<(), FrameError> {
    let mut total = 0_u64;
    for (index, segment) in segments.iter().enumerate() {
        if segment.alignment != MESSAGE_ALIGNMENTS[index] {
            return Err(FrameError::Malformed);
        }
        if segment.data.len() > limits.max_segment_bytes as usize {
            return Err(FrameError::LimitExceeded);
        }
        total = total
            .checked_add(u64::try_from(segment.data.len()).map_err(|_| FrameError::LimitExceeded)?)
            .ok_or(FrameError::LimitExceeded)?;
    }
    if total > limits.max_frame_bytes {
        return Err(FrameError::LimitExceeded);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_LIMITS: Limits = Limits {
        max_segment_bytes: 4096,
        max_frame_bytes: 8192,
        max_addresses: 4,
        max_auth_bytes: 64,
    };

    #[test]
    fn header_matches_exact_go_vector() {
        let header = MessageHeader {
            sequence: 0x0807_0605_0403_0201,
            transaction_id: 0x100f_0e0d_0c0b_0a09,
            message_type: 0x1211,
            priority: 0x1413,
            version: 0x1615,
            data_pre_padding_length: 0x1a19_1817,
            data_offset: 0x1c1b,
            ack_sequence: 0x2423_2221_201f_1e1d,
            flags: 0x25,
            compat_version: 0x2726,
            reserved: 0x2928,
        };
        let expected: Vec<u8> = (1..=0x29).collect();
        assert_eq!(header.encode().as_slice(), expected);
        assert_eq!(MessageHeader::decode(&expected), Ok(header));
        assert_eq!(MessageHeader::decode(&[0; 42]), Err(FrameError::Malformed));
    }

    #[test]
    fn message_round_trips_with_owned_segments() {
        let message = Message {
            header: MessageHeader {
                sequence: 1,
                transaction_id: 2,
                message_type: 3,
                data_pre_padding_length: 1,
                data_offset: 4,
                ack_sequence: 5,
                ..MessageHeader::default()
            },
            lengths: MessageLengths {
                front: 5,
                middle: 6,
                data: 4,
            },
            front: b"front".to_vec(),
            middle: b"middle".to_vec(),
            data: vec![0, 1, 2, 3],
        };
        let frame = message.clone().encode(TEST_LIMITS).expect("valid message");
        assert_eq!(
            frame
                .segments
                .iter()
                .map(|segment| segment.alignment)
                .collect::<Vec<_>>(),
            MESSAGE_ALIGNMENTS
        );
        assert_eq!(Message::decode(&frame, TEST_LIMITS), Ok(message));
    }

    #[test]
    fn accepts_omitted_empty_segments_and_rejects_malformed_messages() {
        let header = MessageHeader::default().encode();
        let minimal = Frame {
            tag: Tag::Message,
            segments: vec![Segment {
                alignment: DEFAULT_ALIGNMENT,
                data: header.to_vec(),
            }],
        };
        assert_eq!(
            Message::decode(&minimal, TEST_LIMITS),
            Ok(Message::default())
        );

        let wrong_lengths = Message {
            lengths: MessageLengths {
                front: 2,
                ..MessageLengths::default()
            },
            front: vec![1],
            ..Message::default()
        };
        assert_eq!(
            wrong_lengths.encode(TEST_LIMITS),
            Err(FrameError::Malformed)
        );

        let padded = MessageHeader {
            data_pre_padding_length: 2,
            ..MessageHeader::default()
        }
        .encode();
        let invalid = Frame {
            tag: Tag::Message,
            segments: vec![
                Segment {
                    alignment: 8,
                    data: padded.to_vec(),
                },
                Segment {
                    alignment: 8,
                    data: Vec::new(),
                },
                Segment {
                    alignment: 8,
                    data: Vec::new(),
                },
                Segment {
                    alignment: 4096,
                    data: vec![0],
                },
            ],
        };
        assert_eq!(
            Message::decode(&invalid, TEST_LIMITS),
            Err(FrameError::Malformed)
        );
    }

    #[test]
    fn rejects_wrong_alignment_truncation_and_limits() {
        let header = MessageHeader::default().encode();
        let wrong_alignment = Frame {
            tag: Tag::Message,
            segments: vec![
                Segment {
                    alignment: 8,
                    data: header.to_vec(),
                },
                Segment {
                    alignment: 16,
                    data: Vec::new(),
                },
            ],
        };
        assert_eq!(
            Message::decode(&wrong_alignment, TEST_LIMITS),
            Err(FrameError::Malformed)
        );
        assert_eq!(
            MessageHeader::decode(&header[..40]),
            Err(FrameError::Malformed)
        );
        assert_eq!(
            Message::decode(
                &Frame {
                    tag: Tag::Message,
                    segments: vec![Segment {
                        alignment: 8,
                        data: header.to_vec()
                    }],
                },
                Limits {
                    max_segment_bytes: 40,
                    ..TEST_LIMITS
                }
            ),
            Err(FrameError::LimitExceeded)
        );
    }
}
