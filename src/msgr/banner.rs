use super::frame::FrameError;
use std::io::{self, Read};

const BANNER_PREFIX: &[u8] = b"ceph v2\n";
const BANNER_PAYLOAD_SIZE: u16 = 16;
pub(crate) const REVISION_1_FEATURES: u64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Banner {
    pub(crate) supported: u64,
    pub(crate) required: u64,
}

impl Banner {
    pub(crate) const fn client() -> Self {
        Self {
            supported: REVISION_1_FEATURES,
            required: REVISION_1_FEATURES,
        }
    }

    pub(crate) fn encode(self) -> Vec<u8> {
        let mut output =
            Vec::with_capacity(BANNER_PREFIX.len() + 2 + usize::from(BANNER_PAYLOAD_SIZE));
        output.extend_from_slice(BANNER_PREFIX);
        output.extend_from_slice(&BANNER_PAYLOAD_SIZE.to_le_bytes());
        output.extend_from_slice(&self.supported.to_le_bytes());
        output.extend_from_slice(&self.required.to_le_bytes());
        output
    }

    pub(crate) fn read(reader: &mut impl Read, max_payload: u16) -> Result<Self, FrameError> {
        let mut header = [0; 10];
        read_exact(reader, &mut header)?;
        if &header[..BANNER_PREFIX.len()] != BANNER_PREFIX {
            return Err(FrameError::Malformed);
        }
        let size = u16::from_le_bytes([header[8], header[9]]);
        if size < BANNER_PAYLOAD_SIZE {
            return Err(FrameError::Malformed);
        }
        if size > max_payload {
            return Err(FrameError::LimitExceeded);
        }
        let mut payload = vec![0; usize::from(size)];
        read_exact(reader, &mut payload)?;
        Ok(Self {
            supported: u64::from_le_bytes(
                payload[..8].try_into().map_err(|_| FrameError::Malformed)?,
            ),
            required: u64::from_le_bytes(
                payload[8..16]
                    .try_into()
                    .map_err(|_| FrameError::Malformed)?,
            ),
        })
    }

    pub(crate) fn negotiate(self, peer: Self) -> Result<u64, FrameError> {
        if peer.required & !self.supported != 0 || self.required & !peer.supported != 0 {
            return Err(FrameError::UnsupportedFeature);
        }
        let negotiated = self.supported & peer.supported;
        if negotiated & REVISION_1_FEATURES == 0 {
            return Err(FrameError::UnsupportedFeature);
        }
        Ok(negotiated)
    }
}

fn read_exact(reader: &mut impl Read, output: &mut [u8]) -> Result<(), FrameError> {
    reader
        .read_exact(output)
        .map_err(|error| match error.kind() {
            io::ErrorKind::OutOfMemory => FrameError::LimitExceeded,
            _ => FrameError::Malformed,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn encoding_reading_and_negotiation_match_go() {
        let expected =
            b"ceph v2\n\x10\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00";
        assert_eq!(Banner::client().encode(), expected);
        let peer = Banner::read(&mut Cursor::new(expected), 64).expect("valid banner");
        assert_eq!(Banner::client().negotiate(peer), Ok(REVISION_1_FEATURES));
    }

    #[test]
    fn accepts_extended_payload_and_rejects_invalid_input() {
        let mut extended = Banner::client().encode();
        extended[8..10].copy_from_slice(&17_u16.to_le_bytes());
        extended.push(0xaa);
        assert_eq!(
            Banner::read(&mut Cursor::new(extended), 17),
            Ok(Banner::client())
        );
        assert_eq!(
            Banner::read(&mut Cursor::new(b"ceph v2\n\x11\x00"), 16),
            Err(FrameError::LimitExceeded)
        );
        assert_eq!(
            Banner::read(&mut Cursor::new(b"ceph v1\n\x10\x00"), 16),
            Err(FrameError::Malformed)
        );
        assert_eq!(
            Banner::read(&mut Cursor::new(b"ceph v2\n\x10\x00"), 16),
            Err(FrameError::Malformed)
        );
        assert_eq!(
            Banner::client().negotiate(Banner {
                supported: 0,
                required: 0,
            }),
            Err(FrameError::UnsupportedFeature)
        );
    }
}
