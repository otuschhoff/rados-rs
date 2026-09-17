use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WireError {
    LimitExceeded,
    Malformed,
    UnsupportedVersion { local: u8, required: u8 },
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceeded => formatter.write_str("wire encoding limit exceeded"),
            Self::Malformed => formatter.write_str("malformed wire encoding"),
            Self::UnsupportedVersion { local, required } => {
                write!(
                    formatter,
                    "unsupported compatible version: local={local} required={required}"
                )
            }
        }
    }
}

impl std::error::Error for WireError {}

pub(crate) struct Encoder {
    bytes: Vec<u8>,
    limit: usize,
    error: Option<WireError>,
}

impl Encoder {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            error: None,
        }
    }

    fn reserve(&mut self, length: usize) -> bool {
        if self.error.is_some() {
            return false;
        }
        if length > self.limit.saturating_sub(self.bytes.len()) {
            self.error = Some(WireError::LimitExceeded);
            return false;
        }
        true
    }

    pub(crate) fn raw(&mut self, value: &[u8]) {
        if self.reserve(value.len()) {
            self.bytes.extend_from_slice(value);
        }
    }

    pub(crate) fn u8(&mut self, value: u8) {
        self.raw(&[value]);
    }

    pub(crate) fn u16(&mut self, value: u16) {
        self.raw(&value.to_le_bytes());
    }

    pub(crate) fn u32(&mut self, value: u32) {
        self.raw(&value.to_le_bytes());
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.raw(&value.to_le_bytes());
    }

    pub(crate) fn i8(&mut self, value: i8) {
        self.raw(&value.to_le_bytes());
    }

    pub(crate) fn i16(&mut self, value: i16) {
        self.raw(&value.to_le_bytes());
    }

    pub(crate) fn i32(&mut self, value: i32) {
        self.raw(&value.to_le_bytes());
    }

    pub(crate) fn i64(&mut self, value: i64) {
        self.raw(&value.to_le_bytes());
    }

    pub(crate) fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) {
        let Ok(length) = u32::try_from(value.len()) else {
            self.error = Some(WireError::LimitExceeded);
            return;
        };
        self.u32(length);
        self.raw(value);
    }

    pub(crate) fn string(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    pub(crate) fn versioned(
        &mut self,
        version: u8,
        compatible: u8,
        encode: impl FnOnce(&mut Self),
    ) {
        let mut payload = Self::new(self.limit.min(u32::MAX as usize));
        encode(&mut payload);
        let Ok(payload) = payload.finish() else {
            self.error = Some(WireError::LimitExceeded);
            return;
        };
        let Ok(length) = u32::try_from(payload.len()) else {
            self.error = Some(WireError::LimitExceeded);
            return;
        };
        self.u8(version);
        self.u8(compatible);
        self.u32(length);
        self.raw(&payload);
    }

    pub(crate) fn finish(self) -> Result<Vec<u8>, WireError> {
        self.error.map_or(Ok(self.bytes), Err)
    }
}

pub(crate) struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
    max_bytes: usize,
    error: Option<WireError>,
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(bytes: &'a [u8], max_bytes: usize) -> Self {
        Self {
            bytes,
            offset: 0,
            max_bytes,
            error: None,
        }
    }

    fn take(&mut self, length: usize) -> &'a [u8] {
        if self.error.is_some() || length > self.bytes.len().saturating_sub(self.offset) {
            self.error.get_or_insert(WireError::Malformed);
            return &[];
        }
        let start = self.offset;
        self.offset += length;
        &self.bytes[start..self.offset]
    }

    pub(crate) fn raw(&mut self, length: usize) -> Vec<u8> {
        self.take(length).to_vec()
    }

    pub(crate) fn u8(&mut self) -> u8 {
        self.take(1).first().copied().unwrap_or_default()
    }

    pub(crate) fn u16(&mut self) -> u16 {
        let data = self.take(2);
        let mut value = [0; 2];
        if data.len() == value.len() {
            value.copy_from_slice(data);
        }
        u16::from_le_bytes(value)
    }

    pub(crate) fn u32(&mut self) -> u32 {
        let data = self.take(4);
        let mut value = [0; 4];
        if data.len() == value.len() {
            value.copy_from_slice(data);
        }
        u32::from_le_bytes(value)
    }

    pub(crate) fn u64(&mut self) -> u64 {
        let data = self.take(8);
        let mut value = [0; 8];
        if data.len() == value.len() {
            value.copy_from_slice(data);
        }
        u64::from_le_bytes(value)
    }

    pub(crate) fn i8(&mut self) -> i8 {
        i8::from_le_bytes([self.u8()])
    }

    pub(crate) fn i16(&mut self) -> i16 {
        i16::from_le_bytes(self.u16().to_le_bytes())
    }

    pub(crate) fn i32(&mut self) -> i32 {
        i32::from_le_bytes(self.u32().to_le_bytes())
    }

    pub(crate) fn i64(&mut self) -> i64 {
        i64::from_le_bytes(self.u64().to_le_bytes())
    }

    pub(crate) fn bool(&mut self) -> bool {
        self.u8() != 0
    }

    pub(crate) fn bytes(&mut self) -> Vec<u8> {
        let length = self.u32() as usize;
        if self.error.is_some() {
            return Vec::new();
        }
        if length > self.max_bytes {
            self.error = Some(WireError::LimitExceeded);
            return Vec::new();
        }
        self.raw(length)
    }

    pub(crate) fn string(&mut self) -> String {
        String::from_utf8_lossy(&self.bytes()).into_owned()
    }

    pub(crate) fn versioned(&mut self, local: u8) -> (u8, Decoder<'a>) {
        let version = self.u8();
        let compatible = self.u8();
        let length = self.u32() as usize;
        if self.error.is_some() {
            return (0, Self::new(&[], self.max_bytes));
        }
        if local < compatible {
            self.error = Some(WireError::UnsupportedVersion {
                local,
                required: compatible,
            });
            return (0, Self::new(&[], self.max_bytes));
        }
        if length > self.max_bytes {
            self.error = Some(WireError::LimitExceeded);
            return (0, Self::new(&[], self.max_bytes));
        }
        let payload = self.take(length);
        (version, Self::new(payload, self.max_bytes))
    }

    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    pub(crate) fn finish(&self) -> Result<(), WireError> {
        self.error.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives_are_little_endian_and_bounded() {
        let mut encoder = Encoder::new(14);
        encoder.u8(0x12);
        encoder.u16(0x3456);
        encoder.u32(0x789a_bcde);
        encoder.u64(0x0123_4567_89ab_cdef);
        assert_eq!(encoder.finish(), Err(WireError::LimitExceeded));

        let mut encoder = Encoder::new(15);
        encoder.u8(0x12);
        encoder.u16(0x3456);
        encoder.u32(0x789a_bcde);
        encoder.u64(0x0123_4567_89ab_cdef);
        assert_eq!(
            encoder.finish().expect("exact limit"),
            [
                0x12, 0x56, 0x34, 0xde, 0xbc, 0x9a, 0x78, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23,
                0x01
            ]
        );
    }

    #[test]
    fn signed_boolean_and_byte_values_match_the_go_contract() {
        let mut encoder = Encoder::new(32);
        encoder.i8(-2);
        encoder.i16(-3);
        encoder.i32(-4);
        encoder.i64(-5);
        encoder.bool(true);
        encoder.string("a\0b");
        let bytes = encoder.finish().expect("primitive encoding");
        let mut decoder = Decoder::new(&bytes, 3);
        assert_eq!(decoder.i8(), -2);
        assert_eq!(decoder.i16(), -3);
        assert_eq!(decoder.i32(), -4);
        assert_eq!(decoder.i64(), -5);
        assert!(decoder.bool());
        assert_eq!(decoder.string().as_bytes(), b"a\0b");
        assert_eq!(decoder.finish(), Ok(()));

        let mut permissive = Decoder::new(&[2], 0);
        assert!(permissive.bool());
    }

    #[test]
    fn versioned_payload_is_isolated_and_compatible() {
        let mut encoder = Encoder::new(32);
        encoder.versioned(3, 1, |payload| {
            payload.u8(7);
            payload.u8(99);
        });
        encoder.u8(42);
        let bytes = encoder.finish().expect("encode envelope");

        let mut decoder = Decoder::new(&bytes, 32);
        let (version, mut payload) = decoder.versioned(1);
        assert_eq!(version, 3);
        assert_eq!(payload.u8(), 7);
        assert_eq!(decoder.u8(), 42);
        assert_eq!(payload.remaining(), 1);
        assert_eq!(decoder.finish(), Ok(()));

        let mut incompatible = Decoder::new(&[1, 2, 0, 0, 0, 0], 32);
        let _ = incompatible.versioned(1);
        assert_eq!(
            incompatible.finish(),
            Err(WireError::UnsupportedVersion {
                local: 1,
                required: 2
            })
        );
    }

    #[test]
    fn variable_lengths_reject_limits_and_truncation() {
        let mut limited = Decoder::new(&[2, 0, 0, 0, 1, 2], 1);
        assert!(limited.bytes().is_empty());
        assert_eq!(limited.finish(), Err(WireError::LimitExceeded));

        for length in 0..6 {
            let mut decoder = Decoder::new(&[1, 1, 1, 0, 0, 0][..length], 16);
            let _ = decoder.versioned(1);
            assert_eq!(decoder.finish(), Err(WireError::Malformed));
        }
    }
}
