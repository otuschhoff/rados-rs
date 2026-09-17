use crate::wire::{Decoder, Encoder};
use crate::{Error, ErrorKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WireErrno(pub(crate) i32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WireErrorClass {
    Unknown,
    NotFound,
    Exists,
    Permission,
    Unsupported,
    Invalid,
    QuotaOrFull,
    Conflict,
    Timeout,
    Canceled,
}

impl From<WireErrno> for Error {
    fn from(errno: WireErrno) -> Self {
        let kind = match errno.class() {
            WireErrorClass::Unknown => ErrorKind::Unknown,
            WireErrorClass::NotFound => ErrorKind::NotFound,
            WireErrorClass::Exists => ErrorKind::AlreadyExists,
            WireErrorClass::Permission => ErrorKind::PermissionDenied,
            WireErrorClass::Unsupported => ErrorKind::Unsupported,
            WireErrorClass::Invalid => ErrorKind::InvalidArgument,
            WireErrorClass::QuotaOrFull => ErrorKind::QuotaOrFull,
            WireErrorClass::Conflict => ErrorKind::Conflict,
            WireErrorClass::Timeout => ErrorKind::Timeout,
            WireErrorClass::Canceled => ErrorKind::Canceled,
        };
        Self::from_wire(kind, errno.0)
    }
}

impl WireErrno {
    // Frozen from reference/go/internal/protocol/errno.go.
    pub(crate) const fn class(self) -> WireErrorClass {
        match self.0 {
            -2 => WireErrorClass::NotFound,
            -17 => WireErrorClass::Exists,
            -1 | -13 => WireErrorClass::Permission,
            -38 | -95 => WireErrorClass::Unsupported,
            -22 => WireErrorClass::Invalid,
            -28 | -122 => WireErrorClass::QuotaOrFull,
            -11 | -16 | -35 => WireErrorClass::Conflict,
            -110 => WireErrorClass::Timeout,
            -125 => WireErrorClass::Canceled,
            _ => WireErrorClass::Unknown,
        }
    }

    pub(crate) fn encode(self, encoder: &mut Encoder) {
        encoder.u32(u32::from_le_bytes(self.0.to_le_bytes()));
    }

    pub(crate) fn decode(decoder: &mut Decoder<'_>) -> Self {
        Self(i32::from_le_bytes(decoder.u32().to_le_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_signed_linux_values_without_host_errno_conversion() {
        for (number, class) in [
            (-2, WireErrorClass::NotFound),
            (-17, WireErrorClass::Exists),
            (-1, WireErrorClass::Permission),
            (-13, WireErrorClass::Permission),
            (-38, WireErrorClass::Unsupported),
            (-95, WireErrorClass::Unsupported),
            (-22, WireErrorClass::Invalid),
            (-28, WireErrorClass::QuotaOrFull),
            (-122, WireErrorClass::QuotaOrFull),
            (-11, WireErrorClass::Conflict),
            (-16, WireErrorClass::Conflict),
            (-35, WireErrorClass::Conflict),
            (-110, WireErrorClass::Timeout),
            (-125, WireErrorClass::Canceled),
            (-999, WireErrorClass::Unknown),
            (7, WireErrorClass::Unknown),
        ] {
            let mut encoder = Encoder::new(4);
            WireErrno(number).encode(&mut encoder);
            let bytes = encoder.finish().expect("wire errno");
            let mut decoder = Decoder::new(&bytes, 0);
            let decoded_errno = WireErrno::decode(&mut decoder);
            assert_eq!(decoded_errno.0, number);
            assert_eq!(decoded_errno.class(), class);
            let public_error = Error::from(decoded_errno);
            assert_eq!(public_error.wire_errno(), Some(number));
            assert_eq!(decoder.finish(), Ok(()));
        }
    }
}
