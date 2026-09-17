use crate::{Error, Result};
use std::fmt;

const MAX_IDENTITY_BYTES: usize = 4_096;

macro_rules! byte_identity {
    ($name:ident, $allow_empty:expr) => {
        #[doc = "An owned, byte-preserving RADOS identity."]
        #[derive(Clone, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Vec<u8>);

        impl $name {
            /// Copies and validates an identity without UTF-8 normalization.
            ///
            /// # Errors
            ///
            /// Returns [`ErrorKind::InvalidArgument`](crate::ErrorKind::InvalidArgument)
            /// when the value is empty where forbidden or exceeds 4096 bytes.
            pub fn new(value: impl AsRef<[u8]>) -> Result<Self> {
                let value = value.as_ref();
                if (!$allow_empty && value.is_empty()) || value.len() > MAX_IDENTITY_BYTES {
                    return Err(Error::invalid(stringify!($name)));
                }
                Ok(Self(value.to_vec()))
            }

            /// Returns the exact identity bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&format_args!("{} bytes", self.0.len()))
                    .finish()
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.as_bytes()
            }
        }
    };
}

byte_identity!(ObjectName, false);
byte_identity!(Namespace, true);
byte_identity!(LocatorKey, true);
