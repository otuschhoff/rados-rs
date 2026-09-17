#[allow(dead_code)]
mod codec;
#[allow(dead_code)]
mod crc;

pub(crate) use codec::{Decoder, Encoder, WireError};
pub(crate) use crc::crc32c;
