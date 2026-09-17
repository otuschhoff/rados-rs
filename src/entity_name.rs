use std::error::Error;
use std::fmt::{self, Display, Formatter};

pub(crate) const ENTITY_NAME_LENGTH: usize = 9;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntityName {
    entity_type: u8,
    number: i64,
}

impl EntityName {
    pub const fn entity_type(self) -> u8 {
        self.entity_type
    }

    pub const fn number(self) -> i64 {
        self.number
    }

    pub fn decode(input: &[u8]) -> Result<Self, EntityNameError> {
        let bytes: &[u8; ENTITY_NAME_LENGTH] = input.try_into().map_err(|_| EntityNameError {
            actual: input.len(),
        })?;
        Ok(Self {
            entity_type: bytes[0],
            number: i64::from_le_bytes(
                bytes[1..]
                    .try_into()
                    .expect("the fixed-size entity name has eight number bytes"),
            ),
        })
    }

    pub fn encode(self) -> [u8; ENTITY_NAME_LENGTH] {
        let mut output = [0; ENTITY_NAME_LENGTH];
        output[0] = self.entity_type;
        output[1..].copy_from_slice(&self.number.to_le_bytes());
        output
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntityNameError {
    actual: usize,
}

impl Display for EntityNameError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "entity name must contain exactly {ENTITY_NAME_LENGTH} bytes, got {}",
            self.actual
        )
    }
}

impl Error for EntityNameError {}
