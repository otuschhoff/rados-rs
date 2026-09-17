use crate::{Error, Result};

const MAX_SUB_OPERATIONS: usize = 1_024;
const MAX_OPERATION_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
enum ReadAction {
    Read { offset: u64, length: u64 },
    Stat,
    AssertExists,
    AssertVersion(u64),
}

/// A bounded, single-use atomic read-operation builder.
#[derive(Debug, Default)]
pub struct ReadOp {
    actions: Vec<ReadAction>,
}

impl ReadOp {
    /// Creates an empty operation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn push(mut self, action: ReadAction) -> Result<Self> {
        if self.actions.len() == MAX_SUB_OPERATIONS {
            return Err(Error::invalid("ReadOp"));
        }
        self.actions.push(action);
        Ok(self)
    }

    /// Appends a bounded read.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error on range overflow or excessive length.
    pub fn read(self, offset: u64, length: u64) -> Result<Self> {
        offset
            .checked_add(length)
            .ok_or_else(|| Error::invalid("ReadOp::read"))?;
        if length > MAX_OPERATION_BYTES as u64 {
            return Err(Error::invalid("ReadOp::read"));
        }
        self.push(ReadAction::Read { offset, length })
    }

    /// Appends a stat operation.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error when the sub-operation limit is reached.
    pub fn stat(self) -> Result<Self> {
        self.push(ReadAction::Stat)
    }

    /// Requires the object to exist.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error when the sub-operation limit is reached.
    pub fn assert_exists(self) -> Result<Self> {
        self.push(ReadAction::AssertExists)
    }

    /// Requires an exact object version.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error when the sub-operation limit is reached.
    pub fn assert_version(self, version: u64) -> Result<Self> {
        self.push(ReadAction::AssertVersion(version))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum WriteAction {
    Create { exclusive: bool },
    Write { offset: u64, data: Vec<u8> },
    WriteFull(Vec<u8>),
    Append(Vec<u8>),
    Truncate(u64),
    Zero { offset: u64, length: u64 },
    Remove,
    AssertVersion(u64),
}

/// A bounded, single-use atomic write-operation builder.
#[derive(Debug, Default)]
pub struct WriteOp {
    actions: Vec<WriteAction>,
    retained_bytes: usize,
}

impl WriteOp {
    /// Creates an empty operation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn push(mut self, action: WriteAction, retained_bytes: usize) -> Result<Self> {
        let total = self
            .retained_bytes
            .checked_add(retained_bytes)
            .ok_or_else(|| Error::invalid("WriteOp"))?;
        if self.actions.len() == MAX_SUB_OPERATIONS || total > MAX_OPERATION_BYTES {
            return Err(Error::invalid("WriteOp"));
        }
        self.retained_bytes = total;
        self.actions.push(action);
        Ok(self)
    }

    /// Appends object creation.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error when the operation bound is reached.
    pub fn create(self, exclusive: bool) -> Result<Self> {
        self.push(WriteAction::Create { exclusive }, 0)
    }

    /// Appends an owned write.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error on range overflow or retained-byte limits.
    pub fn write(self, offset: u64, data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        offset
            .checked_add(u64::try_from(data.len()).map_err(|_| Error::invalid("WriteOp::write"))?)
            .ok_or_else(|| Error::invalid("WriteOp::write"))?;
        self.push(
            WriteAction::Write {
                offset,
                data: data.to_vec(),
            },
            data.len(),
        )
    }

    /// Appends an owned full-object write.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error when retained-byte limits are exceeded.
    pub fn write_full(self, data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        self.push(WriteAction::WriteFull(data.to_vec()), data.len())
    }

    /// Appends owned bytes to the object.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error when retained-byte limits are exceeded.
    pub fn append(self, data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        self.push(WriteAction::Append(data.to_vec()), data.len())
    }

    /// Appends a truncate operation.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error when the operation bound is reached.
    pub fn truncate(self, size: u64) -> Result<Self> {
        self.push(WriteAction::Truncate(size), 0)
    }

    /// Appends a zero operation.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error on range overflow or operation limits.
    pub fn zero(self, offset: u64, length: u64) -> Result<Self> {
        offset
            .checked_add(length)
            .ok_or_else(|| Error::invalid("WriteOp::zero"))?;
        self.push(WriteAction::Zero { offset, length }, 0)
    }

    /// Appends object removal.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error when the operation bound is reached.
    pub fn remove(self) -> Result<Self> {
        self.push(WriteAction::Remove, 0)
    }

    /// Requires an exact object version.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error when the operation bound is reached.
    pub fn assert_version(self, version: u64) -> Result<Self> {
        self.push(WriteAction::AssertVersion(version), 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_builder_owns_input_and_checks_ranges() {
        let mut source = b"payload".to_vec();
        let operation = WriteOp::new().write(5, &source).expect("write");
        source.fill(b'x');
        assert!(matches!(
            operation.actions.as_slice(),
            [WriteAction::Write { offset: 5, data }] if data == b"payload"
        ));
        assert!(WriteOp::new().write(u64::MAX, [0, 1]).is_err());
        assert!(ReadOp::new().read(u64::MAX, 1).is_err());
    }
}
