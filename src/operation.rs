use crate::osd::messages::{OP_FLAG_FAIL_OK, Operation};
use crate::osd::metadata::{self, Entry};
use crate::{Error, OmapEntry, Result, SubOperationFlags};

const MAX_SUB_OPERATIONS: usize = 16;
const MAX_OPERATION_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
enum ReadAction {
    Read { offset: u64, length: u64 },
    Stat,
    AssertExists,
    AssertVersion(u64),
    GetXattr(Vec<u8>),
    GetOmapHeader,
    ListOmap(Vec<u8>),
    Exec(Operation),
    WithFlags { action: Box<Self>, flags: u32 },
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

    /// Appends an extended-attribute read.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error for an empty or NUL-containing name or operation overflow.
    pub fn get_xattr(self, name: impl AsRef<[u8]>) -> Result<Self> {
        let name = valid_xattr_name(name.as_ref(), "ReadOp::get_xattr")?;
        self.push(ReadAction::GetXattr(name))
    }

    /// Appends an OMAP-header read.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error when the operation bound is reached.
    pub fn get_omap_header(self) -> Result<Self> {
        self.push(ReadAction::GetOmapHeader)
    }

    /// Appends a bounded OMAP page read after `after`.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error for a zero limit, oversized payload, or operation overflow.
    pub fn list_omap(self, after: impl AsRef<[u8]>, limit: u64) -> Result<Self> {
        if limit == 0 {
            return Err(Error::invalid("ReadOp::list_omap"));
        }
        let payload = metadata::encode_list_request(after.as_ref(), limit, MAX_OPERATION_BYTES)
            .map_err(|_| Error::invalid("ReadOp::list_omap"))?;
        self.push(ReadAction::ListOmap(payload))
    }

    /// Appends a read-class method call with copied input.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error for invalid names, retained-byte limits, or operation overflow.
    pub fn exec(
        self,
        class: impl AsRef<[u8]>,
        method: impl AsRef<[u8]>,
        input: impl AsRef<[u8]>,
    ) -> Result<Self> {
        self.push(ReadAction::Exec(class_operation(
            class.as_ref(),
            method.as_ref(),
            input.as_ref(),
            false,
            "ReadOp::exec",
        )?))
    }

    /// Applies flags to an existing sub-operation by its zero-based result index.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error for an unknown index or unsupported flag.
    pub fn set_flags(mut self, index: usize, flags: SubOperationFlags) -> Result<Self> {
        if index >= self.actions.len() || flags.bits() & !OP_FLAG_FAIL_OK != 0 {
            return Err(Error::invalid("ReadOp::set_flags"));
        }
        let action = match self.actions.remove(index) {
            ReadAction::WithFlags { action, .. } => *action,
            action => action,
        };
        self.actions.insert(
            index,
            ReadAction::WithFlags {
                action: Box::new(action),
                flags: flags.bits(),
            },
        );
        Ok(self)
    }

    pub(crate) fn into_operations(self) -> Result<Vec<Operation>> {
        if self.actions.is_empty() {
            return Err(Error::invalid("ReadOp"));
        }
        Ok(self.actions.into_iter().map(read_operation).collect())
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
    CompareExtent { offset: u64, data: Vec<u8> },
    SetXattr { name: Vec<u8>, value: Vec<u8> },
    RemoveXattr(Vec<u8>),
    SetOmap(Vec<u8>),
    RemoveOmap(Vec<u8>),
    RemoveOmapRange(Vec<u8>),
    ClearOmap,
    SetOmapHeader(Vec<u8>),
    CompareOmap(Vec<u8>),
    Exec(Operation),
    WithFlags { action: Box<Self>, flags: u32 },
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

    /// Appends a byte comparison at `offset`.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error on range, retained-byte, or operation overflow.
    pub fn compare_extent(self, offset: u64, data: impl AsRef<[u8]>) -> Result<Self> {
        let data = data.as_ref();
        offset
            .checked_add(
                u64::try_from(data.len()).map_err(|_| Error::invalid("WriteOp::compare_extent"))?,
            )
            .ok_or_else(|| Error::invalid("WriteOp::compare_extent"))?;
        self.push(
            WriteAction::CompareExtent {
                offset,
                data: data.to_vec(),
            },
            data.len(),
        )
    }

    /// Appends an extended-attribute update.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error for an invalid name or retained-byte or operation overflow.
    pub fn set_xattr(self, name: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> Result<Self> {
        let name = valid_xattr_name(name.as_ref(), "WriteOp::set_xattr")?;
        let value = value.as_ref();
        let retained = name
            .len()
            .checked_add(value.len())
            .ok_or_else(|| Error::invalid("WriteOp::set_xattr"))?;
        self.push(
            WriteAction::SetXattr {
                name,
                value: value.to_vec(),
            },
            retained,
        )
    }

    /// Appends an extended-attribute removal.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error for an invalid name or retained-byte or operation overflow.
    pub fn remove_xattr(self, name: impl AsRef<[u8]>) -> Result<Self> {
        let name = valid_xattr_name(name.as_ref(), "WriteOp::remove_xattr")?;
        let retained = name.len();
        self.push(WriteAction::RemoveXattr(name), retained)
    }

    /// Appends sorted binary OMAP updates.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error for duplicate keys or retained-byte or operation overflow.
    pub fn set_omap(self, values: impl IntoIterator<Item = OmapEntry>) -> Result<Self> {
        let payload = metadata::encode_map(
            values.into_iter().map(|entry| Entry {
                key: entry.key,
                value: entry.value,
            }),
            MAX_OPERATION_BYTES,
        )
        .map_err(|_| Error::invalid("WriteOp::set_omap"))?;
        let retained = payload.len();
        self.push(WriteAction::SetOmap(payload), retained)
    }

    /// Appends sorted binary OMAP-key removals.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error for duplicate keys or retained-byte or operation overflow.
    pub fn remove_omap(self, keys: impl IntoIterator<Item = Vec<u8>>) -> Result<Self> {
        let payload = metadata::encode_keys(keys, MAX_OPERATION_BYTES)
            .map_err(|_| Error::invalid("WriteOp::remove_omap"))?;
        let retained = payload.len();
        self.push(WriteAction::RemoveOmap(payload), retained)
    }

    /// Appends a half-open binary OMAP-key range removal.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error for an empty/reversed range or retained-byte overflow.
    pub fn remove_omap_range(self, begin: impl AsRef<[u8]>, end: impl AsRef<[u8]>) -> Result<Self> {
        let payload = metadata::encode_range(begin.as_ref(), end.as_ref(), MAX_OPERATION_BYTES)
            .map_err(|_| Error::invalid("WriteOp::remove_omap_range"))?;
        let retained = payload.len();
        self.push(WriteAction::RemoveOmapRange(payload), retained)
    }

    /// Appends an OMAP clear.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error when the operation bound is reached.
    pub fn clear_omap(self) -> Result<Self> {
        self.push(WriteAction::ClearOmap, 0)
    }

    /// Appends an owned OMAP-header update.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error on retained-byte or operation overflow.
    pub fn set_omap_header(self, value: impl AsRef<[u8]>) -> Result<Self> {
        let value = value.as_ref();
        self.push(WriteAction::SetOmapHeader(value.to_vec()), value.len())
    }

    /// Appends an equality comparison for one binary OMAP value.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error on retained-byte or operation overflow.
    pub fn compare_omap(self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) -> Result<Self> {
        let payload =
            metadata::encode_compare(key.as_ref(), value.as_ref(), 1, MAX_OPERATION_BYTES)
                .map_err(|_| Error::invalid("WriteOp::compare_omap"))?;
        let retained = payload.len();
        self.push(WriteAction::CompareOmap(payload), retained)
    }

    /// Appends a potentially mutating class method call with copied input.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error for invalid names, retained-byte limits, or operation overflow.
    pub fn exec(
        self,
        class: impl AsRef<[u8]>,
        method: impl AsRef<[u8]>,
        input: impl AsRef<[u8]>,
    ) -> Result<Self> {
        let operation = class_operation(
            class.as_ref(),
            method.as_ref(),
            input.as_ref(),
            true,
            "WriteOp::exec",
        )?;
        let retained = operation.data_len();
        self.push(WriteAction::Exec(operation), retained)
    }

    /// Applies flags to an existing sub-operation by its zero-based result index.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error for an unknown index or unsupported flag.
    pub fn set_flags(mut self, index: usize, flags: SubOperationFlags) -> Result<Self> {
        if index >= self.actions.len() || flags.bits() & !OP_FLAG_FAIL_OK != 0 {
            return Err(Error::invalid("WriteOp::set_flags"));
        }
        let action = match self.actions.remove(index) {
            WriteAction::WithFlags { action, .. } => *action,
            action => action,
        };
        self.actions.insert(
            index,
            WriteAction::WithFlags {
                action: Box::new(action),
                flags: flags.bits(),
            },
        );
        Ok(self)
    }

    pub(crate) fn into_operations(self) -> Result<Vec<Operation>> {
        if self.actions.is_empty() {
            return Err(Error::invalid("WriteOp"));
        }
        Ok(self.actions.into_iter().map(write_operation).collect())
    }
}

fn valid_xattr_name(name: &[u8], operation: &'static str) -> Result<Vec<u8>> {
    if name.is_empty() || name.contains(&0) || name.len() > u32::MAX as usize {
        return Err(Error::invalid(operation));
    }
    Ok(name.to_vec())
}

fn class_operation(
    class: &[u8],
    method: &[u8],
    input: &[u8],
    mutation: bool,
    operation: &'static str,
) -> Result<Operation> {
    let retained = class
        .len()
        .checked_add(method.len())
        .and_then(|length| length.checked_add(input.len()))
        .ok_or_else(|| Error::invalid(operation))?;
    if class.is_empty()
        || method.is_empty()
        || class.contains(&0)
        || method.contains(&0)
        || class.len() > u8::MAX as usize
        || method.len() > u8::MAX as usize
        || input.len() > u32::MAX as usize
        || retained > MAX_OPERATION_BYTES
    {
        return Err(Error::invalid(operation));
    }
    let class_length = u8::try_from(class.len()).map_err(|_| Error::invalid(operation))?;
    let method_length = u8::try_from(method.len()).map_err(|_| Error::invalid(operation))?;
    let input_length = u32::try_from(input.len()).map_err(|_| Error::invalid(operation))?;
    let mut data = Vec::with_capacity(retained);
    data.extend_from_slice(class);
    data.extend_from_slice(method);
    data.extend_from_slice(input);
    Ok(Operation::Call {
        class_length,
        method_length,
        input_length,
        data,
        mutation,
    })
}

fn read_operation(action: ReadAction) -> Operation {
    match action {
        ReadAction::Read { offset, length } => Operation::Read { offset, length },
        ReadAction::Stat | ReadAction::AssertExists => Operation::Stat,
        ReadAction::AssertVersion(version) => Operation::AssertVersion(version),
        ReadAction::GetXattr(name) => Operation::GetXattr(name),
        ReadAction::GetOmapHeader => Operation::OmapGetHeader,
        ReadAction::ListOmap(payload) => Operation::OmapGetValues(payload),
        ReadAction::Exec(operation) => operation,
        ReadAction::WithFlags { action, flags } => Operation::WithFlags {
            operation: Box::new(read_operation(*action)),
            flags,
        },
    }
}

fn write_operation(action: WriteAction) -> Operation {
    match action {
        WriteAction::Create { exclusive } => Operation::Create { exclusive },
        WriteAction::Write { offset, data } => Operation::Write { offset, data },
        WriteAction::WriteFull(data) => Operation::WriteFull(data),
        WriteAction::Append(data) => Operation::Append(data),
        WriteAction::Truncate(size) => Operation::Truncate { size },
        WriteAction::Zero { offset, length } => Operation::Zero { offset, length },
        WriteAction::Remove => Operation::Remove,
        WriteAction::AssertVersion(version) => Operation::AssertVersion(version),
        WriteAction::CompareExtent { offset, data } => Operation::CompareExtent { offset, data },
        WriteAction::SetXattr { name, value } => Operation::SetXattr { name, value },
        WriteAction::RemoveXattr(name) => Operation::RemoveXattr(name),
        WriteAction::SetOmap(payload) => Operation::OmapSetValues(payload),
        WriteAction::RemoveOmap(payload) => Operation::OmapRemoveKeys(payload),
        WriteAction::RemoveOmapRange(payload) => Operation::OmapRemoveRange(payload),
        WriteAction::ClearOmap => Operation::OmapClear,
        WriteAction::SetOmapHeader(value) => Operation::OmapSetHeader(value),
        WriteAction::CompareOmap(payload) => Operation::OmapCompare(payload),
        WriteAction::Exec(operation) => operation,
        WriteAction::WithFlags { action, flags } => Operation::WithFlags {
            operation: Box::new(write_operation(*action)),
            flags,
        },
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

    #[test]
    fn metadata_builders_sort_copy_validate_and_preserve_create_flags() {
        let operation = WriteOp::new()
            .create(true)
            .expect("create")
            .set_flags(0, SubOperationFlags::FAIL_OK)
            .expect("flags")
            .set_omap([
                OmapEntry {
                    key: b"b".to_vec(),
                    value: b"2".to_vec(),
                },
                OmapEntry {
                    key: b"a".to_vec(),
                    value: b"1".to_vec(),
                },
            ])
            .expect("omap")
            .into_operations()
            .expect("operations");
        assert!(matches!(
            &operation[0],
            Operation::WithFlags { operation, flags }
                if **operation == Operation::Create { exclusive: true }
                    && *flags == OP_FLAG_FAIL_OK
        ));
        assert!(
            matches!(&operation[1], Operation::OmapSetValues(data) if &data[4..9] == b"\x01\0\0\0a")
        );
        assert!(WriteOp::new().set_xattr([], []).is_err());
        assert!(WriteOp::new().remove_omap_range(b"z", b"a").is_err());
    }

    #[test]
    fn builders_enforce_the_certified_operation_limit() {
        let mut operation = ReadOp::new();
        for _ in 0..MAX_SUB_OPERATIONS {
            operation = operation.stat().expect("within bound");
        }
        assert!(operation.stat().is_err());
        assert!(ReadOp::new().into_operations().is_err());
        assert!(WriteOp::new().into_operations().is_err());
    }

    #[test]
    fn setting_flags_replaces_the_existing_wrapper() {
        let operations = WriteOp::new()
            .create(true)
            .expect("create")
            .set_flags(0, SubOperationFlags::FAIL_OK)
            .expect("set")
            .set_flags(0, SubOperationFlags::empty())
            .expect("replace")
            .into_operations()
            .expect("operations");
        assert!(matches!(
            operations.as_slice(),
            [Operation::WithFlags { operation, flags }]
                if **operation == Operation::Create { exclusive: true } && *flags == 0
        ));
    }

    #[test]
    fn class_builders_copy_and_validate_names_and_mutation_intent() {
        let mut input = b"input".to_vec();
        let read = ReadOp::new()
            .exec(b"class", b"method", &input)
            .expect("read class")
            .into_operations()
            .expect("operations");
        input.fill(b'x');
        assert!(matches!(
            read.as_slice(),
            [Operation::Call { data, mutation: false, .. }] if data == b"classmethodinput"
        ));
        let write = WriteOp::new()
            .exec(b"class", b"method", b"input")
            .expect("write class")
            .into_operations()
            .expect("operations");
        assert!(write[0].is_mutation());
        assert!(ReadOp::new().exec([], b"method", []).is_err());
        assert!(WriteOp::new().exec(b"class", b"bad\0name", []).is_err());
    }
}
