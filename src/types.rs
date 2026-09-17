use crate::{Error, ErrorKind, Result};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

/// A clonable cancellation signal for an operation.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    /// Creates a new uncanceled token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Reports whether cancellation has been requested.
    #[must_use]
    pub fn is_canceled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Per-operation deadline and explicit cancellation state.
#[derive(Clone, Debug, Default)]
pub struct OperationOptions {
    deadline: Option<Instant>,
    cancellation: Option<CancellationToken>,
}

impl OperationOptions {
    /// Creates options with no override; the client's finite default applies.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            deadline: None,
            cancellation: None,
        }
    }

    /// Sets an absolute monotonic deadline.
    #[must_use]
    pub const fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Sets a duration relative to the current monotonic instant.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error if the duration overflows `Instant`.
    pub fn with_timeout(self, timeout: Duration) -> Result<Self> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| Error::invalid("OperationOptions::with_timeout"))?;
        Ok(self.with_deadline(deadline))
    }

    /// Attaches explicit cancellation state.
    #[must_use]
    pub fn with_cancellation(mut self, cancellation: CancellationToken) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    pub(crate) fn check(&self, operation: &'static str) -> Result<()> {
        if self
            .cancellation
            .as_ref()
            .is_some_and(CancellationToken::is_canceled)
        {
            return Err(Error::new(ErrorKind::Canceled).with_operation(operation));
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(Error::new(ErrorKind::Timeout).with_operation(operation));
        }
        Ok(())
    }
}

/// Object metadata returned with read and stat results.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectInfo {
    pub size: u64,
    pub modified_at: SystemTime,
    pub version: u64,
}

/// One owned compound-operation result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubOperationResult {
    pub data: Vec<u8>,
    pub code: i32,
    pub value: u64,
    pub error: Option<Error>,
}

/// A version and ordered owned sub-operation results.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OperationResult {
    pub version: u64,
    pub results: Vec<SubOperationResult>,
}

/// Canonical short name for an operation result.
pub type OpResult = OperationResult;

/// An owned server-side class call result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassResult {
    pub data: Vec<u8>,
    pub code: i32,
}

/// Flags applied to one compound sub-operation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SubOperationFlags(u32);

impl SubOperationFlags {
    /// Continue the compound operation if this sub-operation fails.
    pub const FAIL_OK: Self = Self(1 << 1);

    /// Creates an empty flag set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Reports whether all flags in `mask` are set.
    #[must_use]
    pub const fn contains(self, mask: Self) -> bool {
        self.0 & mask.0 == mask.0
    }
}

/// One owned extended attribute.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Xattr {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

/// One owned binary OMAP entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OmapEntry {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// A bounded page and continuation indication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page<T> {
    pub values: Vec<T>,
    pub more: bool,
}

/// One byte-preserving object enumeration result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectEntry {
    pub name: Vec<u8>,
    pub namespace: Vec<u8>,
    pub locator: Vec<u8>,
}

/// An opaque, pool-scoped object enumeration position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectCursor {
    pub(crate) pool_id: i64,
    pub(crate) namespace: Vec<u8>,
    pub(crate) value: Vec<u8>,
    pub(crate) end: bool,
}

impl ObjectCursor {
    /// Reports whether this is the terminal cursor.
    #[must_use]
    pub const fn is_end(&self) -> bool {
        self.end
    }
}

/// A bounded object page and its continuation cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectPage {
    pub values: Vec<ObjectEntry>,
    pub next: ObjectCursor,
    pub more: bool,
}

/// One watch notification with owned data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchEvent {
    pub notify_id: u64,
    pub cookie: u64,
    pub notifier: u64,
    pub data: Vec<u8>,
}

/// One owned notification acknowledgment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotifyAcknowledgment {
    pub client: u64,
    pub cookie: u64,
    pub data: Vec<u8>,
}

/// One watcher that did not acknowledge before the server timeout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NotifyTimeout {
    pub client: u64,
    pub cookie: u64,
}

/// A notify result preserving acknowledgments and timeouts separately.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotifyReply {
    pub acknowledged: Vec<NotifyAcknowledgment>,
    pub timed_out: Vec<NotifyTimeout>,
}

/// Maximum event capacity accepted when a watch is created.
pub const MAX_WATCH_QUEUE: u32 = 65_536;

/// An owned watch registration.
#[derive(Debug)]
pub struct Watch {
    pub(crate) cookie: u64,
}

impl Watch {
    /// Returns the server-assigned watch cookie.
    #[must_use]
    pub const fn cookie(&self) -> u64 {
        self.cookie
    }
}

/// One active watcher.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Watcher {
    pub client: String,
    pub address: String,
    pub cookie: u64,
    pub timeout: Duration,
}

/// Ceph lock mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockMode {
    Exclusive,
    Shared,
}

/// Lock acquisition options.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LockOptions {
    pub cookie: String,
    pub tag: String,
    pub description: String,
    pub duration: Duration,
    pub renew: bool,
}

/// One active lock owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Locker {
    pub client: String,
    pub cookie: String,
    pub address: String,
    pub description: String,
    pub expiration: SystemTime,
    pub mode: LockMode,
    pub tag: String,
}

/// Named snapshot metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    pub id: u64,
    pub name: String,
    pub created_at: SystemTime,
}

/// An owned self-managed snapshot write context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotContext {
    pub sequence: u64,
    pub snapshots: Vec<u64>,
}

/// Cluster capacity counters in KiB and objects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterStats {
    pub kib: u64,
    pub kib_used: u64,
    pub kib_available: u64,
    pub objects: u64,
}

/// Pool I/O and storage counters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoolStats {
    pub bytes_used: u64,
    pub objects: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

/// Owned command output and textual status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandResult {
    pub output: Vec<u8>,
    pub status: String,
}

/// One sparse extent and its owned bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SparseExtent {
    pub offset: u64,
    pub data: Vec<u8>,
}

/// Server-side checksum algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChecksumType {
    XxHash32,
    XxHash64,
    Crc32c,
}

/// One inconsistent object report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InconsistentObject {
    pub object: Vec<u8>,
    pub shards: Vec<i32>,
    pub errors: Vec<String>,
}

/// One inconsistent placement-group report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InconsistentPg {
    pub pg: String,
    pub errors: Vec<String>,
}
