use std::fmt;

/// A result returned by the RADOS client API.
pub type Result<T> = std::result::Result<T, Error>;

/// Stable, host-independent error classifications.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    NotFound,
    AlreadyExists,
    PermissionDenied,
    Unsupported,
    InvalidArgument,
    QuotaOrFull,
    Conflict,
    Timeout,
    Canceled,
    Closed,
    NotConnected,
    OutcomeUnknown,
    WatchInterrupted,
    Unknown,
}

/// A structured client error that preserves signed Ceph/Linux wire values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    kind: ErrorKind,
    cause_kind: Option<ErrorKind>,
    operation: Option<&'static str>,
    target: Option<String>,
    wire_errno: Option<i32>,
}

impl Error {
    pub(crate) const fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            cause_kind: None,
            operation: None,
            target: None,
            wire_errno: None,
        }
    }

    pub(crate) fn invalid(operation: &'static str) -> Self {
        Self::new(ErrorKind::InvalidArgument).with_operation(operation)
    }

    pub(crate) fn not_connected(operation: &'static str) -> Self {
        Self::new(ErrorKind::NotConnected).with_operation(operation)
    }

    pub(crate) fn closed(operation: &'static str) -> Self {
        Self::new(ErrorKind::Closed).with_operation(operation)
    }

    pub(crate) const fn from_wire(kind: ErrorKind, wire_errno: i32) -> Self {
        Self {
            kind,
            cause_kind: None,
            operation: None,
            target: None,
            wire_errno: Some(wire_errno),
        }
    }

    /// Constructs an unknown-outcome error that also preserves its cancellation cause.
    #[must_use]
    pub const fn outcome_unknown(cause: ErrorKind) -> Self {
        Self {
            kind: ErrorKind::OutcomeUnknown,
            cause_kind: Some(cause),
            operation: None,
            target: None,
            wire_errno: None,
        }
    }

    pub(crate) fn with_operation(mut self, operation: &'static str) -> Self {
        self.operation = Some(operation);
        self
    }

    pub(crate) fn with_safe_target(mut self, bytes: &[u8]) -> Self {
        self.target = Some(format!("{} bytes", bytes.len()));
        self
    }

    /// Returns the primary stable classification.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Returns whether this error has the requested primary or preserved cause classification.
    #[must_use]
    pub fn is_kind(&self, kind: ErrorKind) -> bool {
        self.kind == kind || self.cause_kind == Some(kind)
    }

    /// Returns the operation name, when one is safe and relevant to expose.
    #[must_use]
    pub const fn operation(&self) -> Option<&'static str> {
        self.operation
    }

    /// Returns sanitized target text, when available.
    #[must_use]
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    /// Returns the original signed Ceph/Linux errno, without host-OS conversion.
    #[must_use]
    pub const fn wire_errno(&self) -> Option<i32> {
        self.wire_errno
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.operation, self.wire_errno) {
            (Some(operation), Some(errno)) => {
                write!(formatter, "{operation} failed with Ceph wire errno {errno}")
            }
            (Some(operation), None) => write!(formatter, "{operation} failed: {:?}", self.kind),
            (None, Some(errno)) => write!(formatter, "Ceph wire errno {errno}"),
            (None, None) => write!(formatter, "RADOS error: {:?}", self.kind),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_errors_preserve_signed_values() {
        for (errno, kind) in [
            (-2, ErrorKind::NotFound),
            (-17, ErrorKind::AlreadyExists),
            (-13, ErrorKind::PermissionDenied),
            (-95, ErrorKind::Unsupported),
            (-22, ErrorKind::InvalidArgument),
            (-122, ErrorKind::QuotaOrFull),
            (-35, ErrorKind::Conflict),
            (-110, ErrorKind::Timeout),
            (-125, ErrorKind::Canceled),
            (-999, ErrorKind::Unknown),
            (7, ErrorKind::Unknown),
        ] {
            let error = Error::from_wire(kind, errno);
            assert_eq!(error.kind(), kind);
            assert_eq!(error.wire_errno(), Some(errno));
        }
    }
}
