use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::frame::{FrameError, Tag};

pub(crate) const DEFAULT_MAX_SESSIONS: usize = 256;
pub(crate) const DEFAULT_MAX_RECEIVE_BYTES: usize = 256 << 20;
const RECEIVE_COPY_FACTOR: usize = 5;
const CONTROL_BYTES_PER_SESSION: usize = 16 << 10;

#[derive(Debug)]
pub(crate) struct ReceiveBudget {
    sessions: Arc<Semaphore>,
    bytes: Arc<Semaphore>,
    controls: Arc<Semaphore>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ReceiveCharge(Option<Arc<OwnedSemaphorePermit>>);

impl ReceiveBudget {
    pub(crate) fn new(sessions: usize, bytes: usize) -> Result<Arc<Self>, FrameError> {
        let controls = sessions
            .checked_mul(CONTROL_BYTES_PER_SESSION)
            .ok_or(FrameError::Malformed)?;
        if sessions == 0
            || bytes == 0
            || sessions > Semaphore::MAX_PERMITS
            || bytes > Semaphore::MAX_PERMITS
            || controls > Semaphore::MAX_PERMITS
        {
            return Err(FrameError::Malformed);
        }
        Ok(Arc::new(Self {
            sessions: Arc::new(Semaphore::new(sessions)),
            bytes: Arc::new(Semaphore::new(bytes)),
            controls: Arc::new(Semaphore::new(controls)),
        }))
    }

    pub(crate) fn defaults() -> Arc<Self> {
        Self::new(DEFAULT_MAX_SESSIONS, DEFAULT_MAX_RECEIVE_BYTES)
            .expect("valid default receive budget")
    }

    pub(crate) fn admit(&self) -> Result<OwnedSemaphorePermit, FrameError> {
        Arc::clone(&self.sessions)
            .try_acquire_owned()
            .map_err(|_| FrameError::LimitExceeded)
    }

    pub(crate) fn reserve(&self, tag: Tag, wire_bytes: u64) -> Result<ReceiveCharge, FrameError> {
        let bytes = usize::try_from(wire_bytes)
            .ok()
            .and_then(|bytes| bytes.checked_mul(RECEIVE_COPY_FACTOR))
            .and_then(|bytes| u32::try_from(bytes).ok())
            .ok_or(FrameError::LimitExceeded)?;
        let pool = if tag == Tag::Message {
            &self.bytes
        } else {
            &self.controls
        };
        let permit = Arc::clone(pool)
            .try_acquire_many_owned(bytes)
            .map_err(|_| FrameError::LimitExceeded)?;
        Ok(ReceiveCharge(Some(Arc::new(permit))))
    }
}

impl ReceiveCharge {
    pub(crate) fn is_charged(&self) -> bool {
        self.0.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_receive_budget_bounds_sessions_bytes_and_controls() {
        let budget = ReceiveBudget::new(1, 100).unwrap();
        let session = budget.admit().unwrap();
        assert!(matches!(budget.admit(), Err(FrameError::LimitExceeded)));
        let message = budget.reserve(Tag::Message, 20).unwrap();
        assert!(message.is_charged());
        assert!(budget.reserve(Tag::Message, 1).is_err());
        let control = budget.reserve(Tag::Ack, 32).unwrap();
        let clone = message.clone();
        drop(message);
        assert!(budget.reserve(Tag::Message, 1).is_err());
        drop(clone);
        assert!(budget.reserve(Tag::Message, 20).is_ok());
        drop(control);
        drop(session);
        assert!(budget.admit().is_ok());
        assert!(ReceiveBudget::new(0, 1).is_err());
        assert!(ReceiveBudget::new(1, 0).is_err());
        assert!(budget.reserve(Tag::Message, u64::MAX).is_err());
    }
}
