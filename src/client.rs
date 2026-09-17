use crate::{
    Config, Error, ErrorKind, LocatorKey, Namespace, ObjectName, OperationOptions, Result,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug)]
struct ClientInner {
    config: Config,
    closed: AtomicBool,
}

/// A cheaply clonable client handle. Construction performs no network I/O.
#[derive(Clone, Debug)]
pub struct Client(Arc<ClientInner>);

impl Client {
    /// Validates and owns a configuration without starting workers or doing I/O.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error when required local configuration is absent.
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self(Arc::new(ClientInner {
            config,
            closed: AtomicBool::new(false),
        })))
    }

    /// Connects the client when the R03-R05 transport stack is available.
    ///
    /// # Errors
    ///
    /// R02 returns `NotConnected`; cancellation, expiry, and closure are checked first.
    pub async fn connect(&self, options: OperationOptions) -> Result<()> {
        std::future::ready(()).await;
        self.ready("Client::connect", &options)?;
        Err(Error::new(ErrorKind::NotConnected).with_operation("Client::connect"))
    }

    /// Opens an immutable pool view by byte-preserving name.
    ///
    /// # Errors
    ///
    /// Returns cancellation, deadline, closure, identity, or not-connected errors.
    pub async fn open_pool(
        &self,
        name: impl AsRef<[u8]>,
        options: OperationOptions,
    ) -> Result<Pool> {
        std::future::ready(()).await;
        self.ready("Client::open_pool", &options)?;
        let name = ObjectName::new(name)?;
        Err(Error::not_connected("Client::open_pool").with_safe_target(name.as_bytes()))
    }

    /// Creates an immutable unresolved pool view without network I/O.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument or closed error.
    pub fn pool(&self, name: impl AsRef<[u8]>) -> Result<Pool> {
        self.ready("Client::pool", &OperationOptions::new())?;
        Ok(Pool {
            client: self.clone(),
            name: ObjectName::new(name)?,
            namespace: Namespace::new([])?,
            locator: LocatorKey::new([])?,
            read_snapshot: None,
        })
    }

    /// Waits for the captured mutation watermark once transport is available.
    ///
    /// # Errors
    ///
    /// Returns cancellation, deadline, closure, or not-connected errors.
    pub async fn flush(&self, options: OperationOptions) -> Result<()> {
        std::future::ready(()).await;
        self.ready("Client::flush", &options)?;
        Err(Error::not_connected("Client::flush"))
    }

    /// Stops admission and drains workers once transport is available.
    ///
    /// # Errors
    ///
    /// Returns cancellation or deadline errors. Repeated shutdown is successful.
    pub async fn shutdown(&self, options: OperationOptions) -> Result<()> {
        std::future::ready(()).await;
        options.check("Client::shutdown")?;
        self.close();
        Ok(())
    }

    /// Idempotently closes the shared client without blocking or network I/O.
    pub fn close(&self) {
        self.0.closed.store(true, Ordering::Release);
    }

    /// Reports whether any clone has closed the shared client.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.0.closed.load(Ordering::Acquire)
    }

    /// Returns the owned immutable configuration.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.0.config
    }

    fn ready(&self, operation: &'static str, options: &OperationOptions) -> Result<()> {
        if self.is_closed() {
            return Err(Error::closed(operation));
        }
        options.check(operation)
    }
}

/// An immutable pool view.
#[derive(Clone, Debug)]
pub struct Pool {
    client: Client,
    name: ObjectName,
    namespace: Namespace,
    locator: LocatorKey,
    read_snapshot: Option<u64>,
}

impl Pool {
    /// Returns a sibling view with an owned byte-preserving namespace.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error when the namespace exceeds its bound.
    pub fn with_namespace(mut self, namespace: impl AsRef<[u8]>) -> Result<Self> {
        self.namespace = Namespace::new(namespace)?;
        Ok(self)
    }

    /// Returns a sibling view with an owned byte-preserving locator key.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error when the locator exceeds its bound.
    pub fn with_locator(mut self, locator: impl AsRef<[u8]>) -> Result<Self> {
        self.locator = LocatorKey::new(locator)?;
        Ok(self)
    }

    #[must_use]
    pub const fn with_read_snapshot(mut self, snapshot: u64) -> Self {
        self.read_snapshot = Some(snapshot);
        self
    }

    /// Returns an owned object view.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error for an empty or oversized object name.
    pub fn object(&self, name: impl AsRef<[u8]>) -> Result<ObjectRef> {
        Ok(ObjectRef {
            pool: self.clone(),
            name: ObjectName::new(name)?,
        })
    }

    #[must_use]
    pub fn name(&self) -> &[u8] {
        self.name.as_bytes()
    }

    /// Returns the byte-preserving namespace.
    #[must_use]
    pub fn namespace(&self) -> &[u8] {
        self.namespace.as_bytes()
    }

    /// Returns the byte-preserving locator key.
    #[must_use]
    pub fn locator(&self) -> &[u8] {
        self.locator.as_bytes()
    }

    /// Returns the selected read snapshot, if any.
    #[must_use]
    pub const fn read_snapshot(&self) -> Option<u64> {
        self.read_snapshot
    }

    /// Returns the shared client handle.
    #[must_use]
    pub const fn client(&self) -> &Client {
        &self.client
    }
}

/// An immutable object view with owned byte identities.
#[derive(Clone, Debug)]
pub struct ObjectRef {
    pool: Pool,
    name: ObjectName,
}

impl ObjectRef {
    #[must_use]
    pub fn name(&self) -> &[u8] {
        self.name.as_bytes()
    }

    #[must_use]
    pub fn pool(&self) -> &Pool {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    fn client() -> Client {
        Client::new(
            Config::default()
                .with_monitors(["127.0.0.1:3300"])
                .expect("monitors"),
        )
        .expect("client")
    }

    #[test]
    fn immutable_views_copy_byte_identities() {
        let client = client();
        let pool = client.pool(b"pool").expect("pool");
        let sibling = pool
            .clone()
            .with_namespace([0xff, 0])
            .expect("namespace")
            .with_locator(b"locator")
            .expect("locator");
        let object = sibling.object([0, 0xfe]).expect("object");

        assert_eq!(pool.namespace(), b"");
        assert_eq!(object.pool().namespace(), [0xff, 0]);
        assert_eq!(object.name(), [0, 0xfe]);
    }

    #[test]
    fn close_is_shared_and_idempotent() {
        let client = client();
        let clone = client.clone();
        client.close();
        client.close();
        assert!(clone.is_closed());
        assert_eq!(
            clone.pool(b"pool").expect_err("closed").kind(),
            ErrorKind::Closed
        );
    }

    #[test]
    fn shutdown_is_shared_and_idempotent() {
        fn complete<T>(future: impl Future<Output = T>) -> T {
            let mut future = pin!(future);
            let mut context = Context::from_waker(Waker::noop());
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => value,
                Poll::Pending => panic!("local lifecycle future unexpectedly pending"),
            }
        }

        let client = client();
        complete(client.shutdown(OperationOptions::new())).expect("first shutdown");
        complete(client.shutdown(OperationOptions::new())).expect("repeated shutdown");
        assert!(client.is_closed());
    }

    #[test]
    fn public_handles_and_builders_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<Client>();
        assert_send_sync::<Pool>();
        assert_send_sync::<ObjectRef>();
        assert_send_sync::<ReadOp>();
        assert_send_sync::<WriteOp>();
        assert_send_sync::<CancellationToken>();
        assert_send_sync::<OperationOptions>();
        assert_send_sync::<Config>();
        assert_send_sync::<SecretKey>();
        assert_send_sync::<Error>();
        assert_send_sync::<ErrorKind>();
        assert_send_sync::<ObjectName>();
        assert_send_sync::<Namespace>();
        assert_send_sync::<LocatorKey>();
        assert_send_sync::<ObjectInfo>();
        assert_send_sync::<SubOperationResult>();
        assert_send_sync::<OperationResult>();
        assert_send_sync::<ClassResult>();
        assert_send_sync::<SubOperationFlags>();
        assert_send_sync::<Xattr>();
        assert_send_sync::<OmapEntry>();
        assert_send_sync::<Page<ObjectEntry>>();
        assert_send_sync::<ObjectEntry>();
        assert_send_sync::<ObjectCursor>();
        assert_send_sync::<ObjectPage>();
        assert_send_sync::<Watch>();
        assert_send_sync::<WatchEvent>();
        assert_send_sync::<NotifyAcknowledgment>();
        assert_send_sync::<NotifyTimeout>();
        assert_send_sync::<NotifyReply>();
        assert_send_sync::<Watcher>();
        assert_send_sync::<LockMode>();
        assert_send_sync::<LockOptions>();
        assert_send_sync::<Locker>();
        assert_send_sync::<Snapshot>();
        assert_send_sync::<SnapshotContext>();
        assert_send_sync::<ClusterStats>();
        assert_send_sync::<PoolStats>();
        assert_send_sync::<CommandResult>();
        assert_send_sync::<SparseExtent>();
        assert_send_sync::<ChecksumType>();
        assert_send_sync::<InconsistentObject>();
        assert_send_sync::<InconsistentPg>();
    }
}
