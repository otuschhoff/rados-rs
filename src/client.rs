use crate::cephx::connector;
use crate::cephx::core::{SERVICE_AUTH, SERVICE_MONITOR, TicketBlob};
use crate::maps::{Fsid, Limits as MapLimits};
use crate::mon::client::{
    MonitorClient, MonitorConfig, MonitorError, SessionFactory, authenticated_session_factory,
};
use crate::mon::messages::MessageLimits;
use crate::mon::seeds::{SeedError, SeedLimits, resolve_seeds};
use crate::msgr::control::ClientIdent;
use crate::msgr::frame::Limits as FrameLimits;
use crate::msgr::session::{Config as SessionConfig, ReconnectPolicy, SessionError};
use crate::protocol::address::{EntityAddr, EntityAddrVec};
use crate::protocol::features::GlobalFeatures;
use crate::{
    Config, Error, ErrorKind, LocatorKey, Namespace, ObjectName, OperationOptions, Result,
    SecurityMode,
};
use std::fmt;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

const MAX_KEY_BYTES: usize = 65_536;
const FRAME_LIMITS: FrameLimits = FrameLimits {
    max_segment_bytes: 8 << 20,
    max_frame_bytes: 32 << 20,
    max_addresses: 64,
    max_auth_bytes: 1 << 20,
};
const MAP_LIMITS: MapLimits = MapLimits {
    max_bytes: 32 << 20,
    max_monitors: 64,
    max_addresses: 64,
    max_locations: 64,
    max_pools: 4096,
    max_osds: 65_536,
    max_pg_mappings: 1 << 20,
    max_collection_entries: 1 << 20,
};
const CANCELLATION_POLL: Duration = Duration::from_millis(10);

struct ClientInner {
    config: Config,
    closed: AtomicBool,
    lifecycle: Mutex<()>,
    monitor: RwLock<Option<Arc<MonitorClient>>>,
    #[cfg(test)]
    factory: Option<SessionFactory>,
}

/// A cheaply clonable client handle. Construction performs no network I/O.
#[derive(Clone)]
pub struct Client(Arc<ClientInner>);

impl fmt::Debug for Client {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Client")
            .field("config", &self.0.config)
            .field("closed", &self.is_closed())
            .field(
                "connected",
                &self
                    .monitor()
                    .is_some_and(|monitor| monitor_is_ready(&monitor)),
            )
            .finish()
    }
}

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
            lifecycle: Mutex::new(()),
            monitor: RwLock::new(None),
            #[cfg(test)]
            factory: None,
        })))
    }

    #[cfg(test)]
    fn with_factory(config: Config, factory: SessionFactory) -> Result<Self> {
        config.validate()?;
        Ok(Self(Arc::new(ClientInner {
            config,
            closed: AtomicBool::new(false),
            lifecycle: Mutex::new(()),
            monitor: RwLock::new(None),
            factory: Some(factory),
        })))
    }

    /// Connects and authenticates the client, then waits for initial monitor maps.
    ///
    /// # Errors
    ///
    /// Returns a stable configuration, transport, authentication, cancellation, or timeout error.
    pub async fn connect(&self, options: OperationOptions) -> Result<()> {
        let options = bounded_options(
            options,
            self.0.config.operation_timeout(),
            "Client::connect",
        )?;
        self.ready("Client::connect", &options)?;
        let _lifecycle = match self.0.lifecycle.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                wait_client_bounded(
                    async { Ok(self.0.lifecycle.lock().await) },
                    &options,
                    "Client::connect",
                )
                .await?
            }
        };
        self.ready("Client::connect", &options)?;
        if self
            .monitor()
            .is_some_and(|monitor| monitor_is_ready(&monitor))
        {
            return Ok(());
        }
        if let Some(stale) = self.take_monitor() {
            stale.close();
            let _ = wait_shutdown_bounded(stale, &options, "Client::connect").await;
        }

        let (config, factory) =
            wait_client_bounded(self.monitor_configuration(), &options, "Client::connect").await?;
        let monitor = Arc::new(
            MonitorClient::spawn(config, factory)
                .map_err(|error| map_monitor_error(error, "Client::connect"))?,
        );
        if !self.install_monitor(Arc::clone(&monitor)) {
            monitor.close();
            let _ = wait_shutdown_bounded(monitor, &options, "Client::connect").await;
            return Err(Error::closed("Client::connect"));
        }
        let result = wait_bounded(monitor.wait_ready(), &options, "Client::connect").await;
        if result.is_err() || self.is_closed() {
            self.remove_monitor(&monitor);
            monitor.close();
            let _ = wait_shutdown_bounded(monitor, &options, "Client::connect").await;
            return result.and_then(|_| Err(Error::closed("Client::connect")));
        }
        Ok(())
    }

    /// Returns the connected cluster FSID.
    #[must_use]
    pub fn fsid(&self) -> Option<String> {
        self.monitor()
            .filter(|monitor| monitor.terminal().is_none())
            .and_then(|monitor| monitor.snapshot().connected_fsid())
            .map(|fsid| fsid.to_string())
    }

    /// Returns the authenticated monitor-assigned global instance ID.
    #[must_use]
    pub fn instance_id(&self) -> Option<u64> {
        self.monitor()
            .filter(|monitor| monitor.terminal().is_none())
            .and_then(|monitor| monitor.snapshot().global_id())
    }

    /// Lists current pool names in deterministic order.
    ///
    /// # Errors
    ///
    /// Returns cancellation, deadline, closure, or not-connected errors.
    pub async fn list_pools(&self, options: OperationOptions) -> Result<Vec<String>> {
        std::future::ready(()).await;
        self.ready("Client::list_pools", &options)?;
        let monitor = self.connected_monitor("Client::list_pools")?;
        Ok(monitor
            .snapshot()
            .list_pools()
            .into_iter()
            .map(|pool| pool.name().to_owned())
            .collect())
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
        let monitor = self.connected_monitor("Client::open_pool")?;
        let state = monitor.snapshot();
        let map = state
            .osdmap()
            .ok_or_else(|| Error::not_connected("Client::open_pool"))?;
        let text = std::str::from_utf8(name.as_bytes()).map_err(|_| {
            Error::new(ErrorKind::NotFound)
                .with_operation("Client::open_pool")
                .with_safe_target(name.as_bytes())
        })?;
        let pool = map.pool_by_name(text).ok_or_else(|| {
            Error::new(ErrorKind::NotFound)
                .with_operation("Client::open_pool")
                .with_safe_target(name.as_bytes())
        })?;
        self.resolved_pool(pool.id(), pool.name().as_bytes())
    }

    /// Opens an immutable pool view by its current numeric ID.
    ///
    /// # Errors
    ///
    /// Returns cancellation, deadline, closure, not-connected, or not-found errors.
    pub async fn open_pool_by_id(&self, id: i64, options: OperationOptions) -> Result<Pool> {
        std::future::ready(()).await;
        self.ready("Client::open_pool_by_id", &options)?;
        let monitor = self.connected_monitor("Client::open_pool_by_id")?;
        let state = monitor.snapshot();
        let map = state
            .osdmap()
            .ok_or_else(|| Error::not_connected("Client::open_pool_by_id"))?;
        let pool = map.pool_by_id(id).ok_or_else(|| {
            Error::new(ErrorKind::NotFound).with_operation("Client::open_pool_by_id")
        })?;
        self.resolved_pool(pool.id(), pool.name().as_bytes())
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
            id: None,
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
        let options = bounded_options(
            options,
            self.0.config.operation_timeout(),
            "Client::shutdown",
        )?;
        options.check("Client::shutdown")?;
        self.close();
        let _lifecycle = match self.0.lifecycle.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                wait_client_bounded(
                    async { Ok(self.0.lifecycle.lock().await) },
                    &options,
                    "Client::shutdown",
                )
                .await?
            }
        };
        let Some(monitor) = self.monitor() else {
            return Ok(());
        };
        wait_shutdown_bounded(Arc::clone(&monitor), &options, "Client::shutdown").await?;
        self.remove_monitor(&monitor);
        Ok(())
    }

    /// Idempotently closes the shared client without blocking or network I/O.
    pub fn close(&self) {
        self.0.closed.store(true, Ordering::Release);
        if let Some(monitor) = self.monitor() {
            monitor.close();
        }
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

    fn connected_monitor(&self, operation: &'static str) -> Result<Arc<MonitorClient>> {
        let monitor = self
            .monitor()
            .ok_or_else(|| Error::not_connected(operation))?;
        if !monitor_is_ready(&monitor) {
            return Err(Error::not_connected(operation));
        }
        Ok(monitor)
    }

    fn resolved_pool(&self, id: i64, name: &[u8]) -> Result<Pool> {
        Ok(Pool {
            client: self.clone(),
            id: Some(id),
            name: ObjectName::new(name)?,
            namespace: Namespace::new([])?,
            locator: LocatorKey::new([])?,
            read_snapshot: None,
        })
    }

    fn monitor(&self) -> Option<Arc<MonitorClient>> {
        self.0
            .monitor
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn install_monitor(&self, monitor: Arc<MonitorClient>) -> bool {
        let mut slot = self
            .0
            .monitor
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.is_closed() {
            return false;
        }
        *slot = Some(monitor);
        true
    }

    fn take_monitor(&self) -> Option<Arc<MonitorClient>> {
        self.0
            .monitor
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    fn remove_monitor(&self, monitor: &Arc<MonitorClient>) {
        let mut slot = self
            .0
            .monitor
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, monitor))
        {
            *slot = None;
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn monitor_configuration(&self) -> Result<(MonitorConfig, SessionFactory)> {
        let key = self
            .0
            .config
            .key()
            .ok_or_else(|| Error::invalid("Client::connect"))?;
        let encoded_key =
            std::str::from_utf8(key.expose()).map_err(|_| Error::invalid("Client::connect"))?;
        let credential =
            crate::cephx::parse_key(self.0.config.entity(), encoded_key, MAX_KEY_BYTES)
                .map_err(|_| Error::invalid("Client::connect"))?;
        let endpoints = resolve_seeds(
            self.0.config.monitors(),
            None,
            SeedLimits {
                max_seeds: 64,
                max_addresses: 64,
            },
        )
        .await
        .map_err(|error| map_seed_error(&error, "Client::connect"))?;
        let expected_fsid = self.0.config.cluster_fsid().map(parse_fsid).transpose()?;
        let placeholder =
            EntityAddr::ipv4_v2(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
                .map_err(|_| Error::invalid("Client::connect"))?;
        let client_cookie = random_nonzero("Client::connect")?;
        let session_config = SessionConfig {
            limits: FRAME_LIMITS,
            max_queued_messages: 16,
            max_retained_bytes: 1 << 20,
            max_in_flight_transactions: 16,
            max_reconnect_attempts: 2,
            max_handshake_transitions: 16,
            reconnect_policy: ReconnectPolicy::ReplayPending,
            client_ident: ClientIdent {
                addresses: EntityAddrVec(vec![placeholder.clone()]),
                target_address: placeholder.clone(),
                global_id: 0,
                global_sequence: 0,
                supported_features: GlobalFeatures::MONITOR_CLIENT.0,
                required_features: GlobalFeatures::MESSAGE_ADDRESS_V2.0,
                flags: 0,
                cookie: 0,
            },
            client_cookie,
            server_cookie: 0,
            global_sequence: 0,
            connect_sequence: 0,
            replacement_cookies: vec![
                random_nonzero("Client::connect")?,
                random_nonzero("Client::connect")?,
                random_nonzero("Client::connect")?,
            ],
        };
        let connector_config = connector::Config {
            credential,
            target_address: placeholder,
            message_limits: FRAME_LIMITS,
            cephx_limits: crate::cephx::crypto::Limits::default(),
            handshake_timeout: self.0.config.handshake_timeout(),
            max_banner_payload: 64,
            requested_keys: SERVICE_AUTH | SERVICE_MONITOR,
            allow_crc: self.0.config.security_mode() == SecurityMode::Crc,
            global_id: 0,
            old_ticket: TicketBlob {
                secret_id: 0,
                blob: Vec::new(),
            },
            now: Arc::new(unix_now),
            challenge: Arc::new(crate::cephx::connector::MonitorConnector::os_challenge),
        };
        #[cfg(test)]
        let factory = self.0.factory.clone().unwrap_or_else(|| {
            authenticated_session_factory(
                connector_config,
                session_config,
                self.0.config.dial_timeout(),
            )
        });
        #[cfg(not(test))]
        let factory = authenticated_session_factory(
            connector_config,
            session_config,
            self.0.config.dial_timeout(),
        );
        Ok((
            MonitorConfig {
                seeds: endpoints,
                expected_fsid,
                hostname: self.0.config.entity().to_owned(),
                map_limits: MAP_LIMITS,
                message_limits: MessageLimits {
                    max_bytes: 32 << 20,
                    max_maps: 16,
                },
                max_seed_attempts: 64,
                history_limit: 2,
                operation_timeout: self.0.config.operation_timeout(),
                retry_delay: Duration::from_millis(100),
                subscribe_period: Duration::from_secs(30),
                error_capacity: 16,
            },
            factory,
        ))
    }
}

/// An immutable pool view.
#[derive(Clone, Debug)]
pub struct Pool {
    client: Client,
    id: Option<i64>,
    name: ObjectName,
    namespace: Namespace,
    locator: LocatorKey,
    read_snapshot: Option<u64>,
}

impl Pool {
    /// Returns the current numeric pool ID, or `None` for an unresolved view.
    #[must_use]
    pub const fn id(&self) -> Option<i64> {
        self.id
    }

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

fn parse_fsid(value: &str) -> Result<Fsid> {
    let compact = value
        .bytes()
        .filter(|byte| *byte != b'-')
        .collect::<Vec<_>>();
    if compact.len() != 32 {
        return Err(Error::invalid("Client::connect"));
    }
    let mut bytes = [0_u8; 16];
    let (pairs, remainder) = compact.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(Error::invalid("Client::connect"));
    }
    for (index, pair) in pairs.iter().enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| Error::invalid("Client::connect"))?;
        bytes[index] =
            u8::from_str_radix(text, 16).map_err(|_| Error::invalid("Client::connect"))?;
    }
    Ok(Fsid(bytes))
}

fn random_nonzero(operation: &'static str) -> Result<u64> {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes)
        .map_err(|_| Error::new(ErrorKind::Unknown).with_operation(operation))?;
    Ok(u64::from_le_bytes(bytes).max(1))
}

fn unix_now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
}

async fn wait_bounded<T>(
    future: impl Future<Output = std::result::Result<T, MonitorError>>,
    options: &OperationOptions,
    operation: &'static str,
) -> Result<T> {
    wait_client_bounded(
        async {
            future
                .await
                .map_err(|error| map_monitor_error(error, operation))
        },
        options,
        operation,
    )
    .await
}

fn bounded_options(
    options: OperationOptions,
    default_timeout: Duration,
    operation: &'static str,
) -> Result<OperationOptions> {
    let default_deadline = Instant::now()
        .checked_add(default_timeout)
        .ok_or_else(|| Error::invalid(operation))?;
    let deadline = options
        .deadline()
        .map_or(default_deadline, |deadline| deadline.min(default_deadline));
    Ok(options.with_deadline(deadline))
}

async fn wait_client_bounded<T>(
    future: impl Future<Output = Result<T>>,
    options: &OperationOptions,
    operation: &'static str,
) -> Result<T> {
    options.check(operation)?;
    let deadline = options
        .deadline()
        .ok_or_else(|| Error::invalid(operation))?;
    let timeout = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
    let cancellation = tokio::time::sleep(CANCELLATION_POLL);
    tokio::pin!(future, timeout, cancellation);
    loop {
        tokio::select! {
            result = &mut future => return result,
            () = &mut timeout => return Err(Error::new(ErrorKind::Timeout).with_operation(operation)),
            () = &mut cancellation => {
                if options.is_canceled() {
                    return Err(Error::new(ErrorKind::Canceled).with_operation(operation));
                }
                cancellation.as_mut().reset(tokio::time::Instant::now() + CANCELLATION_POLL);
            }
        }
    }
}

async fn wait_shutdown_bounded(
    monitor: Arc<MonitorClient>,
    options: &OperationOptions,
    operation: &'static str,
) -> Result<()> {
    wait_client_bounded(
        async move {
            monitor.shutdown().await;
            Ok(())
        },
        options,
        operation,
    )
    .await
}

fn monitor_is_ready(monitor: &MonitorClient) -> bool {
    monitor.terminal().is_none() && monitor.snapshot().osdmap().is_some()
}

fn map_monitor_error(error: MonitorError, operation: &'static str) -> Error {
    let kind = match error {
        MonitorError::Closed | MonitorError::Session(SessionError::Closed) => ErrorKind::Closed,
        MonitorError::InvalidConfig => ErrorKind::InvalidArgument,
        MonitorError::ConnectTimeout => ErrorKind::Timeout,
        MonitorError::ForeignCluster | MonitorError::MapGap => ErrorKind::Conflict,
        MonitorError::Session(SessionError::Cancelled) => ErrorKind::Canceled,
        MonitorError::Session(
            SessionError::UnsupportedFeature | SessionError::UnsupportedPayload,
        ) => ErrorKind::Unsupported,
        MonitorError::Session(SessionError::OutcomeUnknown) => ErrorKind::OutcomeUnknown,
        MonitorError::AttemptsExhausted
        | MonitorError::IdentityUnavailable
        | MonitorError::Session(_)
        | MonitorError::Message(_)
        | MonitorError::Map(_) => ErrorKind::NotConnected,
    };
    Error::new(kind).with_operation(operation)
}

fn map_seed_error(error: &SeedError, operation: &'static str) -> Error {
    let kind = match error {
        SeedError::Lookup { .. } => ErrorKind::NotConnected,
        SeedError::LimitExceeded | SeedError::Malformed(_) | SeedError::UnsupportedVersion => {
            ErrorKind::InvalidArgument
        }
    };
    Error::new(kind).with_operation(operation)
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

#[cfg(all(test, not(rados_packaged_source)))]
mod tests {
    use super::*;
    use crate::mon::client::{MonitorSession, OpenedMonitorSession};
    use crate::mon::messages::{MESSAGE_MON_MAP, MESSAGE_OSD_MAP};
    use crate::msgr::message::{Message, MessageHeader, MessageLengths};
    use crate::wire::Encoder;
    use crate::*;
    use std::future::Future;
    use std::pin::pin;
    use std::sync::atomic::AtomicUsize;
    use std::task::{Context, Poll, Waker};
    use tokio::sync::mpsc;

    const KEY: &str = "AQB7AAAAyAEAABAAMTIzNDU2Nzg5MDEyMzQ1Ng==";

    struct FakeSession {
        incoming: Mutex<mpsc::Receiver<Message>>,
        sent: mpsc::Sender<Message>,
        closed: AtomicBool,
    }

    impl MonitorSession for FakeSession {
        fn send(
            &self,
            message: Message,
        ) -> std::pin::Pin<
            Box<dyn Future<Output = std::result::Result<(), SessionError>> + Send + '_>,
        > {
            Box::pin(async move {
                self.sent
                    .send(message)
                    .await
                    .map_err(|_| SessionError::Closed)
            })
        }

        fn next_incoming(
            &self,
        ) -> std::pin::Pin<Box<dyn Future<Output = Option<Message>> + Send + '_>> {
            Box::pin(async move { self.incoming.lock().await.recv().await })
        }

        fn next_failure(
            &self,
        ) -> std::pin::Pin<Box<dyn Future<Output = SessionError> + Send + '_>> {
            Box::pin(std::future::pending())
        }

        fn close(&self) {
            self.closed.store(true, Ordering::Release);
        }

        fn shutdown(&self) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            Box::pin(async {})
        }
    }

    fn configured() -> Config {
        Config::default()
            .with_monitors(["127.0.0.1:3300"])
            .expect("monitors")
            .with_key(SecretKey::new(KEY).expect("key"))
    }

    fn front_message(
        message_type: u16,
        version: u16,
        compat_version: u16,
        front: Vec<u8>,
    ) -> Message {
        Message {
            header: MessageHeader {
                message_type,
                version,
                compat_version,
                ..MessageHeader::default()
            },
            lengths: MessageLengths {
                front: u32::try_from(front.len()).expect("message length"),
                ..MessageLengths::default()
            },
            front,
            ..Message::default()
        }
    }

    fn monmap_message(bytes: &[u8]) -> Message {
        let mut encoder = Encoder::new((bytes.len() + 4) * 2);
        encoder.bytes(bytes);
        front_message(
            MESSAGE_MON_MAP,
            1,
            1,
            encoder.finish().expect("monmap message"),
        )
    }

    fn osdmap_message(fsid: Fsid, epoch: u32, bytes: &[u8]) -> Message {
        let mut encoder = Encoder::new((bytes.len() + 256) * 2);
        encoder.raw(&fsid.0);
        encoder.u32(0);
        encoder.u32(1);
        encoder.u32(epoch);
        encoder.bytes(bytes);
        encoder.u32(0);
        encoder.u32(epoch);
        front_message(
            MESSAGE_OSD_MAP,
            3,
            1,
            encoder.finish().expect("OSD map message"),
        )
    }

    fn client() -> Client {
        Client::new(
            Config::default()
                .with_monitors(["127.0.0.1:3300"])
                .expect("monitors"),
        )
        .expect("client")
    }

    #[tokio::test]
    async fn connect_publishes_identity_and_current_pools_idempotently() {
        let (incoming_tx, incoming_rx) = mpsc::channel(4);
        let (sent_tx, mut sent_rx) = mpsc::channel(4);
        let session = Arc::new(FakeSession {
            incoming: Mutex::new(incoming_rx),
            sent: sent_tx,
            closed: AtomicBool::new(false),
        });
        let opened = Arc::new(Mutex::new(Some(OpenedMonitorSession {
            session: session.clone(),
            global_id: 42,
        })));
        let calls = Arc::new(AtomicUsize::new(0));
        let factory: SessionFactory = Arc::new({
            let opened = Arc::clone(&opened);
            let calls = Arc::clone(&calls);
            move |_| {
                let opened = Arc::clone(&opened);
                calls.fetch_add(1, Ordering::Relaxed);
                Box::pin(async move { Ok(opened.lock().await.take().expect("single session")) })
            }
        });
        let client = Client::with_factory(configured(), factory).expect("client");
        let connecting = tokio::spawn({
            let client = client.clone();
            async move { client.connect(OperationOptions::new()).await }
        });
        sent_rx.recv().await.expect("subscription");
        let mon_bytes = include_bytes!("../testdata/p04/monmap-v9.bin");
        let monmap = crate::maps::decode_monmap(mon_bytes, MAP_LIMITS).expect("monmap fixture");
        let osd_bytes = include_bytes!("../testdata/p04/osdmap-v8.bin");
        let osdmap = crate::maps::decode_osdmap(osd_bytes, MAP_LIMITS).expect("OSD map fixture");
        incoming_tx
            .send(monmap_message(mon_bytes))
            .await
            .expect("monmap");
        incoming_tx
            .send(osdmap_message(osdmap.fsid(), osdmap.epoch(), osd_bytes))
            .await
            .expect("OSD map");
        connecting.await.expect("connect task").expect("connect");

        assert_eq!(client.fsid(), Some(monmap.fsid().to_string()));
        assert_eq!(client.instance_id(), Some(42));
        client
            .connect(OperationOptions::new())
            .await
            .expect("idempotent connect");
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        let names = client
            .list_pools(OperationOptions::new())
            .await
            .expect("pools");
        assert_eq!(names.len(), osdmap.pools().len());
        if let Some(expected) = osdmap.pools().next() {
            let by_name = client
                .open_pool(expected.name().as_bytes(), OperationOptions::new())
                .await
                .expect("pool by name");
            let by_id = client
                .open_pool_by_id(expected.id(), OperationOptions::new())
                .await
                .expect("pool by ID");
            assert_eq!(by_name.id(), Some(expected.id()));
            assert_eq!(by_id.name(), expected.name().as_bytes());
        }
        assert_eq!(
            client
                .open_pool_by_id(i64::MIN, OperationOptions::new())
                .await
                .expect_err("unknown pool")
                .kind(),
            ErrorKind::NotFound
        );
        client
            .shutdown(OperationOptions::new())
            .await
            .expect("shutdown");
        client
            .shutdown(OperationOptions::new())
            .await
            .expect("idempotent shutdown");
        assert!(session.closed.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn connect_checks_key_cancellation_deadline_and_closed_state() {
        let missing_key = client();
        assert_eq!(
            missing_key
                .connect(OperationOptions::new())
                .await
                .expect_err("missing key")
                .kind(),
            ErrorKind::InvalidArgument
        );
        assert_eq!(
            missing_key
                .list_pools(OperationOptions::new())
                .await
                .expect_err("not connected")
                .kind(),
            ErrorKind::NotConnected
        );
        assert_eq!(missing_key.pool(b"local").expect("pool").id(), None);

        let pending: SessionFactory = Arc::new(|_| Box::pin(std::future::pending()));
        let canceled_client =
            Client::with_factory(configured(), Arc::clone(&pending)).expect("client");
        let cancellation = CancellationToken::new();
        let task = tokio::spawn({
            let client = canceled_client.clone();
            let cancellation = cancellation.clone();
            async move {
                client
                    .connect(OperationOptions::new().with_cancellation(cancellation))
                    .await
            }
        });
        tokio::task::yield_now().await;
        cancellation.cancel();
        assert_eq!(
            task.await
                .expect("connect task")
                .expect_err("canceled")
                .kind(),
            ErrorKind::Canceled
        );

        let deadline_client = Client::with_factory(configured(), pending).expect("client");
        assert_eq!(
            deadline_client
                .connect(
                    OperationOptions::new()
                        .with_timeout(Duration::from_millis(1))
                        .expect("timeout"),
                )
                .await
                .expect_err("deadline")
                .kind(),
            ErrorKind::Timeout
        );
        deadline_client.close();
        assert_eq!(
            deadline_client
                .connect(OperationOptions::new())
                .await
                .expect_err("closed")
                .kind(),
            ErrorKind::Closed
        );
    }

    #[tokio::test]
    async fn terminal_monitor_state_is_not_connected() {
        let (incoming_tx, incoming_rx) = mpsc::channel(4);
        let (sent_tx, mut sent_rx) = mpsc::channel(4);
        let session = Arc::new(FakeSession {
            incoming: Mutex::new(incoming_rx),
            sent: sent_tx,
            closed: AtomicBool::new(false),
        });
        let opened = Arc::new(Mutex::new(Some(OpenedMonitorSession {
            session,
            global_id: 42,
        })));
        let factory: SessionFactory = Arc::new(move |_| {
            let opened = Arc::clone(&opened);
            Box::pin(async move {
                opened
                    .lock()
                    .await
                    .take()
                    .ok_or(MonitorError::AttemptsExhausted)
            })
        });
        let client = Client::with_factory(configured(), factory).expect("client");
        let connecting = tokio::spawn({
            let client = client.clone();
            async move { client.connect(OperationOptions::new()).await }
        });
        sent_rx.recv().await.expect("subscription");
        let mon_bytes = include_bytes!("../testdata/p04/monmap-v9.bin");
        let osd_bytes = include_bytes!("../testdata/p04/osdmap-v8.bin");
        let osdmap = crate::maps::decode_osdmap(osd_bytes, MAP_LIMITS).expect("OSD map fixture");
        incoming_tx
            .send(monmap_message(mon_bytes))
            .await
            .expect("monmap");
        incoming_tx
            .send(osdmap_message(osdmap.fsid(), osdmap.epoch(), osd_bytes))
            .await
            .expect("OSD map");
        connecting.await.expect("connect task").expect("connect");
        drop(incoming_tx);

        let monitor = client.monitor().expect("monitor");
        while monitor.terminal().is_none() {
            tokio::task::yield_now().await;
        }
        assert_eq!(client.fsid(), None);
        assert_eq!(client.instance_id(), None);
        assert_eq!(
            client
                .list_pools(OperationOptions::new())
                .await
                .expect_err("terminal monitor")
                .kind(),
            ErrorKind::NotConnected
        );
        client
            .shutdown(OperationOptions::new())
            .await
            .expect("shutdown");
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

    #[tokio::test]
    async fn closed_client_rejects_monitor_publication() {
        let pending: SessionFactory = Arc::new(|_| Box::pin(std::future::pending()));
        let address = "127.0.0.1:3300".parse().expect("address");
        let monitor = Arc::new(
            MonitorClient::spawn(
                MonitorConfig {
                    seeds: vec![crate::mon::seeds::Endpoint {
                        address,
                        entity_address: EntityAddr::ipv4_v2(address).expect("entity address"),
                        priority: 0,
                        weight: 0,
                    }],
                    expected_fsid: None,
                    hostname: "test".to_owned(),
                    map_limits: MAP_LIMITS,
                    message_limits: MessageLimits {
                        max_bytes: 1024,
                        max_maps: 1,
                    },
                    max_seed_attempts: 1,
                    history_limit: 0,
                    operation_timeout: Duration::from_secs(1),
                    retry_delay: Duration::ZERO,
                    subscribe_period: Duration::from_secs(1),
                    error_capacity: 1,
                },
                pending,
            )
            .expect("monitor"),
        );
        let client = client();
        client.close();
        assert!(!client.install_monitor(Arc::clone(&monitor)));
        assert!(client.monitor().is_none());
        monitor.close();
        monitor.shutdown().await;
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
