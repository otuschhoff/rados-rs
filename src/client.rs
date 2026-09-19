use crate::cephx::connector;
use crate::cephx::core::{SERVICE_AUTH, SERVICE_MONITOR, SERVICE_OSD, TicketBlob};
use crate::maps::{Fsid, Limits as MapLimits};
use crate::mon::client::{
    MonitorClient, MonitorConfig, MonitorError, SessionFactory, authenticated_session_factory,
};
use crate::mon::messages::MessageLimits;
use crate::mon::seeds::{SeedError, SeedLimits, resolve_seeds};
use crate::msgr::control::ClientIdent;
use crate::msgr::frame::Limits as FrameLimits;
use crate::msgr::session::{Config as SessionConfig, ReconnectPolicy, SessionError};
use crate::osd::metadata;
use crate::osd::{
    Client as OSDClient, ClientError, CompoundResult, HObject, NO_SNAP, OSDMutation,
    Operation as OSDOperation, Target as OSDTarget, compare_hobject,
};
use crate::protocol::address::{EntityAddr, EntityAddrVec};
use crate::protocol::features::GlobalFeatures;
use crate::{
    Config, Error, ErrorKind, LocatorKey, Namespace, ObjectEntry, ObjectInfo, ObjectName,
    ObjectPage, OmapEntry, OpResult, OperationOptions, Page, ReadOp, Result, SecurityMode,
    SubOperationResult, WriteOp, Xattr,
};
use std::cmp::Ordering as CmpOrdering;
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
    authority: Arc<RwLock<Option<Arc<connector::MonitorConnector>>>>,
    objecter: Arc<OSDClient>,
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
        let authority = Arc::new(RwLock::new(None));
        let objecter = Arc::new(OSDClient::new(
            Arc::clone(&authority),
            FRAME_LIMITS,
            config.dial_timeout(),
            config.handshake_timeout(),
            config.security_mode() == SecurityMode::Crc,
        ));
        Ok(Self(Arc::new(ClientInner {
            config,
            closed: AtomicBool::new(false),
            lifecycle: Mutex::new(()),
            monitor: RwLock::new(None),
            authority,
            objecter,
            #[cfg(test)]
            factory: None,
        })))
    }

    #[cfg(test)]
    fn with_factory(config: Config, factory: SessionFactory) -> Result<Self> {
        config.validate()?;
        let authority = Arc::new(RwLock::new(None));
        let objecter = Arc::new(OSDClient::new(
            Arc::clone(&authority),
            FRAME_LIMITS,
            config.dial_timeout(),
            config.handshake_timeout(),
            config.security_mode() == SecurityMode::Crc,
        ));
        Ok(Self(Arc::new(ClientInner {
            config,
            closed: AtomicBool::new(false),
            lifecycle: Mutex::new(()),
            monitor: RwLock::new(None),
            authority,
            objecter,
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
            self.clear_authority();
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
        let operation = "Client::flush";
        let options = bounded_options(options, self.0.config.operation_timeout(), operation)?;
        self.ready(operation, &options)?;
        self.connected_monitor(operation)?;
        self.0
            .objecter
            .flush(&options)
            .await
            .map_err(|error| map_osd_error(error, operation))
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
        self.0.objecter.begin_shutdown();
        let flush_result = self
            .0
            .objecter
            .flush(&options)
            .await
            .map_err(|error| map_osd_error(error, "Client::shutdown"));
        let mut cleanup_result = Ok(());
        self.close();
        if self.0.objecter.has_sessions()
            && let Err(error) = wait_client_bounded(
                async {
                    self.0.objecter.shutdown().await;
                    Ok(())
                },
                &options,
                "Client::shutdown",
            )
            .await
        {
            cleanup_result = Err(error);
        }
        if let Some(monitor) = self.monitor() {
            if let Err(error) =
                wait_shutdown_bounded(Arc::clone(&monitor), &options, "Client::shutdown").await
                && cleanup_result.is_ok()
            {
                cleanup_result = Err(error);
            }
            self.remove_monitor(&monitor);
        }
        flush_result.and(cleanup_result)
    }

    /// Idempotently closes the shared client without blocking or network I/O.
    pub fn close(&self) {
        self.0.closed.store(true, Ordering::Release);
        self.0.objecter.close();
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
            self.clear_authority();
        }
    }

    fn clear_authority(&self) {
        self.0
            .authority
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
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
            requested_keys: SERVICE_AUTH | SERVICE_MONITOR | SERVICE_OSD,
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
                Arc::clone(&self.0.authority),
            )
        });
        #[cfg(not(test))]
        let factory = authenticated_session_factory(
            connector_config,
            session_config,
            self.0.config.dial_timeout(),
            Arc::clone(&self.0.authority),
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

    /// Returns the first object-enumeration cursor for this pool view.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error for an unresolved pool.
    pub fn begin_object_cursor(&self) -> Result<crate::ObjectCursor> {
        let pool_id = self
            .id
            .ok_or_else(|| Error::invalid("Pool::begin_object_cursor"))?;
        new_object_cursor(
            pool_id,
            self.namespace.as_bytes(),
            &HObject {
                key: Vec::new(),
                object: Vec::new(),
                snapshot: 0,
                hash: 0,
                max: false,
                namespace: Vec::new(),
                pool: i64::MIN,
            },
        )
    }

    /// Returns the terminal object-enumeration cursor for this pool view.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error for an unresolved pool.
    pub fn end_object_cursor(&self) -> Result<crate::ObjectCursor> {
        let pool_id = self
            .id
            .ok_or_else(|| Error::invalid("Pool::end_object_cursor"))?;
        Ok(crate::ObjectCursor {
            pool_id,
            namespace: self.namespace.as_bytes().to_vec(),
            value: Vec::new(),
            end: true,
        })
    }

    /// Splits a cursor interval into near-equal reversed-hash partitions.
    ///
    /// # Errors
    ///
    /// Returns an invalid-argument error for foreign, reversed, or excessive partitions.
    pub fn split_cursor(
        &self,
        begin: &crate::ObjectCursor,
        end: &crate::ObjectCursor,
        partitions: u32,
    ) -> Result<Vec<crate::ObjectCursor>> {
        const MAX_PARTITIONS: u32 = 1 << 20;
        let pool_id = self
            .id
            .ok_or_else(|| Error::invalid("Pool::split_cursor"))?;
        if partitions == 0
            || partitions > MAX_PARTITIONS
            || !self.owns_cursor(begin)
            || !self.owns_cursor(end)
            || compare_object_cursors(begin, end)? == CmpOrdering::Greater
        {
            return Err(Error::invalid("Pool::split_cursor"));
        }
        if begin.is_end() {
            return Ok(vec![begin.clone(); partitions as usize + 1]);
        }
        let start = cursor_hobject(begin)?;
        let finish = cursor_hobject(end)?;
        let start_hash = u64::from(start.hash.reverse_bits());
        let finish_hash = if finish.max {
            1_u64 << 32
        } else {
            u64::from(finish.hash.reverse_bits())
        };
        let difference = finish_hash - start_hash;
        let mut boundaries = Vec::with_capacity(partitions as usize + 1);
        boundaries.push(begin.clone());
        for index in 1..partitions {
            let index = u64::from(index);
            let partition_count = u64::from(partitions);
            let reversed = start_hash
                + difference / partition_count * index
                + difference % partition_count * index / partition_count;
            if reversed >= 1_u64 << 32 {
                boundaries.push(self.end_object_cursor()?);
            } else {
                boundaries.push(new_object_cursor(
                    pool_id,
                    self.namespace.as_bytes(),
                    &HObject {
                        key: Vec::new(),
                        object: Vec::new(),
                        snapshot: NO_SNAP,
                        hash: u32::try_from(reversed)
                            .map_err(|_| Error::invalid("Pool::split_cursor"))?
                            .reverse_bits(),
                        max: false,
                        namespace: Vec::new(),
                        pool: pool_id,
                    },
                )?);
            }
        }
        boundaries.push(end.clone());
        Ok(boundaries)
    }

    /// Lists a bounded page of objects after `after`.
    ///
    /// # Errors
    ///
    /// Returns stable validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn list_objects(
        &self,
        after: &crate::ObjectCursor,
        limit: u64,
        options: OperationOptions,
    ) -> Result<ObjectPage> {
        let end = self.end_object_cursor()?;
        self.list_objects_range(after, &end, limit, options).await
    }

    /// Lists a bounded page of objects in the half-open cursor interval.
    ///
    /// # Errors
    ///
    /// Returns stable validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn list_objects_range(
        &self,
        after: &crate::ObjectCursor,
        end: &crate::ObjectCursor,
        limit: u64,
        options: OperationOptions,
    ) -> Result<ObjectPage> {
        let operation = "Pool::list_objects_range";
        let pool_id = self.id.ok_or_else(|| Error::invalid(operation))?;
        let max_entries = FRAME_LIMITS.max_frame_bytes / 12;
        if limit == 0
            || limit > max_entries
            || !self.owns_cursor(after)
            || !self.owns_cursor(end)
            || compare_object_cursors(after, end)? == CmpOrdering::Greater
        {
            return Err(Error::invalid(operation));
        }
        let options =
            bounded_options(options, self.client.0.config.operation_timeout(), operation)?;
        self.client.ready(operation, &options)?;
        let monitor = self.client.connected_monitor(operation)?;
        let finish = cursor_hobject(end)?;
        let mut next = cursor_hobject(after)?;
        let mut values = Vec::with_capacity(usize::try_from(limit).unwrap_or_default());
        while values.len() < usize::try_from(limit).unwrap_or(usize::MAX)
            && compare_hobject(&next, &finish) == CmpOrdering::Less
        {
            let remaining =
                limit - u64::try_from(values.len()).map_err(|_| Error::invalid(operation))?;
            let page = self
                .client
                .0
                .objecter
                .pgnls(
                    &monitor,
                    pool_id,
                    self.namespace.as_bytes().to_vec(),
                    &next,
                    remaining,
                    &options,
                )
                .await
                .map_err(|error| map_osd_error(error, operation))?;
            let map = monitor
                .snapshot()
                .osdmap()
                .ok_or_else(|| Error::not_connected(operation))?;
            let mut entry_cursors = Vec::with_capacity(page.entries.len());
            for entry in &page.entries {
                if self.namespace.as_bytes() != b"\x01"
                    && entry.namespace != self.namespace.as_bytes()
                {
                    return Err(Error::not_connected(operation));
                }
                let placement = map
                    .map_object(pool_id, &entry.object, &entry.locator, &entry.namespace)
                    .map_err(|_| Error::not_connected(operation))?;
                entry_cursors.push(HObject {
                    key: entry.locator.clone(),
                    object: entry.object.clone(),
                    snapshot: NO_SNAP,
                    hash: placement.raw_hash,
                    max: false,
                    namespace: entry.namespace.clone(),
                    pool: pool_id,
                });
            }
            validate_enumeration_page(pool_id, &next, &page.next, &entry_cursors)
                .map_err(|_| Error::not_connected(operation))?;

            let available = usize::try_from(
                limit - u64::try_from(values.len()).map_err(|_| Error::invalid(operation))?,
            )
            .map_err(|_| Error::invalid(operation))?;
            let (page_next, entry_count) = clip_enumeration_page(
                page.next,
                page.entries.len(),
                &entry_cursors,
                &finish,
                available,
            );
            values.extend(
                page.entries
                    .into_iter()
                    .take(entry_count)
                    .map(|entry| ObjectEntry {
                        name: entry.object,
                        namespace: entry.namespace,
                        locator: entry.locator,
                    }),
            );
            next = page_next;
        }
        let next_cursor = if next.max {
            self.end_object_cursor()?
        } else {
            new_object_cursor(pool_id, self.namespace.as_bytes(), &next)?
        };
        let more = compare_hobject(&next, &finish) == CmpOrdering::Less;
        Ok(ObjectPage {
            values,
            next: next_cursor,
            more,
        })
    }

    fn owns_cursor(&self, cursor: &crate::ObjectCursor) -> bool {
        self.id == Some(cursor.pool_id) && self.namespace.as_bytes() == cursor.namespace
    }
}

fn validate_enumeration_page(
    pool_id: i64,
    start: &HObject,
    next: &HObject,
    entries: &[HObject],
) -> Result<()> {
    if !next.max && (next.pool == i64::MIN || next.snapshot != NO_SNAP || next.pool != pool_id) {
        return Err(Error::not_connected("Pool::list_objects_range"));
    }
    let mut previous = start;
    for entry in entries {
        if compare_hobject(entry, previous) == CmpOrdering::Less
            || (!next.max && compare_hobject(entry, next) != CmpOrdering::Less)
        {
            return Err(Error::not_connected("Pool::list_objects_range"));
        }
        previous = entry;
    }
    if !next.max && compare_hobject(next, start) != CmpOrdering::Greater {
        return Err(Error::not_connected("Pool::list_objects_range"));
    }
    Ok(())
}

fn clip_enumeration_page(
    mut next: HObject,
    mut entry_count: usize,
    entry_cursors: &[HObject],
    finish: &HObject,
    available: usize,
) -> (HObject, usize) {
    if compare_hobject(&next, finish) == CmpOrdering::Greater {
        next = finish.clone();
        while entry_count > 0
            && compare_hobject(&entry_cursors[entry_count - 1], finish) != CmpOrdering::Less
        {
            entry_count -= 1;
        }
    }
    if entry_count > available {
        next = entry_cursors[available].clone();
        entry_count = available;
    }
    (next, entry_count)
}

/// Compares two opaque cursors from the same pool and namespace.
///
/// # Errors
///
/// Returns an invalid-argument error for malformed or unrelated cursors.
pub fn compare_object_cursors(
    left: &crate::ObjectCursor,
    right: &crate::ObjectCursor,
) -> Result<CmpOrdering> {
    if left.pool_id != right.pool_id || left.namespace != right.namespace {
        return Err(Error::invalid("compare_object_cursors"));
    }
    match (left.end, right.end) {
        (true, true) => Ok(CmpOrdering::Equal),
        (true, false) => Ok(CmpOrdering::Greater),
        (false, true) => Ok(CmpOrdering::Less),
        (false, false) => Ok(compare_hobject(
            &cursor_hobject(left)?,
            &cursor_hobject(right)?,
        )),
    }
}

fn cursor_hobject(cursor: &crate::ObjectCursor) -> Result<HObject> {
    if cursor.end {
        return Ok(HObject {
            key: Vec::new(),
            object: Vec::new(),
            snapshot: 0,
            hash: 0,
            max: true,
            namespace: Vec::new(),
            pool: 0,
        });
    }
    let object = crate::osd::enumeration::unmarshal_cursor(&cursor.value)
        .map_err(|_| Error::invalid("ObjectCursor"))?;
    let minimum =
        object.snapshot == 0 && object.hash == 0 && !object.max && object.pool == i64::MIN;
    if object.max || (!minimum && (object.pool != cursor.pool_id || object.snapshot != NO_SNAP)) {
        return Err(Error::invalid("ObjectCursor"));
    }
    Ok(object)
}

fn new_object_cursor(
    pool_id: i64,
    namespace: &[u8],
    object: &HObject,
) -> Result<crate::ObjectCursor> {
    Ok(crate::ObjectCursor {
        pool_id,
        namespace: namespace.to_vec(),
        value: crate::osd::enumeration::marshal_cursor(object)
            .map_err(|_| Error::invalid("ObjectCursor"))?,
        end: false,
    })
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

impl Drop for ClientInner {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        self.objecter.close();
        if let Some(monitor) = self
            .monitor
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            monitor.close();
        }
    }
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

    /// Reads up to `length` bytes starting at `offset`.
    ///
    /// # Errors
    ///
    /// Returns stable routing, transport, deadline, cancellation, bounds, or Ceph errors.
    pub async fn read(
        &self,
        offset: u64,
        length: u64,
        options: OperationOptions,
    ) -> Result<(Vec<u8>, ObjectInfo)> {
        let operation = "ObjectRef::read";
        let options = bounded_options(
            options,
            self.pool.client.0.config.operation_timeout(),
            operation,
        )?;
        self.pool.client.ready(operation, &options)?;
        let monitor = self.pool.client.connected_monitor(operation)?;
        let target = self.target(&monitor, operation)?;
        let result = self
            .pool
            .client
            .0
            .objecter
            .read(&monitor, target, offset, length, &options)
            .await
            .map_err(|error| map_osd_error(error, operation))?;
        Ok((
            result.data,
            ObjectInfo {
                size: 0,
                modified_at: UNIX_EPOCH,
                version: result.version,
            },
        ))
    }

    /// Returns object size, modification time, and version.
    ///
    /// # Errors
    ///
    /// Returns stable routing, transport, deadline, cancellation, bounds, or Ceph errors.
    pub async fn stat(&self, options: OperationOptions) -> Result<ObjectInfo> {
        let operation = "ObjectRef::stat";
        let options = bounded_options(
            options,
            self.pool.client.0.config.operation_timeout(),
            operation,
        )?;
        self.pool.client.ready(operation, &options)?;
        let monitor = self.pool.client.connected_monitor(operation)?;
        let target = self.target(&monitor, operation)?;
        let result = self
            .pool
            .client
            .0
            .objecter
            .stat(&monitor, target, &options)
            .await
            .map_err(|error| map_osd_error(error, operation))?;
        let data: [u8; 16] = result
            .data
            .try_into()
            .map_err(|_| Error::new(ErrorKind::NotConnected).with_operation(operation))?;
        let size = u64::from_le_bytes(
            data[..8]
                .try_into()
                .map_err(|_| Error::new(ErrorKind::NotConnected).with_operation(operation))?,
        );
        let seconds = u32::from_le_bytes(
            data[8..12]
                .try_into()
                .map_err(|_| Error::new(ErrorKind::NotConnected).with_operation(operation))?,
        );
        let nanoseconds = u32::from_le_bytes(
            data[12..]
                .try_into()
                .map_err(|_| Error::new(ErrorKind::NotConnected).with_operation(operation))?,
        );
        if nanoseconds >= 1_000_000_000 {
            return Err(Error::new(ErrorKind::NotConnected).with_operation(operation));
        }
        Ok(ObjectInfo {
            size,
            modified_at: UNIX_EPOCH + Duration::new(u64::from(seconds), nanoseconds),
            version: result.version,
        })
    }

    /// Creates the object, optionally requiring that it does not already exist.
    ///
    /// # Errors
    ///
    /// Returns stable validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn create(&self, exclusive: bool, options: OperationOptions) -> Result<OpResult> {
        self.mutate(
            "ObjectRef::create",
            OSDMutation::Create { exclusive },
            options,
        )
        .await
    }

    /// Writes owned bytes at `offset` without truncating other extents.
    ///
    /// # Errors
    ///
    /// Returns stable validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn write(
        &self,
        offset: u64,
        data: impl AsRef<[u8]>,
        options: OperationOptions,
    ) -> Result<OpResult> {
        let data = data.as_ref();
        offset
            .checked_add(u64::try_from(data.len()).map_err(|_| Error::invalid("ObjectRef::write"))?)
            .ok_or_else(|| Error::invalid("ObjectRef::write"))?;
        self.mutate(
            "ObjectRef::write",
            OSDMutation::Write { offset, data },
            options,
        )
        .await
    }

    /// Atomically replaces the complete object contents.
    ///
    /// # Errors
    ///
    /// Returns stable validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn write_full(
        &self,
        data: impl AsRef<[u8]>,
        options: OperationOptions,
    ) -> Result<OpResult> {
        self.mutate(
            "ObjectRef::write_full",
            OSDMutation::WriteFull(data.as_ref()),
            options,
        )
        .await
    }

    /// Appends owned bytes to the object.
    ///
    /// # Errors
    ///
    /// Returns stable validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn append(
        &self,
        data: impl AsRef<[u8]>,
        options: OperationOptions,
    ) -> Result<OpResult> {
        self.mutate(
            "ObjectRef::append",
            OSDMutation::Append(data.as_ref()),
            options,
        )
        .await
    }

    /// Changes the object size, zero-filling growth as defined by RADOS.
    ///
    /// # Errors
    ///
    /// Returns stable validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn truncate(&self, size: u64, options: OperationOptions) -> Result<OpResult> {
        self.mutate(
            "ObjectRef::truncate",
            OSDMutation::Truncate { size },
            options,
        )
        .await
    }

    /// Zeroes an object extent.
    ///
    /// # Errors
    ///
    /// Returns stable validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn zero(
        &self,
        offset: u64,
        length: u64,
        options: OperationOptions,
    ) -> Result<OpResult> {
        offset
            .checked_add(length)
            .ok_or_else(|| Error::invalid("ObjectRef::zero"))?;
        self.mutate(
            "ObjectRef::zero",
            OSDMutation::Zero { offset, length },
            options,
        )
        .await
    }

    /// Removes the object.
    ///
    /// # Errors
    ///
    /// Returns stable validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn remove(&self, options: OperationOptions) -> Result<OpResult> {
        self.mutate("ObjectRef::remove", OSDMutation::Remove, options)
            .await
    }

    /// Reads one extended attribute by its binary name.
    ///
    /// # Errors
    ///
    /// Returns stable validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn get_xattr(
        &self,
        name: impl AsRef<[u8]>,
        options: OperationOptions,
    ) -> Result<Vec<u8>> {
        let result = self
            .execute_read_named(
                ReadOp::new().get_xattr(name)?,
                options,
                "ObjectRef::get_xattr",
            )
            .await?;
        Ok(result
            .results
            .into_iter()
            .next()
            .ok_or_else(|| Error::not_connected("ObjectRef::get_xattr"))?
            .data)
    }

    /// Sets one extended attribute with a binary name and value.
    ///
    /// # Errors
    ///
    /// Returns stable validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn set_xattr(
        &self,
        name: impl AsRef<[u8]>,
        value: impl AsRef<[u8]>,
        options: OperationOptions,
    ) -> Result<OpResult> {
        self.execute_write(WriteOp::new().set_xattr(name, value)?, options)
            .await
    }

    /// Removes one extended attribute by its binary name.
    ///
    /// # Errors
    ///
    /// Returns stable validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn remove_xattr(
        &self,
        name: impl AsRef<[u8]>,
        options: OperationOptions,
    ) -> Result<OpResult> {
        self.execute_write(WriteOp::new().remove_xattr(name)?, options)
            .await
    }

    /// Lists all extended attributes in bytewise name order.
    ///
    /// # Errors
    ///
    /// Returns stable routing, transport, deadline, cancellation, bounds, or Ceph errors.
    pub async fn list_xattrs(&self, options: OperationOptions) -> Result<Vec<Xattr>> {
        let result = self
            .execute_read_operations(
                vec![OSDOperation::GetXattrs],
                options,
                "ObjectRef::list_xattrs",
            )
            .await?;
        let data = result
            .operations
            .first()
            .ok_or_else(|| Error::not_connected("ObjectRef::list_xattrs"))?
            .data
            .as_slice();
        metadata::decode_map(data, data.len().max(1), data.len() / 8 + 1)
            .map(|entries| {
                entries
                    .into_iter()
                    .map(|entry| Xattr {
                        name: entry.key,
                        value: entry.value,
                    })
                    .collect()
            })
            .map_err(|_| Error::not_connected("ObjectRef::list_xattrs"))
    }

    /// Lists a bounded page of OMAP entries after a binary key.
    ///
    /// # Errors
    ///
    /// Returns stable validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn list_omap(
        &self,
        after: impl AsRef<[u8]>,
        limit: u64,
        options: OperationOptions,
    ) -> Result<Page<OmapEntry>> {
        let result = self
            .execute_read_named(
                ReadOp::new().list_omap(after, limit)?,
                options,
                "ObjectRef::list_omap",
            )
            .await?;
        let data = result
            .results
            .first()
            .ok_or_else(|| Error::not_connected("ObjectRef::list_omap"))?
            .data
            .as_slice();
        let maximum = usize::try_from(limit).unwrap_or(usize::MAX);
        let (entries, more) = metadata::decode_page(data, data.len().max(1), maximum)
            .map_err(|_| Error::not_connected("ObjectRef::list_omap"))?;
        Ok(Page {
            values: entries
                .into_iter()
                .map(|entry| OmapEntry {
                    key: entry.key,
                    value: entry.value,
                })
                .collect(),
            more,
        })
    }

    /// Reads the OMAP header.
    ///
    /// # Errors
    ///
    /// Returns stable routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn get_omap_header(&self, options: OperationOptions) -> Result<Vec<u8>> {
        let result = self
            .execute_read_named(
                ReadOp::new().get_omap_header()?,
                options,
                "ObjectRef::get_omap_header",
            )
            .await?;
        Ok(result
            .results
            .into_iter()
            .next()
            .ok_or_else(|| Error::not_connected("ObjectRef::get_omap_header"))?
            .data)
    }

    /// Reads selected binary OMAP keys in bytewise order.
    ///
    /// # Errors
    ///
    /// Returns stable validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn get_omap(
        &self,
        keys: impl IntoIterator<Item = Vec<u8>>,
        options: OperationOptions,
    ) -> Result<Vec<OmapEntry>> {
        let keys = keys.into_iter().collect::<Vec<_>>();
        let maximum = keys.len();
        let max_bytes = usize::try_from(FRAME_LIMITS.max_frame_bytes)
            .map_err(|_| Error::invalid("ObjectRef::get_omap"))?;
        let payload = metadata::encode_keys(keys, max_bytes)
            .map_err(|_| Error::invalid("ObjectRef::get_omap"))?;
        let result = self
            .execute_read_operations(
                vec![OSDOperation::OmapGetValuesByKeys(payload)],
                options,
                "ObjectRef::get_omap",
            )
            .await?;
        let data = result
            .operations
            .first()
            .ok_or_else(|| Error::not_connected("ObjectRef::get_omap"))?
            .data
            .as_slice();
        metadata::decode_map(data, data.len().max(1), maximum)
            .map(|entries| {
                entries
                    .into_iter()
                    .map(|entry| OmapEntry {
                        key: entry.key,
                        value: entry.value,
                    })
                    .collect()
            })
            .map_err(|_| Error::not_connected("ObjectRef::get_omap"))
    }

    /// Executes a consuming compound read as one server-side request.
    ///
    /// # Errors
    ///
    /// Returns stable validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn execute_read(
        &self,
        operation: ReadOp,
        options: OperationOptions,
    ) -> Result<OpResult> {
        self.execute_read_named(operation, options, "ObjectRef::execute_read")
            .await
    }

    async fn execute_read_named(
        &self,
        operation: ReadOp,
        options: OperationOptions,
        operation_name: &'static str,
    ) -> Result<OpResult> {
        self.execute_read_operations(operation.into_operations()?, options, operation_name)
            .await
            .map(|result| public_operation_result(result, operation_name))
    }

    /// Executes a consuming compound write atomically as one server-side request.
    ///
    /// # Errors
    ///
    /// Returns stable validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn execute_write(
        &self,
        operation: WriteOp,
        options: OperationOptions,
    ) -> Result<OpResult> {
        let operation_name = "ObjectRef::execute_write";
        let operations = operation.into_operations()?;
        let options = self.prepare_operation(options, operation_name)?;
        if self.pool.read_snapshot.is_some() {
            return Err(Error::invalid(operation_name));
        }
        let monitor = self.pool.client.connected_monitor(operation_name)?;
        let target = self.target(&monitor, operation_name)?;
        self.pool
            .client
            .0
            .objecter
            .mutate_operations(monitor, target, operations, options)
            .await
            .map(|result| public_operation_result(result, operation_name))
            .map_err(|error| map_osd_error(error, operation_name))
    }

    async fn execute_read_operations(
        &self,
        operations: Vec<OSDOperation>,
        options: OperationOptions,
        operation: &'static str,
    ) -> Result<CompoundResult> {
        let options = self.prepare_operation(options, operation)?;
        let monitor = self.pool.client.connected_monitor(operation)?;
        let target = self.target(&monitor, operation)?;
        self.pool
            .client
            .0
            .objecter
            .execute_operations(&monitor, target, operations, &options)
            .await
            .map_err(|error| map_osd_error(error, operation))
    }

    fn prepare_operation(
        &self,
        options: OperationOptions,
        operation: &'static str,
    ) -> Result<OperationOptions> {
        let options = bounded_options(
            options,
            self.pool.client.0.config.operation_timeout(),
            operation,
        )?;
        self.pool.client.ready(operation, &options)?;
        Ok(options)
    }

    async fn mutate(
        &self,
        operation: &'static str,
        request: OSDMutation<'_>,
        options: OperationOptions,
    ) -> Result<OpResult> {
        let options = bounded_options(
            options,
            self.pool.client.0.config.operation_timeout(),
            operation,
        )?;
        self.pool.client.ready(operation, &options)?;
        if self.pool.read_snapshot.is_some() {
            return Err(Error::invalid(operation));
        }
        let monitor = self.pool.client.connected_monitor(operation)?;
        let target = self.target(&monitor, operation)?;
        let result = self
            .pool
            .client
            .0
            .objecter
            .mutate(monitor, target, request, options)
            .await
            .map_err(|error| map_osd_error(error, operation))?;
        Ok(OpResult {
            version: result.version,
            results: Vec::new(),
        })
    }

    fn target(&self, monitor: &MonitorClient, operation: &'static str) -> Result<OSDTarget> {
        let pool_id = if let Some(id) = self.pool.id {
            id
        } else {
            let name = std::str::from_utf8(self.pool.name.as_bytes())
                .map_err(|_| Error::new(ErrorKind::NotFound).with_operation(operation))?;
            monitor
                .snapshot()
                .osdmap()
                .and_then(|map| map.pool_by_name(name).map(crate::maps::Pool::id))
                .ok_or_else(|| Error::new(ErrorKind::NotFound).with_operation(operation))?
        };
        Ok(OSDTarget {
            pool_id,
            object: self.name.as_bytes().to_vec(),
            locator: self.pool.locator.as_bytes().to_vec(),
            namespace: self.pool.namespace.as_bytes().to_vec(),
            snapshot: self.pool.read_snapshot.unwrap_or(NO_SNAP),
        })
    }
}

fn public_operation_result(result: CompoundResult, operation: &'static str) -> OpResult {
    OpResult {
        version: result.version,
        results: result
            .operations
            .into_iter()
            .map(|item| {
                let error = (item.code < 0).then(|| {
                    Error::from_wire(wire_error_kind(item.code), item.code)
                        .with_operation(operation)
                });
                let value = if item.code > 0 {
                    u64::try_from(item.code).unwrap_or_default()
                } else if item.code <= -4095 {
                    u64::try_from(-4095_i64 - i64::from(item.code)).unwrap_or_default()
                } else if item.operation == 0x1202 && item.data.len() == 16 {
                    u64::from_le_bytes(item.data[..8].try_into().unwrap_or_default())
                } else {
                    0
                };
                SubOperationResult {
                    data: item.data,
                    code: item.code,
                    value,
                    error,
                }
            })
            .collect(),
    }
}

fn map_osd_error(error: ClientError, operation: &'static str) -> Error {
    let (kind, wire_errno) = match error {
        ClientError::Closed => (ErrorKind::Closed, None),
        ClientError::NotConnected | ClientError::NoPrimary | ClientError::RecoveryExhausted => {
            (ErrorKind::NotConnected, None)
        }
        ClientError::LimitExceeded => (ErrorKind::InvalidArgument, None),
        ClientError::MalformedReply => (ErrorKind::NotConnected, None),
        ClientError::Unsupported => (ErrorKind::Unsupported, None),
        ClientError::Timeout => (ErrorKind::Timeout, None),
        ClientError::Cancelled => (ErrorKind::Canceled, None),
        ClientError::QueueSaturated => (ErrorKind::Conflict, None),
        ClientError::OutcomeUnknown(cause) => {
            let cause = match cause {
                crate::osd::UnknownCause::Cancelled => ErrorKind::Canceled,
                crate::osd::UnknownCause::Timeout => ErrorKind::Timeout,
                crate::osd::UnknownCause::Transport => ErrorKind::NotConnected,
            };
            return Error::outcome_unknown(cause).with_operation(operation);
        }
        ClientError::WireErrno(errno) => (wire_error_kind(errno), Some(errno)),
    };
    wire_errno.map_or_else(
        || Error::new(kind).with_operation(operation),
        |errno| Error::from_wire(kind, errno).with_operation(operation),
    )
}

const fn wire_error_kind(errno: i32) -> ErrorKind {
    match errno {
        -2 => ErrorKind::NotFound,
        -17 => ErrorKind::AlreadyExists,
        -13 => ErrorKind::PermissionDenied,
        -95 => ErrorKind::Unsupported,
        -22 => ErrorKind::InvalidArgument,
        -122 => ErrorKind::QuotaOrFull,
        -35 | -11 => ErrorKind::Conflict,
        -110 => ErrorKind::Timeout,
        -125 => ErrorKind::Canceled,
        _ => ErrorKind::Unknown,
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
    fn cursors_are_canonical_scoped_and_split_in_order() {
        let client = client();
        let pool = client.resolved_pool(7, b"pool").expect("pool");
        let begin = pool.begin_object_cursor().expect("begin");
        let end = pool.end_object_cursor().expect("end");
        let boundaries = pool.split_cursor(&begin, &end, 4).expect("split");
        assert_eq!(boundaries.len(), 5);
        assert_eq!(boundaries.first(), Some(&begin));
        assert_eq!(boundaries.last(), Some(&end));
        assert!(
            boundaries.windows(2).all(|pair| {
                compare_object_cursors(&pair[0], &pair[1]) == Ok(CmpOrdering::Less)
            })
        );

        let foreign = client
            .resolved_pool(8, b"other")
            .expect("pool")
            .begin_object_cursor()
            .expect("cursor");
        assert!(compare_object_cursors(&begin, &foreign).is_err());

        let malformed = crate::ObjectCursor {
            pool_id: 7,
            namespace: Vec::new(),
            value: crate::osd::enumeration::marshal_cursor(&HObject {
                key: Vec::new(),
                object: Vec::new(),
                snapshot: 1,
                hash: 0,
                max: false,
                namespace: Vec::new(),
                pool: i64::MIN,
            })
            .expect("encoding"),
            end: false,
        };
        assert!(compare_object_cursors(&malformed, &begin).is_err());
    }

    #[test]
    fn splitting_exhausted_cursor_preserves_empty_range() {
        let client = client();
        let pool = client.resolved_pool(7, b"pool").expect("pool");
        let end = pool.end_object_cursor().expect("end");
        let boundaries = pool.split_cursor(&end, &end, 4).expect("split");

        assert_eq!(boundaries, vec![end; 5]);
    }

    #[test]
    fn overfull_enumeration_page_resumes_at_first_omitted_entry() {
        let entry = |hash: u32| HObject {
            key: Vec::new(),
            object: hash.to_le_bytes().to_vec(),
            snapshot: NO_SNAP,
            hash,
            max: false,
            namespace: Vec::new(),
            pool: 7,
        };
        let entries = [entry(0), entry(0x8000_0000), entry(0x4000_0000)];
        let finish = HObject {
            key: Vec::new(),
            object: Vec::new(),
            snapshot: 0,
            hash: 0,
            max: true,
            namespace: Vec::new(),
            pool: 0,
        };
        let (next, count) = clip_enumeration_page(finish.clone(), 3, &entries, &finish, 2);
        assert_eq!(count, 2);
        assert_eq!(next, entries[2]);
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
    async fn canceled_shutdown_wait_leaves_mutation_admission_open() {
        let client = client();
        let lifecycle = client.0.lifecycle.lock().await;
        let cancellation = CancellationToken::new();
        let shutdown = tokio::spawn({
            let client = client.clone();
            let cancellation = cancellation.clone();
            async move {
                client
                    .shutdown(OperationOptions::new().with_cancellation(cancellation))
                    .await
            }
        });
        tokio::task::yield_now().await;
        cancellation.cancel();
        assert_eq!(
            shutdown
                .await
                .expect("shutdown task")
                .expect_err("canceled")
                .kind(),
            ErrorKind::Canceled
        );
        assert!(!client.0.objecter.mutation_admission_is_closed());
        assert!(!client.is_closed());
        drop(lifecycle);
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
