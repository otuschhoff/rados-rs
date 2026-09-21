use crate::cephx::connector;
use crate::cephx::core::{SERVICE_AUTH, SERVICE_MANAGER, SERVICE_MONITOR, SERVICE_OSD, TicketBlob};
use crate::maps::{Fsid, Limits as MapLimits};
#[cfg(test)]
use crate::mgr::client::SessionFactory as ManagerSessionFactory;
use crate::mgr::client::{
    Config as ManagerConfig, ManagerClient, ManagerError, Snapshot as ManagerSnapshot,
    StateSource as ManagerStateSource,
};
use crate::mon::client::{
    MonitorClient, MonitorConfig, MonitorError, SessionFactory, authenticated_session_factory,
};
use crate::mon::messages::MessageLimits;
use crate::mon::messages::{PoolOperation, PoolOperationReply, decode_allocated_snapshot_id};
use crate::mon::seeds::{SeedError, SeedLimits, resolve_seeds};
use crate::msgr::control::ClientIdent;
use crate::msgr::frame::Limits as FrameLimits;
use crate::msgr::session::{Config as SessionConfig, ReconnectPolicy, SessionError};
use crate::osd::{
    Client as OSDClient, ClientError, CommandResult as OSDCommandResult, CompoundResult, HObject,
    NO_SNAP, OSDMutation, Operation as OSDOperation, Target as OSDTarget, compare_hobject,
    parse_pg,
};
use crate::osd::{lock, metadata, watch as osd_watch};
use crate::protocol::address::{EntityAddr, EntityAddrVec};
use crate::protocol::features::GlobalFeatures;
use crate::{
    ChecksumType, ClassResult, ClusterStats, CommandResult, Config, Error, ErrorKind,
    InconsistentObject, InconsistentPg, LocatorKey, LockMode, LockOptions, Locker, Namespace,
    NotifyAcknowledgment, NotifyReply, NotifyTimeout, ObjectEntry, ObjectInfo, ObjectName,
    ObjectPage, OmapEntry, OpResult, OperationOptions, Page, PoolStats, ReadOp, Result,
    SecurityMode, Snapshot, SnapshotContext, SparseExtent, SubOperationResult, Watch, WatchEvent,
    Watcher, WriteOp, Xattr,
};
use std::cmp::Ordering as CmpOrdering;
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, mpsc, watch};

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
    address_nonce: u32,
    closed: AtomicBool,
    lifecycle: Mutex<()>,
    monitor: RwLock<Option<Arc<MonitorClient>>>,
    manager: RwLock<Option<Arc<ManagerClient>>>,
    authority: Arc<RwLock<Option<Arc<connector::MonitorConnector>>>>,
    objecter: Arc<OSDClient>,
    #[cfg(test)]
    factory: Option<SessionFactory>,
    #[cfg(test)]
    manager_factory: Option<ManagerSessionFactory>,
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
        let address_nonce = random_nonzero_u32("Client::new")?;
        let authority = Arc::new(RwLock::new(None));
        let objecter = Arc::new(OSDClient::new(
            Arc::clone(&authority),
            FRAME_LIMITS,
            config.dial_timeout(),
            config.handshake_timeout(),
            config.security_mode() == SecurityMode::Crc,
            address_nonce,
        ));
        Ok(Self(Arc::new(ClientInner {
            config,
            address_nonce,
            closed: AtomicBool::new(false),
            lifecycle: Mutex::new(()),
            monitor: RwLock::new(None),
            manager: RwLock::new(None),
            authority,
            objecter,
            #[cfg(test)]
            factory: None,
            #[cfg(test)]
            manager_factory: None,
        })))
    }

    #[cfg(test)]
    fn with_factory(config: Config, factory: SessionFactory) -> Result<Self> {
        config.validate()?;
        let address_nonce = random_nonzero_u32("Client::with_factory")?;
        let authority = Arc::new(RwLock::new(None));
        let objecter = Arc::new(OSDClient::new(
            Arc::clone(&authority),
            FRAME_LIMITS,
            config.dial_timeout(),
            config.handshake_timeout(),
            config.security_mode() == SecurityMode::Crc,
            address_nonce,
        ));
        Ok(Self(Arc::new(ClientInner {
            config,
            address_nonce,
            closed: AtomicBool::new(false),
            lifecycle: Mutex::new(()),
            monitor: RwLock::new(None),
            manager: RwLock::new(None),
            authority,
            objecter,
            factory: Some(factory),
            manager_factory: None,
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
            if let Some(manager) = self.take_manager() {
                manager.close();
            }
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
            if let Some(manager) = self.take_manager() {
                manager.close();
            }
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

    /// Returns authenticated session addresses in canonical messenger form.
    #[must_use]
    pub fn session_addresses(&self) -> Vec<String> {
        self.monitor()
            .filter(|monitor| monitor.terminal().is_none())
            .and_then(|monitor| monitor.snapshot().client_addresses())
            .map_or_else(Vec::new, |addresses| {
                addresses
                    .0
                    .iter()
                    .filter_map(format_session_address)
                    .collect()
            })
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

    /// Returns cluster capacity counters.
    ///
    /// # Errors
    ///
    /// Returns monitor identity, transport, deadline, cancellation, or Ceph errors.
    pub async fn cluster_stats(&self, options: OperationOptions) -> Result<ClusterStats> {
        let operation = "Client::cluster_stats";
        let options = bounded_options(options, self.0.config.operation_timeout(), operation)?;
        self.ready(operation, &options)?;
        let monitor = self.connected_monitor(operation)?;
        let reply = monitor
            .statfs(options)
            .await
            .map_err(|error| map_monitor_error(error, operation))?;
        Ok(ClusterStats {
            kib: reply.kib,
            kib_used: reply.kib_used,
            kib_available: reply.kib_available,
            objects: reply.objects,
        })
    }

    /// Sends a monitor command and returns owned command output plus operation outcome.
    ///
    /// The second tuple element reports the command outcome. A monitor wire error can return
    /// both command output and a non-`Ok(())` status.
    pub async fn monitor_command(
        &self,
        command: impl AsRef<[u8]>,
        input: impl AsRef<[u8]>,
        options: OperationOptions,
    ) -> (CommandResult, Result<()>) {
        let operation_name = "Client::monitor_command";
        let options =
            match bounded_options(options, self.0.config.operation_timeout(), operation_name) {
                Ok(options) => options,
                Err(error) => {
                    return (
                        CommandResult {
                            output: Vec::new(),
                            status: String::new(),
                        },
                        Err(error),
                    );
                }
            };
        if let Err(error) = self.ready(operation_name, &options) {
            return (
                CommandResult {
                    output: Vec::new(),
                    status: String::new(),
                },
                Err(error),
            );
        }
        let monitor = match self.connected_monitor(operation_name) {
            Ok(monitor) => monitor,
            Err(error) => {
                return (
                    CommandResult {
                        output: Vec::new(),
                        status: String::new(),
                    },
                    Err(error),
                );
            }
        };
        let command = match command_argv(command.as_ref(), operation_name) {
            Ok(command) => command,
            Err(error) => {
                return (
                    CommandResult {
                        output: Vec::new(),
                        status: String::new(),
                    },
                    Err(error),
                );
            }
        };
        match monitor
            .command(command, input.as_ref().to_vec(), options)
            .await
        {
            Ok((reply, error)) => (
                CommandResult {
                    output: reply.data,
                    status: reply.status,
                },
                error.map_or(Ok(()), |error| {
                    Err(map_monitor_error(error, operation_name))
                }),
            ),
            Err(error) => (
                CommandResult {
                    output: Vec::new(),
                    status: String::new(),
                },
                Err(map_monitor_error(error, operation_name)),
            ),
        }
    }

    /// Sends a manager command and returns owned command output plus operation outcome.
    ///
    /// The second tuple element reports the command outcome. A manager wire error can return
    /// both command output and a non-`Ok(())` status.
    pub async fn manager_command(
        &self,
        command: impl AsRef<[u8]>,
        input: impl AsRef<[u8]>,
        options: OperationOptions,
    ) -> (CommandResult, Result<()>) {
        let operation_name = "Client::manager_command";
        let options =
            match bounded_options(options, self.0.config.operation_timeout(), operation_name) {
                Ok(options) => options,
                Err(error) => {
                    return (
                        CommandResult {
                            output: Vec::new(),
                            status: String::new(),
                        },
                        Err(error),
                    );
                }
            };
        if let Err(error) = self.ready(operation_name, &options) {
            return (
                CommandResult {
                    output: Vec::new(),
                    status: String::new(),
                },
                Err(error),
            );
        }
        let monitor = match self.connected_monitor(operation_name) {
            Ok(monitor) => monitor,
            Err(error) => {
                return (
                    CommandResult {
                        output: Vec::new(),
                        status: String::new(),
                    },
                    Err(error),
                );
            }
        };
        let command = match command_argv(command.as_ref(), operation_name) {
            Ok(command) => command,
            Err(error) => {
                return (
                    CommandResult {
                        output: Vec::new(),
                        status: String::new(),
                    },
                    Err(error),
                );
            }
        };
        let manager = match self.manager_for_monitor(monitor, operation_name) {
            Ok(manager) => manager,
            Err(error) => {
                return (
                    CommandResult {
                        output: Vec::new(),
                        status: String::new(),
                    },
                    Err(error),
                );
            }
        };
        match manager
            .command(command, input.as_ref().to_vec(), options)
            .await
        {
            Ok((reply, error)) => (
                CommandResult {
                    output: reply.data,
                    status: reply.status,
                },
                error.map_or(Ok(()), |error| {
                    Err(map_manager_error(error, operation_name))
                }),
            ),
            Err(error) => (
                CommandResult {
                    output: Vec::new(),
                    status: String::new(),
                },
                Err(map_manager_error(error, operation_name)),
            ),
        }
    }

    /// Sends an OSD command to a specific OSD id and returns output plus operation outcome.
    ///
    /// The second tuple element reports the command outcome. OSD wire errors preserve
    /// command status and output in the returned `CommandResult`.
    pub async fn osd_command(
        &self,
        osd: i64,
        command: impl AsRef<[u8]>,
        input: impl AsRef<[u8]>,
        options: OperationOptions,
    ) -> (CommandResult, Result<()>) {
        let operation_name = "Client::osd_command";
        let options =
            match bounded_options(options, self.0.config.operation_timeout(), operation_name) {
                Ok(options) => options,
                Err(error) => {
                    return (
                        CommandResult {
                            output: Vec::new(),
                            status: String::new(),
                        },
                        Err(error),
                    );
                }
            };
        if let Err(error) = self.ready(operation_name, &options) {
            return (
                CommandResult {
                    output: Vec::new(),
                    status: String::new(),
                },
                Err(error),
            );
        }
        let osd = match i32::try_from(osd) {
            Ok(value) if value >= 0 => value,
            _ => {
                return (
                    CommandResult {
                        output: Vec::new(),
                        status: String::new(),
                    },
                    Err(Error::invalid(operation_name)),
                );
            }
        };
        let monitor = match self.connected_monitor(operation_name) {
            Ok(monitor) => monitor,
            Err(error) => {
                return (
                    CommandResult {
                        output: Vec::new(),
                        status: String::new(),
                    },
                    Err(error),
                );
            }
        };
        let command = match command_argv(command.as_ref(), operation_name) {
            Ok(command) => command,
            Err(error) => {
                return (
                    CommandResult {
                        output: Vec::new(),
                        status: String::new(),
                    },
                    Err(error),
                );
            }
        };
        match self
            .0
            .objecter
            .osd_command(&monitor, osd, command, input.as_ref().to_vec(), &options)
            .await
        {
            Ok((reply, error)) => (
                command_result_from_osd(reply),
                error.map_or(Ok(()), |error| Err(map_osd_error(error, operation_name))),
            ),
            Err(error) => (
                CommandResult {
                    output: Vec::new(),
                    status: String::new(),
                },
                Err(map_osd_error(error, operation_name)),
            ),
        }
    }

    /// Sends a PG command to the acting primary of a parsed placement-group string.
    ///
    /// The PG must be in canonical `pool.seed` form with a decimal pool id and hexadecimal seed.
    /// The second tuple element reports the command outcome while preserving status and output.
    pub async fn pg_command(
        &self,
        pg: &str,
        command: impl AsRef<[u8]>,
        input: impl AsRef<[u8]>,
        options: OperationOptions,
    ) -> (CommandResult, Result<()>) {
        let operation_name = "Client::pg_command";
        let options =
            match bounded_options(options, self.0.config.operation_timeout(), operation_name) {
                Ok(options) => options,
                Err(error) => {
                    return (
                        CommandResult {
                            output: Vec::new(),
                            status: String::new(),
                        },
                        Err(error),
                    );
                }
            };
        if let Err(error) = self.ready(operation_name, &options) {
            return (
                CommandResult {
                    output: Vec::new(),
                    status: String::new(),
                },
                Err(error),
            );
        }
        let Ok(pg) = parse_pg(pg) else {
            return (
                CommandResult {
                    output: Vec::new(),
                    status: String::new(),
                },
                Err(Error::invalid(operation_name)),
            );
        };
        let command = match command_argv(command.as_ref(), operation_name) {
            Ok(command) => command,
            Err(error) => {
                return (
                    CommandResult {
                        output: Vec::new(),
                        status: String::new(),
                    },
                    Err(error),
                );
            }
        };
        let monitor = match self.connected_monitor(operation_name) {
            Ok(monitor) => monitor,
            Err(error) => {
                return (
                    CommandResult {
                        output: Vec::new(),
                        status: String::new(),
                    },
                    Err(error),
                );
            }
        };
        match self
            .0
            .objecter
            .pg_command(&monitor, pg, command, input.as_ref().to_vec(), &options)
            .await
        {
            Ok((reply, error)) => (
                command_result_from_osd(reply),
                error.map_or(Ok(()), |error| Err(map_osd_error(error, operation_name))),
            ),
            Err(error) => (
                CommandResult {
                    output: Vec::new(),
                    status: String::new(),
                },
                Err(map_osd_error(error, operation_name)),
            ),
        }
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

    /// Creates a pool by name.
    ///
    /// # Errors
    ///
    /// Returns validation, monitor identity, transport, deadline, cancellation, or Ceph errors.
    pub async fn create_pool(&self, name: &str, options: OperationOptions) -> Result<()> {
        let operation = "Client::create_pool";
        if name.is_empty() {
            return Err(Error::invalid(operation));
        }
        let options = bounded_options(options, self.0.config.operation_timeout(), operation)?;
        self.ready(operation, &options)?;
        let monitor = self.connected_monitor(operation)?;
        monitor
            .apply_pool_operation(0, PoolOperation::CreatePool, 0, name.to_owned(), options)
            .await
            .map_err(|error| map_monitor_error(error, operation))?;
        Ok(())
    }

    /// Deletes a pool by name.
    ///
    /// # Errors
    ///
    /// Returns validation, monitor identity, transport, deadline, cancellation, not-found,
    /// or Ceph errors.
    pub async fn delete_pool(&self, name: &str, options: OperationOptions) -> Result<()> {
        let operation = "Client::delete_pool";
        if name.is_empty() {
            return Err(Error::invalid(operation));
        }
        let options = bounded_options(options, self.0.config.operation_timeout(), operation)?;
        self.ready(operation, &options)?;
        let monitor = self.connected_monitor(operation)?;
        let map = monitor
            .snapshot()
            .osdmap()
            .ok_or_else(|| Error::not_connected(operation))?;
        let pool_id = map
            .pool_by_name(name)
            .map(crate::maps::Pool::id)
            .ok_or_else(|| Error::new(ErrorKind::NotFound).with_operation(operation))?;
        let pool_id = u32::try_from(pool_id).map_err(|_| Error::invalid(operation))?;
        monitor
            .apply_pool_operation(
                pool_id,
                PoolOperation::DeletePool,
                0,
                "delete".to_owned(),
                options,
            )
            .await
            .map_err(|error| map_monitor_error(error, operation))?;
        Ok(())
    }

    /// Adds one address to the OSD blocklist and waits for a newer OSD map.
    ///
    /// # Errors
    ///
    /// Returns validation, monitor identity, transport, deadline, cancellation, or Ceph errors.
    pub async fn blocklist(
        &self,
        address: &str,
        duration: Duration,
        options: OperationOptions,
    ) -> Result<()> {
        let operation = "Client::blocklist";
        validate_blocklist_arguments(address, duration, operation)?;
        let options = bounded_options(options, self.0.config.operation_timeout(), operation)?;
        self.ready(operation, &options)?;
        let monitor = self.connected_monitor(operation)?;
        let epoch = monitor
            .snapshot()
            .osdmap()
            .map(|map| map.epoch())
            .ok_or_else(|| Error::not_connected(operation))?;
        let payload = blocklist_command_payload(address, duration, operation)?;
        let command = std::str::from_utf8(&payload)
            .map_err(|_| Error::invalid(operation))?
            .to_owned();
        match monitor
            .command(vec![command], Vec::new(), options.clone())
            .await
        {
            Ok((_, None)) => {}
            Ok((_, Some(error))) | Err(error) => {
                return Err(map_monitor_error(error, operation));
            }
        }
        monitor
            .refresh_osdmap(epoch, &options)
            .await
            .map_err(|error| map_monitor_error(error, operation))
    }

    /// Lists inconsistent placement-groups in one pool using the manager JSON API.
    ///
    /// # Errors
    ///
    /// Returns validation, manager transport, cancellation/deadline, or malformed output errors.
    pub async fn list_inconsistent_pgs(
        &self,
        pool_id: i64,
        options: OperationOptions,
    ) -> Result<Vec<InconsistentPg>> {
        let operation = "Client::list_inconsistent_pgs";
        let options = bounded_options(options, self.0.config.operation_timeout(), operation)?;
        self.ready(operation, &options)?;
        if pool_id < 0 {
            return Err(Error::invalid(operation));
        }
        let monitor = self.connected_monitor(operation)?;
        let manager = self.manager_for_monitor(monitor, operation)?;
        let mut command = serde_json::Map::new();
        command.insert(
            "format".to_owned(),
            serde_json::Value::String("json".to_owned()),
        );
        command.insert("pool".to_owned(), serde_json::Value::Number(pool_id.into()));
        command.insert(
            "prefix".to_owned(),
            serde_json::Value::String("pg ls".to_owned()),
        );
        command.insert(
            "states".to_owned(),
            serde_json::Value::Array(vec![serde_json::Value::String("inconsistent".to_owned())]),
        );
        let payload = serde_json::to_vec(&serde_json::Value::Object(command))
            .map_err(|_| Error::invalid(operation))?;
        let command = command_argv(&payload, operation)?;
        let (reply, status) = manager
            .command(command, Vec::new(), options)
            .await
            .map_err(|error| map_manager_error(error, operation))?;
        let status = status.map_or(Ok(()), |error| Err(map_manager_error(error, operation)));
        status?;
        decode_inconsistent_pgs(&reply.data, operation)
    }

    /// Lists inconsistent objects for one canonical placement group.
    ///
    /// # Errors
    ///
    /// Returns validation, routing, transport, cancellation/deadline, bounds, or Ceph errors.
    pub async fn list_inconsistent_objects(
        &self,
        pg: &str,
        options: OperationOptions,
    ) -> Result<Vec<InconsistentObject>> {
        let operation = "Client::list_inconsistent_objects";
        let options = bounded_options(options, self.0.config.operation_timeout(), operation)?;
        self.ready(operation, &options)?;
        let parsed = parse_pg(pg).map_err(|_| Error::invalid(operation))?;
        let monitor = self.connected_monitor(operation)?;
        let objects = self
            .0
            .objecter
            .list_inconsistent_objects(&monitor, parsed, &options)
            .await
            .map_err(|error| map_osd_error(error, operation))?;
        Ok(objects
            .into_iter()
            .map(|item| InconsistentObject {
                object: item.object,
                shards: item.shards,
                errors: item.errors,
            })
            .collect())
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
            write_snapshot_sequence: 0,
            write_snapshots: Vec::new(),
            write_snapshot_valid: true,
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
        if let Some(manager) = self.take_manager() {
            manager.close();
        }
        flush_result.and(cleanup_result)
    }

    /// Idempotently closes the shared client without blocking or network I/O.
    pub fn close(&self) {
        self.0.closed.store(true, Ordering::Release);
        self.0.objecter.close();
        if let Some(manager) = self.manager() {
            manager.close();
        }
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
            write_snapshot_sequence: 0,
            write_snapshots: Vec::new(),
            write_snapshot_valid: true,
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
            if let Some(manager) = self.take_manager() {
                manager.close();
            }
            self.clear_authority();
        }
    }

    fn manager(&self) -> Option<Arc<ManagerClient>> {
        self.0
            .manager
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn install_manager(&self, manager: Arc<ManagerClient>) -> Option<Arc<ManagerClient>> {
        let mut slot = self
            .0
            .manager
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.is_closed() {
            return None;
        }
        if let Some(existing) = slot.as_ref()
            && !existing.is_closed()
        {
            return Some(Arc::clone(existing));
        }
        let replaced = slot.replace(Arc::clone(&manager));
        drop(slot);
        if let Some(replaced) = replaced {
            replaced.close();
        }
        Some(manager)
    }

    fn take_manager(&self) -> Option<Arc<ManagerClient>> {
        self.0
            .manager
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    fn manager_for_monitor(
        &self,
        monitor: Arc<MonitorClient>,
        operation: &'static str,
    ) -> Result<Arc<ManagerClient>> {
        if let Some(manager) = self.manager()
            && !manager.is_closed()
        {
            return Ok(manager);
        }
        let manager = Arc::new(self.build_manager_client(monitor)?);
        let Some(selected) = self.install_manager(Arc::clone(&manager)) else {
            manager.close();
            return Err(Error::closed(operation));
        };
        if !Arc::ptr_eq(&selected, &manager) {
            manager.close();
        }
        Ok(selected)
    }

    fn build_manager_client(&self, monitor: Arc<MonitorClient>) -> Result<ManagerClient> {
        let source = Arc::new(MonitorManagerSource { monitor });
        let config = ManagerConfig {
            source,
            authority_slot: Arc::clone(&self.0.authority),
            frame_limits: FRAME_LIMITS,
            dial_timeout: self.0.config.dial_timeout(),
            handshake_timeout: self.0.config.handshake_timeout(),
            allow_crc: self.0.config.security_mode() == SecurityMode::Crc,
            address_nonce: self.0.address_nonce,
            message_max_bytes: 32 << 20,
            retry_delay: Duration::from_millis(100),
            max_attempts: 64,
        };
        #[cfg(test)]
        let factory = self.0.manager_factory.clone();
        #[cfg(not(test))]
        let factory = None;
        ManagerClient::new(config, factory)
            .map_err(|error| map_manager_error(error, "Client::manager_command"))
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
                .map_err(|_| Error::invalid("Client::connect"))?
                .with_nonce(self.0.address_nonce);
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
            requested_keys: SERVICE_AUTH | SERVICE_MONITOR | SERVICE_OSD | SERVICE_MANAGER,
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
    write_snapshot_sequence: u64,
    write_snapshots: Vec<u64>,
    write_snapshot_valid: bool,
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

    /// Returns a sibling view with an owned self-managed snapshot write context.
    #[must_use]
    pub fn with_write_snapshot(mut self, context: SnapshotContext) -> Self {
        self.write_snapshot_valid = valid_snapshot_context(&context);
        self.write_snapshot_sequence = context.sequence;
        self.write_snapshots = context.snapshots;
        self
    }

    /// Creates a named pool snapshot.
    ///
    /// # Errors
    ///
    /// Returns validation, monitor identity, transport, deadline, cancellation, or Ceph errors.
    pub async fn create_snapshot(&self, name: &str, options: OperationOptions) -> Result<()> {
        if name.is_empty() {
            return Err(Error::invalid("Pool::create_snapshot"));
        }
        self.apply_snapshot_operation(
            PoolOperation::CreateSnapshot,
            0,
            name,
            options,
            "Pool::create_snapshot",
        )
        .await?;
        Ok(())
    }

    /// Removes a named pool snapshot.
    ///
    /// # Errors
    ///
    /// Returns validation, monitor identity, transport, deadline, cancellation, or Ceph errors.
    pub async fn remove_snapshot(&self, name: &str, options: OperationOptions) -> Result<()> {
        if name.is_empty() {
            return Err(Error::invalid("Pool::remove_snapshot"));
        }
        self.apply_snapshot_operation(
            PoolOperation::DeleteSnapshot,
            0,
            name,
            options,
            "Pool::remove_snapshot",
        )
        .await?;
        Ok(())
    }

    /// Allocates a self-managed snapshot ID.
    ///
    /// # Errors
    ///
    /// Returns monitor identity, transport, deadline, cancellation, malformed-reply, or Ceph errors.
    pub async fn create_self_managed_snapshot(&self, options: OperationOptions) -> Result<u64> {
        let operation = "Pool::create_self_managed_snapshot";
        let reply = self
            .apply_snapshot_operation(PoolOperation::CreateSelfManaged, 0, "", options, operation)
            .await?;
        decode_allocated_snapshot_id(&reply.response_data, 8)
            .map_err(|_| Error::new(ErrorKind::NotConnected).with_operation(operation))
    }

    /// Removes a self-managed snapshot ID.
    ///
    /// # Errors
    ///
    /// Returns validation, monitor identity, transport, deadline, cancellation, or Ceph errors.
    pub async fn remove_self_managed_snapshot(
        &self,
        snapshot: u64,
        options: OperationOptions,
    ) -> Result<()> {
        let operation = "Pool::remove_self_managed_snapshot";
        if snapshot == 0 {
            return Err(Error::invalid(operation));
        }
        self.apply_snapshot_operation(
            PoolOperation::DeleteSelfManaged,
            snapshot,
            "",
            options,
            operation,
        )
        .await?;
        Ok(())
    }

    /// Returns named snapshots from the current pool map in snapshot-ID order.
    ///
    /// # Errors
    ///
    /// Returns readiness, deadline, cancellation, or missing-pool errors.
    pub fn list_snapshots(&self, options: OperationOptions) -> Result<Vec<Snapshot>> {
        let pool = self.metadata(options, "Pool::list_snapshots")?;
        Ok(pool
            .snapshots()
            .map(|snapshot| Snapshot {
                id: snapshot.id,
                name: snapshot.name.clone(),
                created_at: UNIX_EPOCH
                    + Duration::new(
                        u64::from(snapshot.timestamp.seconds),
                        snapshot.timestamp.nanoseconds,
                    ),
            })
            .collect())
    }

    /// Looks up one named snapshot in the current pool map.
    ///
    /// # Errors
    ///
    /// Returns validation, readiness, deadline, cancellation, missing-pool, or not-found errors.
    pub fn lookup_snapshot(&self, name: &str, options: OperationOptions) -> Result<Snapshot> {
        let operation = "Pool::lookup_snapshot";
        if name.is_empty() {
            return Err(Error::invalid(operation));
        }
        let pool = self.metadata(options, operation)?;
        pool.snapshots()
            .find(|snapshot| snapshot.name == name)
            .map(|snapshot| Snapshot {
                id: snapshot.id,
                name: snapshot.name.clone(),
                created_at: UNIX_EPOCH
                    + Duration::new(
                        u64::from(snapshot.timestamp.seconds),
                        snapshot.timestamp.nanoseconds,
                    ),
            })
            .ok_or_else(|| Error::new(ErrorKind::NotFound).with_operation(operation))
    }

    /// Reports whether the pool uses self-managed snapshots.
    ///
    /// # Errors
    ///
    /// Returns readiness, deadline, cancellation, or missing-pool errors.
    pub fn uses_self_managed_snapshots(&self, options: OperationOptions) -> Result<bool> {
        Ok(self
            .metadata(options, "Pool::uses_self_managed_snapshots")?
            .uses_self_managed_snapshots())
    }

    /// Returns pool I/O and storage counters.
    ///
    /// # Errors
    ///
    /// Returns readiness, routing, monitor identity, transport, deadline, cancellation,
    /// malformed-reply, or Ceph errors.
    pub async fn stats(&self, options: OperationOptions) -> Result<PoolStats> {
        let operation = "Pool::stats";
        let _ = u32::try_from(self.id.ok_or_else(|| Error::invalid(operation))?)
            .map_err(|_| Error::invalid(operation))?;
        let pool_name = std::str::from_utf8(self.name.as_bytes()).map_err(|_| {
            Error::new(ErrorKind::NotFound)
                .with_operation(operation)
                .with_safe_target(self.name.as_bytes())
        })?;
        let options =
            bounded_options(options, self.client.0.config.operation_timeout(), operation)?;
        self.client.ready(operation, &options)?;
        let monitor = self.client.connected_monitor(operation)?;
        let reply = monitor
            .pool_stats(vec![pool_name.to_owned()], options)
            .await
            .map_err(|error| map_monitor_error(error, operation))?;
        let stats = reply
            .pools
            .get(pool_name)
            .ok_or_else(|| Error::invalid(operation))?;
        Ok(PoolStats {
            bytes_used: stats.bytes_used,
            objects: stats.objects,
            read_bytes: stats.read_bytes,
            write_bytes: stats.write_bytes,
        })
    }

    /// Reports whether the pool is erasure coded.
    ///
    /// # Errors
    ///
    /// Returns readiness, deadline, cancellation, or missing-pool errors.
    pub fn is_erasure_coded(&self, options: OperationOptions) -> Result<bool> {
        Ok(self
            .metadata(options, "Pool::is_erasure_coded")?
            .is_erasure_coded())
    }

    /// Reports whether writes require pool stripe alignment.
    ///
    /// # Errors
    ///
    /// Returns readiness, deadline, cancellation, or missing-pool errors.
    pub fn requires_alignment(&self, options: OperationOptions) -> Result<bool> {
        Ok(self
            .metadata(options, "Pool::requires_alignment")?
            .requires_alignment())
    }

    /// Returns the pool stripe width reported by the current map.
    ///
    /// # Errors
    ///
    /// Returns readiness, deadline, cancellation, or missing-pool errors.
    pub fn required_alignment(&self, options: OperationOptions) -> Result<u64> {
        Ok(u64::from(
            self.metadata(options, "Pool::required_alignment")?
                .stripe_width(),
        ))
    }

    /// Enables one pool application namespace, optionally forcing a conflicting enable.
    ///
    /// # Errors
    ///
    /// Returns validation, monitor identity, transport, deadline, cancellation, or Ceph errors.
    pub async fn enable_application(
        &self,
        name: &str,
        force: bool,
        options: OperationOptions,
    ) -> Result<()> {
        let mut command = serde_json::Map::new();
        command.insert(
            "prefix".to_owned(),
            serde_json::Value::String("osd pool application enable".to_owned()),
        );
        command.insert("app".to_owned(), serde_json::Value::String(name.to_owned()));
        if force {
            command.insert(
                "yes_i_really_mean_it".to_owned(),
                serde_json::Value::Bool(true),
            );
        }
        self.mutate_application(command, options, "Pool::enable_application")
            .await
    }

    /// Sets one pool application metadata key/value pair.
    ///
    /// # Errors
    ///
    /// Returns validation, monitor identity, transport, deadline, cancellation, or Ceph errors.
    pub async fn set_application_metadata(
        &self,
        application: &str,
        key: &str,
        value: &str,
        options: OperationOptions,
    ) -> Result<()> {
        let mut command = serde_json::Map::new();
        command.insert(
            "prefix".to_owned(),
            serde_json::Value::String("osd pool application set".to_owned()),
        );
        command.insert(
            "app".to_owned(),
            serde_json::Value::String(application.to_owned()),
        );
        command.insert("key".to_owned(), serde_json::Value::String(key.to_owned()));
        command.insert(
            "value".to_owned(),
            serde_json::Value::String(value.to_owned()),
        );
        self.mutate_application(command, options, "Pool::set_application_metadata")
            .await
    }

    /// Removes one pool application metadata key.
    ///
    /// # Errors
    ///
    /// Returns validation, monitor identity, transport, deadline, cancellation, or Ceph errors.
    pub async fn remove_application_metadata(
        &self,
        application: &str,
        key: &str,
        options: OperationOptions,
    ) -> Result<()> {
        let mut command = serde_json::Map::new();
        command.insert(
            "prefix".to_owned(),
            serde_json::Value::String("osd pool application rm".to_owned()),
        );
        command.insert(
            "app".to_owned(),
            serde_json::Value::String(application.to_owned()),
        );
        command.insert("key".to_owned(), serde_json::Value::String(key.to_owned()));
        self.mutate_application(command, options, "Pool::remove_application_metadata")
            .await
    }

    /// Lists pool applications in deterministic lexicographic order.
    ///
    /// # Errors
    ///
    /// Returns readiness, deadline, cancellation, or missing-pool errors.
    pub fn list_applications(&self, options: OperationOptions) -> Result<Vec<String>> {
        let metadata = self.application_metadata(options, "Pool::list_applications")?;
        Ok(sorted_application_names(&metadata))
    }

    /// Returns one pool application metadata value.
    ///
    /// # Errors
    ///
    /// Returns readiness, deadline, cancellation, missing-pool, or not-found errors.
    pub fn get_application_metadata(
        &self,
        application: &str,
        key: &str,
        options: OperationOptions,
    ) -> Result<String> {
        let operation = "Pool::get_application_metadata";
        let metadata = self.application_metadata(options, operation)?;
        application_value(&metadata, application, key, operation)
    }

    /// Lists one application metadata map.
    ///
    /// # Errors
    ///
    /// Returns readiness, deadline, cancellation, missing-pool, or not-found errors.
    pub fn list_application_metadata(
        &self,
        application: &str,
        options: OperationOptions,
    ) -> Result<HashMap<String, String>> {
        let operation = "Pool::list_application_metadata";
        let metadata = self.application_metadata(options, operation)?;
        application_values(&metadata, application, operation)
    }

    async fn apply_snapshot_operation(
        &self,
        code: PoolOperation,
        snapshot: u64,
        name: &str,
        options: OperationOptions,
        operation: &'static str,
    ) -> Result<PoolOperationReply> {
        let pool = u32::try_from(self.id.ok_or_else(|| Error::invalid(operation))?)
            .map_err(|_| Error::invalid(operation))?;
        let options =
            bounded_options(options, self.client.0.config.operation_timeout(), operation)?;
        self.client.ready(operation, &options)?;
        let monitor = self.client.connected_monitor(operation)?;
        monitor
            .apply_pool_operation(pool, code, snapshot, name.to_owned(), options)
            .await
            .map_err(|error| map_monitor_error(error, operation))
    }

    fn application_metadata(
        &self,
        options: OperationOptions,
        operation: &'static str,
    ) -> Result<HashMap<String, HashMap<String, String>>> {
        Ok(self
            .metadata(options, operation)?
            .application_metadata()
            .clone())
    }

    async fn mutate_application(
        &self,
        mut command: serde_json::Map<String, serde_json::Value>,
        options: OperationOptions,
        operation: &'static str,
    ) -> Result<()> {
        let _ = u32::try_from(self.id.ok_or_else(|| Error::invalid(operation))?)
            .map_err(|_| Error::invalid(operation))?;
        let pool_name = std::str::from_utf8(self.name.as_bytes()).map_err(|_| {
            Error::new(ErrorKind::NotFound)
                .with_operation(operation)
                .with_safe_target(self.name.as_bytes())
        })?;
        let options =
            bounded_options(options, self.client.0.config.operation_timeout(), operation)?;
        self.client.ready(operation, &options)?;
        let monitor = self.client.connected_monitor(operation)?;
        let epoch = monitor
            .snapshot()
            .osdmap()
            .map(|map| map.epoch())
            .ok_or_else(|| Error::not_connected(operation))?;
        command.insert(
            "pool".to_owned(),
            serde_json::Value::String(pool_name.to_owned()),
        );
        let payload = serde_json::to_vec(&serde_json::Value::Object(command))
            .map_err(|_| Error::invalid(operation))?;
        let command = std::str::from_utf8(&payload)
            .map_err(|_| Error::invalid(operation))?
            .to_owned();
        match monitor
            .command(vec![command], Vec::new(), options.clone())
            .await
        {
            Ok((_, None)) => {}
            Ok((_, Some(error))) | Err(error) => {
                return Err(map_monitor_error(error, operation));
            }
        }
        monitor
            .refresh_osdmap(epoch, &options)
            .await
            .map_err(|error| map_monitor_error(error, operation))
    }

    fn metadata(
        &self,
        options: OperationOptions,
        operation: &'static str,
    ) -> Result<crate::maps::Pool> {
        let id = self.id.ok_or_else(|| Error::invalid(operation))?;
        let options =
            bounded_options(options, self.client.0.config.operation_timeout(), operation)?;
        self.client.ready(operation, &options)?;
        let monitor = self.client.connected_monitor(operation)?;
        let state = monitor.snapshot();
        let pool = state
            .osdmap()
            .and_then(|map| map.pool_by_id(id).cloned())
            .filter(|pool| pool.name().as_bytes() == self.name.as_bytes())
            .ok_or_else(|| Error::new(ErrorKind::NotFound).with_operation(operation))?;
        Ok(pool)
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

fn random_nonzero_u32(operation: &'static str) -> Result<u32> {
    let mut bytes = [0_u8; 4];
    getrandom::fill(&mut bytes)
        .map_err(|_| Error::new(ErrorKind::Unknown).with_operation(operation))?;
    Ok(u32::from_le_bytes(bytes).max(1))
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

struct MonitorManagerSource {
    monitor: Arc<MonitorClient>,
}

impl ManagerStateSource for MonitorManagerSource {
    fn snapshot(&self) -> ManagerSnapshot {
        let state = self.monitor.snapshot();
        let mut unsupported_features = false;
        let target = state.mgrmap().and_then(|mgrmap| {
            if !mgrmap.available() || mgrmap.active_gid() == 0 || mgrmap.active_name().is_empty() {
                return None;
            }
            if !GlobalFeatures(mgrmap.active_features())
                .contains(GlobalFeatures::SERVER_OCTOPUS_MASK)
            {
                unsupported_features = true;
                return None;
            }
            let address = mgrmap.active_v2_address()?.clone();
            Some(crate::mgr::client::ActiveTarget {
                epoch: mgrmap.epoch(),
                gid: mgrmap.active_gid(),
                name: mgrmap.active_name().to_owned(),
                address,
                features: mgrmap.active_features(),
            })
        });
        ManagerSnapshot {
            fsid: state.connected_fsid(),
            target,
            unsupported_features,
        }
    }
}

fn map_monitor_error(error: MonitorError, operation: &'static str) -> Error {
    if let MonitorError::WireErrno(code) = error {
        return Error::from_wire(wire_error_kind(code), code).with_operation(operation);
    }
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
        MonitorError::WireErrno(_) => unreachable!(),
    };
    Error::new(kind).with_operation(operation)
}

fn map_manager_error(error: ManagerError, operation: &'static str) -> Error {
    if let ManagerError::WireErrno(code) = error {
        return Error::from_wire(wire_error_kind(code), code).with_operation(operation);
    }
    let kind = match error {
        ManagerError::Closed | ManagerError::Session(SessionError::Closed) => ErrorKind::Closed,
        ManagerError::InvalidConfig => ErrorKind::InvalidArgument,
        ManagerError::NoActiveManager | ManagerError::IdentityUnavailable => {
            ErrorKind::NotConnected
        }
        ManagerError::UnsupportedManagerFeatures
        | ManagerError::Session(
            SessionError::UnsupportedFeature | SessionError::UnsupportedPayload,
        ) => ErrorKind::Unsupported,
        ManagerError::Session(SessionError::Cancelled) => ErrorKind::Canceled,
        ManagerError::Session(SessionError::OutcomeUnknown) => ErrorKind::OutcomeUnknown,
        ManagerError::Session(_) | ManagerError::Message(_) => ErrorKind::NotConnected,
        ManagerError::WireErrno(_) => unreachable!(),
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

#[derive(Debug)]
pub(crate) struct WatchInner {
    object: ObjectRef,
    cookie: u64,
    timeout_seconds: u32,
    stop: watch::Sender<bool>,
    status: watch::Sender<Option<Error>>,
    done: watch::Sender<bool>,
    operation: Mutex<()>,
    unwatched: AtomicBool,
}

impl Watch {
    /// Returns the watch cookie used by the server.
    #[must_use]
    pub const fn cookie(&self) -> u64 {
        self.cookie
    }

    /// Subscribes to sticky interruption and terminal-error status.
    #[must_use]
    pub fn errors(&self) -> watch::Receiver<Option<Error>> {
        self.inner.status.subscribe()
    }

    /// Subscribes to watch termination. The current value is true once terminated.
    #[must_use]
    pub fn done(&self) -> watch::Receiver<bool> {
        self.inner.done.subscribe()
    }

    /// Acknowledges one delivered notification with owned reply data.
    ///
    /// # Errors
    ///
    /// Returns validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn ack(
        &self,
        notify_id: u64,
        data: impl AsRef<[u8]>,
        options: OperationOptions,
    ) -> Result<()> {
        let payload =
            osd_watch::encode_ack(notify_id, self.cookie, data.as_ref(), max_frame_bytes())
                .map_err(|_| Error::invalid("Watch::ack"))?;
        self.inner
            .object
            .coordination_mutation(
                OSDOperation::NotifyAck {
                    cookie: self.cookie,
                    data: payload,
                },
                options,
                "Watch::ack",
            )
            .await
    }

    /// Stops local delivery and unregisters the watch. A failed unregister may be retried.
    ///
    /// # Errors
    ///
    /// Returns routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn close(&self, options: OperationOptions) -> Result<()> {
        self.inner.stop.send_replace(true);
        self.inner.done.send_replace(true);
        if self.inner.unwatched.load(Ordering::Acquire) {
            return Ok(());
        }
        let options = bounded_options(
            options,
            self.inner.object.pool.client.0.config.operation_timeout(),
            "Watch::close",
        )?;
        let _operation = wait_client_bounded(
            async { Ok(self.inner.operation.lock().await) },
            &options,
            "Watch::close",
        )
        .await?;
        if self.inner.unwatched.load(Ordering::Acquire) {
            return Ok(());
        }
        self.inner
            .object
            .watch_operation(
                self.cookie,
                osd_watch::OPERATION_UNWATCH,
                0,
                0,
                options,
                "Watch::close",
            )
            .await?;
        self.inner.unwatched.store(true, Ordering::Release);
        Ok(())
    }
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

    /// Registers a bounded watch and returns its event receiver.
    ///
    /// # Errors
    ///
    /// Returns invalid argument for a zero or oversized queue, or routing, transport,
    /// deadline, cancellation, and Ceph errors from registration.
    pub async fn watch(
        &self,
        queue: u32,
        options: OperationOptions,
    ) -> Result<(Watch, mpsc::Receiver<WatchEvent>)> {
        if queue == 0 || queue > crate::MAX_WATCH_QUEUE || self.pool.read_snapshot.is_some() {
            return Err(Error::invalid("ObjectRef::watch"));
        }
        let notifications = self.pool.client.0.objecter.notifications();
        let cookie = random_nonzero("ObjectRef::watch")?;
        let timeout_seconds = duration_seconds(self.pool.client.0.config.operation_timeout());
        self.watch_operation(
            cookie,
            osd_watch::OPERATION_REGISTER,
            0,
            timeout_seconds,
            options,
            "ObjectRef::watch",
        )
        .await?;

        let (events_tx, events_rx) = mpsc::channel(queue as usize);
        let (stop, _) = watch::channel(false);
        let (status, _) = watch::channel(None);
        let (done, _) = watch::channel(false);
        let inner = Arc::new(WatchInner {
            object: self.clone(),
            cookie,
            timeout_seconds,
            stop,
            status,
            done,
            operation: Mutex::new(()),
            unwatched: AtomicBool::new(false),
        });
        let worker = tokio::spawn(run_watch(
            Arc::clone(&inner),
            notifications,
            events_tx,
            self.pool.client.0.objecter.watch_stop(),
        ));
        if let Err(worker) = self.pool.client.0.objecter.track_watch_worker(worker) {
            inner.stop.send_replace(true);
            worker.abort();
            let _ = worker.await;
            return Err(Error::closed("ObjectRef::watch"));
        }
        Ok((Watch { cookie, inner }, events_rx))
    }

    /// Notifies all current watchers, preserving partial acknowledgments on timeout.
    ///
    /// The second tuple element reports the operation outcome. In particular, a server
    /// timeout can return both a populated reply and an error.
    pub async fn notify(
        &self,
        data: impl AsRef<[u8]>,
        options: OperationOptions,
    ) -> (NotifyReply, Result<()>) {
        let operation_name = "ObjectRef::notify";
        let caller_deadline = options.deadline();
        let options = match bounded_options(
            options,
            self.pool.client.0.config.operation_timeout(),
            operation_name,
        ) {
            Ok(options) => options,
            Err(error) => return (NotifyReply::default(), Err(error)),
        };
        let mut notifications = self.pool.client.0.objecter.notifications();
        let mut client_stop = self.pool.client.0.objecter.watch_stop();
        let cookie = match random_nonzero(operation_name) {
            Ok(cookie) => cookie,
            Err(error) => return (NotifyReply::default(), Err(error)),
        };
        let timeout_seconds = notify_timeout_seconds(self.pool.client.0.config.operation_timeout());
        let Ok(payload) =
            osd_watch::encode_notify(timeout_seconds, data.as_ref(), max_frame_bytes())
        else {
            return (NotifyReply::default(), Err(Error::invalid(operation_name)));
        };
        let result = match self
            .coordination_mutation_result(
                OSDOperation::Notify {
                    cookie,
                    data: payload,
                },
                options.clone(),
                operation_name,
            )
            .await
        {
            Ok(result) => result,
            Err(error) => return (NotifyReply::default(), Err(error)),
        };
        let Some(item) = result.operations.first() else {
            return (
                NotifyReply::default(),
                Err(Error::outcome_unknown(ErrorKind::NotConnected).with_operation(operation_name)),
            );
        };
        if item.data.len() != 8 {
            return (
                NotifyReply::default(),
                Err(Error::outcome_unknown(ErrorKind::NotConnected).with_operation(operation_name)),
            );
        }
        let notify_id = u64::from_le_bytes(item.data[..8].try_into().unwrap_or_default());
        let completion_deadline = caller_deadline.unwrap_or_else(|| {
            Instant::now()
                .checked_add(self.pool.client.0.config.operation_timeout())
                .and_then(|deadline| deadline.checked_add(Duration::from_secs(5)))
                .unwrap_or_else(Instant::now)
        });
        let completion_options = OperationOptions::new().with_deadline(completion_deadline);
        let completion = wait_client_bounded(
            wait_for_notify_completion(&mut notifications, &mut client_stop, cookie),
            &completion_options,
            operation_name,
        )
        .await;
        let notification = match completion {
            Ok(notification) => notification,
            Err(error) => {
                return (
                    NotifyReply::default(),
                    Err(Error::outcome_unknown(error.kind()).with_operation(operation_name)),
                );
            }
        };
        let reply = match decode_notify_reply(&notification.data, operation_name) {
            Ok(reply) => reply,
            Err(error) => {
                return (
                    NotifyReply::default(),
                    Err(Error::outcome_unknown(error.kind()).with_operation(operation_name)),
                );
            }
        };
        if notification.notify_id != notify_id {
            return (
                reply,
                Err(Error::outcome_unknown(ErrorKind::NotConnected).with_operation(operation_name)),
            );
        }
        let outcome = if notification.result < 0 {
            Err(
                Error::from_wire(wire_error_kind(notification.result), notification.result)
                    .with_operation(operation_name),
            )
        } else {
            Ok(())
        };
        (reply, outcome)
    }

    /// Lists active watchers on this object.
    ///
    /// # Errors
    ///
    /// Returns routing, transport, deadline, cancellation, bounds, or Ceph errors.
    pub async fn list_watchers(&self, options: OperationOptions) -> Result<Vec<Watcher>> {
        let operation_name = "ObjectRef::list_watchers";
        let result = self
            .execute_read_operations(vec![OSDOperation::ListWatchers], options, operation_name)
            .await?;
        let data = result
            .operations
            .first()
            .ok_or_else(|| Error::not_connected(operation_name))?
            .data
            .as_slice();
        let watchers = osd_watch::decode_watchers(data, max_frame_bytes(), data.len() / 17 + 1)
            .map_err(|_| Error::not_connected(operation_name))?;
        Ok(watchers
            .into_iter()
            .map(|watcher| Watcher {
                client: format!("client.{}", watcher.client),
                address: watcher.address,
                cookie: watcher.cookie,
                timeout: Duration::from_secs(u64::from(watcher.timeout_seconds)),
            })
            .collect())
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

    /// Reads allocated extents in one bounded server request.
    ///
    /// # Errors
    ///
    /// Returns validation, routing, transport, deadline, cancellation, malformed-reply, or Ceph errors.
    pub async fn sparse_read(
        &self,
        offset: u64,
        length: u64,
        options: OperationOptions,
    ) -> Result<(Vec<SparseExtent>, ObjectInfo)> {
        let operation = "ObjectRef::sparse_read";
        if length > i32::MAX as u64 || offset.checked_add(length).is_none() {
            return Err(Error::invalid(operation));
        }
        let result = self
            .execute_special_read(
                OSDOperation::SparseRead { offset, length },
                options,
                operation,
            )
            .await?;
        let item = result
            .operations
            .first()
            .ok_or_else(|| Error::not_connected(operation))?;
        let extents = crate::osd::special::decode_sparse_read(
            &item.data,
            offset,
            length,
            max_frame_bytes(),
            max_frame_bytes() / 16,
        )
        .map_err(|_| Error::not_connected(operation))?;
        Ok((
            extents,
            ObjectInfo {
                size: 0,
                modified_at: UNIX_EPOCH,
                version: result.version,
            },
        ))
    }

    /// Computes server-side checksums and returns the count-prefixed payload.
    ///
    /// # Errors
    ///
    /// Returns validation, routing, transport, deadline, cancellation, malformed-reply, or Ceph errors.
    pub async fn checksum(
        &self,
        kind: ChecksumType,
        seed: impl AsRef<[u8]>,
        offset: u64,
        length: u64,
        chunk: u64,
        options: OperationOptions,
    ) -> Result<Vec<u8>> {
        let operation = "ObjectRef::checksum";
        let (kind, width) = match kind {
            ChecksumType::XxHash32 => (0, 4),
            ChecksumType::XxHash64 => (1, 8),
            ChecksumType::Crc32c => (2, 4),
        };
        let seed = seed.as_ref();
        if seed.len() != width
            || length > i32::MAX as u64
            || offset.checked_add(length).is_none()
            || chunk > u64::from(u32::MAX)
            || chunk != 0 && (length == 0 || !length.is_multiple_of(chunk))
        {
            return Err(Error::invalid(operation));
        }
        let result = self
            .execute_special_read(
                OSDOperation::Checksum {
                    offset,
                    length,
                    chunk: u32::try_from(chunk).map_err(|_| Error::invalid(operation))?,
                    kind,
                    seed: seed.to_vec(),
                },
                options,
                operation,
            )
            .await?;
        let data = result
            .operations
            .first()
            .ok_or_else(|| Error::not_connected(operation))?
            .data
            .clone();
        crate::osd::special::validate_checksum(&data, width, max_frame_bytes())
            .map_err(|_| Error::not_connected(operation))?;
        Ok(data)
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

    /// Rolls this object back to a named pool snapshot.
    ///
    /// # Errors
    ///
    /// Returns snapshot lookup, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn rollback_to_snapshot(
        &self,
        name: &str,
        options: OperationOptions,
    ) -> Result<OpResult> {
        let snapshot = self.pool.lookup_snapshot(name, options.clone())?;
        self.rollback(snapshot.id, options, "ObjectRef::rollback_to_snapshot")
            .await
    }

    /// Rolls this object back to a self-managed snapshot.
    ///
    /// # Errors
    ///
    /// Returns validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn rollback_to_self_managed_snapshot(
        &self,
        snapshot: u64,
        options: OperationOptions,
    ) -> Result<OpResult> {
        let operation = "ObjectRef::rollback_to_self_managed_snapshot";
        if snapshot == 0 {
            return Err(Error::invalid(operation));
        }
        self.rollback(snapshot, options, operation).await
    }

    async fn rollback(
        &self,
        snapshot: u64,
        options: OperationOptions,
        operation: &'static str,
    ) -> Result<OpResult> {
        self.coordination_mutation_result(OSDOperation::Rollback(snapshot), options, operation)
            .await
            .map(|result| public_operation_result(result, operation))
    }

    /// Repeats `pattern` over one server-side write range.
    ///
    /// # Errors
    ///
    /// Returns validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn write_same(
        &self,
        offset: u64,
        length: u64,
        pattern: impl AsRef<[u8]>,
        options: OperationOptions,
    ) -> Result<OpResult> {
        let operation = "ObjectRef::write_same";
        let pattern = pattern.as_ref();
        if pattern.is_empty()
            || length == 0
            || !length.is_multiple_of(pattern.len() as u64)
            || offset.checked_add(length).is_none()
        {
            return Err(Error::invalid(operation));
        }
        self.coordination_mutation_result(
            OSDOperation::WriteSame {
                offset,
                length,
                pattern: pattern.to_vec(),
            },
            options,
            operation,
        )
        .await
        .map(|result| public_operation_result(result, operation))
    }

    /// Sends object and write allocation hints as one advisory operation.
    ///
    /// # Errors
    ///
    /// Returns routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn set_allocation_hint(
        &self,
        expected_object_size: u64,
        expected_write_size: u64,
        options: OperationOptions,
    ) -> Result<OpResult> {
        let operation = "ObjectRef::set_allocation_hint";
        self.coordination_mutation_result(
            OSDOperation::AllocationHint {
                expected_object_size,
                expected_write_size,
            },
            options,
            operation,
        )
        .await
        .map(|result| public_operation_result(result, operation))
    }

    /// Copies one source object in one server-side operation.
    ///
    /// # Errors
    ///
    /// Returns validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn copy_from(
        &self,
        source: &ObjectRef,
        source_version: u64,
        options: OperationOptions,
    ) -> Result<OpResult> {
        self.copy_from_inner(
            source,
            source_version,
            None,
            options,
            "ObjectRef::copy_from",
        )
        .await
    }

    /// Copies one source object with the frozen truncate-context suffix.
    ///
    /// # Errors
    ///
    /// Returns validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn copy_from2(
        &self,
        source: &ObjectRef,
        source_version: u64,
        truncate_sequence: u32,
        truncate_size: u64,
        options: OperationOptions,
    ) -> Result<OpResult> {
        self.copy_from_inner(
            source,
            source_version,
            Some((truncate_sequence, truncate_size)),
            options,
            "ObjectRef::copy_from2",
        )
        .await
    }

    async fn copy_from_inner(
        &self,
        source: &ObjectRef,
        source_version: u64,
        truncate: Option<(u32, u64)>,
        options: OperationOptions,
        operation: &'static str,
    ) -> Result<OpResult> {
        if !Arc::ptr_eq(&self.pool.client.0, &source.pool.client.0) {
            return Err(Error::invalid(operation));
        }
        let (osd_operation, _) = source.copy_operation(source_version, truncate, operation)?;
        self.coordination_mutation_result(osd_operation, options, operation)
            .await
            .map(|result| public_operation_result(result, operation))
    }

    pub(crate) fn copy_operation(
        &self,
        source_version: u64,
        truncate: Option<(u32, u64)>,
        operation: &'static str,
    ) -> Result<(OSDOperation, Client)> {
        let source_pool = self.pool.id.ok_or_else(|| Error::invalid(operation))?;
        let encoded = crate::osd::special::encode_copy_source(
            &crate::osd::special::CopySource {
                object: self.name.as_bytes(),
                pool: source_pool,
                locator: self.pool.locator.as_bytes(),
                namespace: self.pool.namespace.as_bytes(),
            },
            truncate,
            max_frame_bytes(),
        )
        .map_err(|_| Error::invalid(operation))?;
        let source_snapshot = self.pool.read_snapshot.unwrap_or(NO_SNAP);
        let osd_operation = if truncate.is_some() {
            OSDOperation::CopyFrom2 {
                source_snapshot,
                source_version,
                source: encoded,
            }
        } else {
            OSDOperation::CopyFrom {
                source_snapshot,
                source_version,
                source: encoded,
            }
        };
        Ok((osd_operation, self.pool.client.clone()))
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

    /// Executes one server-side object-class method as a conservative read-class call.
    ///
    /// # Errors
    ///
    /// Returns validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn exec(
        &self,
        class: impl AsRef<[u8]>,
        method: impl AsRef<[u8]>,
        input: impl AsRef<[u8]>,
        options: OperationOptions,
    ) -> Result<ClassResult> {
        let result = self
            .execute_read_named(
                ReadOp::new().exec(class, method, input)?,
                options,
                "ObjectRef::exec",
            )
            .await?;
        let result = result
            .results
            .into_iter()
            .next()
            .ok_or_else(|| Error::not_connected("ObjectRef::exec"))?;
        Ok(ClassResult {
            data: result.data,
            code: result.code,
        })
    }

    /// Acquires or renews a named advisory object lock.
    ///
    /// # Errors
    ///
    /// Returns validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn lock(
        &self,
        name: &str,
        mode: LockMode,
        lock_options: LockOptions,
        options: OperationOptions,
    ) -> Result<()> {
        let lock_type = match mode {
            LockMode::Exclusive => lock::LOCK_EXCLUSIVE,
            LockMode::Shared => lock::LOCK_SHARED,
        };
        let payload = lock::encode_lock(
            &lock::Request {
                name,
                lock_type,
                cookie: &lock_options.cookie,
                tag: &lock_options.tag,
                description: &lock_options.description,
                duration: lock_options.duration,
                renew: lock_options.renew,
            },
            max_frame_bytes(),
        )
        .map_err(|_| Error::invalid("ObjectRef::lock"))?;
        self.execute_write_named(
            WriteOp::new().exec(b"lock", b"lock", payload)?,
            options,
            "ObjectRef::lock",
        )
        .await?;
        Ok(())
    }

    /// Releases the caller's named lock cookie.
    ///
    /// # Errors
    ///
    /// Returns validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn unlock(&self, name: &str, cookie: &str, options: OperationOptions) -> Result<()> {
        let payload = lock::encode_unlock(name, cookie, max_frame_bytes())
            .map_err(|_| Error::invalid("ObjectRef::unlock"))?;
        self.execute_write_named(
            WriteOp::new().exec(b"lock", b"unlock", payload)?,
            options,
            "ObjectRef::unlock",
        )
        .await?;
        Ok(())
    }

    /// Lists the owners of a named advisory object lock.
    ///
    /// # Errors
    ///
    /// Returns validation, routing, transport, deadline, cancellation, decode, or Ceph errors.
    pub async fn list_lockers(&self, name: &str, options: OperationOptions) -> Result<Vec<Locker>> {
        let payload = lock::encode_get_info(name, max_frame_bytes())
            .map_err(|_| Error::invalid("ObjectRef::list_lockers"))?;
        let result = self
            .execute_read_named(
                ReadOp::new().exec(b"lock", b"get_info", payload)?,
                options,
                "ObjectRef::list_lockers",
            )
            .await?;
        let data = result
            .results
            .into_iter()
            .next()
            .ok_or_else(|| Error::not_connected("ObjectRef::list_lockers"))?
            .data;
        let info = lock::decode_info(&data, data.len().max(1), data.len() / 13 + 1)
            .map_err(|_| Error::not_connected("ObjectRef::list_lockers"))?;
        let mode = match info.lock_type {
            lock::LOCK_EXCLUSIVE => LockMode::Exclusive,
            lock::LOCK_SHARED => LockMode::Shared,
            _ if info.holders.is_empty() => return Ok(Vec::new()),
            _ => return Err(Error::not_connected("ObjectRef::list_lockers")),
        };
        Ok(info
            .holders
            .into_iter()
            .map(|holder| Locker {
                client: format!("client.{}", holder.client),
                cookie: holder.cookie,
                address: holder.address,
                description: holder.description,
                expiration: holder.expiration,
                mode,
                tag: info.tag.clone(),
            })
            .collect())
    }

    /// Breaks one named advisory lock owner by client identity and cookie.
    ///
    /// # Errors
    ///
    /// Returns validation, routing, transport, deadline, cancellation, or Ceph errors.
    pub async fn break_lock(
        &self,
        name: &str,
        client: &str,
        cookie: &str,
        options: OperationOptions,
    ) -> Result<()> {
        let client =
            parse_lock_client(client).ok_or_else(|| Error::invalid("ObjectRef::break_lock"))?;
        let payload = lock::encode_break(name, client, cookie, max_frame_bytes())
            .map_err(|_| Error::invalid("ObjectRef::break_lock"))?;
        self.execute_write_named(
            WriteOp::new().exec(b"lock", b"break_lock", payload)?,
            options,
            "ObjectRef::break_lock",
        )
        .await?;
        Ok(())
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
        self.execute_write_named(operation, options, "ObjectRef::execute_write")
            .await
    }

    async fn execute_write_named(
        &self,
        operation: WriteOp,
        options: OperationOptions,
        operation_name: &'static str,
    ) -> Result<OpResult> {
        if operation
            .copy_sources()
            .any(|source| !Arc::ptr_eq(&source.0, &self.pool.client.0))
        {
            return Err(Error::invalid(operation_name));
        }
        let operations = operation.into_operations()?;
        let options = self.prepare_operation(options, operation_name)?;
        if self.pool.read_snapshot.is_some() || !self.pool.write_snapshot_valid {
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

    async fn execute_special_read(
        &self,
        operation: OSDOperation,
        options: OperationOptions,
        operation_name: &'static str,
    ) -> Result<CompoundResult> {
        let options = self.prepare_operation(options, operation_name)?;
        let monitor = self.pool.client.connected_monitor(operation_name)?;
        let target = self.target(&monitor, operation_name)?;
        let result = self
            .pool
            .client
            .0
            .objecter
            .execute_operations(&monitor, target, vec![operation], &options)
            .await
            .map_err(|error| map_osd_error(error, operation_name))?;
        let item = result
            .operations
            .first()
            .ok_or_else(|| Error::not_connected(operation_name))?;
        if item.code < 0 {
            return Err(Error::from_wire(wire_error_kind(item.code), item.code)
                .with_operation(operation_name));
        }
        Ok(result)
    }

    async fn coordination_mutation(
        &self,
        operation: OSDOperation,
        options: OperationOptions,
        operation_name: &'static str,
    ) -> Result<()> {
        self.coordination_mutation_result(operation, options, operation_name)
            .await?;
        Ok(())
    }

    async fn coordination_mutation_result(
        &self,
        operation: OSDOperation,
        options: OperationOptions,
        operation_name: &'static str,
    ) -> Result<CompoundResult> {
        let allows_failure = matches!(operation, OSDOperation::AllocationHint { .. });
        let options = self.prepare_operation(options, operation_name)?;
        if self.pool.read_snapshot.is_some() || !self.pool.write_snapshot_valid {
            return Err(Error::invalid(operation_name));
        }
        let monitor = self.pool.client.connected_monitor(operation_name)?;
        let target = self.target(&monitor, operation_name)?;
        let result = self
            .pool
            .client
            .0
            .objecter
            .mutate_operations(monitor, target, vec![operation], options)
            .await
            .map_err(|error| map_osd_error(error, operation_name))?;
        let item = result
            .operations
            .first()
            .ok_or_else(|| Error::not_connected(operation_name))?;
        if item.code < 0 && !allows_failure {
            return Err(Error::from_wire(wire_error_kind(item.code), item.code)
                .with_operation(operation_name));
        }
        Ok(result)
    }

    async fn watch_operation(
        &self,
        cookie: u64,
        operation: u8,
        generation: u32,
        timeout: u32,
        options: OperationOptions,
        operation_name: &'static str,
    ) -> Result<()> {
        self.coordination_mutation(
            OSDOperation::Watch {
                cookie,
                version: 0,
                operation,
                generation,
                timeout,
            },
            options,
            operation_name,
        )
        .await
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
        if self.pool.read_snapshot.is_some() || !self.pool.write_snapshot_valid {
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
            snapshot_sequence: self.pool.write_snapshot_sequence,
            write_snapshots: self.pool.write_snapshots.clone(),
        })
    }
}

fn valid_snapshot_context(context: &SnapshotContext) -> bool {
    context
        .snapshots
        .iter()
        .enumerate()
        .all(|(index, snapshot)| {
            *snapshot <= context.sequence
                && (index == 0 || *snapshot < context.snapshots[index - 1])
        })
}

fn duration_seconds(duration: Duration) -> u32 {
    let rounded = duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() != 0));
    u32::try_from(rounded.max(1)).unwrap_or(u32::MAX)
}

fn notify_timeout_seconds(duration: Duration) -> u32 {
    duration_seconds(duration).saturating_sub(5).max(1)
}

fn max_frame_bytes() -> usize {
    usize::try_from(FRAME_LIMITS.max_frame_bytes).unwrap_or(usize::MAX)
}

async fn wait_for_notify_completion(
    notifications: &mut tokio::sync::broadcast::Receiver<osd_watch::Notification>,
    client_stop: &mut watch::Receiver<bool>,
    cookie: u64,
) -> Result<osd_watch::Notification> {
    let operation = "ObjectRef::notify";
    loop {
        if *client_stop.borrow() {
            return Err(Error::closed(operation));
        }
        tokio::select! {
            received = notifications.recv() => match received {
                Ok(notification)
                    if notification.cookie == cookie
                        && notification.opcode == osd_watch::EVENT_COMPLETE =>
                {
                    return Ok(notification);
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    return Err(Error::new(ErrorKind::OutcomeUnknown).with_operation(operation));
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    return Err(Error::closed(operation));
                }
            },
            changed = client_stop.changed() => {
                if changed.is_err() || *client_stop.borrow() {
                    return Err(Error::closed(operation));
                }
            }
        }
    }
}

fn decode_notify_reply(data: &[u8], operation: &'static str) -> Result<NotifyReply> {
    let (acknowledged, timed_out) =
        osd_watch::decode_notify_result(data, max_frame_bytes(), data.len() / 16 + 1)
            .map_err(|_| Error::not_connected(operation))?;
    Ok(NotifyReply {
        acknowledged: acknowledged
            .into_iter()
            .map(|item| NotifyAcknowledgment {
                client: item.client,
                cookie: item.cookie,
                data: item.data,
            })
            .collect(),
        timed_out: timed_out
            .into_iter()
            .map(|item| NotifyTimeout {
                client: item.client,
                cookie: item.cookie,
            })
            .collect(),
    })
}

async fn run_watch(
    watch: Arc<WatchInner>,
    mut notifications: tokio::sync::broadcast::Receiver<osd_watch::Notification>,
    events: mpsc::Sender<WatchEvent>,
    mut client_stop: watch::Receiver<bool>,
) {
    if *watch.stop.borrow() || *client_stop.borrow() {
        watch.done.send_replace(true);
        return;
    }
    let period = Duration::from_secs(u64::from(watch.timeout_seconds)) / 3;
    let mut keepalive = tokio::time::interval(period.max(Duration::from_secs(1)));
    keepalive.tick().await;
    let mut stop = watch.stop.subscribe();
    let mut generation = 0_u32;
    loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    break;
                }
            }
            changed = client_stop.changed() => {
                if changed.is_err() || *client_stop.borrow() {
                    break;
                }
            }
            received = notifications.recv() => match received {
                Ok(notification)
                    if notification.cookie == 0
                        && notification.opcode == osd_watch::EVENT_DISCONNECT =>
                {
                    if !recover_watch(&watch, &mut generation).await {
                        break;
                    }
                }
                Ok(notification) if notification.cookie != watch.cookie => {}
                Ok(notification) if notification.opcode == osd_watch::EVENT_NOTIFY => {
                    let event = WatchEvent {
                        notify_id: notification.notify_id,
                        cookie: notification.cookie,
                        notifier: notification.notifier,
                        data: notification.data,
                    };
                    if events.try_send(event).is_err() {
                        report_watch_error(&watch, ErrorKind::WatchInterrupted);
                        break;
                    }
                }
                Ok(notification) if notification.opcode == osd_watch::EVENT_DISCONNECT => {
                    report_watch_error(&watch, ErrorKind::WatchInterrupted);
                    if !recover_watch(&watch, &mut generation).await {
                        break;
                    }
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    report_watch_error(&watch, ErrorKind::WatchInterrupted);
                    break;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    report_watch_error(&watch, ErrorKind::Closed);
                    break;
                }
            },
            _ = keepalive.tick() => {
                let operation_guard = watch.operation.lock().await;
                let options = worker_options(&watch);
                let ping = watch.object.watch_operation(
                    watch.cookie,
                    osd_watch::OPERATION_PING,
                    generation,
                    0,
                    options,
                    "Watch::keepalive",
                ).await;
                drop(operation_guard);
                if ping.is_err() {
                    report_watch_error(&watch, ErrorKind::WatchInterrupted);
                    if !recover_watch(&watch, &mut generation).await {
                        break;
                    }
                }
            }
        }
    }
    watch.done.send_replace(true);
}

async fn recover_watch(watch: &WatchInner, generation: &mut u32) -> bool {
    let Some(next_generation) = generation.checked_add(1) else {
        report_watch_error(watch, ErrorKind::WatchInterrupted);
        return false;
    };
    *generation = next_generation;
    let _operation = watch.operation.lock().await;
    if *watch.stop.borrow() {
        return false;
    }
    let reconnect = watch
        .object
        .watch_operation(
            watch.cookie,
            osd_watch::OPERATION_RECONNECT,
            *generation,
            watch.timeout_seconds,
            worker_options(watch),
            "Watch::reconnect",
        )
        .await;
    if reconnect.is_ok() {
        return true;
    }
    *generation = 0;
    let register = watch
        .object
        .watch_operation(
            watch.cookie,
            osd_watch::OPERATION_REGISTER,
            0,
            watch.timeout_seconds,
            worker_options(watch),
            "Watch::reregister",
        )
        .await;
    if let Err(error) = register {
        watch.status.send_if_modified(|status| {
            if status.is_some() {
                false
            } else {
                *status = Some(error);
                true
            }
        });
        false
    } else {
        true
    }
}

fn worker_options(watch: &WatchInner) -> OperationOptions {
    let lease_slice =
        (Duration::from_secs(u64::from(watch.timeout_seconds)) / 3).max(Duration::from_secs(1));
    let timeout = lease_slice.min(watch.object.pool.client.0.config.operation_timeout());
    OperationOptions::new()
        .with_timeout(timeout)
        .unwrap_or_default()
}

fn report_watch_error(watch: &WatchInner, kind: ErrorKind) {
    watch.status.send_if_modified(|status| {
        if status.is_some() {
            false
        } else {
            *status = Some(Error::new(kind).with_operation("ObjectRef::watch"));
            true
        }
    });
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

fn parse_lock_client(value: &str) -> Option<u64> {
    value.strip_prefix("client.")?.parse::<u64>().ok()
}

fn command_result_from_osd(reply: OSDCommandResult) -> CommandResult {
    CommandResult {
        output: reply.output,
        status: reply.status,
    }
}

fn command_argv(command: &[u8], operation: &'static str) -> Result<Vec<String>> {
    let Some(start) = command.iter().position(|byte| !byte.is_ascii_whitespace()) else {
        return Err(Error::invalid(operation));
    };
    let Some(end) = command.iter().rposition(|byte| !byte.is_ascii_whitespace()) else {
        return Err(Error::invalid(operation));
    };
    let trimmed = &command[start..=end];
    let value: serde_json::Value =
        serde_json::from_slice(trimmed).map_err(|_| Error::invalid(operation))?;
    match value {
        serde_json::Value::Object(_) => {
            let command = std::str::from_utf8(trimmed).map_err(|_| Error::invalid(operation))?;
            Ok(vec![command.to_owned()])
        }
        _ => Err(Error::invalid(operation)),
    }
}

pub(crate) fn decode_inconsistent_pgs(
    data: &[u8],
    operation: &'static str,
) -> Result<Vec<InconsistentPg>> {
    let Some(start) = data.iter().position(|byte| !byte.is_ascii_whitespace()) else {
        return Ok(Vec::new());
    };
    let Some(end) = data.iter().rposition(|byte| !byte.is_ascii_whitespace()) else {
        return Ok(Vec::new());
    };
    let trimmed = &data[start..=end];
    if !matches!(trimmed.first(), Some(b'[' | b'{')) {
        return Err(Error::invalid(operation));
    }
    let value: serde_json::Value =
        serde_json::from_slice(trimmed).map_err(|_| Error::invalid(operation))?;
    let entries = match value {
        serde_json::Value::Array(entries) => entries,
        serde_json::Value::Object(mut object) => {
            let Some(value) = object.remove("pg_stats") else {
                return Ok(Vec::new());
            };
            if value.is_null() {
                return Ok(Vec::new());
            }
            value
                .as_array()
                .cloned()
                .ok_or_else(|| Error::invalid(operation))?
        }
        _ => return Err(Error::invalid(operation)),
    };
    let mut result = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(object) = entry.as_object() else {
            return Err(Error::invalid(operation));
        };
        let Some(pgid) = object.get("pgid").and_then(serde_json::Value::as_str) else {
            return Err(Error::invalid(operation));
        };
        if pgid.is_empty() {
            return Err(Error::invalid(operation));
        }
        result.push(InconsistentPg {
            pg: pgid.to_owned(),
            errors: Vec::new(),
        });
    }
    Ok(result)
}

fn format_session_address(address: &EntityAddr) -> Option<String> {
    let endpoint = address.endpoint()?;
    let prefix = if address.is_v2() { "v2" } else { "v1" };
    Some(format!("{prefix}:{endpoint}/{}", address.nonce()))
}

fn validate_blocklist_arguments(
    address: &str,
    duration: Duration,
    operation: &'static str,
) -> Result<()> {
    if crate::protocol::address::parse_entity_addr(address).is_err()
        || duration.subsec_nanos() != 0
        || duration.as_secs() > u64::from(u32::MAX)
    {
        return Err(Error::invalid(operation));
    }
    Ok(())
}

fn blocklist_command_payload(
    address: &str,
    duration: Duration,
    operation: &'static str,
) -> Result<Vec<u8>> {
    let mut command = serde_json::Map::new();
    command.insert(
        "prefix".to_owned(),
        serde_json::Value::String("osd blocklist".to_owned()),
    );
    command.insert(
        "blocklistop".to_owned(),
        serde_json::Value::String("add".to_owned()),
    );
    command.insert(
        "addr".to_owned(),
        serde_json::Value::String(address.to_owned()),
    );
    if duration > Duration::ZERO {
        let seconds = duration.as_secs();
        let expire = serde_json::from_str::<serde_json::Value>(&format!("{seconds}.0"))
            .map_err(|_| Error::invalid(operation))?;
        command.insert("expire".to_owned(), expire);
    }
    serde_json::to_vec(&serde_json::Value::Object(command)).map_err(|_| Error::invalid(operation))
}

fn sorted_application_names(metadata: &HashMap<String, HashMap<String, String>>) -> Vec<String> {
    let mut applications = metadata.keys().cloned().collect::<Vec<_>>();
    applications.sort();
    applications
}

fn application_values(
    metadata: &HashMap<String, HashMap<String, String>>,
    application: &str,
    operation: &'static str,
) -> Result<HashMap<String, String>> {
    metadata
        .get(application)
        .cloned()
        .ok_or_else(|| Error::new(ErrorKind::NotFound).with_operation(operation))
}

fn application_value(
    metadata: &HashMap<String, HashMap<String, String>>,
    application: &str,
    key: &str,
    operation: &'static str,
) -> Result<String> {
    application_values(metadata, application, operation)?
        .remove(key)
        .ok_or_else(|| Error::new(ErrorKind::NotFound).with_operation(operation))
}

fn map_osd_error(error: ClientError, operation: &'static str) -> Error {
    let (kind, wire_errno) = match error {
        ClientError::Closed => (ErrorKind::Closed, None),
        ClientError::NotConnected
        | ClientError::StaleMap
        | ClientError::NoPrimary
        | ClientError::RecoveryExhausted
        | ClientError::MalformedReply => (ErrorKind::NotConnected, None),
        ClientError::LimitExceeded => (ErrorKind::InvalidArgument, None),
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
    use crate::mon::messages::{MESSAGE_MON_COMMAND_REPLY, MESSAGE_MON_MAP, MESSAGE_OSD_MAP};
    use crate::msgr::message::{Message, MessageHeader, MessageLengths};
    use crate::wire::{Decoder, Encoder};
    use crate::*;
    use std::future::Future;
    use std::pin::pin;
    use std::sync::atomic::AtomicUsize;
    use std::task::{Context, Poll, Waker};
    use tokio::sync::{broadcast, mpsc, watch};

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

    fn monitor_command_reply(
        transaction_id: u64,
        result: i32,
        status: &str,
        command: &[&str],
        output: &[u8],
    ) -> Message {
        let mut encoder = Encoder::new(1024);
        encoder.u64(1);
        encoder.i16(-1);
        encoder.u64(0);
        encoder.i32(result);
        encoder.string(status);
        encoder.u32(u32::try_from(command.len()).expect("command count"));
        for item in command {
            encoder.string(item);
        }
        let mut message = front_message(
            MESSAGE_MON_COMMAND_REPLY,
            1,
            0,
            encoder.finish().expect("command reply"),
        );
        message.header.transaction_id = transaction_id;
        message.lengths.data = u32::try_from(output.len()).expect("output length");
        message.data = output.to_vec();
        message
    }

    fn statfs_reply(transaction_id: u64, fsid: Fsid) -> Message {
        let mut encoder = Encoder::new(128);
        encoder.raw(&fsid.0);
        encoder.u64(43);
        encoder.u64(100);
        encoder.u64(40);
        encoder.u64(60);
        encoder.u64(7);
        let mut message = front_message(
            crate::mon::messages::MESSAGE_STATFS_REPLY,
            1,
            1,
            encoder.finish().expect("statfs reply"),
        );
        message.header.transaction_id = transaction_id;
        message
    }

    fn pool_stats_reply(transaction_id: u64, fsid: Fsid, pool: &str) -> Message {
        let mut front = Encoder::new(16 << 10);
        front.u64(9);
        front.i16(-1);
        front.u64(0);
        front.raw(&fsid.0);
        front.u32(1);
        front.string(pool);
        front.versioned(7, 5, |pool_stats| {
            pool_stats.versioned(2, 2, |collection| {
                collection.versioned(20, 14, |sum| {
                    for index in 0..40 {
                        let value = match index {
                            0 => 100_u64,
                            1 => 3,
                            8 => 5,
                            10 => 7,
                            22 => 11,
                            37 => 13,
                            _ => 0,
                        };
                        if (28..=31).contains(&index) {
                            sum.i32(i32::try_from(value).expect("sum value"));
                        } else {
                            sum.u64(value);
                        }
                    }
                });
                collection.u32(0);
            });
            pool_stats.i64(0);
            pool_stats.i64(0);
            pool_stats.i32(0);
            pool_stats.i32(0);
            pool_stats.versioned(1, 1, |store| {
                for index in 0..10 {
                    let value = match index {
                        3 => 200_u64,
                        8 => 17,
                        _ => 0,
                    };
                    store.u64(value);
                }
            });
            pool_stats.i32(1);
        });
        front.bool(true);
        let mut message = front_message(
            crate::mon::messages::MESSAGE_GET_POOL_STATS_REPLY,
            2,
            1,
            front.finish().expect("pool stats reply"),
        );
        message.header.transaction_id = transaction_id;
        message
    }

    fn pool_operation_reply(
        transaction_id: u64,
        fsid: Fsid,
        result: i32,
        epoch: u32,
        has_response_data: bool,
    ) -> Message {
        let mut encoder = Encoder::new(128);
        encoder.u64(0);
        encoder.i16(-1);
        encoder.u64(0);
        encoder.raw(&fsid.0);
        encoder.i32(result);
        encoder.u32(epoch);
        encoder.u8(u8::from(has_response_data));
        if has_response_data {
            encoder.bytes(&1_u64.to_le_bytes());
        }
        let mut message = front_message(
            crate::mon::messages::MESSAGE_POOL_OPERATION_REPLY,
            1,
            1,
            encoder.finish().expect("pool operation reply"),
        );
        message.header.transaction_id = transaction_id;
        message
    }

    fn client() -> Client {
        Client::new(
            Config::default()
                .with_monitors(["127.0.0.1:3300"])
                .expect("monitors"),
        )
        .expect("client")
    }

    fn test_object() -> ObjectRef {
        ObjectRef {
            pool: Pool {
                client: client(),
                id: Some(7),
                name: ObjectName::new(b"pool").expect("pool"),
                namespace: Namespace::new(b"").expect("namespace"),
                locator: LocatorKey::new(b"").expect("locator"),
                read_snapshot: None,
                write_snapshot_sequence: 0,
                write_snapshots: Vec::new(),
                write_snapshot_valid: true,
            },
            name: ObjectName::new(b"object").expect("object"),
        }
    }

    fn test_watch(object: ObjectRef, cookie: u64) -> Arc<WatchInner> {
        let (stop, _) = watch::channel(false);
        let (status, _) = watch::channel(None);
        let (done, _) = watch::channel(false);
        Arc::new(WatchInner {
            object,
            cookie,
            timeout_seconds: 3_600,
            stop,
            status,
            done,
            operation: Mutex::new(()),
            unwatched: AtomicBool::new(false),
        })
    }

    #[tokio::test]
    async fn compound_copy_rejects_a_cross_client_source_before_network_access() {
        let destination = test_object();
        let source = test_object();
        let operation = WriteOp::new()
            .copy_from(&source, 3)
            .expect("copy operation");
        let error = destination
            .execute_write(operation, OperationOptions::new())
            .await
            .expect_err("cross-client source");
        assert_eq!(error.kind(), ErrorKind::InvalidArgument);
    }

    #[test]
    fn compound_copy_builders_preserve_source_context_and_variant() {
        let destination = test_object();
        let mut source = destination.pool().object(b"source").expect("source object");
        source.pool.read_snapshot = Some(9);
        let operation = WriteOp::new()
            .copy_from(&source, 3)
            .expect("copy")
            .copy_from2(&source, 4, 5, 6)
            .expect("copy2");
        assert!(
            operation
                .copy_sources()
                .all(|client| { Arc::ptr_eq(&client.0, &destination.pool.client.0) })
        );
        let operations = operation.into_operations().expect("operations");
        assert!(matches!(
            &operations[0],
            OSDOperation::CopyFrom {
                source_snapshot: 9,
                source_version: 3,
                source,
            } if !source.is_empty()
        ));
        assert!(matches!(
            &operations[1],
            OSDOperation::CopyFrom2 {
                source_snapshot: 9,
                source_version: 4,
                source,
            } if source.ends_with(&[5, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0])
        ));
    }

    #[tokio::test]
    async fn watch_forwards_owned_events_and_stops_on_overflow() {
        let (notifications, receiver) = broadcast::channel(4);
        let (events_tx, mut events_rx) = mpsc::channel(1);
        let (_client_stop_tx, client_stop) = watch::channel(false);
        let inner = test_watch(test_object(), 9);
        let mut done = inner.done.subscribe();
        let status = inner.status.subscribe();
        let worker = tokio::spawn(run_watch(
            Arc::clone(&inner),
            receiver,
            events_tx,
            client_stop,
        ));
        notifications
            .send(osd_watch::Notification {
                cookie: 9,
                version: 1,
                notify_id: 11,
                opcode: osd_watch::EVENT_NOTIFY,
                data: vec![0, 0xff],
                result: 0,
                notifier: 12,
            })
            .expect("first notification");
        notifications
            .send(osd_watch::Notification {
                cookie: 9,
                version: 2,
                notify_id: 13,
                opcode: osd_watch::EVENT_NOTIFY,
                data: vec![1],
                result: 0,
                notifier: 14,
            })
            .expect("overflow notification");
        tokio::time::timeout(Duration::from_secs(1), done.wait_for(|done| *done))
            .await
            .expect("watch stop timeout")
            .expect("done channel");
        let event = events_rx.recv().await.expect("first event");
        assert_eq!(
            event,
            WatchEvent {
                notify_id: 11,
                cookie: 9,
                notifier: 12,
                data: vec![0, 0xff],
            }
        );
        assert_eq!(
            status.borrow().as_ref().map(Error::kind),
            Some(ErrorKind::WatchInterrupted)
        );
        worker.await.expect("watch worker");
    }

    #[tokio::test]
    async fn watch_stops_when_event_receiver_is_dropped() {
        let (notifications, receiver) = broadcast::channel(1);
        let (events_tx, events_rx) = mpsc::channel(1);
        drop(events_rx);
        let (_client_stop_tx, client_stop) = watch::channel(false);
        let inner = test_watch(test_object(), 4);
        let mut done = inner.done.subscribe();
        let worker = tokio::spawn(run_watch(
            Arc::clone(&inner),
            receiver,
            events_tx,
            client_stop,
        ));
        notifications
            .send(osd_watch::Notification {
                cookie: 4,
                version: 1,
                notify_id: 2,
                opcode: osd_watch::EVENT_NOTIFY,
                data: Vec::new(),
                result: 0,
                notifier: 3,
            })
            .expect("notification");
        tokio::time::timeout(Duration::from_secs(1), done.wait_for(|done| *done))
            .await
            .expect("watch stop timeout")
            .expect("done channel");
        assert_eq!(
            inner.status.borrow().as_ref().map(Error::kind),
            Some(ErrorKind::WatchInterrupted)
        );
        worker.await.expect("watch worker");
    }

    #[tokio::test]
    async fn watch_worker_observes_stop_set_before_start() {
        let (_notifications, receiver) = broadcast::channel(1);
        let (events_tx, _events_rx) = mpsc::channel(1);
        let (client_stop_tx, client_stop) = watch::channel(false);
        client_stop_tx.send_replace(true);
        let inner = test_watch(test_object(), 4);
        let mut done = inner.done.subscribe();
        let worker = tokio::spawn(run_watch(
            Arc::clone(&inner),
            receiver,
            events_tx,
            client_stop,
        ));
        tokio::time::timeout(Duration::from_secs(1), done.wait_for(|done| *done))
            .await
            .expect("watch stop timeout")
            .expect("done channel");
        worker.await.expect("watch worker");
    }

    #[tokio::test]
    async fn session_failure_triggers_immediate_watch_recovery() {
        let (notifications, receiver) = broadcast::channel(1);
        let (events_tx, _events_rx) = mpsc::channel(1);
        let (_client_stop_tx, client_stop) = watch::channel(false);
        let inner = test_watch(test_object(), 4);
        let mut done = inner.done.subscribe();
        let worker = tokio::spawn(run_watch(
            Arc::clone(&inner),
            receiver,
            events_tx,
            client_stop,
        ));
        notifications
            .send(osd_watch::Notification {
                cookie: 0,
                version: 0,
                notify_id: 0,
                opcode: osd_watch::EVENT_DISCONNECT,
                data: Vec::new(),
                result: 0,
                notifier: 0,
            })
            .expect("session failure");
        tokio::time::timeout(Duration::from_secs(1), done.wait_for(|done| *done))
            .await
            .expect("watch recovery timeout")
            .expect("done channel");
        assert!(inner.status.borrow().is_some());
        worker.await.expect("watch worker");
    }

    #[test]
    fn notify_reply_preserves_acknowledgments_and_timeouts() {
        let mut encoder = Encoder::new(256);
        encoder.u32(1);
        encoder.u64(11);
        encoder.u64(12);
        encoder.bytes(&[0, 0xff]);
        encoder.u32(1);
        encoder.u64(21);
        encoder.u64(22);
        let bytes = encoder.finish().expect("notify reply");
        let reply = decode_notify_reply(&bytes, "test").expect("decoded reply");
        assert_eq!(
            reply.acknowledged,
            vec![NotifyAcknowledgment {
                client: 11,
                cookie: 12,
                data: vec![0, 0xff],
            }]
        );
        assert_eq!(
            reply.timed_out,
            vec![NotifyTimeout {
                client: 21,
                cookie: 22,
            }]
        );
        assert_eq!(duration_seconds(Duration::from_millis(1)), 1);
        assert_eq!(duration_seconds(Duration::from_millis(1_001)), 2);
        assert_eq!(notify_timeout_seconds(Duration::from_secs(4)), 1);
        assert_eq!(notify_timeout_seconds(Duration::from_secs(30)), 25);
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
            client_addresses: EntityAddrVec(vec![
                crate::protocol::address::parse_entity_addr("v2:192.0.2.1:3300/7")
                    .expect("session address"),
            ]),
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
        let addresses = client.session_addresses();
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0], "v2:192.0.2.1:3300/7");
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
            client_addresses: EntityAddrVec(Vec::new()),
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

    #[tokio::test]
    async fn monitor_command_rejects_malformed_input() {
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
            client_addresses: EntityAddrVec(Vec::new()),
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

        let (reply, result) = client
            .monitor_command(b"[]", b"opaque", OperationOptions::new())
            .await;
        assert_eq!(reply.output, Vec::<u8>::new());
        assert!(reply.status.is_empty());
        assert_eq!(
            result.expect_err("invalid input").kind(),
            ErrorKind::InvalidArgument
        );
        client
            .shutdown(OperationOptions::new())
            .await
            .expect("shutdown");
    }

    #[tokio::test]
    async fn blocklist_rejects_malformed_arguments_before_connection() {
        let client = client();
        let cases = [
            ("not-an-address", Duration::from_secs(1)),
            ("v2:192.0.2.1:6800/1", Duration::from_millis(1)),
            (
                "v2:192.0.2.1:6800/1",
                Duration::from_secs(u64::from(u32::MAX) + 1),
            ),
        ];
        for (address, duration) in cases {
            assert_eq!(
                client
                    .blocklist(address, duration, OperationOptions::new())
                    .await
                    .expect_err("invalid blocklist arguments")
                    .kind(),
                ErrorKind::InvalidArgument
            );
        }
    }

    #[test]
    fn blocklist_command_payload_uses_numeric_float_expiration() {
        let payload =
            blocklist_command_payload("v2:192.0.2.1:6800/1", Duration::from_secs(60), "test")
                .expect("payload");
        assert_eq!(
            String::from_utf8(payload).expect("utf8"),
            r#"{"addr":"v2:192.0.2.1:6800/1","blocklistop":"add","expire":60.0,"prefix":"osd blocklist"}"#
        );

        let zero = blocklist_command_payload("v2:192.0.2.1:6800/1", Duration::ZERO, "test")
            .expect("payload");
        assert_eq!(
            String::from_utf8(zero).expect("utf8"),
            r#"{"addr":"v2:192.0.2.1:6800/1","blocklistop":"add","prefix":"osd blocklist"}"#
        );
    }

    #[test]
    fn decode_inconsistent_pgs_accepts_supported_shapes() {
        let operation = "test";
        assert_eq!(
            decode_inconsistent_pgs(b"", operation).expect("empty"),
            vec![]
        );
        assert_eq!(
            decode_inconsistent_pgs(br#"[{"pgid":"7.1a"}]"#, operation).expect("array"),
            vec![InconsistentPg {
                pg: "7.1a".to_owned(),
                errors: Vec::new()
            }]
        );
        assert_eq!(
            decode_inconsistent_pgs(br#"{"pg_stats":[{"pgid":"3.f"}]}"#, operation)
                .expect("envelope"),
            vec![InconsistentPg {
                pg: "3.f".to_owned(),
                errors: Vec::new()
            }]
        );
        assert_eq!(
            decode_inconsistent_pgs(br#"{"pg_stats":null}"#, operation).expect("null"),
            vec![]
        );
        assert_eq!(
            decode_inconsistent_pgs(br"{}", operation).expect("missing pg_stats"),
            vec![]
        );
    }

    #[test]
    fn decode_inconsistent_pgs_rejects_malformed_and_empty_pgid() {
        let operation = "test";
        for value in [
            br"null".as_slice(),
            br#"{"pg_stats":{}}"#.as_slice(),
            br#"[{"pgid":""}]"#.as_slice(),
            br#"[{"pgid":1}]"#.as_slice(),
            br#"[{"wrong":"7.1a"}]"#.as_slice(),
        ] {
            assert_eq!(
                decode_inconsistent_pgs(value, operation)
                    .expect_err("malformed response")
                    .kind(),
                ErrorKind::InvalidArgument
            );
        }
    }

    #[test]
    fn command_argv_accepts_any_single_json_object_and_rejects_non_objects() {
        let operation = "test";
        assert_eq!(
            command_argv(br#"  {"prefix":"status"}  "#, operation).expect("object"),
            vec!["{\"prefix\":\"status\"}".to_owned()]
        );
        assert_eq!(
            command_argv(b"{}", operation).expect("empty object"),
            vec!["{}".to_owned()]
        );
        for value in [b"[]".as_slice(), b"\"text\"".as_slice(), b"0".as_slice()] {
            assert_eq!(
                command_argv(value, operation)
                    .expect_err("non-object should fail")
                    .kind(),
                ErrorKind::InvalidArgument
            );
        }
    }

    #[test]
    fn application_helpers_sort_own_and_report_missing_items() {
        let metadata = HashMap::from([
            (
                "zeta".to_owned(),
                HashMap::from([("k1".to_owned(), "v1".to_owned())]),
            ),
            (
                "alpha".to_owned(),
                HashMap::from([("k2".to_owned(), "v2".to_owned())]),
            ),
        ]);
        assert_eq!(
            sorted_application_names(&metadata),
            vec!["alpha".to_owned(), "zeta".to_owned()]
        );

        let mut values = application_values(&metadata, "alpha", "op").expect("values");
        values.insert("k2".to_owned(), "changed".to_owned());
        assert_eq!(
            application_value(&metadata, "alpha", "k2", "op").expect("value"),
            "v2"
        );

        assert_eq!(
            application_values(&metadata, "missing", "op")
                .expect_err("missing app")
                .kind(),
            ErrorKind::NotFound
        );
        assert_eq!(
            application_value(&metadata, "alpha", "missing", "op")
                .expect_err("missing key")
                .kind(),
            ErrorKind::NotFound
        );
    }

    #[test]
    fn session_address_formatting_is_canonical() {
        let v2 =
            crate::protocol::address::parse_entity_addr("v2:192.0.2.1:3300/7").expect("v2 address");
        let v1 = crate::protocol::address::parse_entity_addr("v1:[2001:db8::1]:6789/3")
            .expect("v1 address");
        assert_eq!(
            format_session_address(&v2),
            Some("v2:192.0.2.1:3300/7".to_owned())
        );
        assert_eq!(
            format_session_address(&v1),
            Some("v1:[2001:db8::1]:6789/3".to_owned())
        );
    }

    #[tokio::test]
    async fn application_mutation_waits_for_newer_osd_map() {
        let (incoming_tx, incoming_rx) = mpsc::channel(8);
        let (sent_tx, mut sent_rx) = mpsc::channel(8);
        let session = Arc::new(FakeSession {
            incoming: Mutex::new(incoming_rx),
            sent: sent_tx,
            closed: AtomicBool::new(false),
        });
        let opened = Arc::new(Mutex::new(Some(OpenedMonitorSession {
            session,
            global_id: 42,
            client_addresses: EntityAddrVec(Vec::new()),
        })));
        let factory: SessionFactory = Arc::new(move |_| {
            let opened = Arc::clone(&opened);
            Box::pin(async move { Ok(opened.lock().await.take().expect("single session")) })
        });
        let client = Client::with_factory(configured(), factory).expect("client");
        let connecting = tokio::spawn({
            let client = client.clone();
            async move { client.connect(OperationOptions::new()).await }
        });
        sent_rx.recv().await.expect("subscription");

        let mon_bytes = include_bytes!("../testdata/p04/monmap-v9.bin");
        let full_bytes = include_bytes!("../testdata/p04/osdmap-v8.bin");
        let full_map = crate::maps::decode_osdmap(full_bytes, MAP_LIMITS).expect("full map");
        incoming_tx
            .send(monmap_message(mon_bytes))
            .await
            .expect("monmap");
        incoming_tx
            .send(osdmap_message(
                full_map.fsid(),
                full_map.epoch(),
                full_bytes,
            ))
            .await
            .expect("osdmap");
        connecting.await.expect("connect task").expect("connect");

        let pool = client.resolved_pool(7, b"data").expect("pool");
        let pending = tokio::spawn(async move {
            pool.set_application_metadata("test", "k", "v", OperationOptions::new())
                .await
        });
        let request = sent_rx.recv().await.expect("monitor command request");
        assert_eq!(
            request.header.message_type,
            crate::mon::messages::MESSAGE_MON_COMMAND
        );
        incoming_tx
            .send(monitor_command_reply(
                request.header.transaction_id,
                0,
                "ok",
                &["{}"],
                b"",
            ))
            .await
            .expect("command reply");

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!pending.is_finished());

        drop(incoming_tx);
        let error = pending
            .await
            .expect("mutation task")
            .expect_err("refresh should fail after terminal session");
        assert!(matches!(
            error.kind(),
            ErrorKind::Closed | ErrorKind::NotConnected
        ));
        client
            .shutdown(OperationOptions::new())
            .await
            .expect("shutdown");
    }

    #[tokio::test]
    async fn monitor_command_preserves_partial_error_result() {
        let (incoming_tx, incoming_rx) = mpsc::channel(8);
        let (sent_tx, mut sent_rx) = mpsc::channel(8);
        let session = Arc::new(FakeSession {
            incoming: Mutex::new(incoming_rx),
            sent: sent_tx,
            closed: AtomicBool::new(false),
        });
        let opened = Arc::new(Mutex::new(Some(OpenedMonitorSession {
            session,
            global_id: 42,
            client_addresses: EntityAddrVec(Vec::new()),
        })));
        let factory: SessionFactory = Arc::new(move |_| {
            let opened = Arc::clone(&opened);
            Box::pin(async move { Ok(opened.lock().await.take().expect("single session")) })
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

        let pending = tokio::spawn({
            let client = client.clone();
            async move {
                client
                    .monitor_command(
                        b"{\"prefix\":\"status\"}",
                        b"\0binary\xff",
                        OperationOptions::new(),
                    )
                    .await
            }
        });
        let request = sent_rx.recv().await.expect("monitor command request");
        assert_eq!(
            request.header.message_type,
            crate::mon::messages::MESSAGE_MON_COMMAND
        );
        incoming_tx
            .send(monitor_command_reply(
                request.header.transaction_id,
                -13,
                "denied",
                &["{\"prefix\":\"status\"}"],
                b"partial-output",
            ))
            .await
            .expect("command reply");

        let (reply, result) = pending.await.expect("join");
        assert_eq!(reply.output, b"partial-output");
        assert_eq!(reply.status, "denied");
        let error = result.expect_err("server error");
        assert_eq!(error.kind(), ErrorKind::PermissionDenied);
        client
            .shutdown(OperationOptions::new())
            .await
            .expect("shutdown");
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn public_cluster_pool_stats_and_pool_create_delete_behaviors() {
        let (incoming_tx, incoming_rx) = mpsc::channel(16);
        let (sent_tx, mut sent_rx) = mpsc::channel(16);
        let session = Arc::new(FakeSession {
            incoming: Mutex::new(incoming_rx),
            sent: sent_tx,
            closed: AtomicBool::new(false),
        });
        let opened = Arc::new(Mutex::new(Some(OpenedMonitorSession {
            session,
            global_id: 42,
            client_addresses: EntityAddrVec(Vec::new()),
        })));
        let factory: SessionFactory = Arc::new(move |_| {
            let opened = Arc::clone(&opened);
            Box::pin(async move { Ok(opened.lock().await.take().expect("single session")) })
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

        let pending_stats = tokio::spawn({
            let client = client.clone();
            async move { client.cluster_stats(OperationOptions::new()).await }
        });
        let stats_request = sent_rx.recv().await.expect("statfs request");
        assert_eq!(
            stats_request.header.message_type,
            crate::mon::messages::MESSAGE_STATFS
        );
        incoming_tx
            .send(statfs_reply(
                stats_request.header.transaction_id,
                osdmap.fsid(),
            ))
            .await
            .expect("statfs reply");
        let cluster = pending_stats.await.expect("join").expect("cluster stats");
        assert_eq!(cluster.kib, 100);
        assert_eq!(cluster.kib_used, 40);
        assert_eq!(cluster.kib_available, 60);
        assert_eq!(cluster.objects, 7);

        let pool = client.resolved_pool(7, b"data").expect("pool");
        let pending_pool_stats =
            tokio::spawn(async move { pool.stats(OperationOptions::new()).await });
        let pool_stats_request = sent_rx.recv().await.expect("pool stats request");
        assert_eq!(
            pool_stats_request.header.message_type,
            crate::mon::messages::MESSAGE_GET_POOL_STATS
        );
        incoming_tx
            .send(pool_stats_reply(
                pool_stats_request.header.transaction_id,
                osdmap.fsid(),
                "data",
            ))
            .await
            .expect("pool stats reply");
        let stats = pending_pool_stats.await.expect("join").expect("pool stats");
        assert_eq!(stats.bytes_used, 217);
        assert_eq!(stats.objects, 3);
        assert_eq!(stats.read_bytes, 5 << 10);
        assert_eq!(stats.write_bytes, 7 << 10);

        let create = tokio::spawn({
            let client = client.clone();
            async move {
                client
                    .create_pool("p12-created", OperationOptions::new())
                    .await
            }
        });
        let create_request = sent_rx.recv().await.expect("create request");
        assert_eq!(
            create_request.header.message_type,
            crate::mon::messages::MESSAGE_POOL_OPERATION
        );
        let mut create_decoder = Decoder::new(&create_request.front, create_request.front.len());
        create_decoder.u64();
        create_decoder.i16();
        create_decoder.u64();
        create_decoder.raw(16);
        assert_eq!(create_decoder.u32(), 0);
        assert_eq!(create_decoder.u32(), 0x01);
        incoming_tx
            .send(pool_operation_reply(
                create_request.header.transaction_id,
                osdmap.fsid(),
                0,
                osdmap.epoch(),
                false,
            ))
            .await
            .expect("create reply");
        create.await.expect("join").expect("create pool");

        assert_eq!(
            client
                .delete_pool("missing", OperationOptions::new())
                .await
                .expect_err("missing pool")
                .kind(),
            ErrorKind::NotFound
        );
        client
            .shutdown(OperationOptions::new())
            .await
            .expect("shutdown");
    }

    #[tokio::test]
    async fn pool_stats_missing_requested_pool_is_invalid() {
        let (incoming_tx, incoming_rx) = mpsc::channel(8);
        let (sent_tx, mut sent_rx) = mpsc::channel(8);
        let session = Arc::new(FakeSession {
            incoming: Mutex::new(incoming_rx),
            sent: sent_tx,
            closed: AtomicBool::new(false),
        });
        let opened = Arc::new(Mutex::new(Some(OpenedMonitorSession {
            session,
            global_id: 42,
            client_addresses: EntityAddrVec(Vec::new()),
        })));
        let factory: SessionFactory = Arc::new(move |_| {
            let opened = Arc::clone(&opened);
            Box::pin(async move { Ok(opened.lock().await.take().expect("single session")) })
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

        let pool = client.resolved_pool(7, b"data").expect("pool");
        let pending = tokio::spawn(async move { pool.stats(OperationOptions::new()).await });
        let request = sent_rx.recv().await.expect("pool stats request");
        incoming_tx
            .send(pool_stats_reply(
                request.header.transaction_id,
                osdmap.fsid(),
                "other",
            ))
            .await
            .expect("pool stats reply");
        assert_eq!(
            pending
                .await
                .expect("join")
                .expect_err("missing pool in stats")
                .kind(),
            ErrorKind::InvalidArgument
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

    #[test]
    fn write_snapshot_context_is_owned_and_invalidity_is_sticky() {
        let pool = test_object().pool.clone();
        let view = pool.clone().with_write_snapshot(SnapshotContext {
            sequence: 9,
            snapshots: vec![9, 7, 3],
        });
        assert!(view.write_snapshot_valid);
        assert_eq!(view.write_snapshot_sequence, 9);
        assert_eq!(view.write_snapshots, [9, 7, 3]);

        let invalid = pool.with_write_snapshot(SnapshotContext {
            sequence: 9,
            snapshots: vec![7, 7],
        });
        assert!(!invalid.write_snapshot_valid);
    }

    #[tokio::test]
    async fn invalid_write_snapshot_context_rejects_basic_mutation_before_io() {
        let object = test_object();
        let invalid = object
            .pool
            .with_write_snapshot(SnapshotContext {
                sequence: 9,
                snapshots: vec![7, 7],
            })
            .object(b"object")
            .expect("object");
        let error = invalid
            .write_full(b"data", OperationOptions::new())
            .await
            .expect_err("invalid context");
        assert_eq!(error.kind(), ErrorKind::InvalidArgument);
    }
}
