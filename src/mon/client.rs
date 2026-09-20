use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use super::messages::{
    CommandReply, MESSAGE_GET_POOL_STATS_REPLY, MESSAGE_MGR_MAP, MESSAGE_MON_COMMAND_REPLY,
    MESSAGE_MON_MAP, MESSAGE_MON_SUBSCRIBE_ACK, MESSAGE_OSD_MAP, MESSAGE_POOL_OPERATION_REPLY,
    MESSAGE_STATFS_REPLY, MessageError, MessageLimits, PoolOperation, PoolOperationReply,
    PoolStatsReply, SUBSCRIBE_ONCE, StatFsReply, Subscription, decode_command_reply,
    decode_get_pool_stats_reply, decode_mgrmap_message, decode_monmap_message, decode_osdmap_batch,
    decode_osdmap_batch_maps, decode_pool_operation_reply, decode_statfs_reply,
    decode_subscribe_ack, encode_command, encode_get_pool_stats, encode_pool_operation,
    encode_statfs, encode_subscribe,
};
use super::seeds::Endpoint;
use crate::OperationOptions;
use crate::maps::{
    Fsid, Limits as MapLimits, MapError, MgrMap, MonMap, OSDMap, Pool, apply_osdmap_incremental,
};
use crate::msgr::message::Message;
use crate::msgr::session::SessionError;
use crate::msgr::session::{Config as SessionConfig, Machine};
use crate::msgr::supervisor::Connector;
use crate::msgr::supervisor::Session;
use crate::protocol::address::EntityAddrVec;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MonitorError {
    Closed,
    InvalidConfig,
    ConnectTimeout,
    AttemptsExhausted,
    ForeignCluster,
    IdentityUnavailable,
    MapGap,
    Session(SessionError),
    Message(MessageError),
    Map(MapError),
    WireErrno(i32),
}

impl fmt::Display for MonitorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => formatter.write_str("monitor client closed"),
            Self::InvalidConfig => formatter.write_str("invalid monitor client configuration"),
            Self::ConnectTimeout => formatter.write_str("monitor connection attempt timed out"),
            Self::AttemptsExhausted => formatter.write_str("monitor seed attempts exhausted"),
            Self::ForeignCluster => formatter.write_str("monitor returned a foreign cluster FSID"),
            Self::IdentityUnavailable => {
                formatter.write_str("monitor map arrived before cluster identity was established")
            }
            Self::MapGap => formatter.write_str("OSD map epoch gap"),
            Self::Session(error) => write!(formatter, "monitor session failed: {error:?}"),
            Self::Message(error) => write!(formatter, "monitor message failed: {error}"),
            Self::Map(error) => write!(formatter, "monitor map failed: {error}"),
            Self::WireErrno(code) => write!(formatter, "monitor operation failed: errno {code}"),
        }
    }
}

impl std::error::Error for MonitorError {}

impl From<SessionError> for MonitorError {
    fn from(error: SessionError) -> Self {
        Self::Session(error)
    }
}

impl From<MessageError> for MonitorError {
    fn from(error: MessageError) -> Self {
        Self::Message(error)
    }
}

impl From<MapError> for MonitorError {
    fn from(error: MapError) -> Self {
        Self::Map(error)
    }
}

#[derive(Clone)]
pub(crate) struct MonitorConfig {
    pub(crate) seeds: Vec<Endpoint>,
    pub(crate) expected_fsid: Option<Fsid>,
    pub(crate) hostname: String,
    pub(crate) map_limits: MapLimits,
    pub(crate) message_limits: MessageLimits,
    pub(crate) max_seed_attempts: usize,
    pub(crate) history_limit: usize,
    pub(crate) operation_timeout: Duration,
    pub(crate) retry_delay: Duration,
    pub(crate) subscribe_period: Duration,
    pub(crate) error_capacity: usize,
}

impl MonitorConfig {
    fn validate(&self) -> Result<(), MonitorError> {
        if self.seeds.is_empty()
            || self.max_seed_attempts == 0
            || self.operation_timeout.is_zero()
            || self.subscribe_period.is_zero()
            || self.error_capacity == 0
            || self.message_limits.max_bytes == 0
            || self.message_limits.max_maps == 0
            || self.map_limits.max_bytes == 0
            || self.map_limits.max_monitors == 0
            || self.map_limits.max_addresses == 0
            || self.map_limits.max_locations == 0
            || self.map_limits.max_pools == 0
            || self.map_limits.max_osds == 0
            || self.map_limits.max_pg_mappings == 0
            || self.map_limits.max_collection_entries == 0
        {
            return Err(MonitorError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct MonitorState {
    generation: u64,
    connected_fsid: Option<Fsid>,
    global_id: Option<u64>,
    client_addresses: Option<EntityAddrVec>,
    monmap: Option<Arc<MonMap>>,
    osdmap: Option<Arc<OSDMap>>,
    mgrmap: Option<Arc<MgrMap>>,
}

impl MonitorState {
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn connected_fsid(&self) -> Option<Fsid> {
        self.connected_fsid
    }

    pub(crate) fn global_id(&self) -> Option<u64> {
        self.global_id
    }

    pub(crate) fn client_addresses(&self) -> Option<EntityAddrVec> {
        self.client_addresses.clone()
    }

    pub(crate) fn monmap(&self) -> Option<Arc<MonMap>> {
        self.monmap.clone()
    }

    pub(crate) fn osdmap(&self) -> Option<Arc<OSDMap>> {
        self.osdmap.clone()
    }

    pub(crate) fn mgrmap(&self) -> Option<Arc<MgrMap>> {
        self.mgrmap.clone()
    }

    pub(crate) fn list_pools(&self) -> Vec<Arc<Pool>> {
        let Some(map) = &self.osdmap else {
            return Vec::new();
        };
        let mut pools: Vec<_> = map.pools().cloned().map(Arc::new).collect();
        pools.sort_by(|left, right| {
            left.name()
                .cmp(right.name())
                .then(left.id().cmp(&right.id()))
        });
        pools
    }

    fn ready(&self) -> bool {
        self.connected_fsid.is_some() && self.monmap.is_some() && self.osdmap.is_some()
    }
}

pub(crate) trait MonitorSession: Send + Sync {
    fn send(&self, message: Message) -> BoxFuture<'_, Result<(), SessionError>>;
    fn next_incoming(&self) -> BoxFuture<'_, Option<Message>>;
    fn next_failure(&self) -> BoxFuture<'_, SessionError>;
    fn close(&self);
    fn shutdown(&self) -> BoxFuture<'_, ()>;
}

impl MonitorSession for Session {
    fn send(&self, message: Message) -> BoxFuture<'_, Result<(), SessionError>> {
        Box::pin(async move {
            let request = self.admit(message, true).await?;
            request.result().await.map(|_| ())
        })
    }

    fn next_incoming(&self) -> BoxFuture<'_, Option<Message>> {
        Box::pin(Session::next_incoming(self))
    }

    fn next_failure(&self) -> BoxFuture<'_, SessionError> {
        Box::pin(async move {
            loop {
                if let Some(error) = self.terminal() {
                    return error;
                }
                if self.next_event().await.is_none() {
                    return self.terminal().unwrap_or(SessionError::Closed);
                }
            }
        })
    }

    fn close(&self) {
        Session::close(self);
    }

    fn shutdown(&self) -> BoxFuture<'_, ()> {
        Box::pin(Session::shutdown(self))
    }
}

pub(crate) struct OpenedMonitorSession {
    pub(crate) session: Arc<dyn MonitorSession>,
    pub(crate) global_id: u64,
    pub(crate) client_addresses: EntityAddrVec,
}

pub(crate) type OpenFuture =
    Pin<Box<dyn Future<Output = Result<OpenedMonitorSession, MonitorError>> + Send>>;
pub(crate) type SessionFactory = Arc<dyn Fn(Endpoint) -> OpenFuture + Send + Sync>;

pub(crate) struct MonitorClient {
    state: watch::Receiver<Arc<MonitorState>>,
    history: Arc<Mutex<VecDeque<Arc<MonitorState>>>>,
    errors: mpsc::Receiver<MonitorError>,
    terminal: watch::Receiver<Option<MonitorError>>,
    refresh: mpsc::Sender<u32>,
    commands: mpsc::Sender<MonitorCommand>,
    statfs: mpsc::Sender<StatFsCommand>,
    pool_stats: mpsc::Sender<PoolStatsCommand>,
    pool_operations: mpsc::Sender<PoolOperationCommand>,
    stop: watch::Sender<bool>,
    owner: Mutex<Option<JoinHandle<()>>>,
}

impl MonitorClient {
    pub(crate) fn spawn(
        config: MonitorConfig,
        factory: SessionFactory,
    ) -> Result<Self, MonitorError> {
        config.validate()?;
        let initial = Arc::new(MonitorState {
            connected_fsid: config.expected_fsid,
            ..MonitorState::default()
        });
        let (state_tx, state) = watch::channel(initial);
        let history = Arc::new(Mutex::new(VecDeque::new()));
        let (errors_tx, errors) = mpsc::channel(config.error_capacity);
        let (terminal_tx, terminal) = watch::channel(None);
        let (refresh, refresh_rx) = mpsc::channel(1);
        let (commands, commands_rx) = mpsc::channel(16);
        let (statfs, statfs_rx) = mpsc::channel(16);
        let (pool_stats, pool_stats_rx) = mpsc::channel(16);
        let (pool_operations, pool_operations_rx) = mpsc::channel(16);
        let (stop, stop_rx) = watch::channel(false);
        let owner_history = Arc::clone(&history);
        let owner = tokio::spawn(async move {
            Owner {
                pinned_fsid: config.expected_fsid,
                config,
                factory,
                next_seed: 0,
                state: MonitorState::default(),
                state_tx,
                history: owner_history,
                errors: errors_tx,
                terminal: terminal_tx,
                stop: stop_rx,
                refresh_epoch: None,
                refresh_rx,
                commands_rx,
                statfs_rx,
                pool_stats_rx,
                pool_operations_rx,
                next_transaction_id: 1,
                foreign_seeds: HashSet::new(),
            }
            .run()
            .await;
        });
        Ok(Self {
            state,
            history,
            errors,
            terminal,
            refresh,
            commands,
            statfs,
            pool_stats,
            pool_operations,
            stop,
            owner: Mutex::new(Some(owner)),
        })
    }

    pub(crate) fn snapshot(&self) -> Arc<MonitorState> {
        self.state.borrow().clone()
    }

    pub(crate) async fn history(&self) -> Vec<Arc<MonitorState>> {
        self.history.lock().await.iter().cloned().collect()
    }

    pub(crate) async fn wait_ready(&self) -> Result<Arc<MonitorState>, MonitorError> {
        let mut state = self.state.clone();
        let mut terminal = self.terminal.clone();
        loop {
            let current = state.borrow().clone();
            if current.ready() {
                return Ok(current);
            }
            if let Some(error) = *terminal.borrow() {
                return Err(error);
            }
            tokio::select! {
                changed = state.changed() => {
                    if changed.is_err() {
                        return Err(terminal.borrow().unwrap_or(MonitorError::Closed));
                    }
                }
                changed = terminal.changed() => {
                    if changed.is_err() {
                        return Err(terminal.borrow().unwrap_or(MonitorError::Closed));
                    }
                }
            }
        }
    }

    pub(crate) async fn next_error(&mut self) -> Option<MonitorError> {
        self.errors.recv().await
    }

    pub(crate) fn terminal(&self) -> Option<MonitorError> {
        *self.terminal.borrow()
    }

    pub(crate) async fn refresh_osdmap(
        &self,
        after: u32,
        options: &OperationOptions,
    ) -> Result<(), MonitorError> {
        let mut state = self.state.clone();
        let mut terminal = self.terminal.clone();
        let deadline = options.deadline();
        let deadline_wait = async move {
            match deadline {
                Some(deadline) => {
                    tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        let cancellation = tokio::time::sleep(Duration::from_millis(10));
        tokio::pin!(deadline_wait, cancellation);
        let mut request = after;
        loop {
            if options.is_canceled() {
                return Err(MonitorError::Session(SessionError::Cancelled));
            }
            if options
                .deadline()
                .is_some_and(|deadline| std::time::Instant::now() >= deadline)
            {
                return Err(MonitorError::ConnectTimeout);
            }
            match self.refresh.try_send(request) {
                Ok(()) => break,
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(self.terminal().unwrap_or(MonitorError::Closed));
                }
                Err(mpsc::error::TrySendError::Full(returned)) => request = returned,
            }
            tokio::select! {
                () = &mut deadline_wait => return Err(MonitorError::ConnectTimeout),
                () = &mut cancellation => {
                    cancellation.as_mut().reset(
                        tokio::time::Instant::now() + Duration::from_millis(10)
                    );
                }
                changed = terminal.changed() => {
                    if changed.is_err() {
                        return Err(MonitorError::Closed);
                    }
                }
            }
        }
        loop {
            if options.is_canceled() {
                return Err(MonitorError::Session(SessionError::Cancelled));
            }
            if options
                .deadline()
                .is_some_and(|deadline| std::time::Instant::now() >= deadline)
            {
                return Err(MonitorError::ConnectTimeout);
            }
            if state
                .borrow()
                .osdmap()
                .is_some_and(|map| map.epoch() > after)
            {
                return Ok(());
            }
            if let Some(error) = *terminal.borrow() {
                return Err(error);
            }
            tokio::select! {
                changed = state.changed() => {
                    if changed.is_err() {
                        return Err(MonitorError::Closed);
                    }
                }
                changed = terminal.changed() => {
                    if changed.is_err() {
                        return Err(MonitorError::Closed);
                    }
                }
                () = &mut deadline_wait => return Err(MonitorError::ConnectTimeout),
                () = &mut cancellation => {
                    cancellation.as_mut().reset(
                        tokio::time::Instant::now() + Duration::from_millis(10)
                    );
                }
            }
        }
    }

    pub(crate) async fn apply_pool_operation(
        &self,
        pool: u32,
        operation: PoolOperation,
        snapshot: u64,
        name: String,
        options: OperationOptions,
    ) -> Result<PoolOperationReply, MonitorError> {
        let (reply, receive) = oneshot::channel();
        let mut command = PoolOperationCommand {
            transaction_id: 0,
            pool,
            operation,
            snapshot,
            name,
            options: options.clone(),
            reply,
        };
        let deadline = options.deadline();
        let deadline_wait = async move {
            match deadline {
                Some(deadline) => {
                    tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        tokio::pin!(deadline_wait);
        loop {
            if options.is_canceled() {
                return Err(MonitorError::Session(SessionError::Cancelled));
            }
            if options
                .deadline()
                .is_some_and(|deadline| std::time::Instant::now() >= deadline)
            {
                return Err(MonitorError::ConnectTimeout);
            }
            match self.pool_operations.try_send(command) {
                Ok(()) => break,
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(self.terminal().unwrap_or(MonitorError::Closed));
                }
                Err(mpsc::error::TrySendError::Full(returned)) => command = returned,
            }
            tokio::select! {
                () = &mut deadline_wait => return Err(MonitorError::ConnectTimeout),
                () = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
        let reply = receive
            .await
            .map_err(|_| self.terminal().unwrap_or(MonitorError::Closed))??;
        let mut state = self.state.clone();
        let mut terminal = self.terminal.clone();
        loop {
            if options.is_canceled() {
                return Err(MonitorError::Session(SessionError::Cancelled));
            }
            if options
                .deadline()
                .is_some_and(|deadline| std::time::Instant::now() >= deadline)
            {
                return Err(MonitorError::ConnectTimeout);
            }
            if state
                .borrow()
                .osdmap()
                .is_some_and(|map| map.epoch() >= reply.epoch)
            {
                return Ok(reply);
            }
            if let Some(error) = *terminal.borrow() {
                return Err(error);
            }
            let _ = self.refresh.try_send(reply.epoch.saturating_sub(1));
            tokio::select! {
                changed = state.changed() => {
                    if changed.is_err() {
                        return Err(self.terminal().unwrap_or(MonitorError::Closed));
                    }
                }
                changed = terminal.changed() => {
                    if changed.is_err() {
                        return Err(self.terminal().unwrap_or(MonitorError::Closed));
                    }
                }
                () = tokio::time::sleep(Duration::from_millis(10)) => {}
            }
        }
    }

    pub(crate) async fn command(
        &self,
        command: Vec<String>,
        input: Vec<u8>,
        options: OperationOptions,
    ) -> Result<(CommandReply, Option<MonitorError>), MonitorError> {
        let (reply, receive) = oneshot::channel();
        let mut request = MonitorCommand {
            transaction_id: 0,
            command,
            input,
            options: options.clone(),
            reply,
        };
        loop {
            if options.is_canceled() {
                return Err(MonitorError::Session(SessionError::Cancelled));
            }
            if options
                .deadline()
                .is_some_and(|deadline| std::time::Instant::now() >= deadline)
            {
                return Err(MonitorError::ConnectTimeout);
            }
            match self.commands.try_send(request) {
                Ok(()) => break,
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(self.terminal().unwrap_or(MonitorError::Closed));
                }
                Err(mpsc::error::TrySendError::Full(returned)) => request = returned,
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        receive
            .await
            .map_err(|_| self.terminal().unwrap_or(MonitorError::Closed))?
    }

    pub(crate) async fn statfs(
        &self,
        options: OperationOptions,
    ) -> Result<StatFsReply, MonitorError> {
        let (reply, receive) = oneshot::channel();
        let mut request = StatFsCommand {
            transaction_id: 0,
            options: options.clone(),
            reply,
        };
        loop {
            if options.is_canceled() {
                return Err(MonitorError::Session(SessionError::Cancelled));
            }
            if options
                .deadline()
                .is_some_and(|deadline| std::time::Instant::now() >= deadline)
            {
                return Err(MonitorError::ConnectTimeout);
            }
            match self.statfs.try_send(request) {
                Ok(()) => break,
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(self.terminal().unwrap_or(MonitorError::Closed));
                }
                Err(mpsc::error::TrySendError::Full(returned)) => request = returned,
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        receive
            .await
            .map_err(|_| self.terminal().unwrap_or(MonitorError::Closed))?
    }

    pub(crate) async fn pool_stats(
        &self,
        pools: Vec<String>,
        options: OperationOptions,
    ) -> Result<PoolStatsReply, MonitorError> {
        let (reply, receive) = oneshot::channel();
        let mut request = PoolStatsCommand {
            transaction_id: 0,
            pools,
            options: options.clone(),
            reply,
        };
        loop {
            if options.is_canceled() {
                return Err(MonitorError::Session(SessionError::Cancelled));
            }
            if options
                .deadline()
                .is_some_and(|deadline| std::time::Instant::now() >= deadline)
            {
                return Err(MonitorError::ConnectTimeout);
            }
            match self.pool_stats.try_send(request) {
                Ok(()) => break,
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(self.terminal().unwrap_or(MonitorError::Closed));
                }
                Err(mpsc::error::TrySendError::Full(returned)) => request = returned,
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        receive
            .await
            .map_err(|_| self.terminal().unwrap_or(MonitorError::Closed))?
    }

    pub(crate) fn close(&self) {
        let _ = self.stop.send(true);
    }

    pub(crate) async fn shutdown(&self) {
        self.close();
        if let Some(owner) = self.owner.lock().await.take() {
            let _ = owner.await;
        }
    }
}

impl Drop for MonitorClient {
    fn drop(&mut self) {
        self.close();
    }
}

struct Owner {
    config: MonitorConfig,
    factory: SessionFactory,
    next_seed: usize,
    pinned_fsid: Option<Fsid>,
    state: MonitorState,
    state_tx: watch::Sender<Arc<MonitorState>>,
    history: Arc<Mutex<VecDeque<Arc<MonitorState>>>>,
    errors: mpsc::Sender<MonitorError>,
    terminal: watch::Sender<Option<MonitorError>>,
    stop: watch::Receiver<bool>,
    refresh_epoch: Option<u32>,
    refresh_rx: mpsc::Receiver<u32>,
    commands_rx: mpsc::Receiver<MonitorCommand>,
    statfs_rx: mpsc::Receiver<StatFsCommand>,
    pool_stats_rx: mpsc::Receiver<PoolStatsCommand>,
    pool_operations_rx: mpsc::Receiver<PoolOperationCommand>,
    next_transaction_id: u64,
    foreign_seeds: HashSet<SocketAddr>,
}

struct MonitorCommand {
    transaction_id: u64,
    command: Vec<String>,
    input: Vec<u8>,
    options: OperationOptions,
    reply: oneshot::Sender<Result<(CommandReply, Option<MonitorError>), MonitorError>>,
}

struct StatFsCommand {
    transaction_id: u64,
    options: OperationOptions,
    reply: oneshot::Sender<Result<StatFsReply, MonitorError>>,
}

struct PoolStatsCommand {
    transaction_id: u64,
    pools: Vec<String>,
    options: OperationOptions,
    reply: oneshot::Sender<Result<PoolStatsReply, MonitorError>>,
}

struct PoolOperationCommand {
    transaction_id: u64,
    pool: u32,
    operation: PoolOperation,
    snapshot: u64,
    name: String,
    options: OperationOptions,
    reply: oneshot::Sender<Result<PoolOperationReply, MonitorError>>,
}

impl Owner {
    async fn run(mut self) {
        loop {
            if *self.stop.borrow() {
                self.finish(MonitorError::Closed);
                return;
            }
            let (endpoint, opened) = match self.open_next().await {
                Ok(opened) => opened,
                Err(error) => {
                    self.finish(error);
                    return;
                }
            };
            match self.run_session(opened).await {
                SessionOutcome::Stop => {
                    self.finish(MonitorError::Closed);
                    return;
                }
                SessionOutcome::ForeignCluster => {
                    self.foreign_seeds.insert(endpoint);
                    if self.foreign_seeds.len()
                        == self
                            .config
                            .seeds
                            .iter()
                            .map(|seed| seed.address)
                            .collect::<HashSet<_>>()
                            .len()
                    {
                        self.finish(MonitorError::ForeignCluster);
                        return;
                    }
                }
                SessionOutcome::Failover => {}
            }
            if !self.config.retry_delay.is_zero() {
                let delay = tokio::time::sleep(self.config.retry_delay);
                tokio::pin!(delay);
                tokio::select! {
                    () = &mut delay => {}
                    changed = self.stop.changed() => {
                        if changed.is_err() || *self.stop.borrow() {
                            self.finish(MonitorError::Closed);
                            return;
                        }
                    }
                }
            }
        }
    }

    async fn open_next(&mut self) -> Result<(SocketAddr, OpenedMonitorSession), MonitorError> {
        for _ in 0..self.config.max_seed_attempts {
            if *self.stop.borrow() {
                return Err(MonitorError::Closed);
            }
            let endpoint = self.config.seeds[self.next_seed].clone();
            let address = endpoint.address;
            self.next_seed = (self.next_seed + 1) % self.config.seeds.len();
            let future = (self.factory)(endpoint);
            let result = tokio::select! {
                result = tokio::time::timeout(self.config.operation_timeout, future) => {
                    result.unwrap_or(Err(MonitorError::ConnectTimeout))
                }
                changed = self.stop.changed() => {
                    let _ = changed;
                    return Err(MonitorError::Closed);
                }
            };
            match result {
                Ok(opened) => return Ok((address, opened)),
                Err(error) => self.report(error),
            }
        }
        Err(MonitorError::AttemptsExhausted)
    }

    #[allow(clippy::too_many_lines)]
    async fn run_session(&mut self, opened: OpenedMonitorSession) -> SessionOutcome {
        let session = opened.session;
        let mut pending_command: Option<MonitorCommand> = None;
        let mut pending_statfs: Option<StatFsCommand> = None;
        let mut pending_pool_stats: Option<PoolStatsCommand> = None;
        let mut pending_pool_operation: Option<PoolOperationCommand> = None;
        self.state.global_id = Some(opened.global_id);
        self.state.client_addresses = Some(opened.client_addresses.clone());
        self.publish().await;
        if let Err(error) = self.subscribe(&session, false).await {
            self.report(error);
            session.close();
            session.shutdown().await;
            return SessionOutcome::Failover;
        }
        if self.refresh_epoch.is_some()
            && let Err(error) = self.subscribe(&session, true).await
        {
            self.report(error);
        }
        let timer = tokio::time::sleep(self.config.subscribe_period);
        tokio::pin!(timer);
        loop {
            enum Event {
                Stop,
                Incoming(Option<Message>),
                Failure(SessionError),
                Subscribe,
                Refresh(Option<u32>),
                Command(Option<MonitorCommand>),
                StatFs(Option<StatFsCommand>),
                PoolStats(Option<PoolStatsCommand>),
                PoolOperation(Option<PoolOperationCommand>),
                RequestCheck,
            }
            let has_pending_request = pending_command.is_some()
                || pending_statfs.is_some()
                || pending_pool_stats.is_some()
                || pending_pool_operation.is_some();
            let request_check = tokio::time::sleep(Duration::from_millis(10));
            tokio::pin!(request_check);
            let event = tokio::select! {
                changed = self.stop.changed() => {
                    let _ = changed;
                    Event::Stop
                }
                message = session.next_incoming() => Event::Incoming(message),
                error = session.next_failure() => Event::Failure(error),
                () = &mut timer => Event::Subscribe,
                epoch = self.refresh_rx.recv() => Event::Refresh(epoch),
                command = self.commands_rx.recv(), if pending_command.is_none() => {
                    Event::Command(command)
                }
                command = self.statfs_rx.recv(), if pending_statfs.is_none() => {
                    Event::StatFs(command)
                }
                command = self.pool_stats_rx.recv(), if pending_pool_stats.is_none() => {
                    Event::PoolStats(command)
                }
                command = self.pool_operations_rx.recv(), if pending_pool_operation.is_none() => {
                    Event::PoolOperation(command)
                }
                () = &mut request_check, if has_pending_request => {
                    Event::RequestCheck
                }
            };
            match event {
                Event::Stop => {
                    session.close();
                    session.shutdown().await;
                    return SessionOutcome::Stop;
                }
                Event::Incoming(Some(message))
                    if message.header.message_type == MESSAGE_MON_COMMAND_REPLY =>
                {
                    if pending_command.as_ref().is_none_or(|pending| {
                        pending.transaction_id != message.header.transaction_id
                    }) {
                        self.report(MonitorError::Message(MessageError::Malformed(
                            "uncorrelated monitor command reply",
                        )));
                        continue;
                    }
                    let result = decode_command_reply(
                        &message,
                        self.config.message_limits.max_bytes,
                        self.config.map_limits.max_collection_entries,
                    )
                    .map_err(MonitorError::from)
                    .map(|reply| {
                        let error =
                            (reply.result != 0).then_some(MonitorError::WireErrno(reply.result));
                        (reply, error)
                    });
                    let command = pending_command
                        .take()
                        .expect("transaction guard requires a pending monitor command");
                    let _ = command.reply.send(result);
                }
                Event::Incoming(Some(message))
                    if message.header.message_type == MESSAGE_STATFS_REPLY =>
                {
                    if pending_statfs.as_ref().is_none_or(|pending| {
                        pending.transaction_id != message.header.transaction_id
                    }) {
                        self.report(MonitorError::Message(MessageError::Malformed(
                            "uncorrelated statfs reply",
                        )));
                        continue;
                    }
                    let result =
                        decode_statfs_reply(&message, self.config.message_limits.max_bytes)
                            .map_err(MonitorError::from);
                    let command = pending_statfs
                        .take()
                        .expect("transaction guard requires a pending statfs command");
                    if result
                        .as_ref()
                        .is_ok_and(|reply| Some(reply.fsid) != self.pinned_fsid)
                    {
                        let _ = command.reply.send(Err(MonitorError::ForeignCluster));
                        fail_pending_command(&mut pending_command);
                        fail_pending_pool_stats(&mut pending_pool_stats);
                        fail_pending_pool_operation(&mut pending_pool_operation);
                        self.report(MonitorError::ForeignCluster);
                        session.close();
                        session.shutdown().await;
                        return SessionOutcome::ForeignCluster;
                    }
                    let _ = command.reply.send(result);
                }
                Event::Incoming(Some(message))
                    if message.header.message_type == MESSAGE_GET_POOL_STATS_REPLY =>
                {
                    if pending_pool_stats.as_ref().is_none_or(|pending| {
                        pending.transaction_id != message.header.transaction_id
                    }) {
                        self.report(MonitorError::Message(MessageError::Malformed(
                            "uncorrelated pool-stats reply",
                        )));
                        continue;
                    }
                    let result = decode_get_pool_stats_reply(
                        &message,
                        self.config.message_limits.max_bytes,
                        self.config.map_limits.max_pools,
                        self.config.map_limits.max_collection_entries,
                    )
                    .map_err(MonitorError::from);
                    let command = pending_pool_stats
                        .take()
                        .expect("transaction guard requires a pending pool-stats command");
                    if result
                        .as_ref()
                        .is_ok_and(|reply| Some(reply.fsid) != self.pinned_fsid)
                    {
                        let _ = command.reply.send(Err(MonitorError::ForeignCluster));
                        fail_pending_command(&mut pending_command);
                        fail_pending_statfs(&mut pending_statfs);
                        fail_pending_pool_operation(&mut pending_pool_operation);
                        self.report(MonitorError::ForeignCluster);
                        session.close();
                        session.shutdown().await;
                        return SessionOutcome::ForeignCluster;
                    }
                    let _ = command.reply.send(result);
                }
                Event::Incoming(Some(message))
                    if message.header.message_type == MESSAGE_POOL_OPERATION_REPLY =>
                {
                    if pending_pool_operation.as_ref().is_none_or(|pending| {
                        pending.transaction_id != message.header.transaction_id
                    }) {
                        self.report(MonitorError::Message(MessageError::Malformed(
                            "uncorrelated pool operation reply",
                        )));
                        continue;
                    }
                    let result =
                        decode_pool_operation_reply(&message, self.config.message_limits.max_bytes)
                            .map_err(MonitorError::from);
                    let command = pending_pool_operation
                        .take()
                        .expect("transaction guard requires a pending pool operation");
                    if result
                        .as_ref()
                        .is_ok_and(|reply| Some(reply.fsid) != self.pinned_fsid)
                    {
                        let _ = command.reply.send(Err(MonitorError::ForeignCluster));
                        fail_pending_command(&mut pending_command);
                        fail_pending_statfs(&mut pending_statfs);
                        fail_pending_pool_stats(&mut pending_pool_stats);
                        self.report(MonitorError::ForeignCluster);
                        session.close();
                        session.shutdown().await;
                        return SessionOutcome::ForeignCluster;
                    }
                    let _ = command.reply.send(result.and_then(|reply| {
                        if reply.result != 0 {
                            Err(MonitorError::WireErrno(reply.result))
                        } else {
                            Ok(reply)
                        }
                    }));
                }
                Event::Incoming(Some(message)) => match self.handle_message(message).await {
                    Ok(MessageAction::None) => {}
                    Ok(MessageAction::Resubscribe) => {
                        if let Err(error) = self.subscribe(&session, false).await {
                            self.report(error);
                        }
                    }
                    Err(MonitorError::MapGap) => {
                        self.report(MonitorError::MapGap);
                        if self.refresh_epoch.is_some() {
                            continue;
                        }
                        if self.refresh_epoch.is_none() {
                            self.refresh_epoch = Some(
                                self.state
                                    .osdmap
                                    .as_ref()
                                    .map_or(1, |map| map.epoch().saturating_add(1)),
                            );
                            if let Err(error) = self.subscribe(&session, true).await {
                                self.report(error);
                            }
                        }
                    }
                    Err(MonitorError::ForeignCluster) => {
                        fail_pending_command(&mut pending_command);
                        fail_pending_statfs(&mut pending_statfs);
                        fail_pending_pool_stats(&mut pending_pool_stats);
                        fail_pending_pool_operation(&mut pending_pool_operation);
                        self.report(MonitorError::ForeignCluster);
                        session.close();
                        session.shutdown().await;
                        return SessionOutcome::ForeignCluster;
                    }
                    Err(error) => {
                        fail_pending_command(&mut pending_command);
                        fail_pending_statfs(&mut pending_statfs);
                        fail_pending_pool_stats(&mut pending_pool_stats);
                        fail_pending_pool_operation(&mut pending_pool_operation);
                        self.report(error);
                        session.close();
                        session.shutdown().await;
                        return SessionOutcome::Failover;
                    }
                },
                Event::Incoming(None) => {
                    fail_pending_command(&mut pending_command);
                    fail_pending_statfs(&mut pending_statfs);
                    fail_pending_pool_stats(&mut pending_pool_stats);
                    fail_pending_pool_operation(&mut pending_pool_operation);
                    session.shutdown().await;
                    return SessionOutcome::Failover;
                }
                Event::Failure(error) => {
                    fail_pending_command(&mut pending_command);
                    fail_pending_statfs(&mut pending_statfs);
                    fail_pending_pool_stats(&mut pending_pool_stats);
                    fail_pending_pool_operation(&mut pending_pool_operation);
                    self.report(error.into());
                    session.shutdown().await;
                    return SessionOutcome::Failover;
                }
                Event::Subscribe => {
                    if let Err(error) = self.subscribe(&session, false).await {
                        self.report(error);
                    }
                    timer
                        .as_mut()
                        .reset(tokio::time::Instant::now() + self.config.subscribe_period);
                }
                Event::Refresh(Some(epoch)) => {
                    self.refresh_epoch = Some(
                        self.refresh_epoch
                            .map_or(epoch, |current| current.max(epoch)),
                    );
                    if let Err(error) = self.subscribe(&session, true).await {
                        self.report(error);
                    }
                }
                Event::Refresh(None)
                | Event::Command(None)
                | Event::StatFs(None)
                | Event::PoolStats(None)
                | Event::PoolOperation(None) => {}
                Event::Command(Some(mut command)) => {
                    if command.options.is_canceled() {
                        let _ = command
                            .reply
                            .send(Err(MonitorError::Session(SessionError::Cancelled)));
                        continue;
                    }
                    if command
                        .options
                        .deadline()
                        .is_some_and(|deadline| std::time::Instant::now() >= deadline)
                    {
                        let _ = command.reply.send(Err(MonitorError::ConnectTimeout));
                        continue;
                    }
                    let Some(fsid) = self.pinned_fsid else {
                        let _ = command.reply.send(Err(MonitorError::IdentityUnavailable));
                        continue;
                    };
                    let mut message = match encode_command(
                        fsid,
                        &command.command,
                        &command.input,
                        self.config.message_limits.max_bytes,
                    ) {
                        Ok(message) => message,
                        Err(error) => {
                            let _ = command.reply.send(Err(error.into()));
                            continue;
                        }
                    };
                    command.transaction_id = self.allocate_transaction_id();
                    message.header.transaction_id = command.transaction_id;
                    pending_command = Some(command);
                    if let Err(error) = session.send(message).await {
                        if let Some(command) = pending_command.take() {
                            let _ = command.reply.send(Err(error.into()));
                        }
                        session.close();
                        session.shutdown().await;
                        return SessionOutcome::Failover;
                    }
                }
                Event::StatFs(Some(mut command)) => {
                    if command.options.is_canceled() {
                        let _ = command
                            .reply
                            .send(Err(MonitorError::Session(SessionError::Cancelled)));
                        continue;
                    }
                    if command
                        .options
                        .deadline()
                        .is_some_and(|deadline| std::time::Instant::now() >= deadline)
                    {
                        let _ = command.reply.send(Err(MonitorError::ConnectTimeout));
                        continue;
                    }
                    let Some(fsid) = self.pinned_fsid else {
                        let _ = command.reply.send(Err(MonitorError::IdentityUnavailable));
                        continue;
                    };
                    let epoch = self.state.osdmap.as_ref().map_or(0, |map| map.epoch());
                    let mut message = match encode_statfs(
                        fsid,
                        u64::from(epoch),
                        self.config.message_limits.max_bytes,
                    ) {
                        Ok(message) => message,
                        Err(error) => {
                            let _ = command.reply.send(Err(error.into()));
                            continue;
                        }
                    };
                    command.transaction_id = self.allocate_transaction_id();
                    message.header.transaction_id = command.transaction_id;
                    pending_statfs = Some(command);
                    if let Err(error) = session.send(message).await {
                        if let Some(command) = pending_statfs.take() {
                            let _ = command.reply.send(Err(error.into()));
                        }
                        session.close();
                        session.shutdown().await;
                        return SessionOutcome::Failover;
                    }
                }
                Event::PoolStats(Some(mut command)) => {
                    if command.options.is_canceled() {
                        let _ = command
                            .reply
                            .send(Err(MonitorError::Session(SessionError::Cancelled)));
                        continue;
                    }
                    if command
                        .options
                        .deadline()
                        .is_some_and(|deadline| std::time::Instant::now() >= deadline)
                    {
                        let _ = command.reply.send(Err(MonitorError::ConnectTimeout));
                        continue;
                    }
                    let Some(fsid) = self.pinned_fsid else {
                        let _ = command.reply.send(Err(MonitorError::IdentityUnavailable));
                        continue;
                    };
                    let epoch = self.state.osdmap.as_ref().map_or(0, |map| map.epoch());
                    let mut message = match encode_get_pool_stats(
                        fsid,
                        u64::from(epoch),
                        &command.pools,
                        self.config.message_limits.max_bytes,
                    ) {
                        Ok(message) => message,
                        Err(error) => {
                            let _ = command.reply.send(Err(error.into()));
                            continue;
                        }
                    };
                    command.transaction_id = self.allocate_transaction_id();
                    message.header.transaction_id = command.transaction_id;
                    pending_pool_stats = Some(command);
                    if let Err(error) = session.send(message).await {
                        if let Some(command) = pending_pool_stats.take() {
                            let _ = command.reply.send(Err(error.into()));
                        }
                        session.close();
                        session.shutdown().await;
                        return SessionOutcome::Failover;
                    }
                }
                Event::PoolOperation(Some(mut command)) => {
                    if command.options.is_canceled() {
                        let _ = command
                            .reply
                            .send(Err(MonitorError::Session(SessionError::Cancelled)));
                        continue;
                    }
                    if command
                        .options
                        .deadline()
                        .is_some_and(|deadline| std::time::Instant::now() >= deadline)
                    {
                        let _ = command.reply.send(Err(MonitorError::ConnectTimeout));
                        continue;
                    }
                    let Some(fsid) = self.pinned_fsid else {
                        let _ = command.reply.send(Err(MonitorError::IdentityUnavailable));
                        continue;
                    };
                    let epoch = self.state.osdmap.as_ref().map_or(0, |map| map.epoch());
                    let mut message = match encode_pool_operation(
                        fsid,
                        u64::from(epoch),
                        command.pool,
                        command.operation,
                        command.snapshot,
                        &command.name,
                        self.config.message_limits.max_bytes,
                    ) {
                        Ok(message) => message,
                        Err(error) => {
                            let _ = command.reply.send(Err(error.into()));
                            continue;
                        }
                    };
                    command.transaction_id = self.allocate_transaction_id();
                    message.header.transaction_id = command.transaction_id;
                    pending_pool_operation = Some(command);
                    if let Err(error) = session.send(message).await {
                        if let Some(command) = pending_pool_operation.take() {
                            let _ = command.reply.send(Err(error.into()));
                        }
                        session.close();
                        session.shutdown().await;
                        return SessionOutcome::Failover;
                    }
                }
                Event::RequestCheck => {
                    let command_expired = pending_command.as_ref().is_some_and(|command| {
                        command.options.is_canceled()
                            || command
                                .options
                                .deadline()
                                .is_some_and(|deadline| std::time::Instant::now() >= deadline)
                    });
                    let pool_operation_expired =
                        pending_pool_operation.as_ref().is_some_and(|command| {
                            command.options.is_canceled()
                                || command
                                    .options
                                    .deadline()
                                    .is_some_and(|deadline| std::time::Instant::now() >= deadline)
                        });
                    let statfs_expired = pending_statfs.as_ref().is_some_and(|command| {
                        command.options.is_canceled()
                            || command
                                .options
                                .deadline()
                                .is_some_and(|deadline| std::time::Instant::now() >= deadline)
                    });
                    let pool_stats_expired = pending_pool_stats.as_ref().is_some_and(|command| {
                        command.options.is_canceled()
                            || command
                                .options
                                .deadline()
                                .is_some_and(|deadline| std::time::Instant::now() >= deadline)
                    });
                    if command_expired
                        || statfs_expired
                        || pool_stats_expired
                        || pool_operation_expired
                    {
                        fail_pending_command(&mut pending_command);
                        fail_pending_statfs(&mut pending_statfs);
                        fail_pending_pool_stats(&mut pending_pool_stats);
                        fail_pending_pool_operation(&mut pending_pool_operation);
                        session.close();
                        session.shutdown().await;
                        return SessionOutcome::Failover;
                    }
                }
            }
        }
    }

    fn allocate_transaction_id(&mut self) -> u64 {
        let transaction_id = self.next_transaction_id;
        self.next_transaction_id = self.next_transaction_id.wrapping_add(1);
        if self.next_transaction_id == 0 {
            self.next_transaction_id = 1;
        }
        transaction_id
    }

    async fn subscribe(
        &self,
        session: &Arc<dyn MonitorSession>,
        full_osdmap: bool,
    ) -> Result<(), MonitorError> {
        let mut subscriptions = BTreeMap::new();
        if full_osdmap {
            subscriptions.insert(
                "osdmap".to_owned(),
                Subscription {
                    start: 0,
                    flags: SUBSCRIBE_ONCE,
                },
            );
        } else {
            subscriptions.insert(
                "mgrmap".to_owned(),
                Subscription {
                    start: self
                        .state
                        .mgrmap
                        .as_ref()
                        .map_or(0, |map| u64::from(map.epoch()) + 1),
                    flags: 0,
                },
            );
            subscriptions.insert(
                "monmap".to_owned(),
                Subscription {
                    start: self
                        .state
                        .monmap
                        .as_ref()
                        .map_or(0, |map| u64::from(map.epoch()) + 1),
                    flags: 0,
                },
            );
            subscriptions.insert(
                "osdmap".to_owned(),
                Subscription {
                    start: self
                        .state
                        .osdmap
                        .as_ref()
                        .map_or(0, |map| u64::from(map.epoch()) + 1),
                    flags: 0,
                },
            );
        }
        let message = encode_subscribe(
            &subscriptions,
            &self.config.hostname,
            self.config.message_limits.max_bytes,
        )?;
        tokio::time::timeout(self.config.operation_timeout, session.send(message))
            .await
            .map_err(|_| MonitorError::ConnectTimeout)??;
        Ok(())
    }

    async fn handle_message(&mut self, message: Message) -> Result<MessageAction, MonitorError> {
        match message.header.message_type {
            MESSAGE_MON_SUBSCRIBE_ACK => {
                let ack = decode_subscribe_ack(&message, self.config.message_limits.max_bytes)?;
                self.pin_fsid(ack.fsid)?;
                self.publish().await;
            }
            MESSAGE_MON_MAP => {
                let map = decode_monmap_message(&message, self.config.map_limits)?;
                self.pin_fsid(map.fsid())?;
                if self
                    .state
                    .monmap
                    .as_ref()
                    .is_none_or(|current| map.epoch() > current.epoch())
                {
                    self.state.monmap = Some(Arc::new(map));
                    self.publish().await;
                }
            }
            MESSAGE_OSD_MAP => {
                let batch = decode_osdmap_batch(&message, self.config.message_limits)?;
                let maps = decode_osdmap_batch_maps(&batch, self.config.map_limits)?;
                self.pin_fsid(batch.fsid)?;
                let highest_full_epoch = maps.full_maps.keys().next_back().copied();
                let mut current = self.state.osdmap.as_deref().cloned();
                for (epoch, map) in maps.full_maps {
                    if current.as_ref().is_none_or(|value| epoch > value.epoch()) {
                        current = Some(map);
                    }
                }
                for (epoch, incremental) in maps.incrementals {
                    if current.as_ref().is_some_and(|value| epoch <= value.epoch()) {
                        continue;
                    }
                    let Some(base) = &current else {
                        return Err(MonitorError::MapGap);
                    };
                    if base.epoch().checked_add(1) != Some(epoch) {
                        return Err(MonitorError::MapGap);
                    }
                    current = Some(apply_osdmap_incremental(
                        base,
                        &incremental,
                        self.config.map_limits,
                    )?);
                }
                let current_epoch = current.as_ref().map_or(0, OSDMap::epoch);
                if (maps.newest_map != 0 && current_epoch < maps.newest_map)
                    || (maps.trim_lower_bound != 0 && current_epoch < maps.trim_lower_bound)
                {
                    return Err(MonitorError::MapGap);
                }
                if let Some(map) = current
                    && self
                        .state
                        .osdmap
                        .as_ref()
                        .is_none_or(|old| map.epoch() > old.epoch())
                {
                    self.state.osdmap = Some(Arc::new(map));
                    self.publish().await;
                }
                if self.refresh_epoch.is_some_and(|required| {
                    highest_full_epoch.is_some_and(|epoch| epoch >= required)
                }) {
                    self.refresh_epoch = None;
                    return Ok(MessageAction::Resubscribe);
                }
            }
            MESSAGE_MGR_MAP => {
                if self.pinned_fsid.is_none() {
                    return Err(MonitorError::IdentityUnavailable);
                }
                let map = decode_mgrmap_message(&message, self.config.map_limits)?;
                if self
                    .state
                    .mgrmap
                    .as_ref()
                    .is_none_or(|current| map.epoch() > current.epoch())
                {
                    self.state.mgrmap = Some(Arc::new(map));
                    self.publish().await;
                }
            }
            _ => {}
        }
        Ok(MessageAction::None)
    }

    fn pin_fsid(&mut self, fsid: Fsid) -> Result<(), MonitorError> {
        if self.pinned_fsid.is_some_and(|expected| expected != fsid) {
            return Err(MonitorError::ForeignCluster);
        }
        self.pinned_fsid = Some(fsid);
        self.state.connected_fsid = Some(fsid);
        Ok(())
    }

    async fn publish(&mut self) {
        self.state.generation = self.state.generation.saturating_add(1);
        let next = Arc::new(self.state.clone());
        let previous = self.state_tx.borrow().clone();
        if self.config.history_limit != 0 && previous.generation != 0 {
            let mut history = self.history.lock().await;
            history.push_front(previous);
            history.truncate(self.config.history_limit);
        }
        self.state_tx.send_replace(next);
    }

    fn report(&self, error: MonitorError) {
        let _ = self.errors.try_send(error);
    }

    fn finish(&self, error: MonitorError) {
        self.terminal.send_replace(Some(error));
    }
}

fn fail_pending_pool_operation(command: &mut Option<PoolOperationCommand>) {
    if let Some(command) = command.take() {
        let _ = command
            .reply
            .send(Err(MonitorError::Session(SessionError::OutcomeUnknown)));
    }
}

fn fail_pending_command(command: &mut Option<MonitorCommand>) {
    if let Some(command) = command.take() {
        let _ = command
            .reply
            .send(Err(MonitorError::Session(SessionError::OutcomeUnknown)));
    }
}

fn fail_pending_statfs(command: &mut Option<StatFsCommand>) {
    if let Some(command) = command.take() {
        let _ = command
            .reply
            .send(Err(MonitorError::Session(SessionError::OutcomeUnknown)));
    }
}

fn fail_pending_pool_stats(command: &mut Option<PoolStatsCommand>) {
    if let Some(command) = command.take() {
        let _ = command
            .reply
            .send(Err(MonitorError::Session(SessionError::OutcomeUnknown)));
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SessionOutcome {
    Failover,
    ForeignCluster,
    Stop,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum MessageAction {
    None,
    Resubscribe,
}

pub(crate) fn authenticated_session_factory(
    connector_config: crate::cephx::connector::Config,
    session_config: SessionConfig,
    connect_timeout: Duration,
    authority_slot: Arc<std::sync::RwLock<Option<Arc<crate::cephx::connector::MonitorConnector>>>>,
) -> SessionFactory {
    use crate::cephx::connector::MonitorConnector;

    Arc::new(move |endpoint: Endpoint| {
        let mut connector_config = connector_config.clone();
        connector_config.target_address = endpoint.entity_address.clone();
        let mut session_config = session_config.clone();
        session_config.client_ident.target_address = endpoint.entity_address.clone();
        let authority_slot = Arc::clone(&authority_slot);
        Box::pin(async move {
            if connect_timeout.is_zero() {
                return Err(MonitorError::InvalidConfig);
            }
            let authority = Arc::new(
                MonitorConnector::new(connector_config).map_err(|_| MonitorError::InvalidConfig)?,
            );
            let stream = tokio::time::timeout(
                connect_timeout,
                tokio::net::TcpStream::connect(endpoint.address),
            )
            .await
            .map_err(|_| MonitorError::ConnectTimeout)?
            .map_err(|_| MonitorError::Session(SessionError::Disconnected))?;
            let initial = authority
                .connect(stream)
                .await
                .map_err(SessionError::from)?;
            let global_id = initial
                .authenticated_global_id
                .ok_or(MonitorError::IdentityUnavailable)?;
            *authority_slot
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&authority));
            let retry_authority = Arc::clone(&authority);
            let retry_endpoint = endpoint.address;
            let connector: Connector = Arc::new(move || {
                let authority = Arc::clone(&retry_authority);
                Box::pin(async move {
                    let stream = tokio::time::timeout(
                        connect_timeout,
                        tokio::net::TcpStream::connect(retry_endpoint),
                    )
                    .await
                    .map_err(|_| SessionError::Disconnected)?
                    .map_err(|_| SessionError::Disconnected)?;
                    authority.connect(stream).await.map_err(SessionError::from)
                })
            });
            let client_addresses = session_config.client_ident.addresses.clone();
            let machine = Machine::new(session_config)?;
            Ok(OpenedMonitorSession {
                session: Arc::new(Session::spawn(machine, Some(initial), Some(connector))),
                global_id,
                client_addresses,
            })
        })
    })
}

#[cfg(all(test, not(rados_packaged_source)))]
mod tests {
    use std::fs;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use tokio::sync::Notify;

    use super::*;
    use crate::msgr::message::{MessageHeader, MessageLengths};
    use crate::protocol::address::EntityAddr;
    use crate::wire::{Decoder, Encoder, crc32c};

    struct FakeSession {
        sent: mpsc::Sender<Message>,
        incoming: Mutex<mpsc::Receiver<Message>>,
        failure: Mutex<mpsc::Receiver<SessionError>>,
        closed: AtomicBool,
        closed_notify: Notify,
    }

    impl MonitorSession for FakeSession {
        fn send(&self, message: Message) -> BoxFuture<'_, Result<(), SessionError>> {
            Box::pin(async move {
                self.sent
                    .send(message)
                    .await
                    .map_err(|_| SessionError::Closed)
            })
        }

        fn next_incoming(&self) -> BoxFuture<'_, Option<Message>> {
            Box::pin(async move { self.incoming.lock().await.recv().await })
        }

        fn next_failure(&self) -> BoxFuture<'_, SessionError> {
            Box::pin(async move {
                tokio::select! {
                    value = async { self.failure.lock().await.recv().await } => {
                        value.unwrap_or(SessionError::Closed)
                    }
                    () = self.closed_notify.notified() => SessionError::Closed,
                }
            })
        }

        fn close(&self) {
            self.closed.store(true, Ordering::Release);
            self.closed_notify.notify_waiters();
        }

        fn shutdown(&self) -> BoxFuture<'_, ()> {
            Box::pin(async move { self.close() })
        }
    }

    struct FakeHandle {
        session: Arc<FakeSession>,
        incoming: mpsc::Sender<Message>,
        failure: mpsc::Sender<SessionError>,
        sent: Mutex<mpsc::Receiver<Message>>,
    }

    fn fake_session() -> (OpenedMonitorSession, Arc<FakeHandle>) {
        let (sent_tx, sent_rx) = mpsc::channel(16);
        let (incoming_tx, incoming_rx) = mpsc::channel(16);
        let (failure_tx, failure_rx) = mpsc::channel(2);
        let session = Arc::new(FakeSession {
            sent: sent_tx,
            incoming: Mutex::new(incoming_rx),
            failure: Mutex::new(failure_rx),
            closed: AtomicBool::new(false),
            closed_notify: Notify::new(),
        });
        let handle = Arc::new(FakeHandle {
            session: Arc::clone(&session),
            incoming: incoming_tx,
            failure: failure_tx,
            sent: Mutex::new(sent_rx),
        });
        (
            OpenedMonitorSession {
                session,
                global_id: 42,
                client_addresses: EntityAddrVec(Vec::new()),
            },
            handle,
        )
    }

    fn endpoint(octet: u8) -> Endpoint {
        let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, octet), 3300));
        Endpoint {
            address,
            entity_address: EntityAddr::ipv4_v2(address).expect("test endpoint"),
            priority: 0,
            weight: 0,
        }
    }

    fn limits() -> MapLimits {
        MapLimits {
            max_bytes: 32 << 20,
            max_monitors: 64,
            max_addresses: 64,
            max_locations: 64,
            max_pools: 4096,
            max_osds: 65_536,
            max_pg_mappings: 1 << 20,
            max_collection_entries: 1 << 20,
        }
    }

    fn config() -> MonitorConfig {
        MonitorConfig {
            seeds: vec![endpoint(1), endpoint(2)],
            expected_fsid: None,
            hostname: "test-host".to_owned(),
            map_limits: limits(),
            message_limits: MessageLimits {
                max_bytes: 32 << 20,
                max_maps: 16,
            },
            max_seed_attempts: 2,
            history_limit: 2,
            operation_timeout: Duration::from_secs(1),
            retry_delay: Duration::ZERO,
            subscribe_period: Duration::from_secs(60),
            error_capacity: 8,
        }
    }

    fn fixture(name: &str) -> Vec<u8> {
        fs::read(format!("testdata/p04/{name}")).expect("P04 fixture")
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
                front: u32::try_from(front.len()).expect("test message length"),
                ..MessageLengths::default()
            },
            front,
            ..Message::default()
        }
    }

    fn ack(fsid: Fsid) -> Message {
        let mut encoder = Encoder::new(64);
        encoder.u32(30);
        encoder.raw(&fsid.0);
        front_message(
            MESSAGE_MON_SUBSCRIBE_ACK,
            1,
            1,
            encoder.finish().expect("subscribe ack"),
        )
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

    fn osdmap_message(
        fsid: Fsid,
        incrementals: &[(u32, Vec<u8>)],
        full_maps: &[(u32, Vec<u8>)],
        newest: u32,
    ) -> Message {
        let size = incrementals
            .iter()
            .chain(full_maps)
            .map(|(_, value)| value.len())
            .sum::<usize>()
            + 256;
        let mut encoder = Encoder::new(size * 2);
        encoder.raw(&fsid.0);
        encoder.u32(u32::try_from(incrementals.len()).expect("incremental count"));
        for (epoch, bytes) in incrementals {
            encoder.u32(*epoch);
            encoder.bytes(bytes);
        }
        encoder.u32(u32::try_from(full_maps.len()).expect("full map count"));
        for (epoch, bytes) in full_maps {
            encoder.u32(*epoch);
            encoder.bytes(bytes);
        }
        encoder.u32(0);
        encoder.u32(newest);
        front_message(
            MESSAGE_OSD_MAP,
            3,
            1,
            encoder.finish().expect("OSD map message"),
        )
    }

    fn pool_operation_reply(
        transaction_id: u64,
        fsid: Fsid,
        result: i32,
        epoch: u32,
        snapshot: u64,
    ) -> Message {
        let mut encoder = Encoder::new(128);
        encoder.u64(0);
        encoder.i16(-1);
        encoder.u64(0);
        encoder.raw(&fsid.0);
        encoder.i32(result);
        encoder.u32(epoch);
        encoder.u8(1);
        encoder.bytes(&snapshot.to_le_bytes());
        let mut message = front_message(
            MESSAGE_POOL_OPERATION_REPLY,
            1,
            1,
            encoder.finish().expect("pool operation reply"),
        );
        message.header.transaction_id = transaction_id;
        message
    }

    fn monitor_command_reply(
        transaction_id: u64,
        result: i32,
        status: &str,
        command: &[&str],
        data: &[u8],
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
        message.lengths.data = u32::try_from(data.len()).expect("reply data length");
        message.data = data.to_vec();
        message
    }

    fn statfs_reply(transaction_id: u64, fsid: Fsid) -> Message {
        let mut encoder = Encoder::new(128);
        encoder.raw(&fsid.0);
        encoder.u64(7);
        encoder.u64(100);
        encoder.u64(40);
        encoder.u64(60);
        encoder.u64(9);
        let mut message = front_message(
            MESSAGE_STATFS_REPLY,
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
            MESSAGE_GET_POOL_STATS_REPLY,
            2,
            1,
            front.finish().expect("pool stats reply"),
        );
        message.header.transaction_id = transaction_id;
        message
    }

    async fn assert_pool_operation_wire_error(
        client: &Arc<MonitorClient>,
        handle: &Arc<FakeHandle>,
        fsid: Fsid,
        epoch: u32,
        result: i32,
    ) {
        let operation_client = Arc::clone(client);
        let operation = tokio::spawn(async move {
            operation_client
                .apply_pool_operation(
                    3,
                    PoolOperation::DeleteSelfManaged,
                    17,
                    String::new(),
                    OperationOptions::new(),
                )
                .await
        });
        let request = handle
            .sent
            .lock()
            .await
            .recv()
            .await
            .expect("second pool operation");
        handle
            .incoming
            .send(pool_operation_reply(
                request.header.transaction_id,
                fsid,
                result,
                epoch,
                0,
            ))
            .await
            .expect("error reply");
        assert_eq!(
            operation.await.expect("join"),
            Err(MonitorError::WireErrno(result))
        );
    }

    fn empty_incremental(fsid: Fsid, epoch: u32, full_crc: u32) -> Vec<u8> {
        let mut encoder = Encoder::new(64 << 10);
        encoder.versioned(8, 7, |wrapper| {
            wrapper.versioned(9, 1, |client| {
                client.raw(&fsid.0);
                client.u32(epoch);
                client.raw(&[0; 8]);
                client.i64(-1);
                client.i32(-1);
                client.bytes(&[]);
                client.bytes(&[]);
                client.i32(-1);
                client.u32(0);
                client.u32(0);
                client.u32(0);
                for _ in 0..14 {
                    client.u32(0);
                }
                client.raw(&[0; 16]);
                client.u32(0);
                client.u32(0);
            });
            wrapper.versioned(12, 1, |_| {});
            wrapper.u32(0);
            wrapper.u32(full_crc);
        });
        let mut data = encoder.finish().expect("incremental encoding");
        let crc_offset = data.len() - 8;
        let crc = crc32c(
            crc32c(u32::MAX, &data[..crc_offset]),
            &data[crc_offset + 4..],
        );
        data[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());
        data
    }

    fn decode_subscription(message: &Message) -> BTreeMap<String, Subscription> {
        assert_eq!(
            message.header.message_type,
            super::super::messages::MESSAGE_MON_SUBSCRIBE
        );
        let mut decoder = Decoder::new(&message.front, message.front.len());
        let count = decoder.u32();
        let mut result = BTreeMap::new();
        for _ in 0..count {
            result.insert(
                decoder.string(),
                Subscription {
                    start: decoder.u64(),
                    flags: decoder.u8(),
                },
            );
        }
        assert_eq!(decoder.string(), "test-host");
        decoder.finish().expect("subscription");
        result
    }

    #[tokio::test]
    async fn rotates_seeds_with_bounded_attempts() {
        let (opened, handle) = fake_session();
        let opened = Arc::new(Mutex::new(Some(opened)));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let factory: SessionFactory = Arc::new({
            let calls = Arc::clone(&calls);
            let opened = Arc::clone(&opened);
            move |seed| {
                let calls = Arc::clone(&calls);
                let opened = Arc::clone(&opened);
                Box::pin(async move {
                    calls.lock().await.push(seed.address);
                    if seed.address == endpoint(1).address {
                        Err(MonitorError::Session(SessionError::Disconnected))
                    } else {
                        Ok(opened.lock().await.take().expect("single open"))
                    }
                })
            }
        });
        let client = MonitorClient::spawn(config(), factory).expect("client");
        let sent = handle.sent.lock().await.recv().await.expect("subscription");
        assert_eq!(decode_subscription(&sent).len(), 3);
        assert_eq!(
            calls.lock().await.as_slice(),
            &[endpoint(1).address, endpoint(2).address]
        );
        client.shutdown().await;

        let failures = Arc::new(AtomicUsize::new(0));
        let factory: SessionFactory = Arc::new({
            let failures = Arc::clone(&failures);
            move |_| {
                failures.fetch_add(1, Ordering::Relaxed);
                Box::pin(async { Err(MonitorError::Session(SessionError::Disconnected)) })
            }
        });
        let client = MonitorClient::spawn(config(), factory).expect("client");
        assert!(matches!(
            client.wait_ready().await,
            Err(MonitorError::AttemptsExhausted)
        ));
        assert_eq!(failures.load(Ordering::Relaxed), 2);
        client.shutdown().await;
    }

    #[tokio::test]
    async fn pool_operation_is_serialized_and_correlated() {
        let (opened, handle) = fake_session();
        let opened = Arc::new(Mutex::new(Some(opened)));
        let factory: SessionFactory = Arc::new(move |_| {
            let opened = Arc::clone(&opened);
            Box::pin(async move { Ok(opened.lock().await.take().expect("single open")) })
        });
        let client = Arc::new(MonitorClient::spawn(config(), factory).expect("client"));
        tokio::time::timeout(Duration::from_secs(1), handle.sent.lock().await.recv())
            .await
            .expect("subscription timeout")
            .expect("subscription");
        let map_bytes = fixture("osdmap-v8.bin");
        let map = crate::maps::decode_osdmap(&map_bytes, limits()).expect("map");
        handle.incoming.send(ack(map.fsid())).await.expect("ack");
        handle
            .incoming
            .send(monmap_message(&fixture("monmap-v9.bin")))
            .await
            .expect("monmap");
        handle
            .incoming
            .send(osdmap_message(
                map.fsid(),
                &[],
                &[(map.epoch(), map_bytes)],
                map.epoch(),
            ))
            .await
            .expect("map");
        tokio::time::timeout(Duration::from_secs(1), client.wait_ready())
            .await
            .expect("ready timeout")
            .expect("ready");

        let operation_client = Arc::clone(&client);
        let operation = tokio::spawn(async move {
            operation_client
                .apply_pool_operation(
                    3,
                    PoolOperation::CreateSelfManaged,
                    0,
                    String::new(),
                    OperationOptions::new()
                        .with_timeout(Duration::from_secs(1))
                        .expect("options"),
                )
                .await
        });
        let request = tokio::time::timeout(Duration::from_secs(1), handle.sent.lock().await.recv())
            .await
            .expect("pool operation timeout")
            .expect("pool operation");
        assert_eq!(
            request.header.message_type,
            crate::mon::messages::MESSAGE_POOL_OPERATION
        );
        handle
            .incoming
            .send(pool_operation_reply(
                request.header.transaction_id + 1,
                map.fsid(),
                0,
                map.epoch(),
                99,
            ))
            .await
            .expect("stale reply");
        tokio::task::yield_now().await;
        assert!(!operation.is_finished());
        handle
            .incoming
            .send(pool_operation_reply(
                request.header.transaction_id,
                map.fsid(),
                0,
                map.epoch(),
                17,
            ))
            .await
            .expect("reply");
        let reply = tokio::time::timeout(Duration::from_secs(1), operation)
            .await
            .expect("reply timeout")
            .expect("join")
            .expect("operation");
        assert_eq!(reply.response_data, 17_u64.to_le_bytes());

        assert_pool_operation_wire_error(&client, &handle, map.fsid(), map.epoch(), -13).await;
        assert_pool_operation_wire_error(&client, &handle, map.fsid(), map.epoch(), 13).await;
        tokio::time::timeout(Duration::from_secs(1), client.shutdown())
            .await
            .expect("shutdown timeout");
    }

    #[tokio::test]
    async fn monitor_command_is_correlated_ignores_stale_and_returns_success() {
        let (opened, handle) = fake_session();
        let opened = Arc::new(Mutex::new(Some(opened)));
        let factory: SessionFactory = Arc::new(move |_| {
            let opened = Arc::clone(&opened);
            Box::pin(async move { Ok(opened.lock().await.take().expect("single open")) })
        });
        let client = Arc::new(MonitorClient::spawn(config(), factory).expect("client"));
        handle.sent.lock().await.recv().await.expect("subscription");
        let map_bytes = fixture("osdmap-v8.bin");
        let map = crate::maps::decode_osdmap(&map_bytes, limits()).expect("map");
        handle.incoming.send(ack(map.fsid())).await.expect("ack");
        handle
            .incoming
            .send(monmap_message(&fixture("monmap-v9.bin")))
            .await
            .expect("monmap");
        handle
            .incoming
            .send(osdmap_message(
                map.fsid(),
                &[],
                &[(map.epoch(), map_bytes)],
                map.epoch(),
            ))
            .await
            .expect("map");
        tokio::time::timeout(Duration::from_secs(1), client.wait_ready())
            .await
            .expect("ready timeout")
            .expect("ready");

        let operation_client = Arc::clone(&client);
        let operation = tokio::spawn(async move {
            operation_client
                .command(
                    vec!["{\"prefix\":\"status\"}".to_owned()],
                    b"{\"format\":\"json\"}".to_vec(),
                    OperationOptions::new()
                        .with_timeout(Duration::from_secs(1))
                        .expect("options"),
                )
                .await
        });
        let request = tokio::time::timeout(Duration::from_secs(1), handle.sent.lock().await.recv())
            .await
            .expect("command timeout")
            .expect("command");
        assert_eq!(
            request.header.message_type,
            crate::mon::messages::MESSAGE_MON_COMMAND
        );
        handle
            .incoming
            .send(monitor_command_reply(
                request.header.transaction_id + 1,
                0,
                "stale",
                &["{\"prefix\":\"status\"}"],
                b"stale",
            ))
            .await
            .expect("stale reply");
        tokio::task::yield_now().await;
        assert!(!operation.is_finished());

        handle
            .incoming
            .send(monitor_command_reply(
                request.header.transaction_id,
                0,
                "ok",
                &["{\"prefix\":\"status\"}"],
                b"healthy",
            ))
            .await
            .expect("reply");
        let (reply, error) = tokio::time::timeout(Duration::from_secs(1), operation)
            .await
            .expect("reply timeout")
            .expect("join")
            .expect("result");
        assert_eq!(reply.result, 0);
        assert_eq!(reply.status, "ok");
        assert_eq!(reply.data, b"healthy");
        assert_eq!(error, None);
        client.shutdown().await;
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn statfs_and_pool_stats_lanes_are_correlated_independently() {
        let (opened, handle) = fake_session();
        let opened = Arc::new(Mutex::new(Some(opened)));
        let factory: SessionFactory = Arc::new(move |_| {
            let opened = Arc::clone(&opened);
            Box::pin(async move { Ok(opened.lock().await.take().expect("single open")) })
        });
        let client = Arc::new(MonitorClient::spawn(config(), factory).expect("client"));
        handle.sent.lock().await.recv().await.expect("subscription");
        let map_bytes = fixture("osdmap-v8.bin");
        let map = crate::maps::decode_osdmap(&map_bytes, limits()).expect("map");
        handle.incoming.send(ack(map.fsid())).await.expect("ack");
        handle
            .incoming
            .send(monmap_message(&fixture("monmap-v9.bin")))
            .await
            .expect("monmap");
        handle
            .incoming
            .send(osdmap_message(
                map.fsid(),
                &[],
                &[(map.epoch(), map_bytes)],
                map.epoch(),
            ))
            .await
            .expect("map");
        client.wait_ready().await.expect("ready");

        let statfs_client = Arc::clone(&client);
        let statfs = tokio::spawn(async move {
            statfs_client
                .statfs(
                    OperationOptions::new()
                        .with_timeout(Duration::from_secs(1))
                        .expect("options"),
                )
                .await
        });
        let pool_stats_client = Arc::clone(&client);
        let pool_stats = tokio::spawn(async move {
            pool_stats_client
                .pool_stats(
                    vec!["data".to_owned()],
                    OperationOptions::new()
                        .with_timeout(Duration::from_secs(1))
                        .expect("options"),
                )
                .await
        });

        let first = handle
            .sent
            .lock()
            .await
            .recv()
            .await
            .expect("first request");
        let second = handle
            .sent
            .lock()
            .await
            .recv()
            .await
            .expect("second request");
        let (statfs_request, pool_request) =
            if first.header.message_type == crate::mon::messages::MESSAGE_STATFS {
                (first, second)
            } else {
                (second, first)
            };
        assert_eq!(
            statfs_request.header.message_type,
            crate::mon::messages::MESSAGE_STATFS
        );
        assert_eq!(
            pool_request.header.message_type,
            crate::mon::messages::MESSAGE_GET_POOL_STATS
        );

        handle
            .incoming
            .send(statfs_reply(
                statfs_request.header.transaction_id + 1,
                map.fsid(),
            ))
            .await
            .expect("stale statfs");
        handle
            .incoming
            .send(pool_stats_reply(
                pool_request.header.transaction_id + 1,
                map.fsid(),
                "data",
            ))
            .await
            .expect("stale pool stats");
        tokio::task::yield_now().await;
        assert!(!statfs.is_finished());
        assert!(!pool_stats.is_finished());

        handle
            .incoming
            .send(pool_stats_reply(
                pool_request.header.transaction_id,
                map.fsid(),
                "data",
            ))
            .await
            .expect("pool stats reply");
        handle
            .incoming
            .send(statfs_reply(
                statfs_request.header.transaction_id,
                map.fsid(),
            ))
            .await
            .expect("statfs reply");

        let statfs_reply = statfs.await.expect("join").expect("statfs");
        assert_eq!(statfs_reply.kib, 100);
        let pool_stats_reply = pool_stats.await.expect("join").expect("pool stats");
        assert_eq!(pool_stats_reply.pools["data"].bytes_used, 217);
        client.shutdown().await;
    }

    #[tokio::test]
    async fn monitor_command_nonzero_result_preserves_reply_and_errno() {
        let (opened, handle) = fake_session();
        let opened = Arc::new(Mutex::new(Some(opened)));
        let factory: SessionFactory = Arc::new(move |_| {
            let opened = Arc::clone(&opened);
            Box::pin(async move { Ok(opened.lock().await.take().expect("single open")) })
        });
        let client = Arc::new(MonitorClient::spawn(config(), factory).expect("client"));
        handle.sent.lock().await.recv().await.expect("subscription");
        let map_bytes = fixture("osdmap-v8.bin");
        let map = crate::maps::decode_osdmap(&map_bytes, limits()).expect("map");
        handle.incoming.send(ack(map.fsid())).await.expect("ack");
        handle
            .incoming
            .send(monmap_message(&fixture("monmap-v9.bin")))
            .await
            .expect("monmap");
        handle
            .incoming
            .send(osdmap_message(
                map.fsid(),
                &[],
                &[(map.epoch(), map_bytes)],
                map.epoch(),
            ))
            .await
            .expect("map");
        client.wait_ready().await.expect("ready");

        for code in [-13, 13] {
            let operation_client = Arc::clone(&client);
            let operation = tokio::spawn(async move {
                operation_client
                    .command(
                        vec!["{\"prefix\":\"status\"}".to_owned()],
                        b"{\"format\":\"json\"}".to_vec(),
                        OperationOptions::new(),
                    )
                    .await
            });
            let request = handle
                .sent
                .lock()
                .await
                .recv()
                .await
                .expect("command request");
            handle
                .incoming
                .send(monitor_command_reply(
                    request.header.transaction_id,
                    code,
                    "permission denied",
                    &["{\"prefix\":\"status\"}"],
                    b"partial",
                ))
                .await
                .expect("reply");
            let (reply, error) = operation.await.expect("join").expect("reply");
            assert_eq!(reply.status, "permission denied");
            assert_eq!(reply.data, b"partial");
            assert_eq!(error, Some(MonitorError::WireErrno(code)));
        }
        client.shutdown().await;
    }

    #[tokio::test]
    async fn monitor_command_predispatch_cancellation_is_immediate() {
        let (opened, _handle) = fake_session();
        let opened = Arc::new(Mutex::new(Some(opened)));
        let factory: SessionFactory = Arc::new(move |_| {
            let opened = Arc::clone(&opened);
            Box::pin(async move { Ok(opened.lock().await.take().expect("single open")) })
        });
        let client = MonitorClient::spawn(config(), factory).expect("client");
        let cancellation = crate::CancellationToken::new();
        cancellation.cancel();
        assert_eq!(
            client
                .command(
                    vec!["{\"prefix\":\"status\"}".to_owned()],
                    b"{\"format\":\"json\"}".to_vec(),
                    OperationOptions::new().with_cancellation(cancellation),
                )
                .await,
            Err(MonitorError::Session(SessionError::Cancelled))
        );
        client.shutdown().await;
    }

    #[tokio::test]
    async fn monitor_command_postdispatch_cancellation_or_deadline_is_outcome_unknown_and_resets_session()
     {
        for cancel_instead_of_deadline in [true, false] {
            let (opened, handle) = fake_session();
            let opened = Arc::new(Mutex::new(Some(opened)));
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
            let client = Arc::new(MonitorClient::spawn(config(), factory).expect("client"));
            handle.sent.lock().await.recv().await.expect("subscription");
            let map_bytes = fixture("osdmap-v8.bin");
            let map = crate::maps::decode_osdmap(&map_bytes, limits()).expect("map");
            handle.incoming.send(ack(map.fsid())).await.expect("ack");
            handle
                .incoming
                .send(monmap_message(&fixture("monmap-v9.bin")))
                .await
                .expect("monmap");
            handle
                .incoming
                .send(osdmap_message(
                    map.fsid(),
                    &[],
                    &[(map.epoch(), map_bytes)],
                    map.epoch(),
                ))
                .await
                .expect("map");
            tokio::time::timeout(Duration::from_secs(1), client.wait_ready())
                .await
                .expect("ready timeout")
                .expect("ready");

            let cancellation = crate::CancellationToken::new();
            let options = if cancel_instead_of_deadline {
                OperationOptions::new().with_cancellation(cancellation.clone())
            } else {
                OperationOptions::new()
                    .with_timeout(Duration::from_millis(50))
                    .expect("options")
            };
            let operation_client = Arc::clone(&client);
            let operation = tokio::spawn(async move {
                operation_client
                    .command(
                        vec!["{\"prefix\":\"status\"}".to_owned()],
                        b"{\"format\":\"json\"}".to_vec(),
                        options,
                    )
                    .await
            });
            handle
                .sent
                .lock()
                .await
                .recv()
                .await
                .expect("command request");
            if cancel_instead_of_deadline {
                cancellation.cancel();
            }
            assert_eq!(
                operation.await.expect("join"),
                Err(MonitorError::Session(SessionError::OutcomeUnknown))
            );
            assert!(handle.session.closed.load(Ordering::Acquire));
            client.shutdown().await;
        }
    }

    #[tokio::test]
    async fn foreign_pool_operation_reply_closes_session_and_fails_over() {
        let (first, handle) = fake_session();
        let (second, second_handle) = fake_session();
        let sessions = Arc::new(Mutex::new(VecDeque::from([first, second])));
        let factory: SessionFactory = Arc::new(move |_| {
            let sessions = Arc::clone(&sessions);
            Box::pin(
                async move { Ok(sessions.lock().await.pop_front().expect("scripted session")) },
            )
        });
        let client = Arc::new(MonitorClient::spawn(config(), factory).expect("client"));
        handle.sent.lock().await.recv().await.expect("subscription");
        let map_bytes = fixture("osdmap-v8.bin");
        let map = crate::maps::decode_osdmap(&map_bytes, limits()).expect("map");
        handle.incoming.send(ack(map.fsid())).await.expect("ack");
        handle
            .incoming
            .send(monmap_message(&fixture("monmap-v9.bin")))
            .await
            .expect("monmap");
        handle
            .incoming
            .send(osdmap_message(
                map.fsid(),
                &[],
                &[(map.epoch(), map_bytes)],
                map.epoch(),
            ))
            .await
            .expect("map");
        client.wait_ready().await.expect("ready");

        let operation_client = Arc::clone(&client);
        let operation = tokio::spawn(async move {
            operation_client
                .apply_pool_operation(
                    3,
                    PoolOperation::CreateSelfManaged,
                    0,
                    String::new(),
                    OperationOptions::new(),
                )
                .await
        });
        let request = handle
            .sent
            .lock()
            .await
            .recv()
            .await
            .expect("pool operation");
        handle
            .incoming
            .send(pool_operation_reply(
                request.header.transaction_id,
                Fsid([9; 16]),
                0,
                map.epoch(),
                17,
            ))
            .await
            .expect("foreign reply");
        assert_eq!(
            operation.await.expect("join"),
            Err(MonitorError::ForeignCluster)
        );
        second_handle
            .sent
            .lock()
            .await
            .recv()
            .await
            .expect("replacement subscription");
        assert!(handle.session.closed.load(Ordering::Acquire));
        client.shutdown().await;
    }

    #[tokio::test]
    async fn dispatched_pool_operation_timeout_is_outcome_unknown_and_resets_session() {
        let (opened, handle) = fake_session();
        let opened = Arc::new(Mutex::new(Some(opened)));
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
        let client = Arc::new(MonitorClient::spawn(config(), factory).expect("client"));
        handle.sent.lock().await.recv().await.expect("subscription");
        let map_bytes = fixture("osdmap-v8.bin");
        let map = crate::maps::decode_osdmap(&map_bytes, limits()).expect("map");
        handle.incoming.send(ack(map.fsid())).await.expect("ack");
        handle
            .incoming
            .send(monmap_message(&fixture("monmap-v9.bin")))
            .await
            .expect("monmap");
        handle
            .incoming
            .send(osdmap_message(
                map.fsid(),
                &[],
                &[(map.epoch(), map_bytes)],
                map.epoch(),
            ))
            .await
            .expect("map");
        tokio::time::timeout(Duration::from_secs(1), client.wait_ready())
            .await
            .expect("ready timeout")
            .expect("ready");

        let operation_client = Arc::clone(&client);
        let operation = tokio::spawn(async move {
            operation_client
                .apply_pool_operation(
                    3,
                    PoolOperation::CreateSelfManaged,
                    0,
                    String::new(),
                    OperationOptions::new()
                        .with_timeout(Duration::from_millis(50))
                        .expect("options"),
                )
                .await
        });
        handle
            .sent
            .lock()
            .await
            .recv()
            .await
            .expect("pool operation");
        assert_eq!(
            operation.await.expect("join"),
            Err(MonitorError::Session(SessionError::OutcomeUnknown))
        );
        assert!(handle.session.closed.load(Ordering::Acquire));
        client.shutdown().await;
    }

    #[tokio::test]
    async fn committed_pool_operation_without_visible_map_times_out() {
        let (opened, handle) = fake_session();
        let opened = Arc::new(Mutex::new(Some(opened)));
        let factory: SessionFactory = Arc::new(move |_| {
            let opened = Arc::clone(&opened);
            Box::pin(async move { Ok(opened.lock().await.take().expect("single open")) })
        });
        let client = Arc::new(MonitorClient::spawn(config(), factory).expect("client"));
        handle.sent.lock().await.recv().await.expect("subscription");
        let map_bytes = fixture("osdmap-v8.bin");
        let map = crate::maps::decode_osdmap(&map_bytes, limits()).expect("map");
        handle.incoming.send(ack(map.fsid())).await.expect("ack");
        handle
            .incoming
            .send(monmap_message(&fixture("monmap-v9.bin")))
            .await
            .expect("monmap");
        handle
            .incoming
            .send(osdmap_message(
                map.fsid(),
                &[],
                &[(map.epoch(), map_bytes)],
                map.epoch(),
            ))
            .await
            .expect("map");
        tokio::time::timeout(Duration::from_secs(1), client.wait_ready())
            .await
            .expect("ready timeout")
            .expect("ready");

        let operation_client = Arc::clone(&client);
        let operation = tokio::spawn(async move {
            operation_client
                .apply_pool_operation(
                    3,
                    PoolOperation::CreateSelfManaged,
                    0,
                    String::new(),
                    OperationOptions::new()
                        .with_timeout(Duration::from_millis(100))
                        .expect("options"),
                )
                .await
        });
        let request = handle
            .sent
            .lock()
            .await
            .recv()
            .await
            .expect("pool operation");
        handle
            .incoming
            .send(pool_operation_reply(
                request.header.transaction_id,
                map.fsid(),
                0,
                map.epoch() + 1,
                17,
            ))
            .await
            .expect("successful reply");
        assert_eq!(
            operation.await.expect("join"),
            Err(MonitorError::ConnectTimeout)
        );
        client.shutdown().await;
    }

    #[tokio::test]
    async fn fatal_message_marks_pending_pool_operation_outcome_unknown() {
        let (first, handle) = fake_session();
        let (second, _second_handle) = fake_session();
        let sessions = Arc::new(Mutex::new(VecDeque::from([first, second])));
        let factory: SessionFactory = Arc::new(move |_| {
            let sessions = Arc::clone(&sessions);
            Box::pin(
                async move { Ok(sessions.lock().await.pop_front().expect("scripted session")) },
            )
        });
        let client = Arc::new(MonitorClient::spawn(config(), factory).expect("client"));
        handle.sent.lock().await.recv().await.expect("subscription");
        let map_bytes = fixture("osdmap-v8.bin");
        let map = crate::maps::decode_osdmap(&map_bytes, limits()).expect("map");
        handle.incoming.send(ack(map.fsid())).await.expect("ack");
        handle
            .incoming
            .send(monmap_message(&fixture("monmap-v9.bin")))
            .await
            .expect("monmap");
        handle
            .incoming
            .send(osdmap_message(
                map.fsid(),
                &[],
                &[(map.epoch(), map_bytes)],
                map.epoch(),
            ))
            .await
            .expect("map");
        client.wait_ready().await.expect("ready");

        let operation_client = Arc::clone(&client);
        let operation = tokio::spawn(async move {
            operation_client
                .apply_pool_operation(
                    3,
                    PoolOperation::CreateSelfManaged,
                    0,
                    String::new(),
                    OperationOptions::new(),
                )
                .await
        });
        handle
            .sent
            .lock()
            .await
            .recv()
            .await
            .expect("pool operation");
        handle
            .incoming
            .send(ack(Fsid([9; 16])))
            .await
            .expect("foreign message");
        assert_eq!(
            operation.await.expect("join"),
            Err(MonitorError::Session(SessionError::OutcomeUnknown))
        );
        client.shutdown().await;
    }

    #[tokio::test]
    async fn rejects_wrong_fsid_and_fails_over() {
        let (first, first_handle) = fake_session();
        let (second, second_handle) = fake_session();
        let sessions = Arc::new(Mutex::new(VecDeque::from([first, second])));
        let expected = Fsid([7; 16]);
        let mut client_config = config();
        client_config.expected_fsid = Some(expected);
        let factory: SessionFactory = Arc::new(move |_| {
            let sessions = Arc::clone(&sessions);
            Box::pin(
                async move { Ok(sessions.lock().await.pop_front().expect("scripted session")) },
            )
        });
        let mut client = MonitorClient::spawn(client_config, factory).expect("client");
        first_handle
            .sent
            .lock()
            .await
            .recv()
            .await
            .expect("first subscription");
        first_handle
            .incoming
            .send(ack(Fsid([8; 16])))
            .await
            .expect("foreign ack");
        assert_eq!(
            client.next_error().await,
            Some(MonitorError::ForeignCluster)
        );
        second_handle
            .sent
            .lock()
            .await
            .recv()
            .await
            .expect("replacement subscription");
        assert!(first_handle.session.closed.load(Ordering::Acquire));
        client.shutdown().await;

        let (first, first_handle) = fake_session();
        let (second, second_handle) = fake_session();
        let sessions = Arc::new(Mutex::new(VecDeque::from([first, second])));
        let mut client_config = config();
        client_config.expected_fsid = Some(expected);
        let factory: SessionFactory = Arc::new(move |_| {
            let sessions = Arc::clone(&sessions);
            Box::pin(
                async move { Ok(sessions.lock().await.pop_front().expect("scripted session")) },
            )
        });
        let client = MonitorClient::spawn(client_config, factory).expect("client");
        first_handle
            .sent
            .lock()
            .await
            .recv()
            .await
            .expect("first subscription");
        first_handle
            .incoming
            .send(ack(Fsid([8; 16])))
            .await
            .expect("first foreign ack");
        second_handle
            .sent
            .lock()
            .await
            .recv()
            .await
            .expect("second subscription");
        second_handle
            .incoming
            .send(ack(Fsid([9; 16])))
            .await
            .expect("second foreign ack");
        assert!(matches!(
            client.wait_ready().await,
            Err(MonitorError::ForeignCluster)
        ));
        client.shutdown().await;
    }

    #[tokio::test]
    async fn subscriptions_progress_with_published_epochs() {
        let (opened, handle) = fake_session();
        let factory: SessionFactory = Arc::new(move |_| {
            let opened = opened.session.clone();
            Box::pin(async move {
                Ok(OpenedMonitorSession {
                    session: opened,
                    global_id: 42,
                    client_addresses: EntityAddrVec(Vec::new()),
                })
            })
        });
        let client = MonitorClient::spawn(config(), factory).expect("client");
        let initial = handle
            .sent
            .lock()
            .await
            .recv()
            .await
            .expect("initial subscription");
        assert!(
            decode_subscription(&initial)
                .values()
                .all(|value| value.start == 0)
        );

        let mon_bytes = fixture("monmap-v9.bin");
        let monmap = crate::maps::decode_monmap(&mon_bytes, limits()).expect("fixture monmap");
        let osd_bytes = fixture("osdmap-v8.bin");
        let osdmap = crate::maps::decode_osdmap(&osd_bytes, limits()).expect("fixture OSD map");
        handle
            .incoming
            .send(monmap_message(&mon_bytes))
            .await
            .expect("monmap");
        handle
            .incoming
            .send(osdmap_message(
                osdmap.fsid(),
                &[],
                &[(osdmap.epoch(), osd_bytes)],
                osdmap.epoch(),
            ))
            .await
            .expect("OSD map");
        tokio::task::yield_now().await;
        let snapshot = client.snapshot();
        assert_eq!(snapshot.connected_fsid(), Some(monmap.fsid()));
        assert_eq!(snapshot.global_id(), Some(42));
        assert_eq!(snapshot.monmap().expect("monmap").epoch(), monmap.epoch());
        assert_eq!(snapshot.osdmap().expect("OSD map").epoch(), osdmap.epoch());
        assert_eq!(snapshot.list_pools().len(), osdmap.pools().len());
        client.shutdown().await;
    }

    #[tokio::test]
    async fn full_and_incremental_maps_converge_and_history_is_bounded() {
        let (mut owner, state) = test_owner();
        let full_bytes = fixture("osdmap-v8.bin");
        let full = crate::maps::decode_osdmap(&full_bytes, limits()).expect("full map");
        let incremental_bytes = empty_incremental(full.fsid(), full.epoch() + 1, 123);
        let incremental = crate::maps::decode_osdmap_incremental(&incremental_bytes, limits())
            .expect("incremental map");
        assert_eq!(incremental.epoch(), full.epoch() + 1);
        let expected =
            apply_osdmap_incremental(&full, &incremental, limits()).expect("expected map");
        owner
            .handle_message(osdmap_message(
                full.fsid(),
                &[(incremental.epoch(), incremental_bytes)],
                &[(full.epoch(), full_bytes)],
                incremental.epoch(),
            ))
            .await
            .expect("map batch");
        assert_eq!(
            owner.state.osdmap.as_ref().expect("OSD map").epoch(),
            expected.epoch()
        );
        owner
            .handle_message(ack(full.fsid()))
            .await
            .expect("ack publish");
        owner
            .handle_message(ack(full.fsid()))
            .await
            .expect("ack publish");
        assert_eq!(owner.history.lock().await.len(), 2);
        assert_eq!(state.borrow().generation(), owner.state.generation());
    }

    #[tokio::test]
    async fn gap_requests_full_map_then_resubscribes() {
        let (opened, handle) = fake_session();
        let factory: SessionFactory = Arc::new(move |_| {
            let session = opened.session.clone();
            Box::pin(async move {
                Ok(OpenedMonitorSession {
                    session,
                    global_id: 42,
                    client_addresses: EntityAddrVec(Vec::new()),
                })
            })
        });
        let mut client = MonitorClient::spawn(config(), factory).expect("client");
        handle
            .sent
            .lock()
            .await
            .recv()
            .await
            .expect("initial subscription");
        let full_bytes = fixture("osdmap-v8.bin");
        let full = crate::maps::decode_osdmap(&full_bytes, limits()).expect("full map");
        handle.incoming.send(ack(full.fsid())).await.expect("ack");
        handle
            .incoming
            .send(osdmap_message(full.fsid(), &[], &[], full.epoch() + 1))
            .await
            .expect("gap");
        assert_eq!(client.next_error().await, Some(MonitorError::MapGap));
        let request = handle
            .sent
            .lock()
            .await
            .recv()
            .await
            .expect("full map request");
        let subscriptions = decode_subscription(&request);
        assert_eq!(
            subscriptions.get("osdmap"),
            Some(&Subscription {
                start: 0,
                flags: SUBSCRIBE_ONCE,
            })
        );
        handle
            .incoming
            .send(osdmap_message(full.fsid(), &[], &[], 0))
            .await
            .expect("stale batch");
        assert!(handle.sent.lock().await.try_recv().is_err());
        handle
            .incoming
            .send(osdmap_message(
                full.fsid(),
                &[],
                &[(full.epoch(), full_bytes)],
                full.epoch(),
            ))
            .await
            .expect("replacement full map");
        let resumed = handle
            .sent
            .lock()
            .await
            .recv()
            .await
            .expect("resubscription");
        assert_eq!(
            decode_subscription(&resumed)
                .get("osdmap")
                .map(|value| value.start),
            Some(u64::from(full.epoch()) + 1)
        );
        client.shutdown().await;
    }

    #[tokio::test]
    async fn malformed_osdmap_batch_does_not_pin_fsid() {
        let (mut owner, _state) = test_owner();
        let foreign = Fsid([0xff; 16]);
        let malformed = osdmap_message(foreign, &[], &[(1, vec![0])], 1);
        assert!(owner.handle_message(malformed).await.is_err());
        assert_eq!(owner.pinned_fsid, None);

        let expected = Fsid([7; 16]);
        owner
            .handle_message(ack(expected))
            .await
            .expect("valid identity after malformed batch");
        assert_eq!(owner.pinned_fsid, Some(expected));
    }

    #[tokio::test]
    async fn newer_maps_replace_and_older_maps_do_not_regress_state() {
        let (mut owner, _state) = test_owner();
        let full_bytes = fixture("osdmap-v8.bin");
        let full = crate::maps::decode_osdmap(&full_bytes, limits()).expect("full map");
        owner
            .handle_message(osdmap_message(
                full.fsid(),
                &[],
                &[(full.epoch(), full_bytes.clone())],
                full.epoch(),
            ))
            .await
            .expect("new map");
        let generation = owner.state.generation;
        owner
            .handle_message(osdmap_message(
                full.fsid(),
                &[],
                &[(full.epoch(), full_bytes)],
                full.epoch(),
            ))
            .await
            .expect("duplicate map");
        assert_eq!(owner.state.generation, generation);
    }

    #[tokio::test]
    async fn shutdown_closes_active_session_and_joins_owner() {
        let (opened, handle) = fake_session();
        let factory: SessionFactory = Arc::new(move |_| {
            let session = opened.session.clone();
            Box::pin(async move {
                Ok(OpenedMonitorSession {
                    session,
                    global_id: 42,
                    client_addresses: EntityAddrVec(Vec::new()),
                })
            })
        });
        let client = MonitorClient::spawn(config(), factory).expect("client");
        handle.sent.lock().await.recv().await.expect("subscription");
        client.shutdown().await;
        assert!(handle.session.closed.load(Ordering::Acquire));
        assert_eq!(client.terminal(), Some(MonitorError::Closed));
    }

    fn test_owner() -> (Owner, watch::Receiver<Arc<MonitorState>>) {
        let (state_tx, state) = watch::channel(Arc::new(MonitorState::default()));
        let (errors, _) = mpsc::channel(8);
        let (terminal, _) = watch::channel(None);
        let (_, stop) = watch::channel(false);
        let (_, refresh_rx) = mpsc::channel(1);
        let (_, commands_rx) = mpsc::channel(1);
        let (_, statfs_rx) = mpsc::channel(1);
        let (_, pool_stats_rx) = mpsc::channel(1);
        let (_, pool_operations_rx) = mpsc::channel(1);
        (
            Owner {
                config: config(),
                factory: Arc::new(|_| Box::pin(async { Err(MonitorError::AttemptsExhausted) })),
                next_seed: 0,
                pinned_fsid: None,
                state: MonitorState::default(),
                state_tx,
                history: Arc::new(Mutex::new(VecDeque::new())),
                errors,
                terminal,
                stop,
                refresh_epoch: None,
                refresh_rx,
                commands_rx,
                statfs_rx,
                pool_stats_rx,
                pool_operations_rx,
                next_transaction_id: 1,
                foreign_seeds: HashSet::new(),
            },
            state,
        )
    }
}
