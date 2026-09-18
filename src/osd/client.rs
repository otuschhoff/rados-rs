use std::collections::HashMap;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crate::OperationOptions;
use crate::cephx::connector::{MonitorConnector, ServiceConfig, ServiceConnector};
use crate::maps::PG;
use crate::mon::client::MonitorClient;
use crate::msgr::control::ClientIdent;
use crate::msgr::frame::Limits as FrameLimits;
use crate::msgr::message::Message;
use crate::msgr::session::{Config as SessionConfig, Machine, ReconnectPolicy, SessionError};
use crate::msgr::supervisor::{Connector, Session};
use crate::protocol::address::{EntityAddr, EntityAddrVec};
use crate::protocol::features::GlobalFeatures;
use tokio::sync::{Mutex as AsyncMutex, watch};
use tokio::task::JoinHandle;

use super::backoff::{
    BACKOFF_BLOCK, BACKOFF_UNBLOCK, Backoff, HObject, MESSAGE_OSD_BACKOFF, decode_backoff,
    encode_acknowledgment,
};
use super::messages::{
    FLAG_IGNORE_CACHE, FLAG_IGNORE_OVERLAY, FLAG_REDIRECTED, FLAG_RETRY, Limits, Operation, Reply,
    Request, decode_reply, encode_request,
};

const ENTITY_OSD: u8 = 4;
const MAX_ATTEMPTS: usize = 3;
const MAX_RETIRED_SESSIONS: usize = 16;
const CANCELLATION_POLL: Duration = Duration::from_millis(10);
const TRANSIENT_REFRESH_WAIT: Duration = Duration::from_millis(250);
const READ_REPLY_FRONT_BYTES: u64 = 144;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Target {
    pub(crate) pool_id: i64,
    pub(crate) object: Vec<u8>,
    pub(crate) locator: Vec<u8>,
    pub(crate) namespace: Vec<u8>,
    pub(crate) snapshot: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReadResult {
    pub(crate) data: Vec<u8>,
    pub(crate) version: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Closed,
    NotConnected,
    NoPrimary,
    LimitExceeded,
    MalformedReply,
    Unsupported,
    Timeout,
    Cancelled,
    QueueSaturated,
    RecoveryExhausted,
    WireErrno(i32),
}

struct SessionEntry {
    endpoint: SocketAddr,
    authority: Arc<MonitorConnector>,
    session: Arc<OSDSession>,
}

#[derive(Default)]
struct OSDSessionState {
    backoffs: HashMap<u64, Backoff>,
    failure: Option<Error>,
}

struct OSDSession {
    raw: Arc<Session>,
    state: Arc<AsyncMutex<OSDSessionState>>,
    changed: watch::Sender<u64>,
    owner: AsyncMutex<Option<JoinHandle<()>>>,
    limits: Limits,
}

pub(crate) struct Client {
    authority: Arc<RwLock<Option<Arc<MonitorConnector>>>>,
    sessions: Mutex<HashMap<i32, SessionEntry>>,
    retired: Mutex<Vec<Arc<OSDSession>>>,
    next_transaction: AtomicU64,
    incarnation: AtomicI32,
    closed: AtomicBool,
    frame_limits: FrameLimits,
    message_limits: Limits,
    dial_timeout: Duration,
    handshake_timeout: Duration,
    allow_crc: bool,
}

impl Client {
    pub(crate) fn new(
        authority: Arc<RwLock<Option<Arc<MonitorConnector>>>>,
        frame_limits: FrameLimits,
        dial_timeout: Duration,
        handshake_timeout: Duration,
        allow_crc: bool,
    ) -> Self {
        Self {
            authority,
            sessions: Mutex::new(HashMap::new()),
            retired: Mutex::new(Vec::new()),
            next_transaction: AtomicU64::new(1),
            incarnation: AtomicI32::new(0),
            closed: AtomicBool::new(false),
            frame_limits,
            message_limits: Limits {
                max_bytes: u32::try_from(frame_limits.max_frame_bytes).unwrap_or(u32::MAX),
                max_operations: 4,
            },
            dial_timeout,
            handshake_timeout,
            allow_crc,
        }
    }

    pub(crate) async fn read(
        &self,
        monitor: &MonitorClient,
        target: Target,
        offset: u64,
        length: u64,
        options: &OperationOptions,
    ) -> Result<ReadResult, Error> {
        let minimum_reply_bytes = READ_REPLY_FRONT_BYTES
            .checked_add(target.object.len() as u64)
            .ok_or(Error::LimitExceeded)?;
        if offset.checked_add(length).is_none()
            || minimum_reply_bytes > u64::from(self.message_limits.max_bytes)
            || length > u64::from(self.message_limits.max_bytes) - minimum_reply_bytes
        {
            return Err(Error::LimitExceeded);
        }
        self.execute(monitor, target, Operation::Read { offset, length }, options)
            .await
    }

    pub(crate) async fn stat(
        &self,
        monitor: &MonitorClient,
        target: Target,
        options: &OperationOptions,
    ) -> Result<ReadResult, Error> {
        self.execute(monitor, target, Operation::Stat, options)
            .await
    }

    #[allow(clippy::too_many_lines)]
    async fn execute(
        &self,
        monitor: &MonitorClient,
        mut target: Target,
        operation: Operation,
        options: &OperationOptions,
    ) -> Result<ReadResult, Error> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        let transaction_id = self
            .next_transaction
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| Error::LimitExceeded)?;
        let client_incarnation = self.client_incarnation()?;
        let mut flags = 0;
        for attempt in 0..MAX_ATTEMPTS {
            if self.closed.load(Ordering::Acquire) {
                return Err(Error::Closed);
            }
            check_options(options)?;
            let state = monitor.snapshot();
            let map = state.osdmap().ok_or(Error::NotConnected)?;
            let placement = map
                .place_object(
                    target.pool_id,
                    &target.object,
                    &target.locator,
                    &target.namespace,
                )
                .map_err(|_| Error::NoPrimary)?;
            if placement.acting_primary < 0 {
                return Err(Error::NoPrimary);
            }
            let addresses = map
                .osd_client_addresses(placement.acting_primary)
                .ok_or(Error::NoPrimary)?;
            if attempt > 0 {
                flags |= FLAG_RETRY;
            }
            let session = self.session(placement.acting_primary, addresses)?;
            let global_id = self
                .authority
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .map_or(0, |authority| authority.metadata().global_id);
            let operations = [operation];
            let message = encode_request(
                &Request {
                    map_epoch: map.epoch(),
                    pg: placement.pg,
                    shard: placement.primary_shard,
                    sharded: placement.sharded,
                    object_hash: placement.raw_hash,
                    pool_id: target.pool_id,
                    object: &target.object,
                    locator: &target.locator,
                    namespace: &target.namespace,
                    snapshot: target.snapshot,
                    transaction_id,
                    client_global_id: global_id,
                    client_incarnation,
                    retry: i32::try_from(attempt).map_err(|_| Error::LimitExceeded)?,
                    flags,
                    features: GlobalFeatures::OSD_CLIENT.0,
                    operations: &operations,
                },
                self.message_limits,
            )
            .map_err(map_message_error)?;
            let object = HObject {
                key: target.locator.clone(),
                object: target.object.clone(),
                snapshot: target.snapshot,
                hash: placement.raw_hash,
                max: false,
                namespace: target.namespace.clone(),
                pool: target.pool_id,
            };
            let reply_message = match session
                .submit(placement.pg, &object, message, options)
                .await
            {
                Ok(reply) => reply,
                Err(Error::QueueSaturated) => return Err(Error::QueueSaturated),
                Err(error) => {
                    self.invalidate(placement.acting_primary, &session);
                    if self.closed.load(Ordering::Acquire) {
                        return Err(Error::Closed);
                    }
                    if matches!(error, Error::Timeout | Error::Cancelled) {
                        return Err(error);
                    }
                    best_effort_refresh_map(monitor, map.epoch(), options).await?;
                    continue;
                }
            };
            let Ok(reply) = decode_reply(&reply_message, self.message_limits) else {
                self.invalidate(placement.acting_primary, &session);
                return Err(Error::MalformedReply);
            };
            if validate_target(&reply, &target.object, placement.pg, attempt).is_err() {
                self.invalidate(placement.acting_primary, &session);
                return Err(Error::MalformedReply);
            }
            if let Some(redirect) = reply.redirect {
                target.pool_id = redirect.pool;
                if !redirect.object.is_empty() {
                    target.object = redirect.object;
                }
                target.locator = redirect.locator;
                target.namespace = redirect.namespace;
                flags |= FLAG_REDIRECTED | FLAG_IGNORE_CACHE | FLAG_IGNORE_OVERLAY;
                continue;
            }
            if reply.result == -11 {
                refresh_map(monitor, map.epoch(), options).await?;
                continue;
            }
            if validate_operation(&reply, operation).is_err() {
                self.invalidate(placement.acting_primary, &session);
                return Err(Error::MalformedReply);
            }
            let operation_reply = &reply.operations[0];
            if operation_reply.code == -11 {
                refresh_map(monitor, map.epoch(), options).await?;
                continue;
            }
            if reply.result < 0 {
                return Err(Error::WireErrno(reply.result));
            }
            if operation_reply.code < 0 {
                return Err(Error::WireErrno(operation_reply.code));
            }
            return Ok(ReadResult {
                data: operation_reply.data.clone(),
                version: reply.version,
            });
        }
        Err(Error::RecoveryExhausted)
    }

    fn session(&self, osd: i32, addresses: &EntityAddrVec) -> Result<Arc<OSDSession>, Error> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        let (target_address, endpoint) = addresses
            .0
            .iter()
            .find_map(|address| {
                address
                    .endpoint()
                    .filter(|value| value.port() != 0)
                    .map(|value| (address.clone(), value))
            })
            .ok_or(Error::NoPrimary)?;
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let authority = self
            .authority
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .ok_or(Error::NotConnected)?;
        if let Some(existing) = sessions.get(&osd) {
            if existing.endpoint == endpoint
                && Arc::ptr_eq(&existing.authority, &authority)
                && existing.session.raw.terminal().is_none()
            {
                return Ok(Arc::clone(&existing.session));
            }
            let stale = Arc::clone(&existing.session);
            self.retire(stale)?;
            sessions.remove(&osd);
        }
        let session = self.spawn_session(&authority, target_address, endpoint)?;
        if self.closed.load(Ordering::Acquire) {
            session.close();
            sessions.insert(
                osd,
                SessionEntry {
                    endpoint,
                    authority,
                    session,
                },
            );
            return Err(Error::Closed);
        }
        sessions.insert(
            osd,
            SessionEntry {
                endpoint,
                authority,
                session: Arc::clone(&session),
            },
        );
        Ok(session)
    }

    fn spawn_session(
        &self,
        authority: &Arc<MonitorConnector>,
        target_address: EntityAddr,
        endpoint: SocketAddr,
    ) -> Result<Arc<OSDSession>, Error> {
        let service = Arc::new(
            ServiceConnector::new(ServiceConfig {
                authority: Arc::clone(authority),
                service_type: ENTITY_OSD,
                target_address: target_address.clone(),
                message_limits: self.frame_limits,
                handshake_timeout: self.handshake_timeout,
                max_banner_payload: 64,
                allow_crc: self.allow_crc,
            })
            .map_err(|_| Error::NotConnected)?,
        );
        let dial_timeout = self.dial_timeout;
        let connector: Connector = Arc::new(move || {
            let service = Arc::clone(&service);
            Box::pin(async move {
                let stream =
                    tokio::time::timeout(dial_timeout, tokio::net::TcpStream::connect(endpoint))
                        .await
                        .map_err(|_| SessionError::Disconnected)?
                        .map_err(|_| SessionError::Disconnected)?;
                service.connect(stream).await.map_err(SessionError::from)
            })
        });
        let placeholder =
            EntityAddr::ipv4_v2(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
                .map_err(|_| Error::NotConnected)?;
        let machine = Machine::new(SessionConfig {
            limits: self.frame_limits,
            max_queued_messages: 16,
            max_retained_bytes: self.frame_limits.max_frame_bytes,
            max_in_flight_transactions: 16,
            max_reconnect_attempts: 2,
            max_handshake_transitions: 16,
            reconnect_policy: ReconnectPolicy::ReplayPending,
            client_ident: ClientIdent {
                addresses: EntityAddrVec(vec![placeholder]),
                target_address,
                global_id: 0,
                global_sequence: 0,
                supported_features: GlobalFeatures::OSD_CLIENT.0,
                required_features: (GlobalFeatures::OSD_REPLY_MUX
                    | GlobalFeatures::PGID64
                    | GlobalFeatures::NEW_OSD_OP_REPLY_ENCODING
                    | GlobalFeatures::MESSAGE_ADDRESS_V2)
                    .0,
                flags: 0,
                cookie: 0,
            },
            client_cookie: random_nonzero()?,
            server_cookie: 0,
            global_sequence: 0,
            connect_sequence: 0,
            replacement_cookies: vec![random_nonzero()?, random_nonzero()?],
        })
        .map_err(map_session_error)?;
        Ok(OSDSession::spawn(
            Arc::new(Session::spawn(machine, None, Some(connector))),
            self.message_limits,
            self.handshake_timeout,
        ))
    }

    fn invalidate(&self, osd: i32, failed: &Arc<OSDSession>) {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = sessions
            .get(&osd)
            .filter(|entry| Arc::ptr_eq(&entry.session, failed))
        {
            let failed = Arc::clone(&entry.session);
            if self.retire(failed).is_ok() {
                sessions.remove(&osd);
            }
        }
    }

    fn retire(&self, session: Arc<OSDSession>) -> Result<(), Error> {
        session.close();
        let mut retired = self
            .retired
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        retired.retain(|entry| !entry.is_finished());
        if retired.len() >= MAX_RETIRED_SESSIONS {
            return Err(Error::QueueSaturated);
        }
        retired.push(session);
        Ok(())
    }

    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        let sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for entry in sessions.values() {
            entry.session.close();
        }
        let retired = self
            .retired
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for session in retired.iter() {
            session.close();
        }
    }

    fn client_incarnation(&self) -> Result<i32, Error> {
        let current = self.incarnation.load(Ordering::Acquire);
        if current != 0 {
            return Ok(current);
        }
        let mut bytes = [0; 4];
        getrandom::fill(&mut bytes).map_err(|_| Error::NotConnected)?;
        let generated = i32::from_le_bytes(bytes) & i32::MAX | 1;
        match self
            .incarnation
            .compare_exchange(0, generated, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => Ok(generated),
            Err(installed) => Ok(installed),
        }
    }

    pub(crate) fn has_sessions(&self) -> bool {
        !self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
            || !self
                .retired
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
    }

    pub(crate) async fn shutdown(&self) {
        self.close();
        let sessions = {
            let sessions = self
                .sessions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            sessions
                .values()
                .map(|entry| Arc::clone(&entry.session))
                .collect::<Vec<_>>()
        };
        let retired = self
            .retired
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        for session in sessions.iter().chain(&retired) {
            session.shutdown().await;
        }
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.retired
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }
}

impl OSDSession {
    fn spawn(raw: Arc<Session>, limits: Limits, ack_timeout: Duration) -> Arc<Self> {
        let state = Arc::new(AsyncMutex::new(OSDSessionState::default()));
        let (changed, _) = watch::channel(0);
        let session = Arc::new(Self {
            raw: Arc::clone(&raw),
            state: Arc::clone(&state),
            changed: changed.clone(),
            owner: AsyncMutex::new(None),
            limits,
        });
        let owner = tokio::spawn(run_incoming(raw, state, changed, limits, ack_timeout));
        *session.owner.try_lock().expect("new OSD owner lock") = Some(owner);
        session
    }

    async fn submit(
        &self,
        pg: PG,
        object: &HObject,
        message: Message,
        options: &OperationOptions,
    ) -> Result<Message, Error> {
        loop {
            let state = self.state.lock().await;
            if let Some(error) = state.failure {
                return Err(error);
            }
            let blocked = state
                .backoffs
                .values()
                .any(|backoff| backoff.pg == pg && backoff.contains(object));
            if blocked {
                let mut changed = self.changed.subscribe();
                drop(state);
                wait_for_change(&mut changed, options).await?;
                continue;
            }
            let mut request = wait_for(self.raw.admit(message, false), options).await?;
            request.cancel_on_drop();
            drop(state);
            return wait_for(request.result(), options)
                .await?
                .ok_or(Error::MalformedReply);
        }
    }

    fn close(&self) {
        self.raw.close();
    }

    fn is_finished(&self) -> bool {
        self.owner
            .try_lock()
            .is_ok_and(|owner| owner.as_ref().is_none_or(JoinHandle::is_finished))
    }

    async fn shutdown(&self) {
        self.raw.shutdown().await;
        let mut owner = self.owner.lock().await;
        if let Some(task) = owner.as_mut() {
            let _ = task.await;
        }
        *owner = None;
    }
}

impl Drop for OSDSession {
    fn drop(&mut self) {
        self.raw.close();
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.close();
    }
}

async fn run_incoming(
    raw: Arc<Session>,
    state: Arc<AsyncMutex<OSDSessionState>>,
    changed: watch::Sender<u64>,
    limits: Limits,
    ack_timeout: Duration,
) {
    while let Some(message) = raw.next_incoming().await {
        if message.header.message_type == 41 {
            fail_session(&raw, &state, &changed, Error::NotConnected).await;
            return;
        }
        if message.header.message_type != MESSAGE_OSD_BACKOFF {
            continue;
        }
        let Ok(backoff) = decode_backoff(&message, limits) else {
            fail_session(&raw, &state, &changed, Error::MalformedReply).await;
            return;
        };
        {
            let mut current = state.lock().await;
            match backoff.operation {
                BACKOFF_BLOCK => {
                    current.backoffs.insert(backoff.id, backoff.clone());
                }
                BACKOFF_UNBLOCK => {
                    current.backoffs.remove(&backoff.id);
                }
                _ => unreachable!("decoder validates backoff operation"),
            }
            let revision = changed.borrow().wrapping_add(1);
            changed.send_replace(revision);
        }
        if backoff.operation == BACKOFF_BLOCK {
            let Ok(acknowledgment) = encode_acknowledgment(&backoff, limits) else {
                fail_session(&raw, &state, &changed, Error::MalformedReply).await;
                return;
            };
            let sent = tokio::time::timeout(ack_timeout, async {
                match raw.admit(acknowledgment, true).await {
                    Ok(request) => request.result().await.map(|_| ()),
                    Err(error) => Err(error),
                }
            })
            .await
            .unwrap_or(Err(SessionError::Disconnected));
            if sent.is_err() {
                fail_session(&raw, &state, &changed, Error::NotConnected).await;
                return;
            }
        }
    }
    fail_session(&raw, &state, &changed, Error::NotConnected).await;
}

async fn fail_session(
    raw: &Session,
    state: &AsyncMutex<OSDSessionState>,
    changed: &watch::Sender<u64>,
    error: Error,
) {
    state.lock().await.failure.get_or_insert(error);
    let revision = changed.borrow().wrapping_add(1);
    changed.send_replace(revision);
    raw.close();
}

async fn wait_for_change(
    changed: &mut watch::Receiver<u64>,
    options: &OperationOptions,
) -> Result<(), Error> {
    wait_for(
        async { changed.changed().await.map_err(|_| SessionError::Closed) },
        options,
    )
    .await
}

async fn refresh_map(
    monitor: &MonitorClient,
    epoch: u32,
    options: &OperationOptions,
) -> Result<(), Error> {
    check_options(options)?;
    let deadline = options.deadline().ok_or(Error::Timeout)?;
    let refresh = monitor.refresh_osdmap(epoch);
    let timeout = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
    let cancellation = tokio::time::sleep(CANCELLATION_POLL);
    tokio::pin!(refresh, timeout, cancellation);
    loop {
        tokio::select! {
            result = &mut refresh => return result.map_err(|_| Error::NotConnected),
            () = &mut timeout => return Err(Error::Timeout),
            () = &mut cancellation => {
                if options.is_canceled() {
                    return Err(Error::Cancelled);
                }
                cancellation.as_mut().reset(tokio::time::Instant::now() + CANCELLATION_POLL);
            }
        }
    }
}

async fn best_effort_refresh_map(
    monitor: &MonitorClient,
    epoch: u32,
    options: &OperationOptions,
) -> Result<(), Error> {
    check_options(options)?;
    let refresh_deadline = std::time::Instant::now()
        .checked_add(TRANSIENT_REFRESH_WAIT)
        .ok_or(Error::LimitExceeded)?;
    let deadline = options
        .deadline()
        .map_or(refresh_deadline, |operation_deadline| {
            operation_deadline.min(refresh_deadline)
        });
    let bounded = options.clone().with_deadline(deadline);
    match refresh_map(monitor, epoch, &bounded).await {
        Err(Error::Cancelled) => Err(Error::Cancelled),
        _ => check_options(options),
    }
}

fn validate_target(reply: &Reply, object: &[u8], pg: PG, attempt: usize) -> Result<(), Error> {
    if reply.object != object
        || reply.pg != pg
        || (reply.retry >= 0
            && reply.retry != i32::try_from(attempt).map_err(|_| Error::LimitExceeded)?)
    {
        return Err(Error::MalformedReply);
    }
    Ok(())
}

fn validate_operation(reply: &Reply, operation: Operation) -> Result<(), Error> {
    if reply.operations.len() != 1 || reply.operations[0].operation != operation.code() {
        return Err(Error::MalformedReply);
    }
    if let Operation::Read { length, .. } = operation
        && reply.operations[0].data.len() as u64 > length
    {
        return Err(Error::MalformedReply);
    }
    Ok(())
}

fn random_nonzero() -> Result<u64, Error> {
    let mut bytes = [0; 8];
    getrandom::fill(&mut bytes).map_err(|_| Error::NotConnected)?;
    Ok(u64::from_le_bytes(bytes).max(1))
}

fn check_options(options: &OperationOptions) -> Result<(), Error> {
    if options.is_canceled() {
        return Err(Error::Cancelled);
    }
    if options
        .deadline()
        .is_some_and(|deadline| std::time::Instant::now() >= deadline)
    {
        return Err(Error::Timeout);
    }
    Ok(())
}

async fn wait_for<T>(
    future: impl Future<Output = Result<T, SessionError>>,
    options: &OperationOptions,
) -> Result<T, Error> {
    check_options(options)?;
    let deadline = options.deadline().ok_or(Error::Timeout)?;
    let timeout = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
    let cancellation = tokio::time::sleep(CANCELLATION_POLL);
    tokio::pin!(future, timeout, cancellation);
    loop {
        tokio::select! {
            result = &mut future => return result.map_err(map_session_error),
            () = &mut timeout => return Err(Error::Timeout),
            () = &mut cancellation => {
                if options.is_canceled() {
                    return Err(Error::Cancelled);
                }
                cancellation.as_mut().reset(tokio::time::Instant::now() + CANCELLATION_POLL);
            }
        }
    }
}

fn map_session_error(error: SessionError) -> Error {
    match error {
        SessionError::Closed => Error::Closed,
        SessionError::Cancelled => Error::Cancelled,
        SessionError::QueueSaturated | SessionError::TooManyInFlight => Error::QueueSaturated,
        SessionError::UnsupportedFeature | SessionError::UnsupportedPayload => Error::Unsupported,
        SessionError::Disconnected
        | SessionError::TransitionLimit
        | SessionError::ReconnectExhausted
        | SessionError::OutcomeUnknown
        | SessionError::Renewal
        | SessionError::Malformed
        | SessionError::Frame(_) => Error::NotConnected,
    }
}

fn map_message_error(error: super::messages::Error) -> Error {
    match error {
        super::messages::Error::Wire(crate::wire::WireError::LimitExceeded) => Error::LimitExceeded,
        super::messages::Error::UnsupportedVersion
        | super::messages::Error::Wire(crate::wire::WireError::UnsupportedVersion { .. }) => {
            Error::Unsupported
        }
        super::messages::Error::Wire(crate::wire::WireError::Malformed)
        | super::messages::Error::Malformed => Error::MalformedReply,
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncWriteExt, DuplexStream, duplex};

    use super::*;
    use crate::msgr::frame::{CrcCodec, Tag};
    use crate::msgr::message::{MessageHeader, MessageLengths};
    use crate::msgr::supervisor::ConnectionSetup;
    use crate::msgr::transport::Codec;
    use crate::osd::backoff::encode_for_test;

    const FRAME_TEST_LIMITS: FrameLimits = FrameLimits {
        max_segment_bytes: 4096,
        max_frame_bytes: 8192,
        max_addresses: 4,
        max_auth_bytes: 64,
    };
    const MESSAGE_TEST_LIMITS: Limits = Limits {
        max_bytes: 4096,
        max_operations: 4,
    };
    const TEST_OSD_OP: u16 = 42;
    const TEST_OSD_OP_REPLY: u16 = 43;

    fn address() -> EntityAddr {
        EntityAddr::ipv4_v2(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(192, 0, 2, 1),
            3300,
        )))
        .expect("test address")
    }

    fn raw_session(stream: DuplexStream) -> Arc<Session> {
        let address = address();
        let machine = Machine::new(SessionConfig {
            limits: FRAME_TEST_LIMITS,
            max_queued_messages: 4,
            max_retained_bytes: 8192,
            max_in_flight_transactions: 2,
            max_reconnect_attempts: 1,
            max_handshake_transitions: 8,
            reconnect_policy: ReconnectPolicy::ReplayPending,
            client_ident: ClientIdent {
                addresses: EntityAddrVec(vec![address.clone()]),
                target_address: address,
                global_id: 0,
                global_sequence: 0,
                supported_features: 0,
                required_features: 0,
                flags: 0,
                cookie: 0,
            },
            client_cookie: 1,
            server_cookie: 2,
            global_sequence: 0,
            connect_sequence: 0,
            replacement_cookies: vec![3],
        })
        .expect("valid machine");
        Arc::new(Session::spawn(
            machine,
            Some(ConnectionSetup {
                stream: Box::new(stream),
                codec: Codec::Crc(CrcCodec {
                    with_data_crc: true,
                }),
                requires_identification: false,
                authenticated_global_id: None,
                credential_identity: None,
                renewal_after: None,
            }),
            None,
        ))
    }

    fn object() -> HObject {
        HObject {
            key: Vec::new(),
            object: b"blocked".to_vec(),
            snapshot: super::super::messages::NO_SNAP,
            hash: 7,
            max: false,
            namespace: Vec::new(),
            pool: 1,
        }
    }

    fn backoff(operation: u8) -> Backoff {
        let object = object();
        Backoff {
            pg: PG {
                pool: 1,
                seed: 7,
                preferred: -1,
            },
            shard: -1,
            map_epoch: 1,
            operation,
            id: 9,
            begin: object.clone(),
            end: object,
        }
    }

    #[test]
    fn recovery_replies_do_not_require_operation_results() {
        let pg = PG {
            pool: 1,
            seed: 7,
            preferred: -1,
        };
        let operation = Operation::Read {
            offset: 0,
            length: 16,
        };
        let mut reply = Reply {
            object: b"blocked".to_vec(),
            pg,
            result: -11,
            map_epoch: 1,
            retry: 0,
            version: 0,
            redirect: None,
            operations: Vec::new(),
        };
        assert!(validate_target(&reply, b"blocked", pg, 0).is_ok());
        assert_eq!(
            validate_operation(&reply, operation),
            Err(Error::MalformedReply)
        );

        reply.result = 0;
        reply.redirect = Some(super::super::messages::Redirect {
            pool: 2,
            locator: Vec::new(),
            namespace: Vec::new(),
            object: Vec::new(),
        });
        assert!(validate_target(&reply, b"blocked", pg, 0).is_ok());
        assert_eq!(
            validate_operation(&reply, operation),
            Err(Error::MalformedReply)
        );
    }

    fn request_message() -> Message {
        Message {
            header: MessageHeader {
                transaction_id: 41,
                message_type: TEST_OSD_OP,
                ..MessageHeader::default()
            },
            ..Message::default()
        }
    }

    async fn send_message(server: &mut DuplexStream, message: Message) {
        let codec = CrcCodec {
            with_data_crc: true,
        };
        let wire = codec
            .encode(
                &message.encode(FRAME_TEST_LIMITS).expect("message frame"),
                FRAME_TEST_LIMITS,
            )
            .expect("message wire");
        server.write_all(&wire).await.expect("inject message");
    }

    async fn next_message(server: &mut DuplexStream) -> Message {
        let codec = CrcCodec {
            with_data_crc: true,
        };
        loop {
            let frame = codec
                .read_async(server, FRAME_TEST_LIMITS)
                .await
                .expect("outbound frame");
            if frame.tag == Tag::Message {
                return Message::decode(&frame, FRAME_TEST_LIMITS).expect("outbound message");
            }
        }
    }

    #[tokio::test]
    async fn backoff_blocks_admission_until_unblock() {
        let (client, mut server) = duplex(8192);
        let session = OSDSession::spawn(
            raw_session(client),
            MESSAGE_TEST_LIMITS,
            Duration::from_secs(1),
        );
        let mut block =
            encode_for_test(&backoff(BACKOFF_BLOCK), MESSAGE_TEST_LIMITS).expect("block message");
        block.header.sequence = 1;
        send_message(&mut server, block).await;
        let acknowledgment = next_message(&mut server).await;
        assert_eq!(acknowledgment.header.message_type, MESSAGE_OSD_BACKOFF);

        let pending_session = Arc::clone(&session);
        let pending = tokio::spawn(async move {
            pending_session
                .submit(
                    backoff(BACKOFF_BLOCK).pg,
                    &object(),
                    request_message(),
                    &OperationOptions::new()
                        .with_deadline(std::time::Instant::now() + Duration::from_secs(1)),
                )
                .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(20), next_message(&mut server))
                .await
                .is_err()
        );

        let mut unblock = encode_for_test(&backoff(BACKOFF_UNBLOCK), MESSAGE_TEST_LIMITS)
            .expect("unblock message");
        unblock.header.sequence = 2;
        send_message(&mut server, unblock).await;
        let sent = next_message(&mut server).await;
        let mut reply = Message {
            header: MessageHeader {
                sequence: 3,
                transaction_id: sent.header.transaction_id,
                ..MessageHeader::default()
            },
            lengths: MessageLengths {
                front: 2,
                ..MessageLengths::default()
            },
            front: b"ok".to_vec(),
            ..Message::default()
        };
        reply.header.message_type = TEST_OSD_OP_REPLY;
        send_message(&mut server, reply).await;
        assert_eq!(
            pending.await.expect("submit task").expect("reply").front,
            b"ok"
        );
        session.shutdown().await;
    }

    #[tokio::test]
    async fn stalled_backoff_ack_fails_boundedly() {
        let (client, mut server) = duplex(64);
        let session = OSDSession::spawn(
            raw_session(client),
            MESSAGE_TEST_LIMITS,
            Duration::from_millis(20),
        );
        let mut block =
            encode_for_test(&backoff(BACKOFF_BLOCK), MESSAGE_TEST_LIMITS).expect("block message");
        block.header.sequence = 1;
        send_message(&mut server, block).await;
        tokio::time::sleep(Duration::from_millis(40)).await;
        let result = session
            .submit(
                backoff(BACKOFF_BLOCK).pg,
                &object(),
                request_message(),
                &OperationOptions::new()
                    .with_deadline(std::time::Instant::now() + Duration::from_secs(1)),
            )
            .await;
        assert_eq!(result, Err(Error::NotConnected));
        tokio::time::timeout(Duration::from_secs(1), session.shutdown())
            .await
            .expect("bounded shutdown");
    }
}
