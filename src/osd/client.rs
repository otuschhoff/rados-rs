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
use tokio::sync::{Mutex as AsyncMutex, oneshot, watch};
use tokio::task::JoinHandle;

use super::backoff::{
    BACKOFF_BLOCK, BACKOFF_UNBLOCK, Backoff, HObject, MESSAGE_OSD_BACKOFF, decode_backoff,
    encode_acknowledgment,
};
use super::messages::{
    FLAG_IGNORE_CACHE, FLAG_IGNORE_OVERLAY, FLAG_ON_DISK, FLAG_REDIRECTED, FLAG_RETRY, Limits,
    Operation, Reply, Request, decode_reply, encode_request,
};

const ENTITY_OSD: u8 = 4;
const MAX_ATTEMPTS: usize = 3;
const MAX_RETIRED_SESSIONS: usize = 16;
const CANCELLATION_POLL: Duration = Duration::from_millis(10);
const TRANSIENT_REFRESH_WAIT: Duration = Duration::from_millis(250);
const READ_REPLY_FRONT_BYTES: u64 = 144;
const MAX_MUTATIONS: usize = 64;
const MAX_MUTATION_BYTES: u64 = 64 * 32 * 1024 * 1024;

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

pub(crate) type MutationResult = ReadResult;

pub(crate) enum Mutation<'a> {
    Create { exclusive: bool },
    Write { offset: u64, data: &'a [u8] },
    WriteFull(&'a [u8]),
    Append(&'a [u8]),
    Truncate { size: u64 },
    Zero { offset: u64, length: u64 },
    Remove,
}

impl Mutation<'_> {
    fn retained_bytes(&self) -> Result<u64, Error> {
        let data = match self {
            Self::Write { data, .. } | Self::WriteFull(data) | Self::Append(data) => *data,
            Self::Create { .. } | Self::Truncate { .. } | Self::Zero { .. } | Self::Remove => &[],
        };
        u64::try_from(data.len()).map_err(|_| Error::LimitExceeded)
    }

    fn into_owned(self) -> Operation {
        match self {
            Self::Create { exclusive } => Operation::Create { exclusive },
            Self::Write { offset, data } => Operation::Write {
                offset,
                data: data.to_vec(),
            },
            Self::WriteFull(data) => Operation::WriteFull(data.to_vec()),
            Self::Append(data) => Operation::Append(data.to_vec()),
            Self::Truncate { size } => Operation::Truncate { size },
            Self::Zero { offset, length } => Operation::Zero { offset, length },
            Self::Remove => Operation::Remove,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnknownCause {
    Cancelled,
    Timeout,
    Transport,
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
    OutcomeUnknown(UnknownCause),
    WireErrno(i32),
}

#[derive(Default)]
struct MutationState {
    admission_closed: bool,
    next_sequence: u64,
    pending: HashMap<u64, u64>,
    retained_bytes: u64,
    earliest_unknown: Option<u64>,
}

struct MutationCompletion {
    client: Arc<Client>,
    sequence: Option<u64>,
}

enum AdmissionOutcome {
    Request(crate::msgr::supervisor::Request),
    Reply(Message),
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
    mutations: Mutex<MutationState>,
    mutation_changed: watch::Sender<u64>,
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
        let (mutation_changed, _) = watch::channel(0);
        Self {
            authority,
            sessions: Mutex::new(HashMap::new()),
            retired: Mutex::new(Vec::new()),
            next_transaction: AtomicU64::new(1),
            mutations: Mutex::new(MutationState::default()),
            mutation_changed,
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

    pub(crate) async fn mutate(
        self: &Arc<Self>,
        monitor: Arc<MonitorClient>,
        target: Target,
        mutation: Mutation<'_>,
        options: OperationOptions,
    ) -> Result<MutationResult, Error> {
        if target.snapshot != super::messages::NO_SNAP {
            return Err(Error::LimitExceeded);
        }
        let retained = mutation.retained_bytes()?;
        if retained > u64::from(self.message_limits.max_bytes) {
            return Err(Error::LimitExceeded);
        }
        let (sequence, transaction_id) = self.admit_mutation(retained, &options).await?;
        let operation = mutation.into_owned();
        let (result_tx, result_rx) = oneshot::channel();
        let client = Arc::clone(self);
        tokio::spawn(async move {
            let mut completion = MutationCompletion {
                client: Arc::clone(&client),
                sequence: Some(sequence),
            };
            let result = client
                .execute_mutation(&monitor, target, operation, transaction_id, &options)
                .await;
            completion.finish(result.as_ref().err());
            let _ = result_tx.send(result);
        });
        result_rx
            .await
            .unwrap_or(Err(Error::OutcomeUnknown(UnknownCause::Transport)))
    }

    async fn admit_mutation(
        &self,
        retained: u64,
        options: &OperationOptions,
    ) -> Result<(u64, u64), Error> {
        if retained > MAX_MUTATION_BYTES {
            return Err(Error::LimitExceeded);
        }
        loop {
            check_options(options)?;
            let (admission, mut changed) = {
                let mut state = self
                    .mutations
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if self.closed.load(Ordering::Acquire) {
                    return Err(Error::Closed);
                }
                (
                    admit_mutation_state(&mut state, retained)?,
                    self.mutation_changed.subscribe(),
                )
            };
            if let Some(sequence) = admission {
                let transaction_id = match self.take_transaction_id() {
                    Ok(value) => value,
                    Err(error) => {
                        self.complete_mutation(sequence, Some(&error));
                        return Err(error);
                    }
                };
                return Ok((sequence, transaction_id));
            }
            wait_for_change(&mut changed, options).await?;
        }
    }

    fn complete_mutation(&self, sequence: u64, error: Option<&Error>) {
        let mut state = self
            .mutations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if complete_mutation_state(&mut state, sequence, error) {
            let revision = self.mutation_changed.borrow().wrapping_add(1);
            self.mutation_changed.send_replace(revision);
        }
    }

    pub(crate) async fn flush(&self, options: &OperationOptions) -> Result<(), Error> {
        let watermark = self
            .mutations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .next_sequence;
        loop {
            let (waiting, unknown, mut changed) = {
                let state = self
                    .mutations
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                (
                    state.pending.keys().any(|sequence| *sequence <= watermark),
                    state
                        .earliest_unknown
                        .is_some_and(|sequence| sequence <= watermark),
                    self.mutation_changed.subscribe(),
                )
            };
            if !waiting {
                return if unknown {
                    Err(Error::OutcomeUnknown(UnknownCause::Transport))
                } else {
                    Ok(())
                };
            }
            if let Err(error) = wait_for_change(&mut changed, options).await {
                let state = self
                    .mutations
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let unknown = unknown
                    || state
                        .earliest_unknown
                        .is_some_and(|sequence| sequence <= watermark);
                return if unknown {
                    Err(Error::OutcomeUnknown(match error {
                        Error::Cancelled => UnknownCause::Cancelled,
                        Error::Timeout => UnknownCause::Timeout,
                        _ => UnknownCause::Transport,
                    }))
                } else {
                    Err(error)
                };
            }
        }
    }

    pub(crate) fn begin_shutdown(&self) {
        let mut state = self
            .mutations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        close_mutation_admission_state(&mut state);
        let revision = self.mutation_changed.borrow().wrapping_add(1);
        self.mutation_changed.send_replace(revision);
    }

    #[cfg(test)]
    pub(crate) fn mutation_admission_is_closed(&self) -> bool {
        self.mutations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .admission_closed
    }

    fn take_transaction_id(&self) -> Result<u64, Error> {
        self.next_transaction
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| Error::LimitExceeded)
    }

    #[allow(clippy::too_many_lines)]
    async fn execute(
        &self,
        monitor: &MonitorClient,
        target: Target,
        operation: Operation,
        options: &OperationOptions,
    ) -> Result<ReadResult, Error> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        let transaction_id = self.take_transaction_id()?;
        self.execute_routed(monitor, target, operation, transaction_id, false, options)
            .await
    }

    async fn execute_mutation(
        &self,
        monitor: &MonitorClient,
        target: Target,
        operation: Operation,
        transaction_id: u64,
        options: &OperationOptions,
    ) -> Result<MutationResult, Error> {
        self.execute_routed(monitor, target, operation, transaction_id, true, options)
            .await
    }

    #[allow(clippy::too_many_lines)]
    async fn execute_routed(
        &self,
        monitor: &MonitorClient,
        mut target: Target,
        operation: Operation,
        mut transaction_id: u64,
        mutation: bool,
        options: &OperationOptions,
    ) -> Result<ReadResult, Error> {
        let client_incarnation = self.client_incarnation()?;
        let mut flags = 0;
        let mut prior_unknown = None;
        for attempt in 0..MAX_ATTEMPTS {
            if self.closed.load(Ordering::Acquire) {
                return Err(preserve_unknown(Error::Closed, prior_unknown));
            }
            check_options(options).map_err(|error| preserve_unknown(error, prior_unknown))?;
            let state = monitor.snapshot();
            let map = state
                .osdmap()
                .ok_or_else(|| preserve_unknown(Error::NotConnected, prior_unknown))?;
            let placement = map
                .place_object(
                    target.pool_id,
                    &target.object,
                    &target.locator,
                    &target.namespace,
                )
                .map_err(|_| preserve_unknown(Error::NoPrimary, prior_unknown))?;
            if placement.acting_primary < 0 {
                return Err(preserve_unknown(Error::NoPrimary, prior_unknown));
            }
            let addresses = map
                .osd_client_addresses(placement.acting_primary)
                .ok_or_else(|| preserve_unknown(Error::NoPrimary, prior_unknown))?;
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
            let operations = std::slice::from_ref(&operation);
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
                    operations,
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
            let attempt_deadline = std::time::Instant::now()
                .checked_add(self.dial_timeout.saturating_add(self.handshake_timeout))
                .ok_or(Error::LimitExceeded)?;
            let attempt_options = options.clone().with_deadline(
                options
                    .deadline()
                    .map_or(attempt_deadline, |deadline| deadline.min(attempt_deadline)),
            );
            let reply_message = match session
                .submit(placement.pg, &object, message, mutation, &attempt_options)
                .await
            {
                Ok(reply) => reply,
                Err(Error::QueueSaturated) => {
                    return Err(preserve_unknown(Error::QueueSaturated, prior_unknown));
                }
                Err(error) => {
                    self.invalidate(placement.acting_primary, &session);
                    if self.closed.load(Ordering::Acquire) {
                        return Err(preserve_unknown(Error::Closed, prior_unknown));
                    }
                    if let Error::OutcomeUnknown(cause) = error {
                        prior_unknown = Some(prior_unknown.unwrap_or(cause));
                        if wait_for_primary_change(
                            monitor,
                            &target,
                            placement.acting_primary,
                            map.epoch(),
                            options,
                        )
                        .await
                        {
                            continue;
                        }
                        return Err(Error::OutcomeUnknown(prior_unknown.unwrap_or(cause)));
                    }
                    if matches!(error, Error::Timeout | Error::Cancelled) {
                        return Err(preserve_unknown(error, prior_unknown));
                    }
                    best_effort_refresh_map(monitor, map.epoch(), options)
                        .await
                        .map_err(|error| preserve_unknown(error, prior_unknown))?;
                    continue;
                }
            };
            let Ok(reply) = decode_reply(&reply_message, self.message_limits) else {
                self.invalidate(placement.acting_primary, &session);
                return Err(if mutation {
                    Error::OutcomeUnknown(UnknownCause::Transport)
                } else {
                    Error::MalformedReply
                });
            };
            if validate_target(&reply, &target.object, placement.pg, attempt).is_err() {
                self.invalidate(placement.acting_primary, &session);
                return Err(if mutation {
                    Error::OutcomeUnknown(UnknownCause::Transport)
                } else {
                    Error::MalformedReply
                });
            }
            prior_unknown = None;
            if let Some(redirect) = reply.redirect {
                target.pool_id = redirect.pool;
                if !redirect.object.is_empty() {
                    target.object = redirect.object;
                }
                target.locator = redirect.locator;
                target.namespace = redirect.namespace;
                flags |= FLAG_REDIRECTED | FLAG_IGNORE_CACHE | FLAG_IGNORE_OVERLAY;
                if mutation {
                    transaction_id = self.take_transaction_id()?;
                }
                continue;
            }
            if reply.result == -11 {
                refresh_map(monitor, map.epoch(), options).await?;
                if mutation {
                    transaction_id = self.take_transaction_id()?;
                }
                continue;
            }
            if validate_operation(&reply, &operation).is_err() {
                self.invalidate(placement.acting_primary, &session);
                return Err(if mutation {
                    Error::OutcomeUnknown(UnknownCause::Transport)
                } else {
                    Error::MalformedReply
                });
            }
            let operation_reply = &reply.operations[0];
            if operation_reply.code == -11 {
                refresh_map(monitor, map.epoch(), options).await?;
                if mutation {
                    transaction_id = self.take_transaction_id()?;
                }
                continue;
            }
            if mutation && validate_durable_reply(&reply).is_err() {
                self.invalidate(placement.acting_primary, &session);
                return Err(Error::OutcomeUnknown(UnknownCause::Transport));
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
        Err(preserve_unknown(Error::RecoveryExhausted, prior_unknown))
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
        self.begin_shutdown();
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
        mutation: bool,
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
            let admission = admit_with_cancellation(&self.raw, message, options, mutation).await?;
            let AdmissionOutcome::Request(mut request) = admission else {
                let AdmissionOutcome::Reply(reply) = admission else {
                    unreachable!()
                };
                return Ok(reply);
            };
            request.cancel_on_drop();
            drop(state);
            return wait_for_request(&mut request, options, mutation).await;
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

impl MutationCompletion {
    fn finish(&mut self, error: Option<&Error>) {
        if let Some(sequence) = self.sequence.take() {
            self.client.complete_mutation(sequence, error);
        }
    }
}

impl Drop for MutationCompletion {
    fn drop(&mut self) {
        self.finish(Some(&Error::OutcomeUnknown(UnknownCause::Transport)));
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

async fn admit_with_cancellation(
    raw: &Session,
    message: Message,
    options: &OperationOptions,
    mutation: bool,
) -> Result<AdmissionOutcome, Error> {
    check_options(options)?;
    let deadline = options.deadline().ok_or(Error::Timeout)?;
    let timeout = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
    let cancellation = tokio::time::sleep(CANCELLATION_POLL);
    let admission = raw.admit(message, false);
    tokio::pin!(admission, timeout, cancellation);
    loop {
        let cause = tokio::select! {
            result = &mut admission => {
                return result.map(AdmissionOutcome::Request).map_err(map_session_error);
            }
            () = &mut timeout => Some(UnknownCause::Timeout),
            () = &mut cancellation => {
                if options.is_canceled() {
                    Some(UnknownCause::Cancelled)
                } else {
                    cancellation.as_mut().reset(tokio::time::Instant::now() + CANCELLATION_POLL);
                    None
                }
            }
        };
        let Some(cause) = cause else { continue };
        return match admission.await {
            Ok(mut request) => classify_cancel(request.cancel().await, cause, mutation)
                .map(AdmissionOutcome::Reply),
            Err(SessionError::Cancelled) => Err(match cause {
                UnknownCause::Cancelled => Error::Cancelled,
                UnknownCause::Timeout => Error::Timeout,
                UnknownCause::Transport => Error::NotConnected,
            }),
            Err(error) => Err(map_session_error(error)),
        };
    }
}

async fn wait_for_request(
    request: &mut crate::msgr::supervisor::Request,
    options: &OperationOptions,
    mutation: bool,
) -> Result<Message, Error> {
    let deadline = options.deadline().ok_or(Error::Timeout)?;
    let timeout = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
    let cancellation = tokio::time::sleep(CANCELLATION_POLL);
    tokio::pin!(timeout, cancellation);
    loop {
        let cause = tokio::select! {
            result = request.wait_result() => {
                return result
                    .map_err(|error| map_request_error(error, mutation))?
                    .ok_or(Error::MalformedReply);
            }
            () = &mut timeout => Some(UnknownCause::Timeout),
            () = &mut cancellation => {
                if options.is_canceled() {
                    Some(UnknownCause::Cancelled)
                } else {
                    cancellation.as_mut().reset(tokio::time::Instant::now() + CANCELLATION_POLL);
                    None
                }
            }
        };
        let Some(cause) = cause else { continue };
        return classify_cancel(request.cancel().await, cause, mutation);
    }
}

fn classify_cancel(
    result: Result<Option<Message>, SessionError>,
    cause: UnknownCause,
    mutation: bool,
) -> Result<Message, Error> {
    match result {
        Ok(Some(reply)) => Ok(reply),
        Ok(None) => Err(Error::MalformedReply),
        Err(SessionError::Cancelled) => Err(match cause {
            UnknownCause::Cancelled => Error::Cancelled,
            UnknownCause::Timeout => Error::Timeout,
            UnknownCause::Transport => Error::NotConnected,
        }),
        Err(SessionError::OutcomeUnknown) if mutation => Err(Error::OutcomeUnknown(cause)),
        Err(error) => Err(map_request_error(error, mutation)),
    }
}

const fn map_request_error(error: SessionError, mutation: bool) -> Error {
    if mutation && matches!(error, SessionError::OutcomeUnknown) {
        Error::OutcomeUnknown(UnknownCause::Transport)
    } else {
        map_session_error(error)
    }
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

async fn wait_for_primary_change(
    monitor: &MonitorClient,
    target: &Target,
    previous_primary: i32,
    mut epoch: u32,
    options: &OperationOptions,
) -> bool {
    for _ in 0..MAX_ATTEMPTS {
        if check_options(options).is_err() {
            return false;
        }
        let snapshot = monitor.snapshot();
        let Some(map) = snapshot.osdmap() else {
            return false;
        };
        if let Ok(placement) = map.place_object(
            target.pool_id,
            &target.object,
            &target.locator,
            &target.namespace,
        ) && placement.acting_primary != previous_primary
        {
            return placement.acting_primary >= 0;
        }
        epoch = epoch.max(map.epoch());
        let refresh_deadline = std::time::Instant::now()
            .checked_add(TRANSIENT_REFRESH_WAIT)
            .unwrap_or_else(|| options.deadline().unwrap_or_else(std::time::Instant::now));
        let bounded = options.clone().with_deadline(
            options
                .deadline()
                .map_or(refresh_deadline, |deadline| deadline.min(refresh_deadline)),
        );
        let _ = refresh_map(monitor, epoch, &bounded).await;
    }
    false
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

fn validate_operation(reply: &Reply, operation: &Operation) -> Result<(), Error> {
    if reply.operations.len() != 1 || reply.operations[0].operation != operation.code() {
        return Err(Error::MalformedReply);
    }
    if let Operation::Read { length, .. } = operation
        && reply.operations[0].data.len() as u64 > *length
    {
        return Err(Error::MalformedReply);
    }
    Ok(())
}

fn validate_durable_reply(reply: &Reply) -> Result<(), Error> {
    if reply.result == 0 && reply.flags & i64::from(FLAG_ON_DISK) == 0 {
        return Err(Error::OutcomeUnknown(UnknownCause::Transport));
    }
    Ok(())
}

const fn preserve_unknown(error: Error, prior: Option<UnknownCause>) -> Error {
    match prior {
        Some(cause) => Error::OutcomeUnknown(cause),
        None => error,
    }
}

fn complete_mutation_state(
    state: &mut MutationState,
    sequence: u64,
    error: Option<&Error>,
) -> bool {
    let Some(retained) = state.pending.remove(&sequence) else {
        return false;
    };
    state.retained_bytes -= retained;
    if matches!(error, Some(Error::OutcomeUnknown(_)))
        && state
            .earliest_unknown
            .is_none_or(|unknown| sequence < unknown)
    {
        state.earliest_unknown = Some(sequence);
    }
    true
}

fn admit_mutation_state(state: &mut MutationState, retained: u64) -> Result<Option<u64>, Error> {
    if state.admission_closed {
        return Err(Error::Closed);
    }
    if state.pending.len() >= MAX_MUTATIONS
        || retained > MAX_MUTATION_BYTES.saturating_sub(state.retained_bytes)
    {
        return Ok(None);
    }
    state.next_sequence = state
        .next_sequence
        .checked_add(1)
        .ok_or(Error::LimitExceeded)?;
    let sequence = state.next_sequence;
    state.pending.insert(sequence, retained);
    state.retained_bytes += retained;
    Ok(Some(sequence))
}

const fn close_mutation_admission_state(state: &mut MutationState) {
    state.admission_closed = true;
}

#[cfg(feature = "r08-integration")]
pub(crate) fn fuzz_mutation_lifecycle(script: &[u8]) {
    let mut state = MutationState::default();
    for (index, command) in script.iter().copied().take(MAX_MUTATIONS * 4).enumerate() {
        match command % 4 {
            0 if state.pending.len() < MAX_MUTATIONS => {
                let Some(sequence) = state.next_sequence.checked_add(1) else {
                    break;
                };
                let retained = u64::from(command);
                state.next_sequence = sequence;
                state.pending.insert(sequence, retained);
                state.retained_bytes += retained;
            }
            1 | 2 if !state.pending.is_empty() => {
                let offset = index % state.pending.len();
                let sequence = *state.pending.keys().nth(offset).expect("bounded index");
                let error =
                    (command % 4 == 2).then_some(Error::OutcomeUnknown(UnknownCause::Transport));
                assert!(complete_mutation_state(
                    &mut state,
                    sequence,
                    error.as_ref()
                ));
            }
            3 => state.admission_closed = true,
            _ => {}
        }
        assert_eq!(
            state.retained_bytes,
            state.pending.values().copied().sum::<u64>()
        );
        assert!(
            state
                .earliest_unknown
                .is_none_or(|unknown| unknown <= state.next_sequence)
        );
    }
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

const fn map_session_error(error: SessionError) -> Error {
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
            flags: 0,
            result: -11,
            map_epoch: 1,
            retry: 0,
            version: 0,
            redirect: None,
            operations: Vec::new(),
        };
        assert!(validate_target(&reply, b"blocked", pg, 0).is_ok());
        assert_eq!(
            validate_operation(&reply, &operation),
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
            validate_operation(&reply, &operation),
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
                    false,
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
                false,
                &OperationOptions::new()
                    .with_deadline(std::time::Instant::now() + Duration::from_secs(1)),
            )
            .await;
        assert_eq!(result, Err(Error::NotConnected));
        tokio::time::timeout(Duration::from_secs(1), session.shutdown())
            .await
            .expect("bounded shutdown");
    }

    #[tokio::test]
    async fn flush_captures_watermark_and_waits_for_all_prior_mutations() {
        let client = Client::new(
            Arc::new(RwLock::new(None)),
            FRAME_TEST_LIMITS,
            Duration::from_secs(1),
            Duration::from_secs(1),
            false,
        );
        let options = OperationOptions::new()
            .with_deadline(std::time::Instant::now() + Duration::from_secs(1));
        let (first, _) = client.admit_mutation(1, &options).await.expect("first");
        let (second, _) = client.admit_mutation(1, &options).await.expect("second");
        let flush_client = Arc::new(client);
        let flush_owner = Arc::clone(&flush_client);
        let flush_options = options.clone();
        let flush = tokio::spawn(async move { flush_owner.flush(&flush_options).await });
        tokio::task::yield_now().await;
        flush_client
            .complete_mutation(first, Some(&Error::OutcomeUnknown(UnknownCause::Transport)));
        assert!(!flush.is_finished());
        flush_client.complete_mutation(second, None);
        assert_eq!(
            flush.await.expect("flush task"),
            Err(Error::OutcomeUnknown(UnknownCause::Transport))
        );
    }

    #[tokio::test]
    async fn flush_ignores_mutations_admitted_after_its_watermark() {
        let client = Arc::new(Client::new(
            Arc::new(RwLock::new(None)),
            FRAME_TEST_LIMITS,
            Duration::from_secs(1),
            Duration::from_secs(1),
            false,
        ));
        let options = OperationOptions::new()
            .with_deadline(std::time::Instant::now() + Duration::from_secs(1));
        let (first, _) = client.admit_mutation(0, &options).await.expect("first");
        let flush_owner = Arc::clone(&client);
        let flush_options = options.clone();
        let flush = tokio::spawn(async move { flush_owner.flush(&flush_options).await });
        tokio::task::yield_now().await;
        let (second, _) = client.admit_mutation(0, &options).await.expect("second");
        client.complete_mutation(first, None);
        assert_eq!(flush.await.expect("flush task"), Ok(()));
        client.complete_mutation(second, None);
    }

    #[tokio::test]
    async fn mutation_admission_releases_capacity_after_completion() {
        let client = Client::new(
            Arc::new(RwLock::new(None)),
            FRAME_TEST_LIMITS,
            Duration::from_secs(1),
            Duration::from_secs(1),
            false,
        );
        let options = OperationOptions::new()
            .with_deadline(std::time::Instant::now() + Duration::from_secs(1));
        let mut admitted = Vec::new();
        for _ in 0..MAX_MUTATIONS {
            admitted.push(
                client
                    .admit_mutation(0, &options)
                    .await
                    .expect("admission")
                    .0,
            );
        }
        let short = OperationOptions::new()
            .with_deadline(std::time::Instant::now() + Duration::from_millis(10));
        assert_eq!(client.admit_mutation(0, &short).await, Err(Error::Timeout));
        client.complete_mutation(admitted[0], None);
        assert!(client.admit_mutation(0, &options).await.is_ok());
    }

    #[tokio::test]
    async fn unpolled_and_capacity_waiting_admission_futures_leave_no_state() {
        let client = Client::new(
            Arc::new(RwLock::new(None)),
            FRAME_TEST_LIMITS,
            Duration::from_secs(1),
            Duration::from_secs(1),
            false,
        );
        let options = OperationOptions::new()
            .with_deadline(std::time::Instant::now() + Duration::from_secs(1));
        let unpolled = client.admit_mutation(1, &options);
        drop(unpolled);
        assert!(
            client
                .mutations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pending
                .is_empty()
        );

        let mut admitted = Vec::new();
        for _ in 0..MAX_MUTATIONS {
            admitted.push(
                client
                    .admit_mutation(0, &options)
                    .await
                    .expect("admission")
                    .0,
            );
        }
        let mut waiting = Box::pin(client.admit_mutation(0, &options));
        assert!(
            std::future::poll_fn(|context| match waiting.as_mut().poll(context) {
                std::task::Poll::Pending => std::task::Poll::Ready(true),
                std::task::Poll::Ready(_) => std::task::Poll::Ready(false),
            })
            .await
        );
        drop(waiting);
        assert_eq!(
            client
                .mutations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pending
                .len(),
            MAX_MUTATIONS
        );
        for sequence in admitted {
            client.complete_mutation(sequence, None);
        }
    }

    #[tokio::test]
    async fn dropped_result_receiver_does_not_strand_flush_or_retained_bytes() {
        let client = Arc::new(Client::new(
            Arc::new(RwLock::new(None)),
            FRAME_TEST_LIMITS,
            Duration::from_secs(1),
            Duration::from_secs(1),
            false,
        ));
        let options = OperationOptions::new()
            .with_deadline(std::time::Instant::now() + Duration::from_secs(1));
        let (sequence, _) = client.admit_mutation(3, &options).await.expect("admission");
        let (result_tx, result_rx) = oneshot::channel::<Result<(), Error>>();
        drop(result_rx);
        let owner = Arc::clone(&client);
        tokio::spawn(async move {
            owner.complete_mutation(sequence, None);
            let _ = result_tx.send(Ok(()));
        });
        assert_eq!(client.flush(&options).await, Ok(()));
        let state = client
            .mutations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(state.pending.is_empty());
        assert_eq!(state.retained_bytes, 0);
    }

    #[tokio::test]
    async fn aborted_worker_guard_releases_capacity_and_makes_flush_unknown() {
        let client = Arc::new(Client::new(
            Arc::new(RwLock::new(None)),
            FRAME_TEST_LIMITS,
            Duration::from_secs(1),
            Duration::from_secs(1),
            false,
        ));
        let options = OperationOptions::new()
            .with_deadline(std::time::Instant::now() + Duration::from_secs(1));
        let (sequence, _) = client.admit_mutation(7, &options).await.expect("admission");
        let completion = MutationCompletion {
            client: Arc::clone(&client),
            sequence: Some(sequence),
        };
        let worker = tokio::spawn(async move {
            let _completion = completion;
            std::future::pending::<()>().await;
        });
        worker.abort();
        assert!(worker.await.expect_err("aborted worker").is_cancelled());
        assert_eq!(
            client.flush(&options).await,
            Err(Error::OutcomeUnknown(UnknownCause::Transport))
        );
        let state = client
            .mutations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(state.pending.is_empty());
        assert_eq!(state.retained_bytes, 0);
    }

    #[tokio::test]
    async fn mutation_and_transaction_identity_exhaustion_fail_closed() {
        let client = Client::new(
            Arc::new(RwLock::new(None)),
            FRAME_TEST_LIMITS,
            Duration::from_secs(1),
            Duration::from_secs(1),
            false,
        );
        let options = OperationOptions::new()
            .with_deadline(std::time::Instant::now() + Duration::from_secs(1));
        client.next_transaction.store(u64::MAX, Ordering::Relaxed);
        assert_eq!(
            client.admit_mutation(0, &options).await,
            Err(Error::LimitExceeded)
        );
        assert!(
            client
                .mutations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pending
                .is_empty()
        );

        client.next_transaction.store(1, Ordering::Relaxed);
        client
            .mutations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .next_sequence = u64::MAX;
        assert_eq!(
            client.admit_mutation(0, &options).await,
            Err(Error::LimitExceeded)
        );
    }

    #[test]
    fn loom_completion_and_unknown_watermark_are_atomic() {
        loom::model(|| {
            use loom::sync::{Arc as LoomArc, Mutex as LoomMutex};
            use loom::thread;

            let state = LoomArc::new(LoomMutex::new(MutationState {
                next_sequence: 2,
                pending: HashMap::from([(1, 3), (2, 5)]),
                retained_bytes: 8,
                ..MutationState::default()
            }));
            let first = LoomArc::clone(&state);
            let first_owner = thread::spawn(move || {
                let mut state = first.lock().expect("first lock");
                assert!(complete_mutation_state(
                    &mut state,
                    1,
                    Some(&Error::OutcomeUnknown(UnknownCause::Transport))
                ));
            });
            let second = LoomArc::clone(&state);
            let second_owner = thread::spawn(move || {
                assert!(complete_mutation_state(
                    &mut second.lock().expect("second lock"),
                    2,
                    None
                ));
            });
            first_owner.join().expect("first completion");
            second_owner.join().expect("second completion");
            let state = state.lock().expect("flush lock");
            assert!(state.pending.is_empty());
            assert_eq!(state.retained_bytes, 0);
            assert_eq!(state.earliest_unknown, Some(1));
        });
    }

    #[test]
    fn loom_shutdown_and_admission_are_serialized() {
        loom::model(|| {
            use loom::sync::{Arc as LoomArc, Mutex as LoomMutex};
            use loom::thread;

            let state = LoomArc::new(LoomMutex::new(MutationState::default()));
            let admission_state = LoomArc::clone(&state);
            let admission = thread::spawn(move || {
                admit_mutation_state(&mut admission_state.lock().expect("admission lock"), 3)
            });
            let shutdown_state = LoomArc::clone(&state);
            let shutdown = thread::spawn(move || {
                close_mutation_admission_state(&mut shutdown_state.lock().expect("shutdown lock"));
            });
            let admitted = admission.join().expect("admission transition");
            shutdown.join().expect("shutdown transition");
            let state = state.lock().expect("final lock");
            assert!(state.admission_closed);
            match admitted {
                Ok(Some(sequence)) => {
                    assert_eq!(state.pending.get(&sequence), Some(&3));
                    assert_eq!(state.retained_bytes, 3);
                }
                Err(Error::Closed) => {
                    assert!(state.pending.is_empty());
                    assert_eq!(state.retained_bytes, 0);
                }
                result => panic!("unexpected admission result: {result:?}"),
            }
        });
    }

    #[test]
    fn acknowledgment_cannot_masquerade_as_durable_commit() {
        let reply = Reply {
            object: b"object".to_vec(),
            pg: PG {
                pool: 1,
                seed: 2,
                preferred: -1,
            },
            flags: i64::from(super::super::messages::FLAG_ACK),
            result: 0,
            map_epoch: 1,
            retry: 0,
            version: 7,
            redirect: None,
            operations: Vec::new(),
        };
        assert_eq!(
            validate_durable_reply(&reply),
            Err(Error::OutcomeUnknown(UnknownCause::Transport))
        );
    }
}
