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
use crate::wire::WireError;
use tokio::sync::{Mutex as AsyncMutex, broadcast, oneshot, watch};
use tokio::task::JoinHandle;

use super::backoff::{
    BACKOFF_BLOCK, BACKOFF_UNBLOCK, Backoff, HObject, MESSAGE_OSD_BACKOFF, decode_backoff,
    encode_acknowledgment,
};
use super::command::{CommandRequest, decode_command_reply, encode_command_request};
use super::inconsistent::{self, InconsistentObject};
use super::messages::{
    FLAG_IGNORE_CACHE, FLAG_IGNORE_OVERLAY, FLAG_ON_DISK, FLAG_PG_OP, FLAG_REDIRECTED, FLAG_RETRY,
    FLAG_RETURN_VECTOR, Limits, OP_FLAG_FAIL_OK, Operation, OperationResult, Reply, Request,
    decode_reply, encode_request,
};
use super::watch::{MESSAGE_WATCH_NOTIFY, Notification, decode_notification};

const ENTITY_OSD: u8 = 4;
const MAX_ATTEMPTS: usize = 4;
const MAX_RETIRED_SESSIONS: usize = 16;
const CANCELLATION_POLL: Duration = Duration::from_millis(10);
const TRANSIENT_REFRESH_WAIT: Duration = Duration::from_secs(2);
const READ_REPLY_FRONT_BYTES: u64 = 144;
const MAX_MUTATIONS: usize = 64;
const MAX_MUTATION_BYTES: u64 = 64 * 32 * 1024 * 1024;
const MAX_NOTIFICATION_QUEUE: usize = 65_536;
const SCRUB_PAGE_SIZE: u64 = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Target {
    pub(crate) pool_id: i64,
    pub(crate) object: Vec<u8>,
    pub(crate) locator: Vec<u8>,
    pub(crate) namespace: Vec<u8>,
    pub(crate) snapshot: u64,
    pub(crate) snapshot_sequence: u64,
    pub(crate) write_snapshots: Vec<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReadResult {
    pub(crate) data: Vec<u8>,
    pub(crate) version: u64,
}

pub(crate) type MutationResult = ReadResult;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CommandResult {
    pub(crate) result: i32,
    pub(crate) status: String,
    pub(crate) output: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompoundResult {
    pub(crate) operations: Vec<OperationResult>,
    pub(crate) version: u64,
}

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
    StaleMap,
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
    notifications: broadcast::Sender<Notification>,
    watch_stop: watch::Sender<bool>,
    watch_workers: Mutex<Vec<JoinHandle<()>>>,
    incarnation: AtomicI32,
    closed: AtomicBool,
    frame_limits: FrameLimits,
    message_limits: Limits,
    dial_timeout: Duration,
    handshake_timeout: Duration,
    allow_crc: bool,
    address_nonce: u32,
}

impl Client {
    pub(crate) fn new(
        authority: Arc<RwLock<Option<Arc<MonitorConnector>>>>,
        frame_limits: FrameLimits,
        dial_timeout: Duration,
        handshake_timeout: Duration,
        allow_crc: bool,
        address_nonce: u32,
    ) -> Self {
        let (mutation_changed, _) = watch::channel(0);
        let (notifications, _) = broadcast::channel(MAX_NOTIFICATION_QUEUE);
        let (watch_stop, _) = watch::channel(false);
        Self {
            authority,
            sessions: Mutex::new(HashMap::new()),
            retired: Mutex::new(Vec::new()),
            next_transaction: AtomicU64::new(1),
            mutations: Mutex::new(MutationState::default()),
            mutation_changed,
            notifications,
            watch_stop,
            watch_workers: Mutex::new(Vec::new()),
            incarnation: AtomicI32::new(0),
            closed: AtomicBool::new(false),
            frame_limits,
            message_limits: Limits {
                max_bytes: u32::try_from(frame_limits.max_frame_bytes).unwrap_or(u32::MAX),
                max_operations: 16,
            },
            dial_timeout,
            handshake_timeout,
            allow_crc,
            address_nonce,
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

    pub(crate) async fn pgnls(
        &self,
        monitor: &MonitorClient,
        pool_id: i64,
        namespace: Vec<u8>,
        cursor: &HObject,
        count: u64,
        options: &OperationOptions,
    ) -> Result<super::enumeration::ListPage, Error> {
        let state = monitor.snapshot();
        let map = state.osdmap().ok_or(Error::NotConnected)?;
        let operation = super::enumeration::encode_operation(
            cursor,
            count,
            map.epoch(),
            self.message_limits.max_bytes as usize,
        )
        .map_err(|error| map_message_error(error.into()))?;
        let result = self
            .execute_operations(
                monitor,
                Target {
                    pool_id,
                    object: Vec::new(),
                    locator: Vec::new(),
                    namespace,
                    snapshot: super::messages::NO_SNAP,
                    snapshot_sequence: 0,
                    write_snapshots: Vec::new(),
                },
                vec![operation],
                options,
            )
            .await?;
        let data = result
            .operations
            .into_iter()
            .next()
            .ok_or(Error::MalformedReply)?
            .data;
        super::enumeration::decode_page(
            &data,
            self.message_limits.max_bytes as usize,
            self.message_limits.max_bytes as usize / 12,
        )
        .map_err(|error| map_message_error(error.into()))
    }

    pub(crate) async fn list_inconsistent_objects(
        &self,
        monitor: &MonitorClient,
        pg: PG,
        options: &OperationOptions,
    ) -> Result<Vec<InconsistentObject>, Error> {
        let maximum = u64::from(self.message_limits.max_bytes / 12);
        if maximum == 0 {
            return Err(Error::LimitExceeded);
        }
        let max_entries = u32::try_from(maximum.min(u64::from(u32::MAX))).unwrap_or(u32::MAX);
        let mut pager = InconsistentPager::new(maximum);
        loop {
            let operation = inconsistent::encode_scrub_list(
                pager.interval,
                &pager.start,
                SCRUB_PAGE_SIZE,
                self.message_limits.max_bytes,
            )
            .map_err(map_wire_error)?;
            let result = self
                .execute_pg_routed(monitor, pg, vec![operation], options)
                .await?;
            let data = result
                .operations
                .into_iter()
                .next()
                .ok_or(Error::MalformedReply)?
                .data;
            let (next_interval, page) =
                inconsistent::decode_scrub_list(&data, self.message_limits.max_bytes, max_entries)
                    .map_err(map_wire_error)?;
            if pager.push(next_interval, page)? {
                return Ok(pager.result);
            }
        }
    }

    pub(crate) async fn mutate(
        self: &Arc<Self>,
        monitor: Arc<MonitorClient>,
        target: Target,
        mutation: Mutation<'_>,
        options: OperationOptions,
    ) -> Result<MutationResult, Error> {
        let result = self
            .mutate_operations(monitor, target, vec![mutation.into_owned()], options)
            .await?;
        let operation = result
            .operations
            .into_iter()
            .next()
            .ok_or(Error::MalformedReply)?;
        Ok(ReadResult {
            data: operation.data,
            version: result.version,
        })
    }

    pub(crate) async fn osd_command(
        &self,
        monitor: &MonitorClient,
        osd: i32,
        command: Vec<String>,
        input: Vec<u8>,
        options: &OperationOptions,
    ) -> Result<(CommandResult, Option<Error>), Error> {
        self.submit_command(monitor, CommandTarget::Osd(osd), command, input, options)
            .await
    }

    pub(crate) async fn pg_command(
        &self,
        monitor: &MonitorClient,
        pg: PG,
        command: Vec<String>,
        input: Vec<u8>,
        options: &OperationOptions,
    ) -> Result<(CommandResult, Option<Error>), Error> {
        self.submit_command(monitor, CommandTarget::PG(pg), command, input, options)
            .await
    }

    async fn submit_command(
        &self,
        monitor: &MonitorClient,
        target: CommandTarget,
        command: Vec<String>,
        input: Vec<u8>,
        options: &OperationOptions,
    ) -> Result<(CommandResult, Option<Error>), Error> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        if command.is_empty() {
            return Err(Error::LimitExceeded);
        }
        let transaction_id = self.take_transaction_id()?;
        let fsid = monitor
            .snapshot()
            .osdmap()
            .map_or(crate::maps::Fsid::default(), |map| map.fsid());
        for _attempt in 0..MAX_ATTEMPTS {
            if self.closed.load(Ordering::Acquire) {
                return Err(Error::Closed);
            }
            check_options(options)?;
            let state = monitor.snapshot();
            let map = state.osdmap().ok_or(Error::NotConnected)?;
            let route = resolve_command_route(&map, target)?;
            let message = encode_command_request(
                &CommandRequest {
                    fsid,
                    transaction_id,
                    command: &command,
                    input: &input,
                },
                self.message_limits.max_bytes,
            )
            .map_err(map_command_message_error)?;
            let session = self.session(route.primary, &route.addresses)?;
            let reply = match session.submit_direct(message, options).await {
                Ok(reply) => reply,
                Err(Error::QueueSaturated) => return Err(Error::QueueSaturated),
                Err(Error::OutcomeUnknown(cause)) => return Err(Error::OutcomeUnknown(cause)),
                Err(error) => {
                    self.invalidate(route.primary, &session);
                    if matches!(error, Error::Timeout | Error::Cancelled) {
                        return Err(error);
                    }
                    best_effort_refresh_map(monitor, route.epoch, options).await?;
                    continue;
                }
            };
            let reply = decode_command_reply(&reply, self.message_limits.max_bytes)
                .map_err(map_command_message_error);
            let Ok(reply) = reply else {
                self.invalidate(route.primary, &session);
                return Err(Error::MalformedReply);
            };
            if reply.transaction_id != transaction_id {
                self.invalidate(route.primary, &session);
                return Err(Error::MalformedReply);
            }
            let result = CommandResult {
                result: reply.result,
                status: reply.status,
                output: reply.output,
            };
            if result.result == -11 {
                best_effort_refresh_map(monitor, route.epoch, options).await?;
                continue;
            }
            if result.result < 0 {
                return Ok((result.clone(), Some(Error::WireErrno(result.result))));
            }
            return Ok((result, None));
        }
        Err(Error::RecoveryExhausted)
    }

    pub(crate) async fn mutate_operations(
        self: &Arc<Self>,
        monitor: Arc<MonitorClient>,
        target: Target,
        operations: Vec<Operation>,
        options: OperationOptions,
    ) -> Result<CompoundResult, Error> {
        if target.snapshot != super::messages::NO_SNAP
            || operations.is_empty()
            || operations.len() > self.message_limits.max_operations as usize
            || !contains_outcome_sensitive(&operations)
        {
            return Err(Error::LimitExceeded);
        }
        let retained = operations.iter().try_fold(0_u64, |total, operation| {
            total
                .checked_add(u64::try_from(operation.data_len()).map_err(|_| Error::LimitExceeded)?)
                .ok_or(Error::LimitExceeded)
        })?;
        if retained > u64::from(self.message_limits.max_bytes) {
            return Err(Error::LimitExceeded);
        }
        let (sequence, transaction_id) = self.admit_mutation(retained, &options).await?;
        let (result_tx, result_rx) = oneshot::channel();
        let client = Arc::clone(self);
        tokio::spawn(async move {
            let mut completion = MutationCompletion {
                client: Arc::clone(&client),
                sequence: Some(sequence),
            };
            let result = client
                .execute_mutation(&monitor, target, operations, transaction_id, &options)
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

    pub(crate) fn notifications(&self) -> broadcast::Receiver<Notification> {
        self.notifications.subscribe()
    }

    pub(crate) fn watch_stop(&self) -> watch::Receiver<bool> {
        self.watch_stop.subscribe()
    }

    pub(crate) fn track_watch_worker(&self, worker: JoinHandle<()>) -> Result<(), JoinHandle<()>> {
        let mut workers = self
            .watch_workers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.closed.load(Ordering::Acquire) {
            return Err(worker);
        }
        workers.retain(|worker| !worker.is_finished());
        workers.push(worker);
        Ok(())
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
        let result = self
            .execute_operations(monitor, target, vec![operation], options)
            .await?;
        let operation = result
            .operations
            .into_iter()
            .next()
            .ok_or(Error::MalformedReply)?;
        Ok(ReadResult {
            data: operation.data,
            version: result.version,
        })
    }

    pub(crate) async fn execute_operations(
        &self,
        monitor: &MonitorClient,
        target: Target,
        operations: Vec<Operation>,
        options: &OperationOptions,
    ) -> Result<CompoundResult, Error> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        if operations.is_empty() || operations.len() > self.message_limits.max_operations as usize {
            return Err(Error::LimitExceeded);
        }
        let transaction_id = self.take_transaction_id()?;
        self.execute_routed(monitor, target, operations, transaction_id, false, options)
            .await
    }

    async fn execute_mutation(
        &self,
        monitor: &MonitorClient,
        target: Target,
        operations: Vec<Operation>,
        transaction_id: u64,
        options: &OperationOptions,
    ) -> Result<CompoundResult, Error> {
        self.execute_routed(monitor, target, operations, transaction_id, true, options)
            .await
    }

    #[allow(clippy::too_many_lines)]
    async fn execute_routed(
        &self,
        monitor: &MonitorClient,
        mut target: Target,
        operations: Vec<Operation>,
        mut transaction_id: u64,
        mutation: bool,
        options: &OperationOptions,
    ) -> Result<CompoundResult, Error> {
        if !mutation {
            target.snapshot_sequence = 0;
            target.write_snapshots.clear();
        }
        let client_incarnation = self.client_incarnation()?;
        let retry_unknown = operations.iter().all(allows_unknown_retry);
        let durable = contains_durable_mutation(&operations);
        let route_hash = operations.first().and_then(Operation::route_hash);
        if operations
            .iter()
            .skip(1)
            .any(|operation| operation.route_hash() != route_hash)
        {
            return Err(Error::LimitExceeded);
        }
        let mut flags = if route_hash.is_some() {
            FLAG_PG_OP | FLAG_IGNORE_OVERLAY
        } else {
            0
        };
        if operations.len() > 1 {
            flags |= FLAG_RETURN_VECTOR;
        }
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
            let placement = route_hash
                .map_or_else(
                    || {
                        map.place_object(
                            target.pool_id,
                            &target.object,
                            &target.locator,
                            &target.namespace,
                        )
                    },
                    |hash| map.place_raw_hash(target.pool_id, hash),
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
                    snapshot_sequence: target.snapshot_sequence,
                    write_snapshots: &target.write_snapshots,
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
                hash: route_hash.unwrap_or(placement.raw_hash),
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
                        if retry_unknown
                            && wait_for_primary_change(
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
                best_effort_refresh_map(monitor, map.epoch(), options).await?;
                continue;
            }
            if validate_operations(&reply, &operations).is_err() {
                self.invalidate(placement.acting_primary, &session);
                return Err(if mutation {
                    Error::OutcomeUnknown(UnknownCause::Transport)
                } else {
                    Error::MalformedReply
                });
            }
            if reply
                .operations
                .iter()
                .any(|operation| operation.code == -11)
            {
                best_effort_refresh_map(monitor, map.epoch(), options).await?;
                continue;
            }
            if durable && validate_durable_reply(&reply).is_err() {
                self.invalidate(placement.acting_primary, &session);
                return Err(Error::OutcomeUnknown(UnknownCause::Transport));
            }
            if reply.result < 0 {
                return Err(Error::WireErrno(reply.result));
            }
            for (operation, operation_reply) in operations.iter().zip(&reply.operations) {
                if operation_reply.code < 0 && operation.flags() & OP_FLAG_FAIL_OK == 0 {
                    return Err(Error::WireErrno(operation_reply.code));
                }
            }
            return Ok(CompoundResult {
                operations: reply.operations,
                version: reply.version,
            });
        }
        Err(preserve_unknown(Error::RecoveryExhausted, prior_unknown))
    }

    #[allow(clippy::too_many_lines)]
    async fn execute_pg_routed(
        &self,
        monitor: &MonitorClient,
        pg: PG,
        operations: Vec<Operation>,
        options: &OperationOptions,
    ) -> Result<CompoundResult, Error> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        if operations.is_empty() || operations.len() > self.message_limits.max_operations as usize {
            return Err(Error::LimitExceeded);
        }
        let pool_id = i64::try_from(pg.pool).map_err(|_| Error::LimitExceeded)?;
        let transaction_id = self.take_transaction_id()?;
        let client_incarnation = self.client_incarnation()?;
        let retry_unknown = operations.iter().all(allows_unknown_retry);
        let mut flags = FLAG_PG_OP;
        if operations.len() > 1 {
            flags |= FLAG_RETURN_VECTOR;
        }
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
            if map.pool_by_id(pool_id).is_none() {
                return Err(preserve_unknown(Error::WireErrno(-2), prior_unknown));
            }
            let placement = map
                .place_raw_hash(pool_id, pg.seed)
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
            let message = encode_request(
                &Request {
                    map_epoch: map.epoch(),
                    pg: placement.pg,
                    shard: placement.primary_shard,
                    sharded: placement.sharded,
                    object_hash: placement.raw_hash,
                    pool_id,
                    object: &[],
                    locator: &[],
                    namespace: &[],
                    snapshot: super::messages::NO_SNAP,
                    snapshot_sequence: 0,
                    write_snapshots: &[],
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
                key: Vec::new(),
                object: Vec::new(),
                snapshot: super::messages::NO_SNAP,
                hash: placement.raw_hash,
                max: false,
                namespace: Vec::new(),
                pool: pool_id,
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
                .submit(placement.pg, &object, message, false, &attempt_options)
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
                        if retry_unknown
                            && wait_for_pg_primary_change(
                                monitor,
                                pg,
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
                return Err(Error::MalformedReply);
            };
            if validate_target(&reply, &[], placement.pg, attempt).is_err() {
                self.invalidate(placement.acting_primary, &session);
                return Err(Error::MalformedReply);
            }
            prior_unknown = None;
            if reply.redirect.is_some() {
                flags |= FLAG_REDIRECTED | FLAG_IGNORE_CACHE | FLAG_IGNORE_OVERLAY;
                continue;
            }
            if reply.result == -11 {
                best_effort_refresh_map(monitor, map.epoch(), options).await?;
                continue;
            }
            if validate_operations(&reply, &operations).is_err() {
                self.invalidate(placement.acting_primary, &session);
                return Err(Error::MalformedReply);
            }
            if reply
                .operations
                .iter()
                .any(|operation| operation.code == -11)
            {
                best_effort_refresh_map(monitor, map.epoch(), options).await?;
                continue;
            }
            if reply.result < 0 {
                return Err(Error::WireErrno(reply.result));
            }
            for (operation, operation_reply) in operations.iter().zip(&reply.operations) {
                if operation_reply.code < 0 && operation.flags() & OP_FLAG_FAIL_OK == 0 {
                    return Err(Error::WireErrno(operation_reply.code));
                }
            }
            return Ok(CompoundResult {
                operations: reply.operations,
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
                .map_err(|_| Error::NotConnected)?
                .with_nonce(self.address_nonce);
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
            self.notifications.clone(),
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
        self.watch_stop.send_replace(true);
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
            || !self
                .watch_workers
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
        let workers = std::mem::take(
            &mut *self
                .watch_workers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for worker in workers {
            let _ = worker.await;
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
    fn spawn(
        raw: Arc<Session>,
        notifications: broadcast::Sender<Notification>,
        limits: Limits,
        ack_timeout: Duration,
    ) -> Arc<Self> {
        let state = Arc::new(AsyncMutex::new(OSDSessionState::default()));
        let (changed, _) = watch::channel(0);
        let session = Arc::new(Self {
            raw: Arc::clone(&raw),
            state: Arc::clone(&state),
            changed: changed.clone(),
            owner: AsyncMutex::new(None),
            limits,
        });
        let owner = tokio::spawn(run_incoming(
            raw,
            state,
            changed,
            notifications,
            limits,
            ack_timeout,
        ));
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
            let result = wait_for_request(&mut request, options, mutation).await;
            if result.is_err() && self.state.lock().await.failure == Some(Error::StaleMap) {
                return Err(Error::StaleMap);
            }
            return result;
        }
    }

    async fn submit_direct(
        &self,
        message: Message,
        options: &OperationOptions,
    ) -> Result<Message, Error> {
        #[cfg(test)]
        {
            if let Some(hook) = SUBMIT_DIRECT_HOOK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .cloned()
            {
                return hook(message);
            }
        }
        let state = self.state.lock().await;
        if let Some(error) = state.failure {
            return Err(error);
        }
        let admission = admit_with_cancellation(&self.raw, message, options, false).await?;
        let AdmissionOutcome::Request(mut request) = admission else {
            let AdmissionOutcome::Reply(reply) = admission else {
                unreachable!()
            };
            return Ok(reply);
        };
        request.cancel_on_drop();
        drop(state);
        let result = wait_for_request(&mut request, options, false).await;
        if result.is_err() && self.state.lock().await.failure == Some(Error::StaleMap) {
            return Err(Error::StaleMap);
        }
        result
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
    notifications: broadcast::Sender<Notification>,
    limits: Limits,
    ack_timeout: Duration,
) {
    while let Some(message) = raw.next_incoming().await {
        if message.header.message_type == 41 {
            fail_session(&raw, &state, &changed, &notifications, Error::StaleMap).await;
            return;
        }
        if message.header.message_type == MESSAGE_WATCH_NOTIFY {
            let Ok(notification) = decode_notification(&message, limits.max_bytes as usize) else {
                fail_session(
                    &raw,
                    &state,
                    &changed,
                    &notifications,
                    Error::MalformedReply,
                )
                .await;
                return;
            };
            let _ = notifications.send(notification);
            continue;
        }
        if message.header.message_type != MESSAGE_OSD_BACKOFF {
            continue;
        }
        let Ok(backoff) = decode_backoff(&message, limits) else {
            fail_session(
                &raw,
                &state,
                &changed,
                &notifications,
                Error::MalformedReply,
            )
            .await;
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
                fail_session(
                    &raw,
                    &state,
                    &changed,
                    &notifications,
                    Error::MalformedReply,
                )
                .await;
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
                fail_session(&raw, &state, &changed, &notifications, Error::NotConnected).await;
                return;
            }
        }
    }
    fail_session(&raw, &state, &changed, &notifications, Error::NotConnected).await;
}

async fn fail_session(
    raw: &Session,
    state: &AsyncMutex<OSDSessionState>,
    changed: &watch::Sender<u64>,
    notifications: &broadcast::Sender<Notification>,
    error: Error,
) {
    let first_failure = {
        let mut state = state.lock().await;
        if state.failure.is_some() {
            false
        } else {
            state.failure = Some(error);
            true
        }
    };
    if first_failure {
        let _ = notifications.send(Notification {
            cookie: 0,
            version: 0,
            notify_id: 0,
            opcode: super::watch::EVENT_DISCONNECT,
            data: Vec::new(),
            result: 0,
            notifier: 0,
        });
    }
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
                return match result {
                    Ok(Some(reply)) => Ok(reply),
                    Ok(None) => Err(Error::MalformedReply),
                    Err(error) => Err(map_request_error(error, mutation)),
                };
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
    let refresh = monitor.refresh_osdmap(epoch, options);
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

fn contains_outcome_sensitive(operations: &[Operation]) -> bool {
    operations.iter().any(|operation| match operation {
        Operation::Notify { .. } | Operation::NotifyAck { .. } => true,
        Operation::WithFlags { operation, .. } => {
            contains_outcome_sensitive(std::slice::from_ref(operation))
        }
        _ => operation.is_mutation(),
    })
}

fn contains_durable_mutation(operations: &[Operation]) -> bool {
    operations.iter().any(Operation::is_mutation)
}

fn allows_unknown_retry(operation: &Operation) -> bool {
    match operation {
        Operation::Call { .. } | Operation::Notify { .. } | Operation::NotifyAck { .. } => false,
        Operation::WithFlags { operation, .. } => allows_unknown_retry(operation),
        _ => true,
    }
}

async fn wait_for_pg_primary_change(
    monitor: &MonitorClient,
    pg: PG,
    previous_primary: i32,
    mut epoch: u32,
    options: &OperationOptions,
) -> bool {
    let Ok(pool_id) = i64::try_from(pg.pool) else {
        return false;
    };
    for _ in 0..MAX_ATTEMPTS {
        if check_options(options).is_err() {
            return false;
        }
        let snapshot = monitor.snapshot();
        let Some(map) = snapshot.osdmap() else {
            return false;
        };
        if let Ok(placement) = map.place_raw_hash(pool_id, pg.seed)
            && placement.acting_primary != previous_primary
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

fn validate_operations(reply: &Reply, operations: &[Operation]) -> Result<(), Error> {
    if reply.operations.len() != operations.len() {
        return Err(Error::MalformedReply);
    }
    for (reply, operation) in reply.operations.iter().zip(operations) {
        if reply.operation != operation.code() {
            return Err(Error::MalformedReply);
        }
        if let Operation::Read { length, .. } = operation
            && reply.data.len() as u64 > *length
        {
            return Err(Error::MalformedReply);
        }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandTarget {
    Osd(i32),
    PG(PG),
}

#[derive(Clone, Debug)]
struct CommandRoute {
    epoch: u32,
    primary: i32,
    addresses: EntityAddrVec,
}

#[cfg(test)]
type CommandRouteHook = Arc<dyn Fn(CommandTarget) -> Result<CommandRoute, Error> + Send + Sync>;

#[cfg(test)]
static COMMAND_ROUTE_HOOK: Mutex<Option<CommandRouteHook>> = Mutex::new(None);

#[cfg(test)]
type SubmitDirectHook = Arc<dyn Fn(Message) -> Result<Message, Error> + Send + Sync>;

#[cfg(test)]
static SUBMIT_DIRECT_HOOK: Mutex<Option<SubmitDirectHook>> = Mutex::new(None);

#[cfg(test)]
fn set_command_route_hook(hook: Option<CommandRouteHook>) {
    *COMMAND_ROUTE_HOOK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
}

#[cfg(test)]
fn set_submit_direct_hook(hook: Option<SubmitDirectHook>) {
    *SUBMIT_DIRECT_HOOK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
}

struct InconsistentPager {
    interval: u32,
    start: InconsistentObject,
    maximum: u64,
    result: Vec<InconsistentObject>,
}

impl InconsistentPager {
    fn new(maximum: u64) -> Self {
        Self {
            interval: 0,
            start: InconsistentObject::default(),
            maximum,
            result: Vec::new(),
        }
    }

    fn push(&mut self, next_interval: u32, page: Vec<InconsistentObject>) -> Result<bool, Error> {
        if self.interval != 0 && self.interval != next_interval {
            return Err(Error::WireErrno(-11));
        }
        self.interval = next_interval;
        let page_len = u64::try_from(page.len()).map_err(|_| Error::LimitExceeded)?;
        if u64::try_from(self.result.len())
            .map_err(|_| Error::LimitExceeded)?
            .saturating_add(page_len)
            > self.maximum
        {
            return Err(Error::LimitExceeded);
        }
        let next = page.last().cloned();
        self.result.extend(page);
        if page_len < SCRUB_PAGE_SIZE {
            return Ok(true);
        }
        let Some(next) = next else {
            return Err(Error::MalformedReply);
        };
        if next.object == self.start.object
            && next.namespace == self.start.namespace
            && next.locator == self.start.locator
            && next.snapshot == self.start.snapshot
        {
            return Err(Error::MalformedReply);
        }
        self.start = next;
        Ok(false)
    }
}

fn resolve_command_route(
    map: &crate::maps::OSDMap,
    target: CommandTarget,
) -> Result<CommandRoute, Error> {
    #[cfg(test)]
    {
        if let Some(hook) = COMMAND_ROUTE_HOOK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .cloned()
        {
            return hook(target);
        }
    }
    match target {
        CommandTarget::Osd(id) => {
            let addresses = map.osd_client_addresses(id).ok_or(Error::NoPrimary)?;
            Ok(CommandRoute {
                epoch: map.epoch(),
                primary: id,
                addresses: addresses.clone(),
            })
        }
        CommandTarget::PG(pg) => {
            if i64::try_from(pg.pool)
                .ok()
                .and_then(|pool| map.pool_by_id(pool))
                .is_none()
            {
                return Err(Error::WireErrno(-2));
            }
            let placement = map
                .place_raw_hash(
                    i64::try_from(pg.pool).map_err(|_| Error::LimitExceeded)?,
                    pg.seed,
                )
                .map_err(|_| Error::NoPrimary)?;
            if placement.acting_primary < 0 {
                return Err(Error::NoPrimary);
            }
            let addresses = map
                .osd_client_addresses(placement.acting_primary)
                .ok_or(Error::NoPrimary)?;
            Ok(CommandRoute {
                epoch: map.epoch(),
                primary: placement.acting_primary,
                addresses: addresses.clone(),
            })
        }
    }
}

const fn map_command_message_error(error: super::command::Error) -> Error {
    match error {
        super::command::Error::Wire(WireError::LimitExceeded) => Error::LimitExceeded,
        super::command::Error::Wire(WireError::Malformed)
        | super::command::Error::MalformedReply => Error::MalformedReply,
        super::command::Error::Wire(WireError::UnsupportedVersion { .. })
        | super::command::Error::UnsupportedVersion => Error::Unsupported,
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

const fn map_wire_error(error: WireError) -> Error {
    match error {
        WireError::LimitExceeded => Error::LimitExceeded,
        WireError::Malformed => Error::MalformedReply,
        WireError::UnsupportedVersion { .. } => Error::Unsupported,
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use tokio::io::{AsyncWriteExt, DuplexStream, duplex};
    use tokio::sync::{Notify, mpsc};

    use super::*;
    use crate::cephx::connector::Config as ConnectorConfig;
    use crate::cephx::core::{SERVICE_AUTH, TicketBlob};
    use crate::cephx::crypto::Limits as CephxLimits;
    use crate::maps::Limits as MapLimits;
    use crate::mon::client::{
        MonitorConfig, MonitorError, MonitorSession, OpenedMonitorSession, SessionFactory,
    };
    use crate::mon::messages::{
        MESSAGE_MON_MAP, MESSAGE_MON_SUBSCRIBE_ACK, MESSAGE_OSD_MAP, MessageLimits,
    };
    use crate::mon::seeds::Endpoint;
    use crate::msgr::frame::{CrcCodec, Tag};
    use crate::msgr::message::{MessageHeader, MessageLengths};
    use crate::msgr::supervisor::ConnectionSetup;
    use crate::msgr::transport::Codec;
    use crate::osd::backoff::encode_for_test;

    static COMMAND_HOOK_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    use crate::wire::Encoder;

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

    const TEST_COMMAND_REPLY: u16 = 98;
    const TEST_KEY: &str = "AQB7AAAAyAEAABAAMTIzNDU2Nzg5MDEyMzQ1Ng==";

    type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

    struct FakeMonitorSession {
        sent: mpsc::Sender<Message>,
        incoming: AsyncMutex<mpsc::Receiver<Message>>,
        failure: AsyncMutex<mpsc::Receiver<SessionError>>,
        closed: AtomicBool,
        closed_notify: Notify,
    }

    impl MonitorSession for FakeMonitorSession {
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

    struct FakeMonitorHandle {
        incoming: mpsc::Sender<Message>,
        _failure: mpsc::Sender<SessionError>,
        sent: AsyncMutex<mpsc::Receiver<Message>>,
    }

    fn fake_monitor_session() -> (OpenedMonitorSession, Arc<FakeMonitorHandle>) {
        let (sent_tx, sent_rx) = mpsc::channel(16);
        let (incoming_tx, incoming_rx) = mpsc::channel(16);
        let (failure_tx, failure_rx) = mpsc::channel(2);
        let session = Arc::new(FakeMonitorSession {
            sent: sent_tx,
            incoming: AsyncMutex::new(incoming_rx),
            failure: AsyncMutex::new(failure_rx),
            closed: AtomicBool::new(false),
            closed_notify: Notify::new(),
        });
        let handle = Arc::new(FakeMonitorHandle {
            incoming: incoming_tx,
            _failure: failure_tx,
            sent: AsyncMutex::new(sent_rx),
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

    fn map_limits() -> MapLimits {
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

    fn endpoint(octet: u8) -> Endpoint {
        let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, octet), 3300));
        Endpoint {
            address,
            entity_address: EntityAddr::ipv4_v2(address).expect("test endpoint"),
            priority: 0,
            weight: 0,
        }
    }

    fn monitor_config() -> MonitorConfig {
        MonitorConfig {
            seeds: vec![endpoint(1), endpoint(2)],
            expected_fsid: None,
            hostname: "test-host".to_owned(),
            map_limits: map_limits(),
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

    fn ack(fsid: crate::maps::Fsid) -> Message {
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
        fsid: crate::maps::Fsid,
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
            encoder.finish().expect("osdmap message"),
        )
    }

    fn command_reply_message(
        transaction_id: u64,
        result: i32,
        status: &str,
        output: &[u8],
    ) -> Message {
        let mut encoder = Encoder::new(256 + status.len());
        encoder.i32(result);
        encoder.string(status);
        let front = encoder.finish().expect("command reply front");
        Message {
            header: MessageHeader {
                transaction_id,
                message_type: TEST_COMMAND_REPLY,
                version: 1,
                compat_version: 1,
                ..MessageHeader::default()
            },
            lengths: MessageLengths {
                front: u32::try_from(front.len()).expect("front length"),
                data: u32::try_from(output.len()).expect("data length"),
                ..MessageLengths::default()
            },
            front,
            data: output.to_vec(),
            ..Message::default()
        }
    }

    fn test_authority() -> Arc<MonitorConnector> {
        let credential = crate::cephx::parse_key("client.test", TEST_KEY, 64).expect("credential");
        let address = address();
        Arc::new(
            MonitorConnector::new(ConnectorConfig {
                credential,
                target_address: address,
                message_limits: FRAME_TEST_LIMITS,
                cephx_limits: CephxLimits::default(),
                handshake_timeout: Duration::from_secs(1),
                max_banner_payload: 64,
                requested_keys: SERVICE_AUTH,
                allow_crc: true,
                global_id: 0,
                old_ticket: TicketBlob {
                    secret_id: 0,
                    blob: Vec::new(),
                },
                now: Arc::new(|| Duration::from_secs(0)),
                challenge: Arc::new(|| Ok(0x0102_0304_0506_0708)),
            })
            .expect("authority"),
        )
    }

    fn install_session(
        client: &Client,
        authority: &Arc<MonitorConnector>,
        osd: i32,
        addresses: &EntityAddrVec,
        session: Arc<OSDSession>,
    ) {
        let endpoint = addresses
            .0
            .iter()
            .find_map(|address| address.endpoint().filter(|value| value.port() != 0))
            .expect("routable endpoint");
        client
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                osd,
                SessionEntry {
                    endpoint,
                    authority: Arc::clone(authority),
                    session,
                },
            );
    }

    fn routable_addresses(port: u16) -> EntityAddrVec {
        EntityAddrVec(vec![
            EntityAddr::ipv4_v2(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))
                .expect("routable test address"),
        ])
    }

    struct CommandRouteHookGuard;

    impl CommandRouteHookGuard {
        fn install(hook: CommandRouteHook) -> Self {
            set_command_route_hook(Some(hook));
            Self
        }
    }

    impl Drop for CommandRouteHookGuard {
        fn drop(&mut self) {
            set_command_route_hook(None);
        }
    }

    struct SubmitDirectHookGuard;

    impl SubmitDirectHookGuard {
        fn install(hook: SubmitDirectHook) -> Self {
            set_submit_direct_hook(Some(hook));
            Self
        }
    }

    impl Drop for SubmitDirectHookGuard {
        fn drop(&mut self) {
            set_submit_direct_hook(None);
        }
    }

    async fn start_monitor_with_fixture_map() -> (
        Arc<MonitorClient>,
        Arc<FakeMonitorHandle>,
        crate::maps::OSDMap,
        Vec<u8>,
        Vec<u8>,
    ) {
        let (opened, handle) = fake_monitor_session();
        let opened = Arc::new(AsyncMutex::new(Some(opened)));
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
        let monitor =
            Arc::new(MonitorClient::spawn(monitor_config(), factory).expect("monitor client"));
        handle
            .sent
            .lock()
            .await
            .recv()
            .await
            .expect("initial subscribe");
        let monmap_bytes = include_bytes!("../../testdata/p04/monmap-v9.bin").to_vec();
        let osdmap_bytes = include_bytes!("../../testdata/p04/osdmap-v8.bin").to_vec();
        let map = crate::maps::decode_osdmap(&osdmap_bytes, map_limits()).expect("fixture OSD map");
        handle
            .incoming
            .send(ack(map.fsid()))
            .await
            .expect("subscription ack");
        handle
            .incoming
            .send(monmap_message(&monmap_bytes))
            .await
            .expect("monmap");
        handle
            .incoming
            .send(osdmap_message(
                map.fsid(),
                &[],
                &[(map.epoch(), osdmap_bytes.clone())],
                map.epoch(),
            ))
            .await
            .expect("osdmap");
        tokio::time::timeout(Duration::from_secs(1), monitor.wait_ready())
            .await
            .expect("ready timeout")
            .expect("ready");
        (monitor, handle, map, monmap_bytes, osdmap_bytes)
    }

    #[test]
    fn read_target_keeps_read_snapshot_but_drops_write_context() {
        let mut target = Target {
            pool_id: 1,
            object: b"object".to_vec(),
            locator: Vec::new(),
            namespace: Vec::new(),
            snapshot: 7,
            snapshot_sequence: 9,
            write_snapshots: vec![9, 7],
        };

        target.snapshot_sequence = 0;
        target.write_snapshots.clear();

        assert_eq!(target.snapshot, 7);
        assert_eq!(target.snapshot_sequence, 0);
        assert!(target.write_snapshots.is_empty());
    }

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
            validate_operations(&reply, std::slice::from_ref(&operation)),
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
            validate_operations(&reply, std::slice::from_ref(&operation)),
            Err(Error::MalformedReply)
        );
    }

    #[test]
    fn comparisons_alone_are_not_a_mutation_compound() {
        assert!(!contains_outcome_sensitive(&[
            Operation::AssertVersion(7),
            Operation::CompareExtent {
                offset: 0,
                data: b"value".to_vec()
            },
            Operation::OmapCompare(vec![1, 2, 3]),
        ]));
        assert!(contains_outcome_sensitive(&[
            Operation::AssertVersion(7),
            Operation::WriteFull(Vec::new()),
        ]));
    }

    #[test]
    fn notify_operations_are_outcome_sensitive_without_wire_mutation_flags() {
        let notify = Operation::Notify {
            cookie: 1,
            data: Vec::new(),
        };
        let acknowledgment = Operation::NotifyAck {
            cookie: 1,
            data: Vec::new(),
        };
        assert!(!notify.is_mutation());
        assert!(!acknowledgment.is_mutation());
        assert!(contains_outcome_sensitive(std::slice::from_ref(&notify)));
        assert!(contains_outcome_sensitive(std::slice::from_ref(
            &acknowledgment
        )));
        assert!(!allows_unknown_retry(&notify));
        assert!(!allows_unknown_retry(&acknowledgment));
        assert!(!contains_durable_mutation(&[notify, acknowledgment]));
    }

    #[tokio::test]
    async fn closed_client_rejects_late_watch_worker_tracking() {
        let client = Client::new(
            Arc::new(RwLock::new(None)),
            FRAME_TEST_LIMITS,
            Duration::from_secs(1),
            Duration::from_secs(1),
            false,
            1,
        );
        client.close();
        let worker = tokio::spawn(std::future::pending());
        let worker = client
            .track_watch_worker(worker)
            .expect_err("closed client accepted worker");
        worker.abort();
        let _ = worker.await;
        assert!(!client.has_sessions());
    }

    #[tokio::test]
    async fn watch_worker_tracking_reclaims_completed_handles() {
        let client = Client::new(
            Arc::new(RwLock::new(None)),
            FRAME_TEST_LIMITS,
            Duration::from_secs(1),
            Duration::from_secs(1),
            false,
            1,
        );
        client
            .track_watch_worker(tokio::spawn(async {}))
            .expect("track completed worker");
        tokio::task::yield_now().await;
        let pending = tokio::spawn(std::future::pending());
        client
            .track_watch_worker(pending)
            .expect("track pending worker");
        assert_eq!(
            client
                .watch_workers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            1
        );
        client.close();
    }

    #[test]
    fn unknown_class_mutations_are_never_retryable() {
        let call = Operation::Call {
            class_length: 4,
            method_length: 6,
            input_length: 0,
            data: b"classmethod".to_vec(),
            mutation: true,
        };
        assert!(!allows_unknown_retry(&call));
        assert!(!allows_unknown_retry(&Operation::WithFlags {
            operation: Box::new(call),
            flags: 0,
        }));
        assert!(allows_unknown_retry(&Operation::WriteFull(Vec::new())));
    }

    fn scrub_item(name: &[u8]) -> InconsistentObject {
        InconsistentObject {
            object: name.to_vec(),
            namespace: b"ns".to_vec(),
            locator: b"loc".to_vec(),
            snapshot: 1,
            shards: vec![1],
            errors: vec!["x".to_owned()],
        }
    }

    #[test]
    fn inconsistent_pager_finishes_short_page_and_enforces_bounds() {
        let mut pager = InconsistentPager::new(2);
        assert!(pager.push(7, vec![scrub_item(b"a")]).expect("short page"));
        assert_eq!(pager.result.len(), 1);

        let mut bounded = InconsistentPager::new(1);
        assert_eq!(
            bounded.push(1, vec![scrub_item(b"a"), scrub_item(b"b")]),
            Err(Error::LimitExceeded)
        );
    }

    #[test]
    fn inconsistent_pager_rejects_interval_changes_and_nonadvancing_cursor() {
        let full_len = usize::try_from(SCRUB_PAGE_SIZE).expect("page size fits usize");
        let mut interval = InconsistentPager::new(3000);
        let full = vec![scrub_item(b"a"); full_len];
        assert!(!interval.push(9, full).expect("first page"));
        assert_eq!(
            interval.push(10, vec![scrub_item(b"b")]),
            Err(Error::WireErrno(-11))
        );

        let mut cursor = InconsistentPager::new(3000);
        let mut first = vec![scrub_item(b"a"); full_len];
        first[full_len - 1] = scrub_item(b"last");
        assert!(!cursor.push(3, first).expect("first page"));
        let mut repeat = vec![scrub_item(b"b"); full_len];
        repeat[0] = scrub_item(b"last");
        repeat[full_len - 1] = scrub_item(b"last");
        assert_eq!(cursor.push(3, repeat), Err(Error::MalformedReply));
    }

    #[test]
    fn inconsistent_pager_appends_nonoverlapping_pages() {
        let full_len = usize::try_from(SCRUB_PAGE_SIZE).expect("page size fits usize");
        let mut pager = InconsistentPager::new(4000);
        let mut first = vec![scrub_item(b"a"); full_len];
        first[full_len - 1] = scrub_item(b"cursor");
        assert!(!pager.push(11, first).expect("first page"));

        let mut second = vec![scrub_item(b"b"); full_len];
        second[0] = scrub_item(b"next");
        second[full_len - 1] = scrub_item(b"second-cursor");
        assert!(!pager.push(11, second).expect("second page"));
        assert_eq!(pager.result.len(), full_len * 2);
        assert_eq!(pager.result[full_len].object, b"next");
        assert_eq!(pager.start.object, b"second-cursor");
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
            broadcast::channel(4).0,
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
            broadcast::channel(4).0,
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
    async fn osd_map_notification_preserves_stale_map_for_pending_mutation() {
        let (client, mut server) = duplex(8192);
        let session = OSDSession::spawn(
            raw_session(client),
            broadcast::channel(4).0,
            MESSAGE_TEST_LIMITS,
            Duration::from_secs(1),
        );
        let pending_session = Arc::clone(&session);
        let pending = tokio::spawn(async move {
            pending_session
                .submit(
                    backoff(BACKOFF_BLOCK).pg,
                    &object(),
                    request_message(),
                    true,
                    &OperationOptions::new()
                        .with_deadline(std::time::Instant::now() + Duration::from_secs(1)),
                )
                .await
        });
        let _request = next_message(&mut server).await;
        let map = Message {
            header: MessageHeader {
                sequence: 1,
                message_type: 41,
                ..MessageHeader::default()
            },
            ..Message::default()
        };
        send_message(&mut server, map).await;

        assert_eq!(pending.await.expect("submit task"), Err(Error::StaleMap));
        session.shutdown().await;
    }

    #[tokio::test]
    async fn flush_captures_watermark_and_waits_for_all_prior_mutations() {
        let client = Client::new(
            Arc::new(RwLock::new(None)),
            FRAME_TEST_LIMITS,
            Duration::from_secs(1),
            Duration::from_secs(1),
            false,
            1,
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
            1,
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
            1,
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
            1,
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
            1,
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
            1,
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
            1,
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

    #[tokio::test]
    async fn submit_command_retries_eagain_with_same_nonzero_transaction_id() {
        let _hook_lock = COMMAND_HOOK_TEST_LOCK.lock().await;
        let (monitor, handle, map, _monmap, osdmap_bytes) = start_monitor_with_fixture_map().await;
        let authority = test_authority();
        let client = Client::new(
            Arc::new(RwLock::new(Some(Arc::clone(&authority)))),
            FRAME_TEST_LIMITS,
            Duration::from_secs(1),
            Duration::from_secs(1),
            true,
            1,
        );
        let osd = 17;
        let addresses = routable_addresses(4317);
        let map_epoch = map.epoch();
        let map_fsid = map.fsid();
        let addresses_for_hook = addresses.clone();
        let _route_hook = CommandRouteHookGuard::install(Arc::new(move |target| {
            assert_eq!(target, CommandTarget::Osd(osd));
            Ok(CommandRoute {
                epoch: map_epoch,
                primary: osd,
                addresses: addresses_for_hook.clone(),
            })
        }));
        let tids = Arc::new(Mutex::new(Vec::new()));
        let submits = Arc::new(AtomicU64::new(0));
        let tids_for_hook = Arc::clone(&tids);
        let submits_for_hook = Arc::clone(&submits);
        let _submit_hook = SubmitDirectHookGuard::install(Arc::new(move |message| {
            tids_for_hook
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(message.header.transaction_id);
            let attempt = submits_for_hook.fetch_add(1, Ordering::Relaxed);
            Ok(if attempt == 0 {
                command_reply_message(message.header.transaction_id, -11, "again", b"recover")
            } else {
                command_reply_message(message.header.transaction_id, 0, "ok", b"done")
            })
        }));
        let (wire_client, _wire_server) = duplex(8192);
        let session = OSDSession::spawn(
            raw_session(wire_client),
            broadcast::channel(4).0,
            MESSAGE_TEST_LIMITS,
            Duration::from_secs(1),
        );
        install_session(&client, &authority, osd, &addresses, Arc::clone(&session));

        let options = OperationOptions::new()
            .with_deadline(std::time::Instant::now() + Duration::from_secs(3));
        let monitor_for_call = Arc::clone(&monitor);
        let command = tokio::spawn(async move {
            client
                .osd_command(
                    &monitor_for_call,
                    osd,
                    vec!["{\"prefix\":\"status\"}".to_owned()],
                    b"in".to_vec(),
                    &options,
                )
                .await
        });

        handle
            .sent
            .lock()
            .await
            .recv()
            .await
            .expect("best-effort refresh subscribe");
        handle
            .incoming
            .send(osdmap_message(
                map_fsid,
                &[],
                &[(map_epoch, osdmap_bytes)],
                map_epoch,
            ))
            .await
            .expect("refresh map publication");

        let (result, error) = command.await.expect("join").expect("command result");
        assert_eq!(result.status, "ok");
        assert_eq!(result.output, b"done");
        assert_eq!(error, None);
        let captured = tids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(captured.len(), 2);
        assert_ne!(captured[0], 0);
        assert_eq!(captured[0], captured[1]);

        session.shutdown().await;
        monitor.close();
        monitor.shutdown().await;
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn submit_pg_command_reroutes_to_new_primary_after_map_change_retry() {
        let _hook_lock = COMMAND_HOOK_TEST_LOCK.lock().await;
        let (monitor, handle, old_map, _monmap, _osdmap) = start_monitor_with_fixture_map().await;
        let incremental_bytes =
            include_bytes!("../../testdata/p04/osdmap-incremental-v8.bin").to_vec();
        let incremental = crate::maps::decode_osdmap_incremental(&incremental_bytes, map_limits())
            .expect("fixture incremental");
        let authority = test_authority();
        let client = Client::new(
            Arc::new(RwLock::new(Some(Arc::clone(&authority)))),
            FRAME_TEST_LIMITS,
            Duration::from_secs(1),
            Duration::from_secs(1),
            true,
            1,
        );
        let old_primary = 101;
        let new_primary = 202;
        let old_addresses = routable_addresses(5101);
        let new_addresses = routable_addresses(5202);
        let pg = PG {
            pool: 1,
            seed: 7,
            preferred: -1,
        };
        let attempts = Arc::new(AtomicU64::new(0));
        let attempts_for_hook = Arc::clone(&attempts);
        let old_addresses_for_hook = old_addresses.clone();
        let new_addresses_for_hook = new_addresses.clone();
        let old_epoch = old_map.epoch();
        let new_epoch = incremental.epoch();
        let _route_hook = CommandRouteHookGuard::install(Arc::new(move |target| {
            assert_eq!(target, CommandTarget::PG(pg));
            if attempts_for_hook.fetch_add(1, Ordering::Relaxed) == 0 {
                Ok(CommandRoute {
                    epoch: old_epoch,
                    primary: old_primary,
                    addresses: old_addresses_for_hook.clone(),
                })
            } else {
                Ok(CommandRoute {
                    epoch: new_epoch,
                    primary: new_primary,
                    addresses: new_addresses_for_hook.clone(),
                })
            }
        }));
        let routed = Arc::new(Mutex::new(Vec::new()));
        let routed_for_hook = Arc::clone(&routed);
        let submits = Arc::new(AtomicU64::new(0));
        let submits_for_hook = Arc::clone(&submits);
        let _submit_hook = SubmitDirectHookGuard::install(Arc::new(move |message| {
            let idx = submits_for_hook.fetch_add(1, Ordering::Relaxed);
            let osd = if idx == 0 { old_primary } else { new_primary };
            routed_for_hook
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((osd, message.header.transaction_id));
            Ok(if idx == 0 {
                command_reply_message(message.header.transaction_id, -11, "again", b"")
            } else {
                command_reply_message(message.header.transaction_id, 0, "ok", b"rerouted")
            })
        }));
        let (old_wire_client, _old_wire_server) = duplex(8192);
        let (new_wire_client, _new_wire_server) = duplex(8192);
        let old_session = OSDSession::spawn(
            raw_session(old_wire_client),
            broadcast::channel(4).0,
            MESSAGE_TEST_LIMITS,
            Duration::from_secs(1),
        );
        let new_session = OSDSession::spawn(
            raw_session(new_wire_client),
            broadcast::channel(4).0,
            MESSAGE_TEST_LIMITS,
            Duration::from_secs(1),
        );
        install_session(
            &client,
            &authority,
            old_primary,
            &old_addresses,
            Arc::clone(&old_session),
        );
        install_session(
            &client,
            &authority,
            new_primary,
            &new_addresses,
            Arc::clone(&new_session),
        );

        let options = OperationOptions::new()
            .with_deadline(std::time::Instant::now() + Duration::from_secs(3));
        let monitor_for_call = Arc::clone(&monitor);
        let op = tokio::spawn(async move {
            client
                .pg_command(
                    &monitor_for_call,
                    pg,
                    vec!["{\"prefix\":\"pg dump\"}".to_owned()],
                    Vec::new(),
                    &options,
                )
                .await
        });
        handle
            .incoming
            .send(osdmap_message(
                old_map.fsid(),
                &[(incremental.epoch(), incremental_bytes)],
                &[],
                incremental.epoch(),
            ))
            .await
            .expect("publish incremental map");

        let (result, error) = op.await.expect("join").expect("command result");
        assert_eq!(result.status, "ok");
        assert_eq!(result.output, b"rerouted");
        assert_eq!(error, None);
        let routed = routed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(routed.len(), 2);
        assert_eq!(routed[0].0, old_primary);
        assert_eq!(routed[1].0, new_primary);
        assert_eq!(routed[0].1, routed[1].1);

        old_session.shutdown().await;
        new_session.shutdown().await;
        monitor.close();
        monitor.shutdown().await;
    }

    #[tokio::test]
    async fn submit_command_outcome_unknown_returns_immediately_without_replay() {
        let _hook_lock = COMMAND_HOOK_TEST_LOCK.lock().await;
        let (monitor, _handle, map, _monmap, _osdmap) = start_monitor_with_fixture_map().await;
        let authority = test_authority();
        let client = Client::new(
            Arc::new(RwLock::new(Some(Arc::clone(&authority)))),
            FRAME_TEST_LIMITS,
            Duration::from_secs(1),
            Duration::from_secs(1),
            true,
            1,
        );
        let osd = 29;
        let addresses = routable_addresses(4329);
        let addresses_for_hook = addresses.clone();
        let map_epoch = map.epoch();
        let _route_hook = CommandRouteHookGuard::install(Arc::new(move |target| {
            assert_eq!(target, CommandTarget::Osd(osd));
            Ok(CommandRoute {
                epoch: map_epoch,
                primary: osd,
                addresses: addresses_for_hook.clone(),
            })
        }));
        let submits = Arc::new(AtomicU64::new(0));
        let submits_for_hook = Arc::clone(&submits);
        let _submit_hook = SubmitDirectHookGuard::install(Arc::new(move |_message| {
            submits_for_hook.fetch_add(1, Ordering::Relaxed);
            Err(Error::OutcomeUnknown(UnknownCause::Transport))
        }));
        let (wire_client, _wire_server) = duplex(8192);
        let session = OSDSession::spawn(
            raw_session(wire_client),
            broadcast::channel(4).0,
            MESSAGE_TEST_LIMITS,
            Duration::from_secs(1),
        );
        install_session(&client, &authority, osd, &addresses, Arc::clone(&session));

        let outcome = client
            .osd_command(
                &monitor,
                osd,
                vec!["{\"prefix\":\"status\"}".to_owned()],
                Vec::new(),
                &OperationOptions::new()
                    .with_deadline(std::time::Instant::now() + Duration::from_secs(1)),
            )
            .await;
        assert_eq!(outcome, Err(Error::OutcomeUnknown(UnknownCause::Transport)));
        assert_eq!(submits.load(Ordering::Relaxed), 1);

        session.shutdown().await;
        monitor.close();
        monitor.shutdown().await;
    }

    #[tokio::test]
    async fn submit_command_malformed_or_tid_mismatch_invalidates_and_is_terminal() {
        let _hook_lock = COMMAND_HOOK_TEST_LOCK.lock().await;
        for mismatched_tid in [false, true] {
            let (monitor, _handle, map, _monmap, _osdmap) = start_monitor_with_fixture_map().await;
            let authority = test_authority();
            let client = Arc::new(Client::new(
                Arc::new(RwLock::new(Some(Arc::clone(&authority)))),
                FRAME_TEST_LIMITS,
                Duration::from_secs(1),
                Duration::from_secs(1),
                true,
                1,
            ));
            let osd = 31;
            let addresses = routable_addresses(4331);
            let addresses_for_hook = addresses.clone();
            let map_epoch = map.epoch();
            let _route_hook = CommandRouteHookGuard::install(Arc::new(move |target| {
                assert_eq!(target, CommandTarget::Osd(osd));
                Ok(CommandRoute {
                    epoch: map_epoch,
                    primary: osd,
                    addresses: addresses_for_hook.clone(),
                })
            }));
            let _submit_hook = SubmitDirectHookGuard::install(Arc::new(move |message| {
                Ok(if mismatched_tid {
                    command_reply_message(
                        message.header.transaction_id.saturating_add(1),
                        0,
                        "ok",
                        b"",
                    )
                } else {
                    let mut malformed =
                        command_reply_message(message.header.transaction_id, 0, "ok", b"payload");
                    malformed.lengths.front = malformed.lengths.front.saturating_add(1);
                    malformed
                })
            }));
            let (wire_client, _wire_server) = duplex(8192);
            let session = OSDSession::spawn(
                raw_session(wire_client),
                broadcast::channel(4).0,
                MESSAGE_TEST_LIMITS,
                Duration::from_secs(1),
            );
            install_session(&client, &authority, osd, &addresses, Arc::clone(&session));

            let client_for_call = Arc::clone(&client);
            let monitor_for_call = Arc::clone(&monitor);
            let op = tokio::spawn(async move {
                client_for_call
                    .osd_command(
                        &monitor_for_call,
                        osd,
                        vec!["{\"prefix\":\"status\"}".to_owned()],
                        Vec::new(),
                        &OperationOptions::new()
                            .with_deadline(std::time::Instant::now() + Duration::from_secs(1)),
                    )
                    .await
            });

            assert_eq!(op.await.expect("join"), Err(Error::MalformedReply));
            assert!(
                client
                    .sessions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&osd)
                    .is_none()
            );

            session.shutdown().await;
            monitor.close();
            monitor.shutdown().await;
        }
    }

    #[tokio::test]
    async fn submit_command_negative_errno_preserves_status_and_output() {
        let _hook_lock = COMMAND_HOOK_TEST_LOCK.lock().await;
        let (monitor, _handle, map, _monmap, _osdmap) = start_monitor_with_fixture_map().await;
        let authority = test_authority();
        let client = Client::new(
            Arc::new(RwLock::new(Some(Arc::clone(&authority)))),
            FRAME_TEST_LIMITS,
            Duration::from_secs(1),
            Duration::from_secs(1),
            true,
            1,
        );
        let osd = 37;
        let addresses = routable_addresses(4337);
        let addresses_for_hook = addresses.clone();
        let _route_hook = CommandRouteHookGuard::install(Arc::new(move |target| {
            assert_eq!(target, CommandTarget::Osd(osd));
            Ok(CommandRoute {
                epoch: map.epoch(),
                primary: osd,
                addresses: addresses_for_hook.clone(),
            })
        }));
        let _submit_hook = SubmitDirectHookGuard::install(Arc::new(move |message| {
            Ok(command_reply_message(
                message.header.transaction_id,
                -13,
                "permission denied",
                b"partial",
            ))
        }));
        let (wire_client, _wire_server) = duplex(8192);
        let session = OSDSession::spawn(
            raw_session(wire_client),
            broadcast::channel(4).0,
            MESSAGE_TEST_LIMITS,
            Duration::from_secs(1),
        );
        install_session(&client, &authority, osd, &addresses, Arc::clone(&session));

        let pending = tokio::spawn(async move {
            client
                .osd_command(
                    &monitor,
                    osd,
                    vec!["{\"prefix\":\"status\"}".to_owned()],
                    b"request".to_vec(),
                    &OperationOptions::new()
                        .with_deadline(std::time::Instant::now() + Duration::from_secs(1)),
                )
                .await
        });

        let (reply, error) = pending.await.expect("join").expect("command result");
        assert_eq!(reply.result, -13);
        assert_eq!(reply.status, "permission denied");
        assert_eq!(reply.output, b"partial");
        assert_eq!(error, Some(Error::WireErrno(-13)));

        session.shutdown().await;
    }
}
