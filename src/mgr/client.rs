use std::fmt;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use tokio::sync::watch;

use super::messages::{self, CommandReply};
use crate::OperationOptions;
use crate::cephx::connector;
use crate::maps::Fsid;
use crate::msgr::control::ClientIdent;
use crate::msgr::frame::Limits as FrameLimits;
use crate::msgr::message::Message;
use crate::msgr::session::{Config as SessionConfig, ReconnectPolicy, SessionError};
use crate::msgr::supervisor::{Connector, Session};
use crate::protocol::address::{EntityAddr, EntityAddrVec};
use crate::protocol::features::GlobalFeatures;

const ENTITY_MANAGER: u8 = 16;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

type OpenFuture =
    Pin<Box<dyn Future<Output = Result<Arc<dyn ManagerSession>, ManagerError>> + Send>>;

pub(crate) type SessionFactory = Arc<dyn Fn(ActiveTarget) -> OpenFuture + Send + Sync>;
type AuthoritySource =
    Arc<dyn Fn() -> Option<Arc<crate::cephx::connector::MonitorConnector>> + Send + Sync>;

#[derive(Clone)]
pub(crate) struct Snapshot {
    pub(crate) fsid: Option<Fsid>,
    pub(crate) target: Option<ActiveTarget>,
    pub(crate) unsupported_features: bool,
}

pub(crate) trait StateSource: Send + Sync {
    fn snapshot(&self) -> Snapshot;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActiveTarget {
    pub(crate) epoch: u32,
    pub(crate) gid: u64,
    pub(crate) name: String,
    pub(crate) address: EntityAddr,
    pub(crate) features: u64,
}

pub(crate) trait ManagerSession: Send + Sync {
    fn submit(
        &self,
        cancel: watch::Receiver<bool>,
        message: Message,
    ) -> BoxFuture<'_, Result<Message, SessionError>>;
    fn stop(&self);
}

#[derive(Clone)]
pub(crate) struct Config {
    pub(crate) source: Arc<dyn StateSource>,
    pub(crate) authority_slot:
        Arc<std::sync::RwLock<Option<Arc<crate::cephx::connector::MonitorConnector>>>>,
    pub(crate) frame_limits: FrameLimits,
    pub(crate) dial_timeout: Duration,
    pub(crate) handshake_timeout: Duration,
    pub(crate) allow_crc: bool,
    pub(crate) address_nonce: u32,
    pub(crate) message_max_bytes: u32,
    pub(crate) retry_delay: Duration,
    pub(crate) max_attempts: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagerError {
    Closed,
    InvalidConfig,
    NoActiveManager,
    IdentityUnavailable,
    UnsupportedManagerFeatures,
    Session(SessionError),
    Message(messages::MessageError),
    WireErrno(i32),
}

impl fmt::Display for ManagerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => formatter.write_str("manager client closed"),
            Self::InvalidConfig => formatter.write_str("invalid manager client configuration"),
            Self::NoActiveManager => formatter.write_str("no active manager"),
            Self::IdentityUnavailable => formatter.write_str("manager identity unavailable"),
            Self::UnsupportedManagerFeatures => {
                formatter.write_str("unsupported active manager features")
            }
            Self::Session(error) => write!(formatter, "manager session failed: {error:?}"),
            Self::Message(error) => write!(formatter, "manager message failed: {error}"),
            Self::WireErrno(code) => write!(formatter, "manager operation failed: errno {code}"),
        }
    }
}

impl std::error::Error for ManagerError {}

impl From<SessionError> for ManagerError {
    fn from(error: SessionError) -> Self {
        Self::Session(error)
    }
}

impl From<messages::MessageError> for ManagerError {
    fn from(error: messages::MessageError) -> Self {
        Self::Message(error)
    }
}

pub(crate) struct ManagerClient {
    config: Config,
    factory: SessionFactory,
    done: watch::Sender<bool>,
    state: Mutex<State>,
}

struct State {
    closed: bool,
    next_tid: u64,
    session: Option<SessionEntry>,
}

#[derive(Clone)]
struct SessionEntry {
    target: ActiveTarget,
    session: Arc<dyn ManagerSession>,
}

struct ManagedSession {
    inner: Arc<Session>,
}

impl ManagerSession for ManagedSession {
    fn submit(
        &self,
        mut cancel: watch::Receiver<bool>,
        message: Message,
    ) -> BoxFuture<'_, Result<Message, SessionError>> {
        let session = Arc::clone(&self.inner);
        Box::pin(async move {
            let mut request = session.admit(message, false).await?;
            loop {
                if *cancel.borrow() {
                    return request
                        .cancel()
                        .await
                        .and_then(|value| value.ok_or(SessionError::Malformed));
                }
                tokio::select! {
                    result = request.wait_result() => {
                        return result.and_then(|value| value.ok_or(SessionError::Malformed));
                    }
                    changed = cancel.changed() => {
                        if changed.is_err() || *cancel.borrow() {
                            return request
                                .cancel()
                                .await
                                .and_then(|value| value.ok_or(SessionError::Malformed));
                        }
                    }
                }
            }
        })
    }

    fn stop(&self) {
        self.inner.close();
    }
}

impl ManagerClient {
    pub(crate) fn new(
        config: Config,
        factory: Option<SessionFactory>,
    ) -> Result<Self, ManagerError> {
        if config.message_max_bytes == 0
            || config.retry_delay.is_zero()
            || config.max_attempts == 0
            || config.dial_timeout.is_zero()
            || config.handshake_timeout.is_zero()
            || config.frame_limits.max_segment_bytes == 0
            || config.frame_limits.max_frame_bytes == 0
            || config.frame_limits.max_auth_bytes == 0
        {
            return Err(ManagerError::InvalidConfig);
        }
        let (done, _) = watch::channel(false);
        let factory = factory.unwrap_or_else(|| production_session_factory(config.clone()));
        Ok(Self {
            config,
            factory,
            done,
            state: Mutex::new(State {
                closed: false,
                next_tid: 1,
                session: None,
            }),
        })
    }

    pub(crate) async fn command(
        &self,
        command: Vec<String>,
        input: Vec<u8>,
        options: OperationOptions,
    ) -> Result<(CommandReply, Option<ManagerError>), ManagerError> {
        if command.is_empty() {
            return Err(ManagerError::InvalidConfig);
        }
        let tid = self.next_transaction_id()?;
        let mut last_error = None;
        for attempt in 0..self.config.max_attempts {
            if self.is_closed() {
                return Err(ManagerError::Closed);
            }
            if options.is_canceled() {
                return Err(ManagerError::Session(SessionError::Cancelled));
            }
            if options
                .deadline()
                .is_some_and(|deadline| std::time::Instant::now() >= deadline)
            {
                return Err(ManagerError::Session(SessionError::Cancelled));
            }

            let (target, fsid) = match self.current_target() {
                Ok(value) => value,
                Err(ManagerError::NoActiveManager) => {
                    last_error = Some(ManagerError::NoActiveManager);
                    self.wait_retry(&options).await?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let mut request =
                messages::encode_command(fsid, &command, &input, self.config.message_max_bytes)?;
            request.header.transaction_id = tid;
            let session = match self.get_session(target, &options).await {
                Ok(session) => session,
                Err(ManagerError::NoActiveManager) => {
                    last_error = Some(ManagerError::NoActiveManager);
                    self.wait_retry(&options).await?;
                    continue;
                }
                Err(ManagerError::Closed) => return Err(ManagerError::Closed),
                Err(error) => {
                    last_error = Some(error);
                    if attempt + 1 < self.config.max_attempts {
                        self.wait_retry(&options).await?;
                        continue;
                    }
                    break;
                }
            };

            match self
                .submit_pending_aware(session.clone(), request, &options)
                .await
            {
                Ok(None) => {
                    last_error = Some(ManagerError::NoActiveManager);
                    if attempt + 1 < self.config.max_attempts {
                        self.wait_retry(&options).await?;
                        continue;
                    }
                    break;
                }
                Ok(Some(reply_message)) => {
                    if reply_message.header.transaction_id != tid {
                        self.invalidate(&session);
                        return Err(ManagerError::Message(messages::MessageError::Malformed(
                            "manager command reply transaction",
                        )));
                    }
                    let reply = messages::decode_command_reply(
                        &reply_message,
                        self.config.message_max_bytes,
                    )?;
                    if reply.result < 0 {
                        return Ok((reply.clone(), Some(ManagerError::WireErrno(reply.result))));
                    }
                    return Ok((reply, None));
                }
                Err(ManagerError::Session(SessionError::OutcomeUnknown)) => {
                    self.invalidate(&session);
                    return Err(ManagerError::Session(SessionError::OutcomeUnknown));
                }
                Err(ManagerError::Closed) => return Err(ManagerError::Closed),
                Err(error) => {
                    self.invalidate(&session);
                    last_error = Some(error);
                    if attempt + 1 < self.config.max_attempts {
                        self.wait_retry(&options).await?;
                        continue;
                    }
                    break;
                }
            }
        }
        Err(last_error.unwrap_or(ManagerError::NoActiveManager))
    }

    pub(crate) fn close(&self) {
        let active = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.closed {
                return;
            }
            state.closed = true;
            state.session.take()
        };
        self.done.send_replace(true);
        if let Some(active) = active {
            active.session.stop();
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .closed
    }

    async fn submit_pending_aware(
        &self,
        active: SessionEntry,
        message: Message,
        options: &OperationOptions,
    ) -> Result<Option<Message>, ManagerError> {
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let session = Arc::clone(&active.session);
        let mut submit = tokio::spawn(async move { session.submit(cancel_rx, message).await });
        let mut done = self.done.subscribe();
        let mut ticker = tokio::time::interval_at(
            tokio::time::Instant::now() + self.config.retry_delay,
            self.config.retry_delay,
        );
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
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
        tokio::pin!(ticker, deadline_wait, cancellation);

        loop {
            if options.is_canceled() {
                let _ = cancel_tx.send(true);
                let reply = (&mut submit)
                    .await
                    .unwrap_or(Err(SessionError::Disconnected));
                return Err(classify_cancel_result(&reply));
            }
            if options
                .deadline()
                .is_some_and(|deadline| std::time::Instant::now() >= deadline)
            {
                let _ = cancel_tx.send(true);
                let reply = (&mut submit)
                    .await
                    .unwrap_or(Err(SessionError::Disconnected));
                return Err(classify_cancel_result(&reply));
            }

            tokio::select! {
                result = &mut submit => {
                    let reply = result.unwrap_or(Err(SessionError::Disconnected));
                    return reply.map(Some).map_err(ManagerError::from);
                }
                changed = done.changed() => {
                    let _ = changed;
                    let _ = cancel_tx.send(true);
                    let reply = (&mut submit)
                        .await
                        .unwrap_or(Err(SessionError::Disconnected));
                    if matches!(reply, Err(SessionError::OutcomeUnknown)) {
                        return Err(ManagerError::Session(SessionError::OutcomeUnknown));
                    }
                    return Err(ManagerError::Closed);
                }
                () = &mut deadline_wait => {
                    let _ = cancel_tx.send(true);
                    let reply = (&mut submit)
                        .await
                        .unwrap_or(Err(SessionError::Disconnected));
                    return Err(classify_cancel_result(&reply));
                }
                () = &mut cancellation => {
                    if options.is_canceled() {
                        let _ = cancel_tx.send(true);
                        let reply = (&mut submit)
                            .await
                            .unwrap_or(Err(SessionError::Disconnected));
                        return Err(classify_cancel_result(&reply));
                    }
                    cancellation.as_mut().reset(
                        tokio::time::Instant::now() + Duration::from_millis(10)
                    );
                }
                _ = ticker.tick() => {
                    match self.current_target() {
                        Ok((current, _)) if same_target(&current, &active.target) => {}
                        _ => {
                            let _ = cancel_tx.send(true);
                            let reply = (&mut submit)
                                .await
                                .unwrap_or(Err(SessionError::Disconnected));
                            if matches!(reply, Err(SessionError::OutcomeUnknown)) {
                                return Err(ManagerError::Session(SessionError::OutcomeUnknown));
                            }
                            self.invalidate(&active);
                            return Ok(None);
                        }
                    }
                }
            }
        }
    }

    async fn get_session(
        &self,
        target: ActiveTarget,
        options: &OperationOptions,
    ) -> Result<SessionEntry, ManagerError> {
        let previous = {
            let mut slot = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if slot.closed {
                return Err(ManagerError::Closed);
            }
            if let Some(active) = &slot.session
                && same_target(&active.target, &target)
            {
                return Ok(active.clone());
            }
            slot.session.take()
        };
        if let Some(previous) = previous {
            previous.session.stop();
        }

        if options.is_canceled() {
            return Err(ManagerError::Session(SessionError::Cancelled));
        }
        if options
            .deadline()
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
        {
            return Err(ManagerError::Session(SessionError::Cancelled));
        }

        let created = (self.factory)(target.clone()).await?;
        let (current, _) = self.current_target()?;
        if !same_target(&current, &target) {
            created.stop();
            return Err(ManagerError::NoActiveManager);
        }

        let mut slot = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.closed {
            drop(slot);
            created.stop();
            return Err(ManagerError::Closed);
        }
        if let Some(existing) = &slot.session {
            if same_target(&existing.target, &target) {
                let active = existing.clone();
                drop(slot);
                created.stop();
                return Ok(active);
            }
            let replaced = slot
                .session
                .replace(SessionEntry {
                    target: target.clone(),
                    session: Arc::clone(&created),
                })
                .expect("existing manager session");
            drop(slot);
            replaced.session.stop();
            return Ok(SessionEntry {
                target,
                session: created,
            });
        }
        slot.session = Some(SessionEntry {
            target: target.clone(),
            session: Arc::clone(&created),
        });
        drop(slot);
        Ok(SessionEntry {
            target,
            session: created,
        })
    }

    fn current_target(&self) -> Result<(ActiveTarget, Fsid), ManagerError> {
        let snapshot = self.config.source.snapshot();
        let fsid = snapshot.fsid.ok_or(ManagerError::IdentityUnavailable)?;
        if snapshot.unsupported_features {
            return Err(ManagerError::UnsupportedManagerFeatures);
        }
        let target = snapshot.target.ok_or(ManagerError::NoActiveManager)?;
        Ok((target, fsid))
    }

    fn invalidate(&self, active: &SessionEntry) {
        let stale = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.session.as_ref().is_some_and(|current| {
                same_target(&current.target, &active.target)
                    && Arc::ptr_eq(&current.session, &active.session)
            }) {
                state.session.take()
            } else {
                None
            }
        };
        if let Some(stale) = stale {
            stale.session.stop();
        }
    }

    fn next_transaction_id(&self) -> Result<u64, ManagerError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.closed {
            return Err(ManagerError::Closed);
        }
        let tid = state.next_tid;
        if tid == 0 {
            return Err(ManagerError::Session(SessionError::TransitionLimit));
        }
        state.next_tid = state.next_tid.wrapping_add(1);
        Ok(tid)
    }

    async fn wait_retry(&self, options: &OperationOptions) -> Result<(), ManagerError> {
        let mut done = self.done.subscribe();
        let delay = tokio::time::sleep(self.config.retry_delay);
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
        tokio::pin!(delay, deadline_wait, cancellation);
        if options.is_canceled() {
            return Err(ManagerError::Session(SessionError::Cancelled));
        }
        if options
            .deadline()
            .is_some_and(|deadline| std::time::Instant::now() >= deadline)
        {
            return Err(ManagerError::Session(SessionError::Cancelled));
        }
        loop {
            tokio::select! {
                () = &mut delay => return Ok(()),
                () = &mut deadline_wait => {
                    return Err(ManagerError::Session(SessionError::Cancelled));
                }
                () = &mut cancellation => {
                    if options.is_canceled() {
                        return Err(ManagerError::Session(SessionError::Cancelled));
                    }
                    cancellation.as_mut().reset(
                        tokio::time::Instant::now() + Duration::from_millis(10)
                    );
                }
                changed = done.changed() => {
                    let _ = changed;
                    return Err(ManagerError::Closed);
                }
            }
        }
    }
}

impl Drop for ManagerClient {
    fn drop(&mut self) {
        self.close();
    }
}

fn same_target(left: &ActiveTarget, right: &ActiveTarget) -> bool {
    left.gid == right.gid && left.name == right.name && left.address == right.address
}

fn classify_cancel_result(result: &Result<Message, SessionError>) -> ManagerError {
    if matches!(result, Err(SessionError::OutcomeUnknown)) {
        ManagerError::Session(SessionError::OutcomeUnknown)
    } else {
        ManagerError::Session(SessionError::Cancelled)
    }
}

fn authority_source_from_slot(
    slot: Arc<std::sync::RwLock<Option<Arc<crate::cephx::connector::MonitorConnector>>>>,
) -> AuthoritySource {
    Arc::new(move || {
        slot.read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    })
}

fn production_session_factory(config: Config) -> SessionFactory {
    Arc::new(move |target: ActiveTarget| {
        let config = config.clone();
        let authority_source = authority_source_from_slot(Arc::clone(&config.authority_slot));
        Box::pin(async move {
            let endpoint = target
                .address
                .endpoint()
                .ok_or(ManagerError::NoActiveManager)?;
            if endpoint.port() == 0 {
                return Err(ManagerError::NoActiveManager);
            }
            let authority = authority_source().ok_or(ManagerError::IdentityUnavailable)?;
            let service = connector::ServiceConnector::new(connector::ServiceConfig {
                authority,
                service_type: ENTITY_MANAGER,
                target_address: target.address.clone(),
                message_limits: config.frame_limits,
                handshake_timeout: config.handshake_timeout,
                max_banner_payload: 64,
                allow_crc: config.allow_crc,
            })
            .map_err(|_| ManagerError::InvalidConfig)?;
            let stream = tokio::time::timeout(
                config.dial_timeout,
                tokio::net::TcpStream::connect(endpoint),
            )
            .await
            .map_err(|_| ManagerError::Session(SessionError::Disconnected))?
            .map_err(|_| ManagerError::Session(SessionError::Disconnected))?;
            let initial = service
                .connect(stream)
                .await
                .map_err(SessionError::from)
                .map_err(ManagerError::Session)?;

            let reconnect_endpoint = endpoint;
            let dial_timeout = config.dial_timeout;
            let reconnect_config = config.clone();
            let reconnect_target = target.address.clone();
            let reconnect_authority = Arc::clone(&authority_source);
            let connector: Connector = Arc::new(move || {
                let reconnect_target = reconnect_target.clone();
                let reconnect_authority = Arc::clone(&reconnect_authority);
                let reconnect_config = reconnect_config.clone();
                Box::pin(async move {
                    let authority = reconnect_authority().ok_or(SessionError::Disconnected)?;
                    let service = connector::ServiceConnector::new(connector::ServiceConfig {
                        authority,
                        service_type: ENTITY_MANAGER,
                        target_address: reconnect_target,
                        message_limits: reconnect_config.frame_limits,
                        handshake_timeout: reconnect_config.handshake_timeout,
                        max_banner_payload: 64,
                        allow_crc: reconnect_config.allow_crc,
                    })
                    .map_err(|_| SessionError::UnsupportedPayload)?;
                    let stream = tokio::time::timeout(
                        dial_timeout,
                        tokio::net::TcpStream::connect(reconnect_endpoint),
                    )
                    .await
                    .map_err(|_| SessionError::Disconnected)?
                    .map_err(|_| SessionError::Disconnected)?;
                    service.connect(stream).await.map_err(SessionError::from)
                })
            });

            let machine = Session::spawn(
                Machine::new(session_config(&config, target.address.clone())?)?,
                Some(initial),
                Some(connector),
            );
            Ok(Arc::new(ManagedSession {
                inner: Arc::new(machine),
            }) as Arc<dyn ManagerSession>)
        })
    })
}

fn session_config(
    config: &Config,
    target_address: EntityAddr,
) -> Result<SessionConfig, ManagerError> {
    let placeholder =
        EntityAddr::ipv4_v2(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
            .map_err(|_| ManagerError::InvalidConfig)?
            .with_nonce(config.address_nonce);
    let supported = GlobalFeatures::MONITOR_CLIENT
        | GlobalFeatures::MESSAGE_ADDRESS_V2
        | GlobalFeatures::SERVER_OCTOPUS_MASK;
    Ok(SessionConfig {
        limits: config.frame_limits,
        max_queued_messages: 16,
        max_retained_bytes: 1 << 20,
        max_in_flight_transactions: 16,
        max_reconnect_attempts: 2,
        max_handshake_transitions: 16,
        reconnect_policy: ReconnectPolicy::ReplayPending,
        client_ident: ClientIdent {
            addresses: EntityAddrVec(vec![placeholder]),
            target_address,
            global_id: 0,
            global_sequence: 0,
            supported_features: supported.0,
            required_features: (GlobalFeatures::MESSAGE_ADDRESS_V2
                | GlobalFeatures::SERVER_OCTOPUS_MASK)
                .0,
            flags: 0,
            cookie: 0,
        },
        client_cookie: 1,
        server_cookie: 0,
        global_sequence: 0,
        connect_sequence: 0,
        replacement_cookies: vec![2, 3, 4, 5],
    })
}

use crate::msgr::session::Machine;

#[cfg(all(test, not(rados_packaged_source)))]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    type SubmitFn = Arc<
        dyn Fn(watch::Receiver<bool>, Message) -> BoxFuture<'static, Result<Message, SessionError>>
            + Send
            + Sync,
    >;

    struct FakeSource {
        value: std::sync::RwLock<Snapshot>,
    }

    impl StateSource for FakeSource {
        fn snapshot(&self) -> Snapshot {
            self.value
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    struct FakeSession {
        submit: SubmitFn,
        stops: AtomicUsize,
    }

    impl ManagerSession for FakeSession {
        fn submit(
            &self,
            cancel: watch::Receiver<bool>,
            message: Message,
        ) -> BoxFuture<'_, Result<Message, SessionError>> {
            (self.submit)(cancel, message)
        }

        fn stop(&self) {
            self.stops.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn target(epoch: u32, gid: u64, name: &str, endpoint: &str, features: u64) -> ActiveTarget {
        let endpoint: SocketAddr = endpoint.parse().expect("endpoint");
        ActiveTarget {
            epoch,
            gid,
            name: name.to_owned(),
            address: EntityAddr::ipv4_v2(endpoint)
                .expect("address")
                .with_nonce(3),
            features,
        }
    }

    fn config(source: Arc<dyn StateSource>) -> Config {
        Config {
            source,
            authority_slot: Arc::new(std::sync::RwLock::new(None)),
            frame_limits: FrameLimits {
                max_segment_bytes: 8 << 20,
                max_frame_bytes: 32 << 20,
                max_addresses: 64,
                max_auth_bytes: 1 << 20,
            },
            dial_timeout: Duration::from_millis(10),
            handshake_timeout: Duration::from_millis(10),
            allow_crc: false,
            address_nonce: 7,
            message_max_bytes: 1 << 20,
            retry_delay: Duration::from_millis(5),
            max_attempts: 32,
        }
    }

    fn reply(tid: u64, result: i32, status: &str, data: &[u8]) -> Message {
        let mut encoder = crate::wire::Encoder::new(1024);
        encoder.i32(result);
        encoder.string(status);
        let front = encoder.finish().expect("front");
        Message {
            header: crate::msgr::message::MessageHeader {
                transaction_id: tid,
                message_type: messages::MESSAGE_MGR_COMMAND_REPLY,
                version: 1,
                compat_version: 1,
                ..crate::msgr::message::MessageHeader::default()
            },
            lengths: crate::msgr::message::MessageLengths {
                front: u32::try_from(front.len()).expect("front"),
                middle: 0,
                data: u32::try_from(data.len()).expect("data"),
            },
            front,
            middle: Vec::new(),
            data: data.to_vec(),
        }
    }

    #[tokio::test]
    async fn no_active_manager_times_out_with_cancellation() {
        let source = Arc::new(FakeSource {
            value: std::sync::RwLock::new(Snapshot {
                fsid: Some(Fsid([1; 16])),
                target: None,
                unsupported_features: false,
            }),
        });
        let client = ManagerClient::new(
            config(source),
            Some(Arc::new(|_| {
                Box::pin(async { panic!("session must not be created") })
            })),
        )
        .expect("client");
        let cancellation = crate::CancellationToken::new();
        cancellation.cancel();
        let error = client
            .command(
                vec!["{\"prefix\":\"status\"}".to_owned()],
                b"{}".to_vec(),
                OperationOptions::new().with_cancellation(cancellation),
            )
            .await
            .expect_err("cancelled");
        assert_eq!(error, ManagerError::Session(SessionError::Cancelled));
    }

    #[tokio::test]
    async fn preserves_errno_status_and_output() {
        let source = Arc::new(FakeSource {
            value: std::sync::RwLock::new(Snapshot {
                fsid: Some(Fsid([2; 16])),
                target: Some(target(
                    42,
                    7,
                    "active",
                    "192.0.2.50:7000",
                    GlobalFeatures::SERVER_OCTOPUS_MASK.0,
                )),
                unsupported_features: false,
            }),
        });
        let factory: SessionFactory = Arc::new(|_| {
            Box::pin(async {
                Ok(Arc::new(FakeSession {
                    submit: Arc::new(|_, message| {
                        Box::pin(async move {
                            Ok(reply(
                                message.header.transaction_id,
                                -13,
                                "operation not permitted",
                                b"audit-log",
                            ))
                        })
                    }),
                    stops: AtomicUsize::new(0),
                }) as Arc<dyn ManagerSession>)
            })
        });
        let client = ManagerClient::new(config(source), Some(factory)).expect("client");
        let (reply, error) = client
            .command(
                vec!["{\"prefix\":\"status\"}".to_owned()],
                b"{}".to_vec(),
                OperationOptions::new(),
            )
            .await
            .expect("command result");
        assert_eq!(reply.status, "operation not permitted");
        assert_eq!(reply.data, b"audit-log");
        assert_eq!(error, Some(ManagerError::WireErrno(-13)));
    }

    #[tokio::test]
    async fn non_negative_manager_result_is_success() {
        let source = Arc::new(FakeSource {
            value: std::sync::RwLock::new(Snapshot {
                fsid: Some(Fsid([9; 16])),
                target: Some(target(
                    42,
                    7,
                    "active",
                    "192.0.2.50:7000",
                    GlobalFeatures::SERVER_OCTOPUS_MASK.0,
                )),
                unsupported_features: false,
            }),
        });
        let factory: SessionFactory = Arc::new(|_| {
            Box::pin(async {
                Ok(Arc::new(FakeSession {
                    submit: Arc::new(|_, message| {
                        Box::pin(async move {
                            Ok(reply(message.header.transaction_id, 7, "ok", b"payload"))
                        })
                    }),
                    stops: AtomicUsize::new(0),
                }) as Arc<dyn ManagerSession>)
            })
        });
        let client = ManagerClient::new(config(source), Some(factory)).expect("client");
        let (reply, error) = client
            .command(
                vec!["{\"prefix\":\"status\"}".to_owned()],
                b"{}".to_vec(),
                OperationOptions::new(),
            )
            .await
            .expect("command result");
        assert_eq!(reply.result, 7);
        assert_eq!(reply.status, "ok");
        assert_eq!(reply.data, b"payload");
        assert_eq!(error, None);
    }

    #[tokio::test]
    async fn rejects_tid_mismatch() {
        let source = Arc::new(FakeSource {
            value: std::sync::RwLock::new(Snapshot {
                fsid: Some(Fsid([3; 16])),
                target: Some(target(
                    42,
                    7,
                    "active",
                    "192.0.2.50:7000",
                    GlobalFeatures::SERVER_OCTOPUS_MASK.0,
                )),
                unsupported_features: false,
            }),
        });
        let factory: SessionFactory = Arc::new(|_| {
            Box::pin(async {
                Ok(Arc::new(FakeSession {
                    submit: Arc::new(|_, message| {
                        Box::pin(async move {
                            Ok(reply(message.header.transaction_id + 1, 0, "ok", b""))
                        })
                    }),
                    stops: AtomicUsize::new(0),
                }) as Arc<dyn ManagerSession>)
            })
        });
        let client = ManagerClient::new(config(source), Some(factory)).expect("client");
        let error = client
            .command(
                vec!["{\"prefix\":\"status\"}".to_owned()],
                b"{}".to_vec(),
                OperationOptions::new(),
            )
            .await
            .expect_err("tid mismatch");
        assert!(matches!(error, ManagerError::Message(_)));
    }

    #[tokio::test]
    async fn postdispatch_cancellation_returns_outcome_unknown_without_replay() {
        let source = Arc::new(FakeSource {
            value: std::sync::RwLock::new(Snapshot {
                fsid: Some(Fsid([4; 16])),
                target: Some(target(
                    42,
                    7,
                    "active",
                    "192.0.2.50:7000",
                    GlobalFeatures::SERVER_OCTOPUS_MASK.0,
                )),
                unsupported_features: false,
            }),
        });
        let attempts = Arc::new(AtomicUsize::new(0));
        let factory: SessionFactory = Arc::new({
            let attempts = Arc::clone(&attempts);
            move |_| {
                let attempts = Arc::clone(&attempts);
                Box::pin(async move {
                    Ok(Arc::new(FakeSession {
                        submit: Arc::new(move |mut cancel, _| {
                            let attempts = Arc::clone(&attempts);
                            Box::pin(async move {
                                attempts.fetch_add(1, Ordering::Relaxed);
                                loop {
                                    if *cancel.borrow() {
                                        return Err(SessionError::OutcomeUnknown);
                                    }
                                    if cancel.changed().await.is_err() {
                                        return Err(SessionError::OutcomeUnknown);
                                    }
                                }
                            })
                        }),
                        stops: AtomicUsize::new(0),
                    }) as Arc<dyn ManagerSession>)
                })
            }
        });

        let client = Arc::new(ManagerClient::new(config(source), Some(factory)).expect("client"));
        let cancellation = crate::CancellationToken::new();
        let pending = tokio::spawn({
            let client = Arc::clone(&client);
            let cancellation = cancellation.clone();
            async move {
                client
                    .command(
                        vec!["{\"prefix\":\"mutating\"}".to_owned()],
                        b"{}".to_vec(),
                        OperationOptions::new().with_cancellation(cancellation),
                    )
                    .await
            }
        });
        tokio::task::yield_now().await;
        cancellation.cancel();
        assert_eq!(
            pending.await.expect("join").expect_err("unknown outcome"),
            ManagerError::Session(SessionError::OutcomeUnknown)
        );
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn predispatch_cancellation_reports_cancelled() {
        let source = Arc::new(FakeSource {
            value: std::sync::RwLock::new(Snapshot {
                fsid: Some(Fsid([5; 16])),
                target: Some(target(
                    42,
                    7,
                    "active",
                    "192.0.2.50:7000",
                    GlobalFeatures::SERVER_OCTOPUS_MASK.0,
                )),
                unsupported_features: false,
            }),
        });
        let factory: SessionFactory = Arc::new(|_| {
            Box::pin(async {
                Ok(Arc::new(FakeSession {
                    submit: Arc::new(|mut cancel, _| {
                        Box::pin(async move {
                            loop {
                                if *cancel.borrow() {
                                    return Err(SessionError::Cancelled);
                                }
                                if cancel.changed().await.is_err() {
                                    return Err(SessionError::Cancelled);
                                }
                            }
                        })
                    }),
                    stops: AtomicUsize::new(0),
                }) as Arc<dyn ManagerSession>)
            })
        });
        let client = Arc::new(ManagerClient::new(config(source), Some(factory)).expect("client"));
        let cancellation = crate::CancellationToken::new();
        let pending = tokio::spawn({
            let client = Arc::clone(&client);
            let cancellation = cancellation.clone();
            async move {
                client
                    .command(
                        vec!["{\"prefix\":\"status\"}".to_owned()],
                        b"{}".to_vec(),
                        OperationOptions::new().with_cancellation(cancellation),
                    )
                    .await
            }
        });
        tokio::task::yield_now().await;
        cancellation.cancel();
        assert_eq!(
            pending.await.expect("join").expect_err("cancelled"),
            ManagerError::Session(SessionError::Cancelled)
        );
    }

    #[tokio::test]
    async fn deadline_cancellation_reports_cancelled_when_submit_confirms_cancel() {
        let source = Arc::new(FakeSource {
            value: std::sync::RwLock::new(Snapshot {
                fsid: Some(Fsid([6; 16])),
                target: Some(target(
                    42,
                    7,
                    "active",
                    "192.0.2.50:7000",
                    GlobalFeatures::SERVER_OCTOPUS_MASK.0,
                )),
                unsupported_features: false,
            }),
        });
        let factory: SessionFactory = Arc::new(|_| {
            Box::pin(async {
                Ok(Arc::new(FakeSession {
                    submit: Arc::new(|mut cancel, _| {
                        Box::pin(async move {
                            loop {
                                if *cancel.borrow() {
                                    return Err(SessionError::Cancelled);
                                }
                                if cancel.changed().await.is_err() {
                                    return Err(SessionError::Cancelled);
                                }
                            }
                        })
                    }),
                    stops: AtomicUsize::new(0),
                }) as Arc<dyn ManagerSession>)
            })
        });
        let client = ManagerClient::new(config(source), Some(factory)).expect("client");
        let error = client
            .command(
                vec!["{\"prefix\":\"status\"}".to_owned()],
                b"{}".to_vec(),
                OperationOptions::new()
                    .with_timeout(Duration::from_millis(1))
                    .expect("timeout"),
            )
            .await
            .expect_err("deadline cancellation");
        assert_eq!(error, ManagerError::Session(SessionError::Cancelled));
    }

    #[tokio::test(start_paused = true)]
    async fn target_recheck_waits_for_retry_delay() {
        let source = Arc::new(FakeSource {
            value: std::sync::RwLock::new(Snapshot {
                fsid: Some(Fsid([7; 16])),
                target: Some(target(
                    43,
                    8,
                    "replacement",
                    "192.0.2.51:7000",
                    GlobalFeatures::SERVER_OCTOPUS_MASK.0,
                )),
                unsupported_features: false,
            }),
        });
        let mut client_config = config(source);
        client_config.retry_delay = Duration::from_millis(5);
        let client = Arc::new(ManagerClient::new(client_config, None).expect("client"));
        let session = Arc::new(FakeSession {
            submit: Arc::new(|mut cancel, _| {
                Box::pin(async move {
                    while !*cancel.borrow() {
                        cancel
                            .changed()
                            .await
                            .map_err(|_| SessionError::Cancelled)?;
                    }
                    Err(SessionError::Cancelled)
                })
            }),
            stops: AtomicUsize::new(0),
        });
        let active = SessionEntry {
            target: target(
                42,
                7,
                "active",
                "192.0.2.50:7000",
                GlobalFeatures::SERVER_OCTOPUS_MASK.0,
            ),
            session,
        };
        let pending = tokio::spawn({
            let client = Arc::clone(&client);
            async move {
                client
                    .submit_pending_aware(
                        active,
                        reply(1, 0, "unused", b""),
                        &OperationOptions::new(),
                    )
                    .await
            }
        });

        tokio::task::yield_now().await;
        assert!(!pending.is_finished());
        tokio::time::advance(Duration::from_millis(4)).await;
        assert!(!pending.is_finished());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(matches!(pending.await.expect("join"), Ok(None)));
    }

    #[test]
    fn transaction_id_overflow_is_terminal() {
        let source = Arc::new(FakeSource {
            value: std::sync::RwLock::new(Snapshot {
                fsid: Some(Fsid([8; 16])),
                target: None,
                unsupported_features: false,
            }),
        });
        let client = ManagerClient::new(config(source), None).expect("client");
        client
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .next_tid = u64::MAX;

        assert_eq!(client.next_transaction_id(), Ok(u64::MAX));
        assert_eq!(
            client.next_transaction_id(),
            Err(ManagerError::Session(SessionError::TransitionLimit))
        );
        assert_eq!(
            client.next_transaction_id(),
            Err(ManagerError::Session(SessionError::TransitionLimit))
        );
    }

    #[test]
    fn authority_source_observes_rotation() {
        let authority = |global_id| {
            let credential = crate::cephx::parse_key(
                "client.test",
                "AQB7AAAAyAEAABAAMTIzNDU2Nzg5MDEyMzQ1Ng==",
                64,
            )
            .expect("credential");
            let target_address =
                EntityAddr::ipv4_v2("127.0.0.1:3300".parse().expect("socket")).expect("address");
            Arc::new(
                crate::cephx::connector::MonitorConnector::new(crate::cephx::connector::Config {
                    credential,
                    target_address,
                    message_limits: FrameLimits {
                        max_segment_bytes: 8 << 20,
                        max_frame_bytes: 32 << 20,
                        max_addresses: 64,
                        max_auth_bytes: 1 << 20,
                    },
                    cephx_limits: crate::cephx::crypto::Limits::default(),
                    handshake_timeout: Duration::from_secs(1),
                    max_banner_payload: 64,
                    requested_keys: crate::cephx::core::SERVICE_AUTH,
                    allow_crc: false,
                    global_id,
                    old_ticket: crate::cephx::core::TicketBlob {
                        secret_id: 0,
                        blob: Vec::new(),
                    },
                    now: Arc::new(|| Duration::from_secs(0)),
                    challenge: Arc::new(|| Ok(1)),
                })
                .expect("connector"),
            )
        };
        let first = authority(1);
        let second = authority(2);
        let slot = Arc::new(std::sync::RwLock::new(Some(Arc::clone(&first))));
        let source = authority_source_from_slot(Arc::clone(&slot));
        let first_seen = source().expect("first authority");
        *slot
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&second));
        let second_seen = source().expect("second authority");
        assert!(Arc::ptr_eq(&first_seen, &first));
        assert!(Arc::ptr_eq(&second_seen, &second));
    }
}
