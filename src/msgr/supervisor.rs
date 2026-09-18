use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{Mutex, mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};

use super::control::Control;
use super::message::Message;
use super::session::{Effect, Event as SessionEvent, Input, Machine, SessionError, Snapshot};
use super::transport::{Codec, Connection, Event as TransportEvent, IoStream};

pub(crate) struct ConnectionSetup {
    pub(crate) stream: Box<dyn IoStream>,
    pub(crate) codec: Codec,
    pub(crate) requires_identification: bool,
    pub(crate) authenticated_global_id: Option<u64>,
    pub(crate) credential_identity: Option<[u8; 32]>,
    pub(crate) renewal_after: Option<Duration>,
}

pub(crate) type ConnectFuture =
    Pin<Box<dyn Future<Output = Result<ConnectionSetup, SessionError>> + Send>>;
pub(crate) type Connector = Arc<dyn Fn() -> ConnectFuture + Send + Sync>;

enum Command {
    Admit {
        request_id: u64,
        message: Message,
        one_way: bool,
        admitted: oneshot::Sender<Result<u64, SessionError>>,
        result: oneshot::Sender<Result<Option<Message>, SessionError>>,
    },
    Cancel {
        request_id: u64,
    },
    ConsumeIncoming,
    RenewalDue,
    Snapshot {
        result: oneshot::Sender<Snapshot>,
    },
}

struct Response {
    admitted: Option<oneshot::Sender<Result<u64, SessionError>>>,
    result: oneshot::Sender<Result<Option<Message>, SessionError>>,
}

struct ConnectResult {
    generation: u64,
    result: Result<ConnectionSetup, SessionError>,
}

pub(crate) struct Session {
    commands: mpsc::Sender<Command>,
    events: Mutex<mpsc::Receiver<SessionEvent>>,
    incoming: Mutex<mpsc::Receiver<Message>>,
    terminal: watch::Receiver<Option<SessionError>>,
    stop: watch::Sender<bool>,
    next_request_id: AtomicU64,
    owner: Mutex<Option<JoinHandle<()>>>,
}

pub(crate) struct Request {
    id: u64,
    transaction_id: u64,
    commands: mpsc::Sender<Command>,
    result: Option<oneshot::Receiver<Result<Option<Message>, SessionError>>>,
    cancel_on_drop: bool,
}

struct AdmissionGuard {
    request_id: u64,
    commands: mpsc::Sender<Command>,
    armed: bool,
}

impl Session {
    pub(crate) fn spawn(
        machine: Machine,
        initial: Option<ConnectionSetup>,
        connector: Option<Connector>,
    ) -> Self {
        let capacity = machine.queue_limit();
        let (commands, command_rx) = mpsc::channel(capacity);
        let (events_tx, events) = mpsc::channel(capacity);
        let (incoming_tx, incoming) = mpsc::channel(capacity);
        let (terminal_tx, terminal) = watch::channel(None);
        let (stop, stop_rx) = watch::channel(false);
        let owner = tokio::spawn(run_owner(
            machine,
            initial,
            connector,
            OwnerChannels {
                commands: command_rx,
                events: events_tx,
                incoming: incoming_tx,
                terminal: terminal_tx,
                stop: stop_rx,
            },
        ));
        Self {
            commands,
            events: Mutex::new(events),
            incoming: Mutex::new(incoming),
            terminal,
            stop,
            next_request_id: AtomicU64::new(1),
            owner: Mutex::new(Some(owner)),
        }
    }

    pub(crate) async fn admit(
        &self,
        message: Message,
        one_way: bool,
    ) -> Result<Request, SessionError> {
        let request_id = self
            .next_request_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| SessionError::TransitionLimit)?;
        let (admitted_tx, admitted_rx) = oneshot::channel();
        let (result_tx, result) = oneshot::channel();
        self.commands
            .try_send(Command::Admit {
                request_id,
                message,
                one_way,
                admitted: admitted_tx,
                result: result_tx,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => SessionError::QueueSaturated,
                mpsc::error::TrySendError::Closed(_) => SessionError::Closed,
            })?;
        let mut guard = AdmissionGuard {
            request_id,
            commands: self.commands.clone(),
            armed: true,
        };
        let transaction_id = admitted_rx.await.map_err(|_| SessionError::Closed)??;
        guard.armed = false;
        Ok(Request {
            id: request_id,
            transaction_id,
            commands: self.commands.clone(),
            result: Some(result),
            cancel_on_drop: false,
        })
    }

    pub(crate) async fn snapshot(&self) -> Result<Snapshot, SessionError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.commands
            .send(Command::Snapshot { result: result_tx })
            .await
            .map_err(|_| SessionError::Closed)?;
        result_rx.await.map_err(|_| SessionError::Closed)
    }

    pub(crate) async fn renewal_due(&self) -> Result<(), SessionError> {
        self.commands
            .send(Command::RenewalDue)
            .await
            .map_err(|_| SessionError::Closed)
    }

    pub(crate) async fn next_event(&self) -> Option<SessionEvent> {
        self.events.lock().await.recv().await
    }

    pub(crate) async fn next_incoming(&self) -> Option<Message> {
        let message = self.incoming.lock().await.recv().await;
        if message.is_some() {
            let command = Command::ConsumeIncoming;
            if let Err(mpsc::error::TrySendError::Full(command)) = self.commands.try_send(command) {
                let commands = self.commands.clone();
                tokio::spawn(async move {
                    let _ = commands.send(command).await;
                });
            }
        }
        message
    }

    pub(crate) fn terminal(&self) -> Option<SessionError> {
        *self.terminal.borrow()
    }

    pub(crate) fn close(&self) {
        let _ = self.stop.send(true);
    }

    pub(crate) async fn shutdown(&self) {
        self.close();
        let mut owner = self.owner.lock().await;
        if let Some(task) = owner.as_mut() {
            let _ = task.await;
        }
        *owner = None;
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.close();
    }
}

impl Request {
    pub(crate) fn transaction_id(&self) -> u64 {
        self.transaction_id
    }

    pub(crate) fn cancel_on_drop(&mut self) {
        self.cancel_on_drop = true;
    }

    pub(crate) async fn result(mut self) -> Result<Option<Message>, SessionError> {
        let outcome = self
            .result
            .as_mut()
            .ok_or(SessionError::Closed)?
            .await
            .map_err(|_| SessionError::Closed)?;
        self.cancel_on_drop = false;
        self.result = None;
        outcome
    }

    pub(crate) async fn cancel(mut self) -> Result<Option<Message>, SessionError> {
        self.cancel_on_drop = false;
        self.commands
            .send(Command::Cancel {
                request_id: self.id,
            })
            .await
            .map_err(|_| SessionError::Closed)?;
        self.result
            .take()
            .ok_or(SessionError::Closed)?
            .await
            .map_err(|_| SessionError::Closed)?
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        if self.cancel_on_drop && self.result.is_some() {
            enqueue_cancel(&self.commands, self.id);
        }
    }
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        if self.armed {
            enqueue_cancel(&self.commands, self.request_id);
        }
    }
}

fn enqueue_cancel(commands: &mpsc::Sender<Command>, request_id: u64) {
    let command = Command::Cancel { request_id };
    if let Err(mpsc::error::TrySendError::Full(command)) = commands.try_send(command) {
        let commands = commands.clone();
        tokio::spawn(async move {
            let _ = commands.send(command).await;
        });
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use std::io::Cursor;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;
    use crate::msgr::control::{ClientIdent, ServerIdent};
    use crate::msgr::frame::{CrcCodec, Limits, Tag};
    use crate::msgr::message::{MessageHeader, MessageLengths};
    use crate::msgr::session::{Config, ReconnectPolicy};
    use crate::protocol::address::{EntityAddr, EntityAddrVec};
    use crate::wire::Decoder;

    const LIMITS: Limits = Limits {
        max_segment_bytes: 4096,
        max_frame_bytes: 8192,
        max_addresses: 4,
        max_auth_bytes: 64,
    };

    fn address() -> EntityAddr {
        let encoded = [
            0x01, 0x01, 0x01, 0x1c, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
            0x04, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0c, 0xe4, 0xc0, 0x00, 0x02, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut decoder = Decoder::new(&encoded, encoded.len());
        EntityAddr::decode(&mut decoder).expect("test address")
    }

    fn machine(max_queued_messages: usize) -> Machine {
        machine_with_server_cookie(max_queued_messages, 2)
    }

    fn machine_with_server_cookie(max_queued_messages: usize, server_cookie: u64) -> Machine {
        let address = address();
        Machine::new(Config {
            limits: LIMITS,
            max_queued_messages,
            max_retained_bytes: 8192,
            max_in_flight_transactions: 1,
            max_reconnect_attempts: 3,
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
            server_cookie,
            global_sequence: 0,
            connect_sequence: 0,
            replacement_cookies: vec![3, 4, 5],
        })
        .expect("valid machine")
    }

    fn message(payload: &[u8]) -> Message {
        Message {
            lengths: MessageLengths {
                front: u32::try_from(payload.len()).expect("test payload"),
                ..MessageLengths::default()
            },
            front: payload.to_vec(),
            ..Message::default()
        }
    }

    fn setup(stream: impl IoStream) -> ConnectionSetup {
        ConnectionSetup {
            stream: Box::new(stream),
            codec: Codec::Crc(CrcCodec {
                with_data_crc: true,
            }),
            requires_identification: false,
            authenticated_global_id: None,
            credential_identity: None,
            renewal_after: None,
        }
    }

    #[tokio::test]
    async fn authenticated_initial_connection_identifies_before_ready() {
        let codec = CrcCodec {
            with_data_crc: true,
        };
        let (client, mut server) = duplex(8192);
        let mut connection = setup(client);
        connection.requires_identification = true;
        connection.authenticated_global_id = Some(42);
        let session = Session::spawn(machine_with_server_cookie(4, 0), Some(connection), None);

        let frame = codec
            .read_async(&mut server, LIMITS)
            .await
            .expect("client identification frame");
        assert!(matches!(
            Control::decode(&frame, LIMITS),
            Ok(Control::ClientIdent(ClientIdent { global_id: 42, .. }))
        ));
        assert_eq!(
            session.snapshot().await.expect("connecting snapshot").state,
            super::super::session::State::Connecting
        );

        let target = address();
        let reply = Control::ServerIdent(ServerIdent {
            addresses: EntityAddrVec(vec![target]),
            global_id: 7,
            global_sequence: 1,
            supported_features: 0,
            required_features: 0,
            flags: 0,
            cookie: 9,
        })
        .encode(LIMITS)
        .expect("server identification");
        server
            .write_all(&codec.encode(&reply, LIMITS).expect("server wire"))
            .await
            .expect("inject server identification");

        loop {
            if matches!(
                session.next_event().await,
                Some(SessionEvent::StateChanged(
                    super::super::session::State::Ready
                ))
            ) {
                break;
            }
        }
        session.shutdown().await;
    }

    #[tokio::test]
    async fn unpolled_admission_has_no_effect_and_queue_is_bounded() {
        let (client, _server) = duplex(256);
        let session = Session::spawn(machine(1), Some(setup(client)), None);
        let unpolled = session.admit(message(b"not admitted"), false);
        drop(unpolled);
        assert_eq!(session.snapshot().await.expect("snapshot").queued, 0);

        let first = session
            .admit(message(b"first"), false)
            .await
            .expect("first");
        assert!(matches!(
            session.admit(message(b"second"), false).await,
            Err(SessionError::QueueSaturated)
        ));
        drop(first);
        session.shutdown().await;
    }

    #[tokio::test]
    async fn dropped_admitted_request_remains_supervised_until_reply() {
        let codec = CrcCodec {
            with_data_crc: true,
        };
        let (client, mut server) = duplex(8192);
        let session = Session::spawn(machine(4), Some(setup(client)), None);
        let request = session
            .admit(message(b"owned"), false)
            .await
            .expect("admit");
        let transaction_id = request.transaction_id();
        drop(request);

        let sent = codec
            .read_async(&mut server, LIMITS)
            .await
            .expect("request frame");
        assert_eq!(sent.tag, Tag::Message);
        let response = Message {
            header: MessageHeader {
                sequence: 1,
                transaction_id,
                ..MessageHeader::default()
            },
            ..Message::default()
        };
        let wire = codec
            .encode(&response.encode(LIMITS).expect("response frame"), LIMITS)
            .expect("response wire");
        server.write_all(&wire).await.expect("inject response");
        let ack = codec
            .read_async(&mut server, LIMITS)
            .await
            .expect("ack frame");
        assert_eq!(ack.tag, Tag::Ack);

        let snapshot = session.snapshot().await.expect("snapshot");
        assert_eq!(snapshot.queued, 0);
        assert_eq!(snapshot.in_flight, 0);
        assert_eq!(snapshot.retained_bytes, 0);
        session.shutdown().await;
    }

    #[tokio::test]
    async fn cancel_on_drop_releases_read_only_request_state() {
        let connector: Connector = Arc::new(|| Box::pin(std::future::pending()));
        let session = Session::spawn(machine(4), None, Some(connector));
        let mut request = session
            .admit(message(b"read-only"), false)
            .await
            .expect("admit");
        request.cancel_on_drop();
        drop(request);
        tokio::task::yield_now().await;

        let snapshot = session.snapshot().await.expect("snapshot");
        assert_eq!(snapshot.queued, 0);
        assert_eq!(snapshot.in_flight, 0);
        assert_eq!(snapshot.retained_bytes, 0);
        session.shutdown().await;
    }

    #[tokio::test]
    async fn cancel_on_drop_while_awaiting_result_releases_request_state() {
        let connector: Connector = Arc::new(|| Box::pin(std::future::pending()));
        let session = Arc::new(Session::spawn(machine(4), None, Some(connector)));
        let mut request = session
            .admit(message(b"read-only"), false)
            .await
            .expect("admit");
        request.cancel_on_drop();
        let task = tokio::spawn(async move { request.result().await });
        tokio::task::yield_now().await;
        task.abort();
        let _ = task.await;
        tokio::task::yield_now().await;

        let snapshot = session.snapshot().await.expect("snapshot");
        assert_eq!(snapshot.queued, 0);
        assert_eq!(snapshot.in_flight, 0);
        assert_eq!(snapshot.retained_bytes, 0);
        session.shutdown().await;
    }

    #[tokio::test]
    async fn explicit_cancel_distinguishes_unsent_and_dispatched_work() {
        let connector: Connector = Arc::new(|| Box::pin(std::future::pending()));
        let disconnected = Session::spawn(machine(4), None, Some(connector));
        let unsent = disconnected
            .admit(message(b"unsent"), false)
            .await
            .expect("admit unsent");
        assert_eq!(unsent.cancel().await, Err(SessionError::Cancelled));
        disconnected.shutdown().await;

        let (client, _server) = duplex(1);
        let dispatched = Session::spawn(machine(4), Some(setup(client)), None);
        let request = dispatched
            .admit(message(&[7; 128]), false)
            .await
            .expect("admit dispatched");
        assert_eq!(request.cancel().await, Err(SessionError::OutcomeUnknown));
        dispatched.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_interrupts_blocked_read_and_write_and_joins_owner() {
        let (client, _server) = duplex(1);
        let session = Session::spawn(machine(4), Some(setup(client)), None);
        let request = session
            .admit(message(&[9; 512]), false)
            .await
            .expect("admit blocked write");
        drop(request);
        session.shutdown().await;
        assert!(matches!(
            session.terminal(),
            None | Some(SessionError::Closed)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn renewal_due_reaches_the_owner_machine() {
        let (client, _server) = duplex(256);
        let mut connection = setup(client);
        connection.renewal_after = Some(Duration::from_secs(10));
        let session = Session::spawn(machine(4), Some(connection), None);
        assert!(matches!(
            session.next_event().await,
            Some(SessionEvent::StateChanged(
                super::super::session::State::Ready
            ))
        ));

        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(
            session.next_event().await,
            Some(SessionEvent::CredentialRenewal)
        );
        session.shutdown().await;
    }

    #[tokio::test]
    async fn event_overflow_is_reported_cumulatively() {
        let (events, mut event_rx) = mpsc::channel(1);
        let (incoming, _) = mpsc::channel(1);
        let (transport_events, _) = mpsc::channel(1);
        let (connect_results, _) = mpsc::channel(1);
        let (terminal, _) = watch::channel(None);
        let (connector_stop, _) = watch::channel(false);
        let mut owner = Owner {
            machine: machine(1),
            connector: None,
            connection: None,
            responses: HashMap::new(),
            events,
            incoming,
            transport_events,
            connect_results,
            terminal,
            connector_stop,
            connectors: JoinSet::new(),
            dropped_events: 0,
            unreported_dropped_events: 0,
        };

        owner.emit_event(SessionEvent::KeepaliveAck);
        owner.emit_event(SessionEvent::Wait);
        assert_eq!(event_rx.recv().await, Some(SessionEvent::KeepaliveAck));
        owner.emit_event(SessionEvent::CredentialRenewal);
        assert_eq!(
            event_rx.recv().await,
            Some(SessionEvent::EventsDropped { count: 1 })
        );
        assert_eq!(owner.dropped_events, 2);
        assert_eq!(owner.unreported_dropped_events, 1);
    }

    #[tokio::test]
    async fn connector_panic_becomes_a_bounded_terminal_failure() {
        let connector: Connector = Arc::new(|| -> ConnectFuture {
            panic!("scripted connector panic");
        });
        let session = Session::spawn(machine(1), None, Some(connector));
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if session.terminal() == Some(SessionError::ReconnectExhausted) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("connector panic reaches terminal state");
        session.shutdown().await;
    }

    #[tokio::test]
    async fn stale_reader_writer_and_connector_results_are_ignored() {
        let mut machine = machine(4);
        assert_eq!(
            machine.step(Input::Start { ready: false }),
            vec![Effect::Connect { generation: 1 }]
        );
        let (events, _) = mpsc::channel(4);
        let (incoming, _) = mpsc::channel(4);
        let (transport_events, _) = mpsc::channel(4);
        let (connect_results, _) = mpsc::channel(4);
        let (terminal, _) = watch::channel(None);
        let (connector_stop, _) = watch::channel(false);
        let mut owner = Owner {
            machine,
            connector: None,
            connection: None,
            responses: HashMap::new(),
            events,
            incoming,
            transport_events,
            connect_results,
            terminal,
            connector_stop,
            connectors: JoinSet::new(),
            dropped_events: 0,
            unreported_dropped_events: 0,
        };
        let before = owner.machine.snapshot();
        owner
            .transport_event(TransportEvent::Fault {
                generation: 0,
                error: SessionError::Disconnected,
            })
            .await;
        owner
            .transport_event(TransportEvent::WriteComplete {
                generation: 0,
                request_id: None,
                result: Ok(()),
            })
            .await;
        assert_eq!(owner.machine.snapshot(), before);

        let (client, mut server) = duplex(16);
        owner
            .connected(ConnectResult {
                generation: 0,
                result: Ok(setup(client)),
            })
            .await;
        assert!(owner.connection.is_none());
        assert_eq!(owner.machine.snapshot().generation, 1);
        let mut byte = [0];
        assert_eq!(server.read(&mut byte).await.expect("stale peer closes"), 0);
    }

    #[test]
    fn synchronous_codec_still_accepts_supervisor_frames() {
        let codec = CrcCodec {
            with_data_crc: true,
        };
        let message = message(b"sync");
        let expected = message.clone().encode(LIMITS).expect("frame");
        let wire = codec.encode(&expected, LIMITS).expect("wire");
        let decoded = codec.read(&mut Cursor::new(wire), LIMITS).expect("decode");
        assert_eq!(Message::decode(&decoded, LIMITS), Ok(message));
    }
}

struct Owner {
    machine: Machine,
    connector: Option<Connector>,
    connection: Option<(u64, Connection)>,
    responses: HashMap<u64, Response>,
    events: mpsc::Sender<SessionEvent>,
    incoming: mpsc::Sender<Message>,
    transport_events: mpsc::Sender<TransportEvent>,
    connect_results: mpsc::Sender<ConnectResult>,
    terminal: watch::Sender<Option<SessionError>>,
    connector_stop: watch::Sender<bool>,
    connectors: JoinSet<()>,
    dropped_events: u64,
    unreported_dropped_events: u64,
}

struct OwnerChannels {
    commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<SessionEvent>,
    incoming: mpsc::Sender<Message>,
    terminal: watch::Sender<Option<SessionError>>,
    stop: watch::Receiver<bool>,
}

async fn run_owner(
    machine: Machine,
    initial: Option<ConnectionSetup>,
    connector: Option<Connector>,
    channels: OwnerChannels,
) {
    let OwnerChannels {
        mut commands,
        events,
        incoming,
        terminal,
        mut stop,
    } = channels;
    let capacity = machine.queue_limit();
    let (transport_events, mut transport_rx) = mpsc::channel(capacity);
    let (connect_results, mut connect_rx) = mpsc::channel(capacity);
    let (connector_stop, _) = watch::channel(false);
    let mut owner = Owner {
        machine,
        connector,
        connection: None,
        responses: HashMap::new(),
        events,
        incoming,
        transport_events,
        connect_results,
        terminal,
        connector_stop,
        connectors: JoinSet::new(),
        dropped_events: 0,
        unreported_dropped_events: 0,
    };

    if let Some(setup) = initial {
        let effects = if setup.requires_identification {
            owner.machine.step(Input::InitialConnection {
                authenticated_global_id: setup.authenticated_global_id,
                credential_identity: setup.credential_identity,
            })
        } else {
            let mut effects = owner.machine.step(Input::Start { ready: true });
            let generation = owner.machine.snapshot().generation;
            effects.extend(owner.machine.step(Input::InitialIdentity {
                generation,
                authenticated_global_id: setup.authenticated_global_id,
                credential_identity: setup.credential_identity,
            }));
            effects
        };
        let generation = owner.machine.snapshot().generation;
        owner.install(generation, setup);
        owner.apply(effects).await;
        owner.dispatch().await;
    } else {
        owner.drive(Input::Start { ready: false }).await;
    }

    loop {
        tokio::select! {
            changed = stop.changed() => {
                let _ = changed;
                owner.drive(Input::Stop).await;
                break;
            }
            command = commands.recv() => {
                let Some(command) = command else {
                    owner.drive(Input::Stop).await;
                    break;
                };
                owner.command(command).await;
            }
            event = transport_rx.recv() => {
                if let Some(event) = event {
                    owner.transport_event(event).await;
                }
            }
            result = connect_rx.recv() => {
                if let Some(result) = result {
                    owner.connected(result).await;
                }
            }
            joined = owner.connectors.join_next(), if !owner.connectors.is_empty() => {
                let _ = joined;
            }
        }
    }

    let _ = owner.connector_stop.send(true);
    if let Some((_, connection)) = owner.connection.take() {
        connection.close().await;
    }
    while owner.connectors.join_next().await.is_some() {}
}

impl Owner {
    async fn command(&mut self, command: Command) {
        match command {
            Command::Admit {
                request_id,
                message,
                one_way,
                admitted,
                result,
            } => {
                self.responses.insert(
                    request_id,
                    Response {
                        admitted: Some(admitted),
                        result,
                    },
                );
                self.drive(Input::Admit {
                    request_id,
                    message,
                    one_way,
                })
                .await;
            }
            Command::Cancel { request_id } => {
                self.drive(Input::Cancel { request_id }).await;
            }
            Command::ConsumeIncoming => self.drive(Input::ConsumeIncoming).await,
            Command::RenewalDue => {
                let generation = self.machine.snapshot().generation;
                self.drive(Input::RenewalDue { generation }).await;
            }
            Command::Snapshot { result } => {
                let mut snapshot = self.machine.snapshot();
                snapshot.dropped_events = self.dropped_events;
                let _ = result.send(snapshot);
            }
        }
    }

    async fn transport_event(&mut self, event: TransportEvent) {
        let input = match event {
            TransportEvent::Frame { generation, frame } => {
                if frame.tag == super::frame::Tag::Message {
                    match Message::decode(&frame, self.machine.limits()) {
                        Ok(message) => Input::Message {
                            generation,
                            message,
                        },
                        Err(error) => Input::Fault {
                            generation,
                            error: SessionError::Frame(error),
                        },
                    }
                } else {
                    match Control::decode(&frame, self.machine.limits()) {
                        Ok(control) => Input::Control {
                            generation,
                            control,
                        },
                        Err(error) => Input::Fault {
                            generation,
                            error: SessionError::Frame(error),
                        },
                    }
                }
            }
            TransportEvent::WriteComplete {
                generation,
                request_id,
                result,
            } => Input::WriteComplete {
                generation,
                request_id,
                result,
            },
            TransportEvent::Fault { generation, error } => Input::Fault { generation, error },
            TransportEvent::RenewalDue { generation } => Input::RenewalDue { generation },
        };
        self.drive(input).await;
    }

    async fn connected(&mut self, result: ConnectResult) {
        let current = self.machine.snapshot().generation;
        match result.result {
            Ok(setup) if result.generation == current => {
                let global_id = setup.authenticated_global_id;
                let identity = setup.credential_identity;
                let effects = self.machine.step(Input::Connected {
                    generation: result.generation,
                    authenticated_global_id: global_id,
                    credential_identity: identity,
                });
                let generation = self.machine.snapshot().generation;
                self.install(generation, setup);
                self.apply(effects).await;
                self.dispatch().await;
            }
            Ok(_) => {}
            Err(_) => {
                self.drive(Input::ConnectFailed {
                    generation: result.generation,
                })
                .await;
            }
        }
    }

    fn install(&mut self, generation: u64, setup: ConnectionSetup) {
        self.connection = Some((
            generation,
            Connection::spawn(
                generation,
                setup.stream,
                setup.codec,
                setup.renewal_after,
                self.machine.limits(),
                self.transport_events.clone(),
            ),
        ));
    }

    async fn drive(&mut self, input: Input) {
        let effects = self.machine.step(input);
        self.apply(effects).await;
        self.dispatch().await;
    }

    async fn dispatch(&mut self) {
        loop {
            let effects = self.machine.step(Input::Dispatch);
            if effects.is_empty() {
                return;
            }
            self.apply(effects).await;
        }
    }

    async fn apply(&mut self, effects: Vec<Effect>) {
        let mut pending: VecDeque<Effect> = effects.into();
        while let Some(effect) = pending.pop_front() {
            match effect {
                Effect::Connect { generation } => self.connect(generation),
                Effect::CloseTransport { generation } => {
                    if self
                        .connection
                        .as_ref()
                        .is_some_and(|active| active.0 == generation)
                        && let Some((_, connection)) = self.connection.take()
                    {
                        connection.close().await;
                    }
                }
                Effect::SendControl {
                    generation,
                    control,
                } => match control.encode(self.machine.limits()) {
                    Ok(frame) => self.send(generation, None, frame, &mut pending).await,
                    Err(error) => pending.extend(self.machine.step(Input::WriteComplete {
                        generation,
                        request_id: None,
                        result: Err(SessionError::Frame(error)),
                    })),
                },
                Effect::SendMessage {
                    generation,
                    request_id,
                    message,
                } => match message.encode(self.machine.limits()) {
                    Ok(frame) => {
                        self.send(generation, Some(request_id), frame, &mut pending)
                            .await;
                    }
                    Err(error) => pending.extend(self.machine.step(Input::WriteComplete {
                        generation,
                        request_id: Some(request_id),
                        result: Err(SessionError::Frame(error)),
                    })),
                },
                Effect::Admitted {
                    request_id,
                    transaction_id,
                } => {
                    if let Some(admitted) = self
                        .responses
                        .get_mut(&request_id)
                        .and_then(|response| response.admitted.take())
                    {
                        let _ = admitted.send(Ok(transaction_id));
                    }
                }
                Effect::Completed { request_id, reply } => {
                    if let Some(mut response) = self.responses.remove(&request_id) {
                        if let Some(admitted) = response.admitted.take() {
                            let _ = admitted.send(Ok(0));
                        }
                        let _ = response.result.send(Ok(reply));
                    }
                }
                Effect::Failed { request_id, error } => {
                    if let Some(mut response) = self.responses.remove(&request_id) {
                        if let Some(admitted) = response.admitted.take() {
                            let _ = admitted.send(Err(error));
                        }
                        let _ = response.result.send(Err(error));
                    }
                }
                Effect::Incoming(message) => {
                    if self.incoming.try_send(message).is_err() {
                        pending.extend(self.machine.step(Input::Fault {
                            generation: self.machine.snapshot().generation,
                            error: SessionError::QueueSaturated,
                        }));
                    }
                }
                Effect::Event(event) => {
                    self.emit_event(event);
                }
                Effect::Terminal(error) => {
                    let _ = self.terminal.send(Some(error));
                }
            }
        }
    }

    fn emit_event(&mut self, event: SessionEvent) {
        if self.unreported_dropped_events != 0 {
            match self.events.try_send(SessionEvent::EventsDropped {
                count: self.dropped_events,
            }) {
                Ok(()) => self.unreported_dropped_events = 0,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.dropped_events = self.dropped_events.saturating_add(1);
                    self.unreported_dropped_events =
                        self.unreported_dropped_events.saturating_add(1);
                    return;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => return,
            }
        }
        if matches!(
            self.events.try_send(event),
            Err(mpsc::error::TrySendError::Full(_))
        ) {
            self.dropped_events = self.dropped_events.saturating_add(1);
            self.unreported_dropped_events = self.unreported_dropped_events.saturating_add(1);
        }
    }

    async fn send(
        &mut self,
        generation: u64,
        request_id: Option<u64>,
        frame: super::frame::Frame,
        pending: &mut VecDeque<Effect>,
    ) {
        let result = match self.connection.as_ref() {
            Some((active_generation, connection)) if *active_generation == generation => {
                connection.write(request_id, frame).await
            }
            _ => Err(SessionError::Disconnected),
        };
        if let Err(error) = result {
            pending.extend(self.machine.step(Input::WriteComplete {
                generation,
                request_id,
                result: Err(error),
            }));
        }
    }

    fn connect(&mut self, generation: u64) {
        let connector = self.connector.clone();
        let results = self.connect_results.clone();
        let mut stop = self.connector_stop.subscribe();
        self.connectors.spawn(async move {
            let result = match connector {
                Some(connector) => {
                    let mut task = tokio::spawn(async move { connector().await });
                    tokio::select! {
                        biased;
                        changed = stop.changed() => {
                            let _ = changed;
                            task.abort();
                            let _ = task.await;
                            return;
                        }
                        result = &mut task => result.unwrap_or(Err(SessionError::Disconnected)),
                    }
                }
                None => Err(SessionError::Disconnected),
            };
            tokio::select! {
                biased;
                changed = stop.changed() => {
                    let _ = changed;
                }
                published = results.send(ConnectResult { generation, result }) => {
                    let _ = published;
                }
            }
        });
    }
}
