use std::collections::{HashMap, VecDeque};

use super::control::{
    CONNECTION_FLAG_LOSSY, ClientIdent, Control, ServerIdent, SessionReconnect, SessionReconnectOk,
    SessionReset, SessionRetry, SessionRetryGlobal,
};
use super::frame::{FrameError, Limits};
use super::message::{MESSAGE_HEADER_SIZE, Message};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum State {
    Disconnected,
    Connecting,
    Reconnecting,
    Ready,
    Wait,
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReconnectPolicy {
    FailPending,
    ReplayPending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionError {
    Closed,
    Disconnected,
    Cancelled,
    QueueSaturated,
    TooManyInFlight,
    TransitionLimit,
    ReconnectExhausted,
    OutcomeUnknown,
    Renewal,
    Malformed,
    UnsupportedFeature,
    UnsupportedPayload,
    Frame(FrameError),
}

#[derive(Clone, Debug)]
pub(crate) struct Config {
    pub(crate) limits: Limits,
    pub(crate) max_queued_messages: usize,
    pub(crate) max_retained_bytes: u64,
    pub(crate) max_in_flight_transactions: usize,
    pub(crate) max_reconnect_attempts: usize,
    pub(crate) max_handshake_transitions: usize,
    pub(crate) reconnect_policy: ReconnectPolicy,
    pub(crate) client_ident: ClientIdent,
    pub(crate) client_cookie: u64,
    pub(crate) server_cookie: u64,
    pub(crate) global_sequence: u64,
    pub(crate) connect_sequence: u64,
    pub(crate) replacement_cookies: Vec<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Input {
    Start {
        ready: bool,
    },
    InitialConnection {
        authenticated_global_id: Option<u64>,
        credential_identity: Option<[u8; 32]>,
    },
    InitialIdentity {
        generation: u64,
        authenticated_global_id: Option<u64>,
        credential_identity: Option<[u8; 32]>,
    },
    Admit {
        request_id: u64,
        message: Message,
        one_way: bool,
    },
    Cancel {
        request_id: u64,
    },
    Dispatch,
    WriteComplete {
        generation: u64,
        request_id: Option<u64>,
        result: Result<(), SessionError>,
    },
    Connected {
        generation: u64,
        authenticated_global_id: Option<u64>,
        credential_identity: Option<[u8; 32]>,
    },
    ConnectFailed {
        generation: u64,
    },
    Control {
        generation: u64,
        control: Control,
    },
    Message {
        generation: u64,
        message: Message,
    },
    Fault {
        generation: u64,
        error: SessionError,
    },
    RenewalDue {
        generation: u64,
    },
    ConsumeIncoming,
    Stop,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Event {
    StateChanged(State),
    SequenceGap { sequence: u64, expected: u64 },
    DuplicateDropped { sequence: u64 },
    Acknowledged { sequence: u64 },
    KeepaliveAck,
    TransportFault(SessionError),
    SessionReset { full: bool },
    Retry { sequence: u64 },
    RetryGlobal { sequence: u64 },
    Wait,
    ReconnectOk { sequence: u64 },
    CredentialRenewal,
    CredentialRenewalCompleted,
    EventsDropped { count: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Effect {
    Connect {
        generation: u64,
    },
    CloseTransport {
        generation: u64,
    },
    SendControl {
        generation: u64,
        control: Control,
    },
    SendMessage {
        generation: u64,
        request_id: u64,
        message: Message,
    },
    Admitted {
        request_id: u64,
        transaction_id: u64,
    },
    Completed {
        request_id: u64,
        reply: Option<Message>,
    },
    Failed {
        request_id: u64,
        error: SessionError,
    },
    Incoming(Message),
    Event(Event),
    Terminal(SessionError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Snapshot {
    pub(crate) state: State,
    pub(crate) generation: u64,
    pub(crate) next_outbound_sequence: u64,
    pub(crate) last_inbound_sequence: u64,
    pub(crate) next_transaction_id: u64,
    pub(crate) client_cookie: u64,
    pub(crate) server_cookie: u64,
    pub(crate) server_global_id: i64,
    pub(crate) server_addresses: super::super::protocol::address::EntityAddrVec,
    pub(crate) server_features: u64,
    pub(crate) global_sequence: u64,
    pub(crate) connect_sequence: u64,
    pub(crate) queued: usize,
    pub(crate) in_flight: usize,
    pub(crate) replay: usize,
    pub(crate) retained_bytes: u64,
    pub(crate) reconnect_attempts: usize,
    pub(crate) handshake_transitions: usize,
    pub(crate) dropped_events: u64,
}

#[derive(Clone, Debug)]
struct Pending {
    request_id: u64,
    message: Message,
    bytes: u64,
    sequence: u64,
    sent: bool,
    may_have_executed: bool,
    one_way: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RenewalState {
    Idle,
    Draining,
    Reconnecting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RenewalPending {
    No,
    Yes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CredentialChange {
    Unknown,
    Unchanged,
    Changed,
}

#[derive(Debug)]
pub(crate) struct Machine {
    config: Config,
    state: State,
    generation: u64,
    pending: Vec<Pending>,
    by_transaction: HashMap<u64, u64>,
    replay: Vec<u64>,
    controls: VecDeque<Control>,
    retained_bytes: u64,
    incoming_count: usize,
    write_busy: bool,
    next_outbound: Option<u64>,
    last_inbound: u64,
    next_transaction_id: Option<u64>,
    client_cookie: u64,
    server_cookie: u64,
    server_global_id: i64,
    server_addresses: super::super::protocol::address::EntityAddrVec,
    server_features: u64,
    global_sequence: u64,
    connect_sequence: u64,
    authenticated_global_id: u64,
    credential_identity: Option<[u8; 32]>,
    candidate_credential_identity: Option<[u8; 32]>,
    credential_change: CredentialChange,
    renewal: RenewalState,
    renewal_pending: RenewalPending,
    server_flags: u64,
    connected_once: bool,
    reconnect_attempts: usize,
    transitions: usize,
    connect_pending: bool,
    terminal_error: Option<SessionError>,
    replacement_cookies: VecDeque<u64>,
}

impl Machine {
    pub(crate) fn new(config: Config) -> Result<Self, SessionError> {
        if config.max_queued_messages == 0
            || config.max_retained_bytes == 0
            || config.max_in_flight_transactions == 0
            || config.max_handshake_transitions == 0
            || config.limits.max_segment_bytes == 0
            || config.limits.max_frame_bytes == 0
        {
            return Err(SessionError::Malformed);
        }
        if config.global_sequence != 0
            && config.client_ident.global_sequence != 0
            && config.global_sequence != config.client_ident.global_sequence
        {
            return Err(SessionError::Malformed);
        }
        let global_sequence = config
            .global_sequence
            .max(config.client_ident.global_sequence);
        let client_cookie = config.client_cookie;
        let server_cookie = config.server_cookie;
        let connect_sequence = config.connect_sequence;
        let replacement_cookies = config.replacement_cookies.iter().copied().collect();
        Ok(Self {
            config,
            state: State::Disconnected,
            generation: 0,
            pending: Vec::new(),
            by_transaction: HashMap::new(),
            replay: Vec::new(),
            controls: VecDeque::new(),
            retained_bytes: 0,
            incoming_count: 0,
            write_busy: false,
            next_outbound: Some(1),
            last_inbound: 0,
            next_transaction_id: Some(1),
            client_cookie,
            server_cookie,
            server_global_id: 0,
            server_addresses: super::super::protocol::address::EntityAddrVec(Vec::new()),
            server_features: 0,
            global_sequence,
            connect_sequence,
            authenticated_global_id: 0,
            credential_identity: None,
            candidate_credential_identity: None,
            credential_change: CredentialChange::Unknown,
            renewal: RenewalState::Idle,
            renewal_pending: RenewalPending::No,
            server_flags: 0,
            connected_once: false,
            reconnect_attempts: 0,
            transitions: 0,
            connect_pending: false,
            terminal_error: None,
            replacement_cookies,
        })
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn step(&mut self, input: Input) -> Vec<Effect> {
        let mut effects = Vec::new();
        match input {
            Input::Start { ready } => self.start(ready, &mut effects),
            Input::InitialConnection {
                authenticated_global_id,
                credential_identity,
            } => {
                if self.state == State::Disconnected && !self.connect_pending {
                    self.connect_pending = true;
                    self.connected(
                        self.generation,
                        authenticated_global_id,
                        credential_identity,
                        &mut effects,
                    );
                }
            }
            Input::InitialIdentity {
                generation,
                authenticated_global_id,
                credential_identity,
            } => {
                if generation == self.generation && self.state == State::Ready {
                    if let Some(global_id) = authenticated_global_id {
                        self.authenticated_global_id = global_id;
                    }
                    self.credential_identity = credential_identity;
                }
            }
            Input::Admit {
                request_id,
                message,
                one_way,
            } => self.admit(request_id, message, one_way, &mut effects),
            Input::Cancel { request_id } => self.cancel(request_id, &mut effects),
            Input::Dispatch => self.dispatch(&mut effects),
            Input::WriteComplete {
                generation,
                request_id,
                result,
            } => {
                if generation == self.generation {
                    self.write_busy = false;
                    match result {
                        Ok(()) => {
                            if let Some(request_id) = request_id
                                && self
                                    .pending(request_id)
                                    .is_some_and(|pending| pending.one_way)
                            {
                                self.remove_pending(request_id);
                                effects.push(Effect::Completed {
                                    request_id,
                                    reply: None,
                                });
                            }
                        }
                        Err(error) => self.fault(error, &mut effects),
                    }
                }
            }
            Input::Connected {
                generation,
                authenticated_global_id,
                credential_identity,
            } => self.connected(
                generation,
                authenticated_global_id,
                credential_identity,
                &mut effects,
            ),
            Input::ConnectFailed { generation } => {
                if generation == self.generation && self.connect_pending {
                    self.connect_pending = false;
                    effects.push(Effect::Event(Event::TransportFault(
                        SessionError::Disconnected,
                    )));
                    self.begin_reconnect(&mut effects);
                }
            }
            Input::Control {
                generation,
                control,
            } => {
                if generation == self.generation {
                    self.control(control, &mut effects);
                }
            }
            Input::Message {
                generation,
                message,
            } => {
                if generation == self.generation {
                    self.message(message, &mut effects);
                }
            }
            Input::Fault { generation, error } => {
                if generation == self.generation {
                    self.fault(error, &mut effects);
                }
            }
            Input::RenewalDue { generation } => {
                self.renewal_due(generation, &mut effects);
            }
            Input::ConsumeIncoming => self.incoming_count = self.incoming_count.saturating_sub(1),
            Input::Stop => self.stop(&mut effects),
        }
        effects
    }

    fn renewal_due(&mut self, generation: u64, effects: &mut Vec<Effect>) {
        if generation != self.generation {
            return;
        }
        if self.renewal == RenewalState::Idle {
            self.renewal = RenewalState::Draining;
            effects.push(Effect::Event(Event::CredentialRenewal));
        } else {
            self.renewal_pending = RenewalPending::Yes;
        }
    }

    pub(crate) fn snapshot(&self) -> Snapshot {
        Snapshot {
            state: self.state,
            generation: self.generation,
            next_outbound_sequence: self.next_outbound.unwrap_or(0),
            last_inbound_sequence: self.last_inbound,
            next_transaction_id: self.next_transaction_id.unwrap_or(0),
            client_cookie: self.client_cookie,
            server_cookie: self.server_cookie,
            server_global_id: self.server_global_id,
            server_addresses: self.server_addresses.clone(),
            server_features: self.server_features,
            global_sequence: self.global_sequence,
            connect_sequence: self.connect_sequence,
            queued: self.pending.iter().filter(|pending| !pending.sent).count(),
            in_flight: self.in_flight_count(),
            replay: self.replay.len(),
            retained_bytes: self.retained_bytes,
            reconnect_attempts: self.reconnect_attempts,
            handshake_transitions: self.transitions,
            dropped_events: 0,
        }
    }

    pub(crate) fn limits(&self) -> Limits {
        self.config.limits
    }

    pub(crate) fn queue_limit(&self) -> usize {
        self.config.max_queued_messages
    }

    fn start(&mut self, ready: bool, effects: &mut Vec<Effect>) {
        if self.state != State::Disconnected
            || self.connect_pending
            || self.terminal_error.is_some()
        {
            return;
        }
        if ready {
            self.connected_once = true;
            self.start_transport(State::Ready, effects);
        } else {
            self.begin_reconnect(effects);
        }
    }

    fn admit(
        &mut self,
        request_id: u64,
        mut message: Message,
        one_way: bool,
        effects: &mut Vec<Effect>,
    ) {
        if let Some(error) = self.terminal_error {
            effects.push(Effect::Failed { request_id, error });
            return;
        }
        if self.state == State::Stopped {
            effects.push(Effect::Failed {
                request_id,
                error: SessionError::Closed,
            });
            return;
        }
        let Ok(bytes) = self.admission_bytes(&message) else {
            effects.push(Effect::Failed {
                request_id,
                error: SessionError::Malformed,
            });
            return;
        };
        if self.pending.len() >= self.config.max_queued_messages
            || bytes
                > self
                    .config
                    .max_retained_bytes
                    .saturating_sub(self.retained_bytes)
            || self.pending(request_id).is_some()
        {
            effects.push(Effect::Failed {
                request_id,
                error: SessionError::QueueSaturated,
            });
            return;
        }
        let transaction_id = if message.header.transaction_id == 0 {
            match self.take_transaction_id() {
                Ok(transaction_id) => transaction_id,
                Err(error) => {
                    self.fail_terminal(error, effects);
                    effects.push(Effect::Failed { request_id, error });
                    return;
                }
            }
        } else if self
            .by_transaction
            .contains_key(&message.header.transaction_id)
        {
            effects.push(Effect::Failed {
                request_id,
                error: SessionError::Malformed,
            });
            return;
        } else {
            message.header.transaction_id
        };
        message.header.transaction_id = transaction_id;
        self.pending.push(Pending {
            request_id,
            message,
            bytes,
            sequence: 0,
            sent: false,
            may_have_executed: false,
            one_way,
        });
        self.by_transaction.insert(transaction_id, request_id);
        self.retained_bytes += bytes;
        effects.push(Effect::Admitted {
            request_id,
            transaction_id,
        });
    }

    fn cancel(&mut self, request_id: u64, effects: &mut Vec<Effect>) {
        let Some(may_have_executed) = self
            .pending(request_id)
            .map(|pending| pending.may_have_executed)
        else {
            return;
        };
        self.remove_pending(request_id);
        effects.push(Effect::Failed {
            request_id,
            error: if may_have_executed {
                SessionError::OutcomeUnknown
            } else {
                SessionError::Cancelled
            },
        });
    }

    fn dispatch(&mut self, effects: &mut Vec<Effect>) {
        if self.write_busy
            || matches!(
                self.state,
                State::Disconnected | State::Wait | State::Stopped
            )
        {
            return;
        }
        if let Some(control) = self.controls.pop_front() {
            self.write_busy = true;
            effects.push(Effect::SendControl {
                generation: self.generation,
                control,
            });
            return;
        }
        if self.state != State::Ready
            || self.in_flight_count() >= self.config.max_in_flight_transactions
        {
            return;
        }
        if self.renewal == RenewalState::Draining {
            if self.in_flight_count() == 0 {
                self.renewal = RenewalState::Reconnecting;
                self.fault(SessionError::Renewal, effects);
            }
            return;
        }
        let Some(index) = self.pending.iter().position(|pending| !pending.sent) else {
            return;
        };
        if self.pending[index].sequence == 0 {
            let sequence = match self.allocate_sequence() {
                Ok(sequence) => sequence,
                Err(error) => {
                    self.fail_terminal(error, effects);
                    return;
                }
            };
            self.pending[index].sequence = sequence;
            self.pending[index].message.header.sequence = sequence;
        }
        let request_id = self.pending[index].request_id;
        self.pending[index].sent = true;
        self.pending[index].may_have_executed = true;
        if !self.replay.contains(&request_id) {
            self.replay.push(request_id);
        }
        self.write_busy = true;
        effects.push(Effect::SendMessage {
            generation: self.generation,
            request_id,
            message: self.pending[index].message.clone(),
        });
    }

    fn connected(
        &mut self,
        generation: u64,
        authenticated_global_id: Option<u64>,
        credential_identity: Option<[u8; 32]>,
        effects: &mut Vec<Effect>,
    ) {
        if generation != self.generation || !self.connect_pending {
            effects.push(Effect::CloseTransport { generation });
            return;
        }
        self.connect_pending = false;
        self.terminal_error = None;
        self.transitions = 0;
        if self.connected_once {
            let Some(next) = self.global_sequence.checked_add(1) else {
                self.fail_terminal(SessionError::TransitionLimit, effects);
                effects.push(Effect::CloseTransport { generation });
                return;
            };
            self.global_sequence = next;
        }
        self.connected_once = true;
        if let Some(global_id) = authenticated_global_id {
            let identity_changed =
                self.authenticated_global_id != 0 && self.authenticated_global_id != global_id;
            self.authenticated_global_id = global_id;
            let Ok(global_id) = i64::try_from(global_id) else {
                self.fail_terminal(SessionError::Malformed, effects);
                effects.push(Effect::CloseTransport { generation });
                return;
            };
            self.config.client_ident.global_id = global_id;
            if identity_changed {
                self.reset_for_new_identity(effects);
            }
        }
        self.credential_change = match credential_identity {
            Some(identity) if self.credential_identity == Some(identity) => {
                CredentialChange::Unchanged
            }
            Some(identity) => {
                self.candidate_credential_identity = Some(identity);
                CredentialChange::Changed
            }
            None => {
                self.candidate_credential_identity = None;
                CredentialChange::Unknown
            }
        };
        if self.server_cookie != 0 {
            let Some(next) = self.connect_sequence.checked_add(1) else {
                self.fail_terminal(SessionError::TransitionLimit, effects);
                effects.push(Effect::CloseTransport { generation });
                return;
            };
            self.connect_sequence = next;
            if !self.start_transport(State::Reconnecting, effects) {
                effects.push(Effect::CloseTransport { generation });
                return;
            }
            self.queue_reconnect(effects);
        } else {
            if !self.refresh_cookie(effects) {
                effects.push(Effect::CloseTransport { generation });
                return;
            }
            self.connect_sequence = 0;
            if !self.start_transport(State::Connecting, effects) {
                effects.push(Effect::CloseTransport { generation });
                return;
            }
            self.queue_client_ident(effects);
        }
    }

    fn message(&mut self, message: Message, effects: &mut Vec<Effect>) {
        if self.state != State::Ready {
            self.fault(SessionError::Malformed, effects);
            return;
        }
        if !self.accept_acknowledgment(message.header.ack_sequence, effects) {
            return;
        }
        let sequence = message.header.sequence;
        if sequence <= self.last_inbound {
            effects.push(Effect::Event(Event::DuplicateDropped { sequence }));
            return;
        }
        if self.last_inbound != u64::MAX && sequence != self.last_inbound + 1 {
            effects.push(Effect::Event(Event::SequenceGap {
                sequence,
                expected: self.last_inbound + 1,
            }));
        }
        self.last_inbound = sequence;
        self.trim_replay(message.header.ack_sequence);
        self.queue_control(Control::Ack(sequence), effects);
        if let Some(request_id) = self
            .by_transaction
            .get(&message.header.transaction_id)
            .copied()
            .filter(|request_id| {
                self.pending(*request_id)
                    .is_some_and(|pending| pending.may_have_executed)
            })
        {
            self.remove_pending(request_id);
            effects.push(Effect::Completed {
                request_id,
                reply: Some(message),
            });
        } else if self.incoming_count >= self.config.max_queued_messages {
            self.fail_terminal(SessionError::QueueSaturated, effects);
        } else {
            self.incoming_count += 1;
            effects.push(Effect::Incoming(message));
        }
    }

    fn control(&mut self, control: Control, effects: &mut Vec<Effect>) {
        match control {
            Control::Ack(sequence) => {
                if self.require_ready(effects) && self.accept_acknowledgment(sequence, effects) {
                    self.trim_replay(sequence);
                    effects.push(Effect::Event(Event::Acknowledged { sequence }));
                }
            }
            Control::Keepalive2(timestamp) => {
                if self.require_ready(effects) {
                    self.queue_control(Control::Keepalive2Ack(timestamp), effects);
                }
            }
            Control::Keepalive2Ack(_) => {
                if self.require_ready(effects) {
                    effects.push(Effect::Event(Event::KeepaliveAck));
                }
            }
            Control::SessionReset(SessionReset { full }) => {
                if self.transition_allowed(State::Reconnecting, effects) {
                    self.reset(full, effects);
                }
            }
            Control::SessionRetry(SessionRetry { connect_sequence }) => {
                if !self.transition_allowed(State::Reconnecting, effects) {
                    return;
                }
                let Some(next) = connect_sequence.checked_add(1) else {
                    self.fail_terminal(SessionError::TransitionLimit, effects);
                    return;
                };
                self.connect_sequence = next;
                effects.push(Effect::Event(Event::Retry { sequence: next }));
                self.queue_reconnect(effects);
            }
            Control::SessionRetryGlobal(SessionRetryGlobal { global_sequence }) => {
                if !self.transition_allowed(State::Reconnecting, effects) {
                    return;
                }
                let Some(next) = self.global_sequence.max(global_sequence).checked_add(1) else {
                    self.fail_terminal(SessionError::TransitionLimit, effects);
                    return;
                };
                self.global_sequence = next;
                effects.push(Effect::Event(Event::RetryGlobal { sequence: next }));
                self.queue_reconnect(effects);
            }
            Control::Wait => {
                if !matches!(self.state, State::Connecting | State::Reconnecting) {
                    self.fault(SessionError::Malformed, effects);
                    return;
                }
                self.transitions += 1;
                self.set_state(State::Wait, effects);
                effects.push(Effect::Event(Event::Wait));
                self.fault(SessionError::Disconnected, effects);
            }
            Control::SessionReconnectOk(SessionReconnectOk { message_sequence }) => {
                if self.transition_allowed(State::Reconnecting, effects)
                    && self.accept_acknowledgment(message_sequence, effects)
                {
                    self.trim_replay(message_sequence);
                    self.prepare_replay();
                    if self.complete_renewal(effects) {
                        self.reconnect_attempts = 0;
                        self.set_state(State::Ready, effects);
                        effects.push(Effect::Event(Event::ReconnectOk {
                            sequence: message_sequence,
                        }));
                    }
                }
            }
            Control::ServerIdent(ident) => self.server_ident(&ident, effects),
            Control::IdentMissingFeatures(_) => {
                self.fail_terminal(SessionError::UnsupportedPayload, effects);
            }
            _ => self.fault(SessionError::UnsupportedPayload, effects),
        }
    }

    fn server_ident(&mut self, ident: &ServerIdent, effects: &mut Vec<Effect>) {
        if self.state != State::Connecting {
            self.fault(SessionError::Malformed, effects);
            return;
        }
        self.transitions += 1;
        if self.transitions > self.config.max_handshake_transitions {
            self.fault(SessionError::TransitionLimit, effects);
            return;
        }
        if ident.required_features & !self.config.client_ident.supported_features != 0
            || self.config.client_ident.required_features & !ident.supported_features != 0
        {
            self.fail_terminal(SessionError::UnsupportedFeature, effects);
            return;
        }
        if !ident
            .addresses
            .0
            .iter()
            .any(|address| address.has_same_endpoint(&self.config.client_ident.target_address))
        {
            self.fault(SessionError::Malformed, effects);
            return;
        }
        self.server_cookie = ident.cookie;
        self.server_global_id = ident.global_id;
        self.server_addresses = ident.addresses.clone();
        self.server_features = ident.supported_features;
        self.server_flags = ident.flags;
        self.fail_sent_unknown(effects);
        if self.complete_renewal(effects) {
            self.reconnect_attempts = 0;
            self.set_state(State::Ready, effects);
        }
    }

    fn complete_renewal(&mut self, effects: &mut Vec<Effect>) -> bool {
        if self.renewal != RenewalState::Reconnecting {
            return true;
        }
        if self.credential_change == CredentialChange::Changed {
            self.credential_identity = self.candidate_credential_identity.take();
            self.renewal = if self.renewal_pending == RenewalPending::Yes {
                self.renewal_pending = RenewalPending::No;
                effects.push(Effect::Event(Event::CredentialRenewal));
                RenewalState::Draining
            } else {
                RenewalState::Idle
            };
            self.credential_change = CredentialChange::Unknown;
            effects.push(Effect::Event(Event::CredentialRenewalCompleted));
            true
        } else {
            self.fault(SessionError::Renewal, effects);
            false
        }
    }

    fn reset(&mut self, full: bool, effects: &mut Vec<Effect>) {
        effects.push(Effect::Event(Event::SessionReset { full }));
        self.server_cookie = 0;
        self.server_flags = 0;
        self.connect_sequence = 0;
        self.last_inbound = 0;
        if full {
            if !self.refresh_cookie(effects) {
                return;
            }
            self.next_outbound = Some(1);
            self.next_transaction_id = Some(1);
            self.fail_all(SessionError::Disconnected, effects);
        } else {
            self.prepare_replay();
        }
        self.set_state(State::Connecting, effects);
        self.queue_client_ident(effects);
    }

    fn fault(&mut self, error: SessionError, effects: &mut Vec<Effect>) {
        if self.terminal_error.is_some()
            || self.state == State::Stopped
            || (self.state == State::Disconnected && self.connect_pending)
        {
            return;
        }
        effects.push(Effect::Event(Event::TransportFault(error)));
        effects.push(Effect::CloseTransport {
            generation: self.generation,
        });
        self.write_busy = false;
        self.controls.clear();
        if self.server_flags & CONNECTION_FLAG_LOSSY != 0 {
            self.fail_sent_unknown(effects);
            self.reset_for_new_identity(effects);
        } else if self.config.reconnect_policy == ReconnectPolicy::FailPending {
            self.fail_all(SessionError::Disconnected, effects);
        } else if self.server_cookie == 0 {
            self.fail_sent_unknown(effects);
        } else {
            self.prepare_replay();
        }
        self.set_state(State::Disconnected, effects);
        self.begin_reconnect(effects);
    }

    fn begin_reconnect(&mut self, effects: &mut Vec<Effect>) {
        if self.config.max_reconnect_attempts == 0
            || self.reconnect_attempts >= self.config.max_reconnect_attempts
        {
            self.fail_terminal(SessionError::ReconnectExhausted, effects);
            return;
        }
        self.reconnect_attempts += 1;
        self.connect_pending = true;
        let Some(generation) = self.generation.checked_add(1) else {
            self.fail_terminal(SessionError::TransitionLimit, effects);
            return;
        };
        self.generation = generation;
        effects.push(Effect::Connect {
            generation: self.generation,
        });
    }

    fn start_transport(&mut self, state: State, effects: &mut Vec<Effect>) -> bool {
        let Some(generation) = self.generation.checked_add(1) else {
            self.fail_terminal(SessionError::TransitionLimit, effects);
            return false;
        };
        self.generation = generation;
        self.set_state(state, effects);
        true
    }

    fn stop(&mut self, effects: &mut Vec<Effect>) {
        if self.state == State::Stopped {
            return;
        }
        self.set_state(State::Stopped, effects);
        self.fail_all(SessionError::Closed, effects);
        self.connect_pending = false;
        effects.push(Effect::CloseTransport {
            generation: self.generation,
        });
    }

    fn fail_terminal(&mut self, error: SessionError, effects: &mut Vec<Effect>) {
        if self.terminal_error.is_some() {
            return;
        }
        self.terminal_error = Some(error);
        effects.push(Effect::Terminal(error));
        effects.push(Effect::Event(Event::TransportFault(error)));
        self.write_busy = false;
        self.controls.clear();
        self.connect_pending = false;
        effects.push(Effect::CloseTransport {
            generation: self.generation,
        });
        self.fail_all(error, effects);
        self.set_state(State::Disconnected, effects);
    }

    fn fail_all(&mut self, error: SessionError, effects: &mut Vec<Effect>) {
        let requests: Vec<(u64, bool)> = self
            .pending
            .iter()
            .map(|pending| (pending.request_id, pending.may_have_executed))
            .collect();
        for (request_id, may_have_executed) in requests {
            effects.push(Effect::Failed {
                request_id,
                error: if may_have_executed && error != SessionError::OutcomeUnknown {
                    SessionError::OutcomeUnknown
                } else {
                    error
                },
            });
        }
        self.pending.clear();
        self.replay.clear();
        self.by_transaction.clear();
        self.retained_bytes = 0;
    }

    fn fail_sent_unknown(&mut self, effects: &mut Vec<Effect>) {
        let sent: Vec<u64> = self
            .pending
            .iter()
            .filter(|pending| pending.sent)
            .map(|pending| pending.request_id)
            .collect();
        for request_id in sent {
            self.remove_pending(request_id);
            effects.push(Effect::Failed {
                request_id,
                error: SessionError::OutcomeUnknown,
            });
        }
        self.replay.clear();
    }

    fn reset_for_new_identity(&mut self, effects: &mut Vec<Effect>) {
        self.server_cookie = 0;
        self.server_flags = 0;
        self.connect_sequence = 0;
        self.last_inbound = 0;
        self.next_outbound = Some(1);
        self.next_transaction_id = Some(1);
        self.fail_all(SessionError::Disconnected, effects);
    }

    fn require_ready(&mut self, effects: &mut Vec<Effect>) -> bool {
        if self.state == State::Ready {
            true
        } else {
            self.fault(SessionError::Malformed, effects);
            false
        }
    }

    fn transition_allowed(&mut self, expected: State, effects: &mut Vec<Effect>) -> bool {
        if self.state != expected {
            self.fault(SessionError::Malformed, effects);
            return false;
        }
        self.transitions += 1;
        if self.transitions > self.config.max_handshake_transitions {
            self.fault(SessionError::TransitionLimit, effects);
            return false;
        }
        true
    }

    fn accept_acknowledgment(&mut self, sequence: u64, effects: &mut Vec<Effect>) -> bool {
        if self
            .next_outbound
            .is_some_and(|next_outbound| sequence != 0 && sequence >= next_outbound)
        {
            self.fault(SessionError::Malformed, effects);
            false
        } else {
            true
        }
    }

    fn queue_control(&mut self, control: Control, effects: &mut Vec<Effect>) {
        if self.controls.len() >= self.config.max_queued_messages {
            self.fault(SessionError::QueueSaturated, effects);
        } else {
            self.controls.push_back(control);
        }
    }

    fn queue_client_ident(&mut self, effects: &mut Vec<Effect>) {
        let mut ident = self.config.client_ident.clone();
        ident.cookie = self.client_cookie;
        ident.global_sequence = self.global_sequence;
        self.queue_control(Control::ClientIdent(ident), effects);
    }

    fn queue_reconnect(&mut self, effects: &mut Vec<Effect>) {
        self.controls.clear();
        self.queue_control(
            Control::SessionReconnect(SessionReconnect {
                addresses: self.config.client_ident.addresses.clone(),
                client_cookie: self.client_cookie,
                server_cookie: self.server_cookie,
                global_sequence: self.global_sequence,
                connect_sequence: self.connect_sequence,
                message_sequence: self.last_inbound,
            }),
            effects,
        );
    }

    fn refresh_cookie(&mut self, effects: &mut Vec<Effect>) -> bool {
        let Some(cookie) = self.replacement_cookies.pop_front() else {
            self.fail_terminal(SessionError::Disconnected, effects);
            return false;
        };
        if cookie == 0 {
            self.fail_terminal(SessionError::Malformed, effects);
            return false;
        }
        self.client_cookie = cookie;
        true
    }

    fn prepare_replay(&mut self) {
        let replay = self.replay.clone();
        for request_id in replay {
            if let Some(pending) = self.pending_mut(request_id) {
                pending.sent = false;
            }
        }
    }

    fn trim_replay(&mut self, sequence: u64) {
        let sequences: HashMap<u64, u64> = self
            .pending
            .iter()
            .map(|pending| (pending.request_id, pending.sequence))
            .collect();
        self.replay.retain(|request_id| {
            sequences
                .get(request_id)
                .is_some_and(|value| *value > sequence)
        });
    }

    fn set_state(&mut self, state: State, effects: &mut Vec<Effect>) {
        if self.state != state {
            self.state = state;
            effects.push(Effect::Event(Event::StateChanged(state)));
        }
    }

    fn allocate_sequence(&mut self) -> Result<u64, SessionError> {
        let sequence = self
            .next_outbound
            .ok_or(SessionError::TransitionLimit)?
            .max(1);
        if sequence == u64::MAX {
            self.next_outbound = None;
        } else {
            self.next_outbound = Some(sequence + 1);
        }
        Ok(sequence)
    }

    fn take_transaction_id(&mut self) -> Result<u64, SessionError> {
        while let Some(next_transaction_id) = self.next_transaction_id {
            let transaction_id = next_transaction_id.max(1);
            if transaction_id == u64::MAX {
                self.next_transaction_id = None;
            } else {
                self.next_transaction_id = Some(transaction_id + 1);
            }
            if !self.by_transaction.contains_key(&transaction_id) {
                return Ok(transaction_id);
            }
        }
        Err(SessionError::TransitionLimit)
    }

    fn admission_bytes(&self, message: &Message) -> Result<u64, SessionError> {
        let front = u32::try_from(message.front.len()).map_err(|_| SessionError::Malformed)?;
        let middle = u32::try_from(message.middle.len()).map_err(|_| SessionError::Malformed)?;
        let data = u32::try_from(message.data.len()).map_err(|_| SessionError::Malformed)?;
        if message.lengths.front != front
            || message.lengths.middle != middle
            || message.lengths.data != data
            || message.header.data_pre_padding_length > data
            || front > self.config.limits.max_segment_bytes
            || middle > self.config.limits.max_segment_bytes
            || data > self.config.limits.max_segment_bytes
        {
            return Err(SessionError::Malformed);
        }
        let bytes = u64::try_from(MESSAGE_HEADER_SIZE)
            .expect("message header size fits u64")
            .checked_add(u64::from(front))
            .and_then(|value| value.checked_add(u64::from(middle)))
            .and_then(|value| value.checked_add(u64::from(data)))
            .ok_or(SessionError::Malformed)?;
        let frame = message
            .clone()
            .encode(self.config.limits)
            .map_err(SessionError::Frame)?;
        if (super::frame::CrcCodec {
            with_data_crc: true,
        })
        .encode(&frame, self.config.limits)
        .is_err()
            || super::secure::validate_frame_size(&frame, self.config.limits).is_err()
        {
            return Err(SessionError::Malformed);
        }
        Ok(bytes)
    }

    fn pending(&self, request_id: u64) -> Option<&Pending> {
        self.pending
            .iter()
            .find(|pending| pending.request_id == request_id)
    }

    fn pending_mut(&mut self, request_id: u64) -> Option<&mut Pending> {
        self.pending
            .iter_mut()
            .find(|pending| pending.request_id == request_id)
    }

    fn remove_pending(&mut self, request_id: u64) {
        let Some(index) = self
            .pending
            .iter()
            .position(|pending| pending.request_id == request_id)
        else {
            return;
        };
        let pending = self.pending.remove(index);
        self.replay.retain(|candidate| *candidate != request_id);
        self.by_transaction
            .remove(&pending.message.header.transaction_id);
        self.retained_bytes -= pending.bytes;
    }

    fn in_flight_count(&self) -> usize {
        self.pending.iter().filter(|pending| pending.sent).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::address::{EntityAddr, EntityAddrVec};
    use crate::wire::Decoder;

    const TEST_LIMITS: Limits = Limits {
        max_segment_bytes: 4096,
        max_frame_bytes: 8192,
        max_addresses: 4,
        max_auth_bytes: 64,
    };

    fn test_address() -> EntityAddr {
        let encoded = [
            0x01, 0x01, 0x01, 0x1c, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
            0x04, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0c, 0xe4, 0xc0, 0x00, 0x02, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut decoder = Decoder::new(&encoded, encoded.len());
        EntityAddr::decode(&mut decoder).expect("valid test address")
    }

    fn config(policy: ReconnectPolicy) -> Config {
        let address = test_address();
        Config {
            limits: TEST_LIMITS,
            max_queued_messages: 8,
            max_retained_bytes: 2048,
            max_in_flight_transactions: 4,
            max_reconnect_attempts: 3,
            max_handshake_transitions: 8,
            reconnect_policy: policy,
            client_ident: ClientIdent {
                addresses: EntityAddrVec(vec![address.clone()]),
                target_address: address,
                global_id: 0,
                global_sequence: 3,
                supported_features: 0x0f,
                required_features: 0x01,
                flags: 0,
                cookie: 0,
            },
            client_cookie: 11,
            server_cookie: 22,
            global_sequence: 3,
            connect_sequence: 0,
            replacement_cookies: vec![41, 42, 43],
        }
    }

    fn message(payload: &[u8]) -> Message {
        Message {
            lengths: super::super::message::MessageLengths {
                front: u32::try_from(payload.len()).expect("test payload fits u32"),
                ..super::super::message::MessageLengths::default()
            },
            front: payload.to_vec(),
            ..Message::default()
        }
    }

    fn ready_machine(policy: ReconnectPolicy) -> Machine {
        let mut machine = Machine::new(config(policy)).expect("valid config");
        assert_eq!(
            machine.step(Input::Start { ready: true }),
            vec![Effect::Event(Event::StateChanged(State::Ready))]
        );
        machine
    }

    fn dispatch_message(machine: &mut Machine, request_id: u64) -> (u64, u64) {
        let effects = machine.step(Input::Dispatch);
        let Effect::SendMessage {
            generation,
            request_id: actual_request_id,
            message,
        } = &effects[0]
        else {
            panic!("expected message dispatch: {effects:?}");
        };
        assert_eq!(*actual_request_id, request_id);
        (*generation, message.header.transaction_id)
    }

    fn complete_write(machine: &mut Machine, generation: u64, request_id: u64) {
        assert!(
            machine
                .step(Input::WriteComplete {
                    generation,
                    request_id: Some(request_id),
                    result: Ok(()),
                })
                .is_empty()
        );
    }

    fn dispatch_control(machine: &mut Machine) {
        let effects = machine.step(Input::Dispatch);
        assert!(
            matches!(&effects[..], [Effect::SendControl { .. }]),
            "{effects:?}"
        );
        let generation = machine.generation;
        assert!(
            machine
                .step(Input::WriteComplete {
                    generation,
                    request_id: None,
                    result: Ok(()),
                })
                .is_empty()
        );
    }

    fn assert_accounting(machine: &Machine) {
        assert!(machine.pending.len() <= machine.config.max_queued_messages);
        assert!(machine.in_flight_count() <= machine.config.max_in_flight_transactions);
        assert_eq!(
            machine.retained_bytes,
            machine
                .pending
                .iter()
                .map(|pending| pending.bytes)
                .sum::<u64>()
        );
        assert!(machine.retained_bytes <= machine.config.max_retained_bytes);
        for pending in &machine.pending {
            assert_eq!(
                machine
                    .by_transaction
                    .get(&pending.message.header.transaction_id),
                Some(&pending.request_id)
            );
        }
        for request_id in &machine.replay {
            let pending = machine.pending(*request_id).expect("active replay request");
            assert_ne!(pending.sequence, 0);
        }
    }

    #[test]
    fn ack_does_not_complete_and_inbound_sequence_rules_are_preserved() {
        let mut machine = ready_machine(ReconnectPolicy::ReplayPending);
        assert!(matches!(
            machine.step(Input::Admit {
                request_id: 7,
                message: message(b"request"),
                one_way: false,
            })[..],
            [Effect::Admitted {
                request_id: 7,
                transaction_id: 1
            }]
        ));
        let (generation, transaction_id) = dispatch_message(&mut machine, 7);
        complete_write(&mut machine, generation, 7);

        assert_eq!(
            machine.step(Input::Control {
                generation,
                control: Control::Ack(1),
            }),
            vec![Effect::Event(Event::Acknowledged { sequence: 1 })]
        );
        assert_eq!(machine.snapshot().in_flight, 1);
        assert_eq!(machine.snapshot().replay, 0);

        let cases = [
            (
                3,
                0,
                Some(Event::SequenceGap {
                    sequence: 3,
                    expected: 1,
                }),
            ),
            (2, 3, Some(Event::DuplicateDropped { sequence: 2 })),
            (4, 3, None),
        ];
        for (sequence, previous, expected_event) in cases {
            machine.last_inbound = previous;
            let effects = machine.step(Input::Message {
                generation,
                message: Message {
                    header: super::super::message::MessageHeader {
                        sequence,
                        transaction_id: if sequence == 4 { transaction_id } else { 0 },
                        ack_sequence: 1,
                        ..super::super::message::MessageHeader::default()
                    },
                    ..Message::default()
                },
            });
            if let Some(event) = expected_event {
                assert!(effects.contains(&Effect::Event(event)), "{effects:?}");
            }
        }
        assert!(machine.pending(7).is_none());
        assert_accounting(&machine);
    }

    #[test]
    fn admission_cancellation_one_way_and_bounds_are_deterministic() {
        let cases = [
            (1, false, SessionError::Cancelled),
            (2, true, SessionError::OutcomeUnknown),
        ];
        for (request_id, dispatch, expected) in cases {
            let mut machine = ready_machine(ReconnectPolicy::ReplayPending);
            machine.step(Input::Admit {
                request_id,
                message: message(b"owned"),
                one_way: false,
            });
            if dispatch {
                let (generation, _) = dispatch_message(&mut machine, request_id);
                complete_write(&mut machine, generation, request_id);
            }
            assert_eq!(
                machine.step(Input::Cancel { request_id }),
                vec![Effect::Failed {
                    request_id,
                    error: expected,
                }]
            );
            assert_accounting(&machine);
        }

        let mut bounded_config = config(ReconnectPolicy::ReplayPending);
        bounded_config.max_queued_messages = 1;
        bounded_config.max_retained_bytes =
            u64::try_from(MESSAGE_HEADER_SIZE + 3).expect("test size fits u64");
        let mut machine = Machine::new(bounded_config).expect("valid config");
        machine.step(Input::Start { ready: true });
        machine.step(Input::Admit {
            request_id: 1,
            message: message(b"one"),
            one_way: false,
        });
        assert_eq!(
            machine.step(Input::Admit {
                request_id: 2,
                message: message(b"two"),
                one_way: false,
            }),
            vec![Effect::Failed {
                request_id: 2,
                error: SessionError::QueueSaturated,
            }]
        );

        let mut one_way = ready_machine(ReconnectPolicy::ReplayPending);
        one_way.step(Input::Admit {
            request_id: 9,
            message: message(b"send"),
            one_way: true,
        });
        let (generation, _) = dispatch_message(&mut one_way, 9);
        assert_eq!(
            one_way.step(Input::WriteComplete {
                generation,
                request_id: Some(9),
                result: Ok(()),
            }),
            vec![Effect::Completed {
                request_id: 9,
                reply: None,
            }]
        );
        assert_accounting(&one_way);
    }

    #[test]
    fn reply_cannot_complete_an_undispatched_request() {
        let mut bounded_config = config(ReconnectPolicy::ReplayPending);
        bounded_config.max_in_flight_transactions = 1;
        let mut machine = Machine::new(bounded_config).expect("valid config");
        machine.step(Input::Start { ready: true });
        for request_id in 1..=2 {
            machine.step(Input::Admit {
                request_id,
                message: message(b"request"),
                one_way: false,
            });
        }
        let (generation, _) = dispatch_message(&mut machine, 1);
        let queued_transaction = machine
            .pending(2)
            .expect("queued request")
            .message
            .header
            .transaction_id;
        let effects = machine.step(Input::Message {
            generation,
            message: Message {
                header: super::super::message::MessageHeader {
                    sequence: 1,
                    transaction_id: queued_transaction,
                    ..super::super::message::MessageHeader::default()
                },
                ..Message::default()
            },
        });
        assert!(
            !effects
                .iter()
                .any(|effect| matches!(effect, Effect::Completed { request_id: 2, .. }))
        );
        assert!(machine.pending(2).is_some());
        assert!(
            effects
                .iter()
                .any(|effect| matches!(effect, Effect::Incoming(_)))
        );
    }

    #[test]
    fn reconnect_policy_replays_or_fails_sent_requests() {
        for (policy, lossy, expect_replay) in [
            (ReconnectPolicy::ReplayPending, false, true),
            (ReconnectPolicy::FailPending, false, false),
            (ReconnectPolicy::ReplayPending, true, false),
            (ReconnectPolicy::FailPending, true, false),
        ] {
            let mut machine = ready_machine(policy);
            machine.server_flags = if lossy { CONNECTION_FLAG_LOSSY } else { 0 };
            machine.step(Input::Admit {
                request_id: 1,
                message: message(b"request"),
                one_way: false,
            });
            let (generation, transaction_id) = dispatch_message(&mut machine, 1);
            complete_write(&mut machine, generation, 1);
            let effects = machine.step(Input::Fault {
                generation,
                error: SessionError::Disconnected,
            });
            if expect_replay {
                assert_eq!(machine.snapshot().replay, 1);
                let connect_generation = machine.generation;
                machine.step(Input::Connected {
                    generation: connect_generation,
                    authenticated_global_id: None,
                    credential_identity: None,
                });
                let transport_generation = machine.generation;
                machine.write_busy = false;
                machine.step(Input::Dispatch);
                machine.write_busy = false;
                let replay = machine.step(Input::Control {
                    generation: transport_generation,
                    control: Control::SessionReconnectOk(SessionReconnectOk {
                        message_sequence: 0,
                    }),
                });
                assert!(replay.contains(&Effect::Event(Event::ReconnectOk { sequence: 0 })));
                let dispatched = machine.step(Input::Dispatch);
                assert!(matches!(
                    &dispatched[..],
                    [Effect::SendMessage { message, .. }]
                        if message.header.transaction_id == transaction_id
                            && message.header.sequence == 1
                ));
            } else {
                assert!(
                    effects.contains(&Effect::Failed {
                        request_id: 1,
                        error: if lossy {
                            SessionError::OutcomeUnknown
                        } else {
                            SessionError::Disconnected
                        },
                    }) || effects.contains(&Effect::Failed {
                        request_id: 1,
                        error: SessionError::OutcomeUnknown,
                    })
                );
                assert_eq!(machine.snapshot().replay, 0);
            }
            assert_accounting(&machine);
        }
    }

    #[test]
    fn retry_reset_and_reconnect_ok_follow_go_transitions() {
        let mut machine = ready_machine(ReconnectPolicy::ReplayPending);
        machine.step(Input::Admit {
            request_id: 1,
            message: message(b"pending"),
            one_way: false,
        });
        let (generation, transaction_id) = dispatch_message(&mut machine, 1);
        complete_write(&mut machine, generation, 1);
        machine.step(Input::Fault {
            generation,
            error: SessionError::Disconnected,
        });
        let connect_generation = machine.generation;
        machine.step(Input::Connected {
            generation: connect_generation,
            authenticated_global_id: None,
            credential_identity: None,
        });
        let generation = machine.generation;
        dispatch_control(&mut machine);

        machine.step(Input::Control {
            generation,
            control: Control::SessionRetry(SessionRetry {
                connect_sequence: 7,
            }),
        });
        assert_eq!(machine.snapshot().connect_sequence, 8);
        dispatch_control(&mut machine);
        machine.step(Input::Control {
            generation,
            control: Control::SessionRetryGlobal(SessionRetryGlobal {
                global_sequence: 10,
            }),
        });
        assert_eq!(machine.snapshot().global_sequence, 11);
        dispatch_control(&mut machine);
        machine.step(Input::Control {
            generation,
            control: Control::SessionReset(SessionReset { full: false }),
        });
        assert_eq!(machine.snapshot().state, State::Connecting);
        assert_eq!(machine.snapshot().client_cookie, 11);
        assert_eq!(machine.snapshot().last_inbound_sequence, 0);
        dispatch_control(&mut machine);
        machine.step(Input::Control {
            generation,
            control: Control::ServerIdent(ServerIdent {
                addresses: machine.config.client_ident.addresses.clone(),
                global_id: 4,
                global_sequence: 11,
                supported_features: 0x0f,
                required_features: 0,
                flags: 0,
                cookie: 303,
            }),
        });
        let replay = machine.step(Input::Dispatch);
        assert!(
            matches!(
                &replay[..],
                [Effect::SendMessage { message, .. }]
                    if message.header.sequence == 1
                        && message.header.transaction_id == transaction_id
            ),
            "unexpected replay effects: {replay:?}"
        );

        let mut full = ready_machine(ReconnectPolicy::ReplayPending);
        full.step(Input::Admit {
            request_id: 5,
            message: message(b"pending"),
            one_way: false,
        });
        let (generation, _) = dispatch_message(&mut full, 5);
        complete_write(&mut full, generation, 5);
        full.state = State::Reconnecting;
        let effects = full.step(Input::Control {
            generation,
            control: Control::SessionReset(SessionReset { full: true }),
        });
        assert!(effects.contains(&Effect::Failed {
            request_id: 5,
            error: SessionError::OutcomeUnknown,
        }));
        let snapshot = full.snapshot();
        assert_eq!(snapshot.client_cookie, 41);
        assert_eq!(snapshot.next_outbound_sequence, 1);
        assert_eq!(snapshot.next_transaction_id, 1);
        assert_eq!(snapshot.retained_bytes, 0);
    }

    #[test]
    fn malformed_states_stale_generations_and_limits_fail_closed() {
        for control in [
            Control::Ack(0),
            Control::Keepalive2(super::super::control::Timestamp {
                seconds: 1,
                nanoseconds: 0,
            }),
            Control::Keepalive2Ack(super::super::control::Timestamp {
                seconds: 1,
                nanoseconds: 0,
            }),
        ] {
            let mut machine = Machine::new(config(ReconnectPolicy::ReplayPending)).expect("config");
            machine.state = State::Connecting;
            machine.generation = 4;
            machine.config.max_reconnect_attempts = 0;
            machine.step(Input::Control {
                generation: 4,
                control,
            });
            assert_eq!(machine.state, State::Disconnected);
            assert!(machine.terminal_error.is_some());
            assert_eq!(machine.last_inbound, 0);
        }

        let mut stale = Machine::new(config(ReconnectPolicy::ReplayPending)).expect("config");
        let connect = stale.step(Input::Start { ready: false });
        assert_eq!(connect, vec![Effect::Connect { generation: 1 }]);
        assert_eq!(
            stale.step(Input::Connected {
                generation: 0,
                authenticated_global_id: None,
                credential_identity: None,
            }),
            vec![Effect::CloseTransport { generation: 0 }]
        );
        assert_eq!(stale.snapshot().state, State::Disconnected);

        let mut overflow = ready_machine(ReconnectPolicy::ReplayPending);
        overflow.next_outbound = Some(u64::MAX);
        overflow.step(Input::Admit {
            request_id: 1,
            message: message(b"last"),
            one_way: false,
        });
        dispatch_message(&mut overflow, 1);
        overflow.write_busy = false;
        overflow.step(Input::Admit {
            request_id: 2,
            message: message(b"wrapped"),
            one_way: false,
        });
        let effects = overflow.step(Input::Dispatch);
        assert!(effects.contains(&Effect::Terminal(SessionError::TransitionLimit)));

        let mut transaction = ready_machine(ReconnectPolicy::ReplayPending);
        transaction.next_transaction_id = Some(u64::MAX);
        transaction.step(Input::Admit {
            request_id: 1,
            message: message(b"last"),
            one_way: false,
        });
        let effects = transaction.step(Input::Admit {
            request_id: 2,
            message: message(b"wrapped"),
            one_way: false,
        });
        assert!(effects.contains(&Effect::Terminal(SessionError::TransitionLimit)));
        assert_eq!(transaction.next_transaction_id, None);
    }

    #[test]
    fn oversized_acknowledgments_fail_for_ack_message_and_reconnect_ok() {
        enum Case {
            Ack,
            Message,
            ReconnectOk,
        }
        for case in [Case::Ack, Case::Message, Case::ReconnectOk] {
            let mut machine = ready_machine(ReconnectPolicy::ReplayPending);
            machine.config.max_reconnect_attempts = 0;
            machine.next_outbound = Some(2);
            let generation = machine.generation;
            match case {
                Case::Ack => {
                    machine.step(Input::Control {
                        generation,
                        control: Control::Ack(2),
                    });
                }
                Case::Message => {
                    machine.step(Input::Message {
                        generation,
                        message: Message {
                            header: super::super::message::MessageHeader {
                                sequence: 1,
                                ack_sequence: 2,
                                ..super::super::message::MessageHeader::default()
                            },
                            ..Message::default()
                        },
                    });
                }
                Case::ReconnectOk => {
                    machine.state = State::Reconnecting;
                    machine.step(Input::Control {
                        generation,
                        control: Control::SessionReconnectOk(SessionReconnectOk {
                            message_sequence: 2,
                        }),
                    });
                }
            }
            assert_eq!(machine.state, State::Disconnected);
            assert!(machine.terminal_error.is_some());
        }
    }

    #[test]
    fn reconnect_and_handshake_budgets_are_bounded() {
        let mut reconnect_config = config(ReconnectPolicy::ReplayPending);
        reconnect_config.max_reconnect_attempts = 2;
        let mut reconnect = Machine::new(reconnect_config).expect("valid config");
        assert_eq!(
            reconnect.step(Input::Start { ready: false }),
            vec![Effect::Connect { generation: 1 }]
        );
        assert!(
            reconnect
                .step(Input::ConnectFailed { generation: 1 })
                .contains(&Effect::Connect { generation: 2 })
        );
        let exhausted = reconnect.step(Input::ConnectFailed { generation: 2 });
        assert!(exhausted.contains(&Effect::Terminal(SessionError::ReconnectExhausted)));
        assert_eq!(reconnect.snapshot().reconnect_attempts, 2);

        let mut handshake = ready_machine(ReconnectPolicy::ReplayPending);
        handshake.state = State::Reconnecting;
        handshake.config.max_handshake_transitions = 1;
        let generation = handshake.generation;
        handshake.step(Input::Control {
            generation,
            control: Control::SessionRetry(SessionRetry {
                connect_sequence: 1,
            }),
        });
        dispatch_control(&mut handshake);
        let exhausted = handshake.step(Input::Control {
            generation,
            control: Control::SessionRetry(SessionRetry {
                connect_sequence: 2,
            }),
        });
        assert!(exhausted.contains(&Effect::Event(Event::TransportFault(
            SessionError::TransitionLimit,
        ))));

        let mut conflict = config(ReconnectPolicy::ReplayPending);
        conflict.global_sequence = 4;
        assert_eq!(Machine::new(conflict).unwrap_err(), SessionError::Malformed);
    }

    #[test]
    fn wait_identity_change_incoming_overflow_and_stop_are_explicit() {
        let mut waiting = Machine::new(config(ReconnectPolicy::ReplayPending)).expect("config");
        waiting.step(Input::Start { ready: false });
        let connect_generation = waiting.generation;
        waiting.step(Input::Connected {
            generation: connect_generation,
            authenticated_global_id: Some(10),
            credential_identity: Some([1; 32]),
        });
        let generation = waiting.generation;
        let effects = waiting.step(Input::Control {
            generation,
            control: Control::Wait,
        });
        assert!(effects.contains(&Effect::Event(Event::StateChanged(State::Wait))));
        assert!(effects.contains(&Effect::Event(Event::Wait)));
        assert!(
            effects
                .iter()
                .any(|effect| matches!(effect, Effect::Connect { .. }))
        );

        let mut identity = ready_machine(ReconnectPolicy::ReplayPending);
        identity.authenticated_global_id = 10;
        identity.step(Input::Admit {
            request_id: 4,
            message: message(b"identity"),
            one_way: false,
        });
        let (generation, _) = dispatch_message(&mut identity, 4);
        complete_write(&mut identity, generation, 4);
        identity.fault(SessionError::Disconnected, &mut Vec::new());
        let connect_generation = identity.generation;
        let effects = identity.step(Input::Connected {
            generation: connect_generation,
            authenticated_global_id: Some(11),
            credential_identity: Some([2; 32]),
        });
        assert!(effects.contains(&Effect::Failed {
            request_id: 4,
            error: SessionError::OutcomeUnknown,
        }));
        assert_eq!(identity.snapshot().next_outbound_sequence, 1);
        assert_eq!(identity.snapshot().server_cookie, 0);

        let mut incoming_config = config(ReconnectPolicy::ReplayPending);
        incoming_config.max_queued_messages = 1;
        let mut incoming = Machine::new(incoming_config).expect("config");
        incoming.step(Input::Start { ready: true });
        let generation = incoming.generation;
        incoming.step(Input::Message {
            generation,
            message: Message {
                header: super::super::message::MessageHeader {
                    sequence: 1,
                    ..super::super::message::MessageHeader::default()
                },
                ..Message::default()
            },
        });
        let overflow = incoming.step(Input::Message {
            generation,
            message: Message {
                header: super::super::message::MessageHeader {
                    sequence: 2,
                    ..super::super::message::MessageHeader::default()
                },
                ..Message::default()
            },
        });
        assert!(overflow.contains(&Effect::Terminal(SessionError::QueueSaturated)));

        let mut stopped = ready_machine(ReconnectPolicy::ReplayPending);
        stopped.step(Input::Admit {
            request_id: 8,
            message: message(b"stop"),
            one_way: false,
        });
        let stopped_effects = stopped.step(Input::Stop);
        assert!(stopped_effects.contains(&Effect::Event(Event::StateChanged(State::Stopped))));
        assert!(stopped_effects.contains(&Effect::Failed {
            request_id: 8,
            error: SessionError::Closed,
        }));
        assert_eq!(stopped.snapshot().state, State::Stopped);
    }

    #[test]
    fn generation_wraparound_fails_closed() {
        let mut machine = Machine::new(config(ReconnectPolicy::ReplayPending)).expect("config");
        machine.generation = u64::MAX;
        let effects = machine.step(Input::Start { ready: false });
        assert!(effects.contains(&Effect::Terminal(SessionError::TransitionLimit)));
        assert!(effects.contains(&Effect::CloseTransport {
            generation: u64::MAX,
        }));
        assert_eq!(machine.snapshot().state, State::Disconnected);
        assert!(machine.terminal_error.is_some());

        let mut connected = Machine::new(config(ReconnectPolicy::ReplayPending)).expect("config");
        connected.generation = u64::MAX - 1;
        assert_eq!(
            connected.step(Input::Start { ready: false }),
            vec![Effect::Connect {
                generation: u64::MAX,
            }]
        );
        let effects = connected.step(Input::Connected {
            generation: u64::MAX,
            authenticated_global_id: None,
            credential_identity: None,
        });
        assert!(effects.contains(&Effect::Terminal(SessionError::TransitionLimit)));
        assert!(
            !effects
                .iter()
                .any(|effect| matches!(effect, Effect::SendControl { .. }))
        );
    }

    #[test]
    fn credential_renewal_drains_and_requires_a_fresh_credential() {
        for (credential, completes) in
            [(Some([2; 32]), true), (Some([1; 32]), false), (None, false)]
        {
            let mut machine = ready_machine(ReconnectPolicy::ReplayPending);
            let initial_generation = machine.generation;
            assert!(
                machine
                    .step(Input::InitialIdentity {
                        generation: initial_generation,
                        authenticated_global_id: Some(7),
                        credential_identity: Some([1; 32]),
                    })
                    .is_empty()
            );
            assert_eq!(machine.authenticated_global_id, 7);
            machine.step(Input::Admit {
                request_id: 1,
                message: message(b"request"),
                one_way: false,
            });
            let (generation, transaction_id) = dispatch_message(&mut machine, 1);
            complete_write(&mut machine, generation, 1);
            assert_eq!(
                machine.step(Input::RenewalDue { generation }),
                vec![Effect::Event(Event::CredentialRenewal)]
            );
            assert!(machine.step(Input::Dispatch).is_empty());

            machine.step(Input::Message {
                generation,
                message: Message {
                    header: super::super::message::MessageHeader {
                        sequence: 1,
                        transaction_id,
                        ..super::super::message::MessageHeader::default()
                    },
                    ..Message::default()
                },
            });
            dispatch_control(&mut machine);
            let reconnect = machine.step(Input::Dispatch);
            assert!(reconnect.contains(&Effect::Event(Event::TransportFault(
                SessionError::Renewal,
            ))));
            let connect_generation = machine.generation;
            machine.step(Input::Connected {
                generation: connect_generation,
                authenticated_global_id: None,
                credential_identity: credential,
            });
            let generation = machine.generation;
            dispatch_control(&mut machine);
            let effects = machine.step(Input::Control {
                generation,
                control: Control::SessionReconnectOk(SessionReconnectOk {
                    message_sequence: 1,
                }),
            });
            assert_eq!(
                effects.contains(&Effect::Event(Event::CredentialRenewalCompleted)),
                completes
            );
            if completes {
                assert_eq!(machine.snapshot().state, State::Ready);
            } else {
                assert_eq!(machine.snapshot().state, State::Disconnected);
                assert!(effects.contains(&Effect::CloseTransport { generation }));
                assert!(effects.iter().any(|effect| matches!(
                    effect,
                    Effect::Connect {
                        generation: next_generation
                    } if *next_generation > generation
                )));
            }
        }
    }

    #[test]
    fn credential_renewal_exhausts_after_successful_unchanged_handshakes() {
        let mut machine = ready_machine(ReconnectPolicy::ReplayPending);
        machine.config.max_reconnect_attempts = 2;
        let initial_generation = machine.generation;
        machine.step(Input::InitialIdentity {
            generation: initial_generation,
            authenticated_global_id: Some(7),
            credential_identity: Some([1; 32]),
        });
        machine.step(Input::RenewalDue {
            generation: initial_generation,
        });
        machine.step(Input::Dispatch);
        let first_generation = machine.generation;
        machine.step(Input::Connected {
            generation: first_generation,
            authenticated_global_id: Some(7),
            credential_identity: Some([1; 32]),
        });
        let first_transport_generation = machine.generation;
        machine.step(Input::Control {
            generation: first_transport_generation,
            control: Control::SessionReconnectOk(SessionReconnectOk {
                message_sequence: 0,
            }),
        });
        let second_generation = machine.generation;
        machine.step(Input::Connected {
            generation: second_generation,
            authenticated_global_id: Some(7),
            credential_identity: None,
        });
        let second_transport_generation = machine.generation;
        let effects = machine.step(Input::Control {
            generation: second_transport_generation,
            control: Control::SessionReconnectOk(SessionReconnectOk {
                message_sequence: 0,
            }),
        });
        assert!(
            effects.contains(&Effect::Terminal(SessionError::ReconnectExhausted)),
            "unexpected renewal exhaustion effects: {effects:?}; snapshot: {:?}",
            machine.snapshot()
        );
        assert_eq!(machine.snapshot().state, State::Disconnected);
    }

    #[test]
    fn renewal_candidate_survives_fault_and_overlapping_due_is_latched() {
        let mut machine = ready_machine(ReconnectPolicy::ReplayPending);
        let generation = machine.generation;
        machine.step(Input::InitialIdentity {
            generation,
            authenticated_global_id: Some(7),
            credential_identity: Some([1; 32]),
        });
        machine.step(Input::RenewalDue { generation });
        machine.step(Input::Dispatch);

        let first_connector_generation = machine.generation;
        machine.step(Input::Connected {
            generation: first_connector_generation,
            authenticated_global_id: Some(7),
            credential_identity: Some([2; 32]),
        });
        let first_transport_generation = machine.generation;
        machine.step(Input::Fault {
            generation: first_transport_generation,
            error: SessionError::Disconnected,
        });

        let second_connector_generation = machine.generation;
        machine.step(Input::Connected {
            generation: second_connector_generation,
            authenticated_global_id: Some(7),
            credential_identity: Some([2; 32]),
        });
        let second_transport_generation = machine.generation;
        assert!(
            machine
                .step(Input::RenewalDue {
                    generation: second_transport_generation,
                })
                .is_empty()
        );
        let effects = machine.step(Input::Control {
            generation: second_transport_generation,
            control: Control::SessionReconnectOk(SessionReconnectOk {
                message_sequence: 0,
            }),
        });
        assert!(effects.contains(&Effect::Event(Event::CredentialRenewalCompleted)));
        assert!(effects.contains(&Effect::Event(Event::CredentialRenewal)));
        assert_eq!(machine.credential_identity, Some([2; 32]));
        assert_eq!(machine.renewal, RenewalState::Draining);
    }

    #[test]
    fn admission_rejects_frames_that_exceed_wire_limits() {
        let mut machine = ready_machine(ReconnectPolicy::ReplayPending);
        let message = Message {
            lengths: super::super::message::MessageLengths {
                front: 4_096,
                middle: 4_055,
                data: 0,
            },
            front: vec![0; 4_096],
            middle: vec![0; 4_055],
            ..Message::default()
        };
        assert_eq!(
            machine.step(Input::Admit {
                request_id: 1,
                message,
                one_way: false,
            }),
            vec![Effect::Failed {
                request_id: 1,
                error: SessionError::Malformed,
            }]
        );
    }

    #[test]
    fn retained_go_fuzz_seeds_preserve_accounting_and_are_reproducible() {
        let seeds: [&[u8]; 5] = [
            &[0x00, 0x08, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            &[0x00, 0x01],
            &[0x00, 0x08, 0x16],
            &[0x03, 0x05, 0x07],
            &[],
        ];
        for seed in seeds {
            let first = run_script(seed);
            let second = run_script(seed);
            assert_eq!(first, second);
        }
    }

    fn run_script(script: &[u8]) -> (Vec<Vec<Effect>>, Snapshot) {
        let mut machine = ready_machine(ReconnectPolicy::ReplayPending);
        machine.config.max_reconnect_attempts = 0;
        let generation = machine.generation;
        let mut transcript = Vec::new();
        for instruction in script {
            let operand = u64::from(instruction >> 4);
            let effects = match instruction & 0x0f {
                0 => machine.step(Input::Admit {
                    request_id: operand + u64::try_from(machine.pending.len()).expect("small test"),
                    message: message(&[
                        u8::try_from(operand).expect("nibble fits u8"),
                        u8::try_from(machine.pending.len()).expect("bounded pending count"),
                    ]),
                    one_way: false,
                }),
                1 => match machine.pending.first().map(|pending| pending.request_id) {
                    Some(request_id) => machine.step(Input::Cancel { request_id }),
                    None => Vec::new(),
                },
                2 => machine.step(Input::Control {
                    generation,
                    control: Control::Ack(operand),
                }),
                3 => machine.step(Input::Control {
                    generation,
                    control: Control::Keepalive2(super::super::control::Timestamp {
                        seconds: u32::try_from(operand).expect("nibble fits u32"),
                        nanoseconds: 0,
                    }),
                }),
                4 => {
                    let transaction_id = machine
                        .pending
                        .first()
                        .map_or(0, |pending| pending.message.header.transaction_id);
                    machine.step(Input::Message {
                        generation,
                        message: Message {
                            header: super::super::message::MessageHeader {
                                sequence: operand + 1,
                                transaction_id,
                                ..super::super::message::MessageHeader::default()
                            },
                            ..Message::default()
                        },
                    })
                }
                5 => machine.step(Input::Message {
                    generation,
                    message: Message {
                        header: super::super::message::MessageHeader {
                            sequence: machine.last_inbound,
                            ..super::super::message::MessageHeader::default()
                        },
                        ..Message::default()
                    },
                }),
                6 => {
                    machine.state = State::Reconnecting;
                    machine.step(Input::Control {
                        generation,
                        control: Control::SessionReset(SessionReset {
                            full: operand & 1 != 0,
                        }),
                    })
                }
                7 => machine.step(Input::Fault {
                    generation,
                    error: SessionError::Malformed,
                }),
                8 => machine.step(Input::Dispatch),
                _ => Vec::new(),
            };
            transcript.push(effects);
            assert_accounting(&machine);
            assert_ne!(machine.state, State::Stopped);
        }
        (transcript, machine.snapshot())
    }
}
