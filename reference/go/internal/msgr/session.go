package msgr

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/otuschhoff/go-librados/internal/protocol"
)

var (
	ErrSessionClosed       = errors.New("messenger session closed")
	ErrSessionDisconnected = errors.New("messenger session disconnected")
	ErrSessionRenewal      = errors.New("messenger session credential renewal")
	ErrQueueSaturated      = errors.New("messenger outbound queue saturated")
	ErrTooManyInFlight     = errors.New("messenger in-flight limit reached")
	ErrTransitionLimit     = errors.New("messenger handshake transition limit reached")
	ErrReconnectExhausted  = errors.New("messenger reconnect attempts exhausted")
	ErrOutcomeUnknown      = errors.New("messenger request outcome unknown")
)

// Transport is an authenticated, framed messenger connection. Close must
// interrupt any blocked ReadFrame or WriteFrame call.
type Transport interface {
	ReadFrame() (Frame, error)
	WriteFrame(Frame) error
	Close() error
}

type AuthenticatedTransport interface {
	Transport
	AuthenticatedGlobalID() uint64
}

type RenewalTransport interface {
	Transport
	RenewalDue() <-chan struct{}
}

// Connector returns a freshly authenticated transport. Session state and
// replay state remain owned by Session; crypto counters remain in Transport.
type Connector interface {
	Connect(context.Context) (Transport, error)
}

type ConnectorFunc func(context.Context) (Transport, error)

func (function ConnectorFunc) Connect(ctx context.Context) (Transport, error) {
	return function(ctx)
}

type CookieSource interface {
	Cookie() (uint64, error)
}

type CookieSourceFunc func() (uint64, error)

func (function CookieSourceFunc) Cookie() (uint64, error) { return function() }

type randomCookieSource struct{}

func (randomCookieSource) Cookie() (uint64, error) {
	for {
		var data [8]byte
		if _, err := rand.Read(data[:]); err != nil {
			return 0, err
		}
		if cookie := binary.LittleEndian.Uint64(data[:]); cookie != 0 {
			return cookie, nil
		}
	}
}

type ReconnectPolicy uint8

const (
	FailPending ReconnectPolicy = iota
	ReplayPending
)

type SessionState uint8

const (
	StateDisconnected SessionState = iota
	StateConnecting
	StateReconnecting
	StateReady
	StateWait
	StateStopped
)

type EventKind uint8

const (
	EventStateChanged EventKind = iota + 1
	EventSequenceGap
	EventDuplicateDropped
	EventAcknowledged
	EventKeepaliveAck
	EventTransportFault
	EventSessionReset
	EventRetry
	EventRetryGlobal
	EventWait
	EventReconnectOK
	EventOverflow
	EventCredentialRenewal
)

type SessionEvent struct {
	Kind          EventKind
	State         SessionState
	Sequence      uint64
	Expected      uint64
	Err           error
	Full          bool
	Time          Timestamp
	DroppedEvents uint64
}

type SessionSnapshot struct {
	State                 SessionState
	AuthenticatedGlobalID uint64
	ServerGlobalID        int64
	ServerAddresses       protocol.EntityAddrVec
	ServerFeatures        uint64
	ServerFlags           uint64
	NextOutboundSequence  uint64
	LastInboundSequence   uint64
	NextTransactionID     uint64
	ClientCookie          uint64
	ServerCookie          uint64
	GlobalSequence        uint64
	ConnectSequence       uint64
	Queued                int
	InFlight              int
	Replay                int
	RetainedBytes         uint64
	ReconnectAttempts     int
	HandshakeTransitions  int
	DroppedEvents         uint64
}

type SessionDiagnosticKind uint8

const (
	DiagnosticCredentialRenewalDue SessionDiagnosticKind = iota + 1
	DiagnosticCredentialRenewalCompleted
)

type SessionDiagnostic struct {
	Kind       SessionDiagnosticKind
	Service    string
	ServiceID  int32
	SessionID  uint64
	Generation uint64
	Timestamp  time.Time
}

type SessionDiagnosticObserver func(SessionDiagnostic)

type SessionConfig struct {
	Limits                    Limits
	MaxQueuedMessages         int
	MaxRetainedBytes          uint64
	MaxInFlightTransactions   int
	MaxReconnectAttempts      int
	MaxHandshakeTransitions   int
	EventBuffer               int
	ReconnectPolicy           ReconnectPolicy
	ClientIdent               ClientIdent
	ClientCookie              uint64
	ServerCookie              uint64
	GlobalSequence            uint64
	GlobalSequenceSource      GlobalSequenceSource
	ConnectSequence           uint64
	CookieSource              CookieSource
	DiagnosticObserver        SessionDiagnosticObserver
	DiagnosticService         string
	DiagnosticServiceID       int32
	DiagnosticSessionID       uint64
	DiagnosticSessionIDSource func() uint64
	DiagnosticNow             func() time.Time
}

type GlobalSequenceSource interface {
	Next(after uint64) (uint64, error)
}

type atomicGlobalSequenceSource struct{ value atomic.Uint64 }

func (source *atomicGlobalSequenceSource) Next(after uint64) (uint64, error) {
	for {
		current := source.value.Load()
		base := max(current, after)
		if base == math.MaxUint64 {
			return 0, ErrTransitionLimit
		}
		if source.value.CompareAndSwap(current, base+1) {
			return base + 1, nil
		}
	}
}

var processGlobalSequences atomicGlobalSequenceSource

func nextGlobalSequence(source GlobalSequenceSource, after uint64) (uint64, error) {
	next, err := source.Next(after)
	if err != nil {
		return 0, err
	}
	if next <= after {
		return 0, fmt.Errorf("%w: global sequence %d does not advance past %d", ErrMalformed, next, after)
	}
	return next, nil
}

type Session struct {
	commands chan any
	events   chan SessionEvent
	incoming chan Message
	terminal chan error
	done     chan struct{}
	stopOnce sync.Once
}

type submitCommand struct {
	ctx      context.Context
	message  Message
	oneWay   bool
	admitted chan struct{}
	result   chan submitResult
}

type submitResult struct {
	message Message
	err     error
}

type cancelCommand struct {
	request *submitCommand
	err     error
}

type snapshotCommand struct{ result chan SessionSnapshot }
type stopCommand struct{ done chan struct{} }

type pumpFrame struct {
	generation uint64
	frame      Frame
}

type pumpWriteResult struct {
	generation uint64
	taskID     uint64
	request    *submitCommand
	err        error
}

type pumpFault struct {
	generation uint64
	err        error
}

type renewalDue struct{ generation uint64 }

type connectRequest struct {
	generation uint64
	ctx        context.Context
}

type connectResult struct {
	generation uint64
	transport  Transport
	err        error
}

type writeTask struct {
	id      uint64
	frame   Frame
	request *submitCommand
	seq     uint64
}

type pendingRequest struct {
	request         *submitCommand
	message         Message
	bytes           uint64
	seq             uint64
	sent            bool
	mayHaveExecuted bool
}

type sessionOwner struct {
	session *Session
	config  SessionConfig

	state         SessionState
	transport     Transport
	generation    uint64
	writeTasks    chan writeTask
	writeBusy     bool
	nextWriteID   uint64
	controlQueue  []Frame
	pending       []*pendingRequest
	byRequest     map[*submitCommand]*pendingRequest
	byTID         map[uint64]*pendingRequest
	replay        []*pendingRequest
	retainedBytes uint64

	nextOutbound          uint64
	sequenceExhausted     bool
	lastInbound           uint64
	nextTID               uint64
	tidExhausted          bool
	clientCookie          uint64
	serverCookie          uint64
	globalSeq             uint64
	connectSeq            uint64
	authenticatedGlobalID uint64
	serverGlobalID        int64
	serverAddresses       protocol.EntityAddrVec
	serverFeatures        uint64
	serverFlags           uint64
	connectedOnce         bool

	reconnectAttempts int
	transitions       int
	connectPending    bool
	partialReset      bool
	terminalErr       error
	renewalPending    bool
	renewalInProgress bool
	droppedEvents     uint64
	reportedDrops     uint64

	connectorRequests chan connectRequest
	connectorResults  chan connectResult
	frames            chan pumpFrame
	writes            chan pumpWriteResult
	faults            chan pumpFault
	renewals          chan renewalDue
	pumpWG            sync.WaitGroup
	connectorContext  context.Context
	connectorCancel   context.CancelFunc
}

func NewSession(transport Transport, connector Connector, config SessionConfig) (*Session, error) {
	if config.MaxQueuedMessages <= 0 || config.MaxRetainedBytes == 0 || config.MaxInFlightTransactions <= 0 {
		return nil, fmt.Errorf("%w: session limits must be positive", ErrQueueSaturated)
	}
	if config.MaxReconnectAttempts < 0 || config.MaxHandshakeTransitions <= 0 || config.EventBuffer < 0 {
		return nil, fmt.Errorf("%w: invalid session configuration", ErrMalformed)
	}
	if config.Limits.MaxSegmentBytes == 0 || config.Limits.MaxFrameBytes == 0 {
		return nil, fmt.Errorf("%w: frame limits must be positive", ErrMalformed)
	}
	if config.DiagnosticObserver != nil && config.DiagnosticSessionIDSource != nil {
		config.DiagnosticSessionID = config.DiagnosticSessionIDSource()
	}
	if config.DiagnosticObserver != nil && (config.DiagnosticService == "" || config.DiagnosticSessionID == 0) {
		return nil, fmt.Errorf("%w: diagnostic service and session ID are required", ErrMalformed)
	}
	if config.DiagnosticNow == nil {
		config.DiagnosticNow = time.Now
	}
	if config.GlobalSequence != 0 && config.ClientIdent.GlobalSequence != 0 && config.GlobalSequence != config.ClientIdent.GlobalSequence {
		return nil, fmt.Errorf("%w: conflicting global sequences", ErrMalformed)
	}
	if config.GlobalSequence == 0 {
		config.GlobalSequence = config.ClientIdent.GlobalSequence
	}
	if config.GlobalSequenceSource == nil {
		config.GlobalSequenceSource = &processGlobalSequences
	}
	minimumAfter := uint64(0)
	if config.GlobalSequence > 0 {
		minimumAfter = config.GlobalSequence - 1
	}
	var err error
	config.GlobalSequence, err = nextGlobalSequence(config.GlobalSequenceSource, minimumAfter)
	if err != nil {
		return nil, err
	}
	config.ClientIdent.GlobalSequence = config.GlobalSequence
	if config.CookieSource == nil {
		config.CookieSource = randomCookieSource{}
	}

	session := &Session{
		commands: make(chan any),
		events:   make(chan SessionEvent, config.EventBuffer),
		incoming: make(chan Message, config.MaxQueuedMessages),
		terminal: make(chan error, 1),
		done:     make(chan struct{}),
	}
	owner := &sessionOwner{
		session:           session,
		config:            config,
		state:             StateDisconnected,
		transport:         transport,
		byRequest:         make(map[*submitCommand]*pendingRequest),
		byTID:             make(map[uint64]*pendingRequest),
		nextOutbound:      1,
		nextTID:           1,
		clientCookie:      config.ClientCookie,
		serverCookie:      config.ServerCookie,
		globalSeq:         config.GlobalSequence,
		connectedOnce:     transport != nil,
		connectSeq:        config.ConnectSequence,
		connectorRequests: make(chan connectRequest),
		connectorResults:  make(chan connectResult),
		frames:            make(chan pumpFrame),
		writes:            make(chan pumpWriteResult),
		faults:            make(chan pumpFault, 2),
		renewals:          make(chan renewalDue),
	}
	connectorCtx, connectorCancel := context.WithCancel(context.Background())
	owner.connectorContext = connectorCtx
	owner.connectorCancel = connectorCancel
	owner.pumpWG.Add(1)
	go owner.connectorPump(connectorCtx, connector)
	go owner.run()
	return session, nil
}

func (session *Session) Submit(ctx context.Context, message Message) (Message, error) {
	return session.submit(ctx, message, false, nil)
}

// SubmitAdmitted invokes admitted after the request is registered by the
// session owner and before waiting for its reply.
func (session *Session) SubmitAdmitted(ctx context.Context, message Message, admitted func()) (Message, error) {
	return session.submit(ctx, message, false, admitted)
}

// Send transmits a one-way message and returns after its frame has been
// accepted by the transport. Callers must resubmit it after reconnect.
func (session *Session) Send(ctx context.Context, message Message) error {
	_, err := session.submit(ctx, message, true, nil)
	return err
}

func (session *Session) submit(ctx context.Context, message Message, oneWay bool, admitted func()) (Message, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	request := &submitCommand{ctx: ctx, message: message, oneWay: oneWay, admitted: make(chan struct{}), result: make(chan submitResult, 1)}
	select {
	case session.commands <- request:
	case <-ctx.Done():
		return Message{}, ctx.Err()
	case <-session.done:
		return Message{}, ErrSessionClosed
	}
	select {
	case <-request.admitted:
		if admitted != nil {
			admitted()
		}
	case <-session.done:
		select {
		case <-request.admitted:
			if admitted != nil {
				admitted()
			}
			result := <-request.result
			return result.message, result.err
		default:
			return Message{}, ErrSessionClosed
		}
	}
	select {
	case result := <-request.result:
		return result.message, result.err
	case <-ctx.Done():
		select {
		case session.commands <- cancelCommand{request: request, err: ctx.Err()}:
		case <-session.done:
			return Message{}, ctx.Err()
		}
		result := <-request.result
		return result.message, result.err
	case <-session.done:
		result := <-request.result
		return result.message, result.err
	}
}

func (session *Session) Snapshot(ctx context.Context) (SessionSnapshot, error) {
	result := make(chan SessionSnapshot, 1)
	select {
	case session.commands <- snapshotCommand{result: result}:
	case <-ctx.Done():
		return SessionSnapshot{}, ctx.Err()
	case <-session.done:
		return SessionSnapshot{State: StateStopped}, ErrSessionClosed
	}
	select {
	case snapshot := <-result:
		return snapshot, nil
	case <-ctx.Done():
		return SessionSnapshot{}, ctx.Err()
	case <-session.done:
		return SessionSnapshot{State: StateStopped}, ErrSessionClosed
	}
}

func (session *Session) Events() <-chan SessionEvent { return session.events }
func (session *Session) Incoming() <-chan Message    { return session.incoming }
func (session *Session) Terminal() <-chan error      { return session.terminal }
func (session *Session) Done() <-chan struct{}       { return session.done }

func (session *Session) Stop() {
	session.stopOnce.Do(func() {
		done := make(chan struct{})
		select {
		case session.commands <- stopCommand{done: done}:
			<-done
		case <-session.done:
		}
	})
}

func (owner *sessionOwner) run() {
	if owner.transport != nil {
		owner.startTransport(owner.transport, StateReady)
	} else {
		owner.beginReconnect()
	}
	for {
		owner.dispatch()
		select {
		case command := <-owner.session.commands:
			switch value := command.(type) {
			case *submitCommand:
				owner.submit(value)
			case cancelCommand:
				owner.cancel(value)
			case snapshotCommand:
				value.result <- owner.snapshot()
			case stopCommand:
				owner.stop(value.done)
				return
			}
		case incoming := <-owner.frames:
			if incoming.generation == owner.generation {
				owner.handleFrame(incoming.frame)
			}
		case written := <-owner.writes:
			if written.generation == owner.generation {
				owner.writeBusy = false
				if written.err != nil {
					owner.handleFault(written.err)
				} else if written.request != nil {
					if pending := owner.byRequest[written.request]; pending != nil && pending.request.oneWay {
						owner.removePending(pending)
						pending.request.result <- submitResult{}
					}
				}
			}
		case fault := <-owner.faults:
			if fault.generation == owner.generation {
				owner.handleFault(fault.err)
			}
		case renewal := <-owner.renewals:
			if renewal.generation == owner.generation {
				owner.renewalPending = true
				owner.renewalInProgress = true
				owner.emit(SessionEvent{Kind: EventCredentialRenewal})
				owner.emitDiagnostic(DiagnosticCredentialRenewalDue)
			}
		case connected := <-owner.connectorResults:
			owner.handleConnected(connected)
		}
	}
}

func (owner *sessionOwner) submit(command *submitCommand) {
	defer func() {
		command.message = Message{}
		if command.admitted != nil {
			close(command.admitted)
		}
	}()
	if err := command.ctx.Err(); err != nil {
		command.result <- submitResult{err: err}
		return
	}
	if owner.terminalErr != nil {
		command.result <- submitResult{err: owner.terminalErr}
		return
	}
	messageBytes, err := admissionMessageBytes(command.message, owner.config.Limits)
	if err != nil {
		command.result <- submitResult{err: err}
		return
	}
	if len(owner.pending) >= owner.config.MaxQueuedMessages || owner.retainedBytes > owner.config.MaxRetainedBytes || messageBytes > owner.config.MaxRetainedBytes-owner.retainedBytes {
		command.result <- submitResult{err: ErrQueueSaturated}
		return
	}
	message := cloneMessage(command.message)
	if message.Header.TransactionID == 0 {
		transactionID, err := owner.takeTID()
		if err != nil {
			owner.failTerminal(err)
			command.result <- submitResult{err: err}
			return
		}
		message.Header.TransactionID = transactionID
	} else if _, exists := owner.byTID[message.Header.TransactionID]; exists {
		command.result <- submitResult{err: fmt.Errorf("%w: duplicate transaction id %d", ErrMalformed, message.Header.TransactionID)}
		return
	}
	pending := &pendingRequest{request: command, message: message, bytes: messageBytes}
	owner.pending = append(owner.pending, pending)
	owner.byRequest[command] = pending
	owner.byTID[message.Header.TransactionID] = pending
	owner.retainedBytes += messageBytes
}

func (owner *sessionOwner) cancel(command cancelCommand) {
	pending := owner.byRequest[command.request]
	if pending == nil {
		return
	}
	owner.removePending(pending)
	if pending.mayHaveExecuted {
		command.request.result <- submitResult{err: fmt.Errorf("%w: %w", ErrOutcomeUnknown, command.err)}
		return
	}
	command.request.result <- submitResult{err: command.err}
}

func (owner *sessionOwner) dispatch() {
	if owner.writeBusy || owner.writeTasks == nil || owner.state == StateDisconnected || owner.state == StateWait || owner.state == StateStopped {
		return
	}
	if len(owner.controlQueue) > 0 {
		frame := owner.controlQueue[0]
		owner.controlQueue = owner.controlQueue[1:]
		owner.sendWrite(writeTask{frame: frame})
		return
	}
	if owner.state != StateReady {
		return
	}
	if owner.renewalPending {
		if owner.inFlightCount() == 0 {
			owner.renewalPending = false
			owner.handleFault(ErrSessionRenewal)
		}
		return
	}
	for _, pending := range owner.pending {
		if pending.sent {
			continue
		}
		if owner.inFlightCount() >= owner.config.MaxInFlightTransactions {
			return
		}
		if err := pending.request.ctx.Err(); err != nil {
			owner.removePending(pending)
			pending.request.result <- submitResult{err: err}
			return
		}
		if pending.seq == 0 {
			sequence, err := owner.allocateSequence()
			if err != nil {
				owner.failTerminal(err)
				return
			}
			pending.seq = sequence
			pending.message.Header.Sequence = pending.seq
		}
		frame, err := EncodeMessage(pending.message, owner.config.Limits)
		if err != nil {
			owner.removePending(pending)
			pending.request.result <- submitResult{err: err}
			return
		}
		pending.sent = true
		pending.mayHaveExecuted = true
		if !containsPending(owner.replay, pending) {
			owner.replay = append(owner.replay, pending)
		}
		owner.sendWrite(writeTask{frame: frame, request: pending.request, seq: pending.seq})
		return
	}
}

func (owner *sessionOwner) sendWrite(task writeTask) {
	owner.nextWriteID++
	task.id = owner.nextWriteID
	owner.writeBusy = true
	owner.writeTasks <- task
}

func (owner *sessionOwner) handleFrame(frame Frame) {
	if frame.Tag == TagMessage {
		if owner.state != StateReady {
			owner.handleFault(fmt.Errorf("%w: message in state %d", ErrMalformed, owner.state))
			return
		}
		message, err := DecodeMessage(frame, owner.config.Limits)
		if err != nil {
			owner.handleFault(err)
			return
		}
		owner.handleMessage(message)
		return
	}
	payload, err := DecodeControl(frame, owner.config.Limits)
	if err != nil {
		owner.handleFault(err)
		return
	}
	owner.handleControl(payload)
}

func (owner *sessionOwner) handleMessage(message Message) {
	if !owner.acceptAcknowledgment(message.Header.AckSequence) {
		return
	}
	sequence := message.Header.Sequence
	if sequence <= owner.lastInbound {
		owner.emit(SessionEvent{Kind: EventDuplicateDropped, Sequence: sequence})
		return
	}
	if owner.lastInbound != math.MaxUint64 && sequence != owner.lastInbound+1 {
		owner.emit(SessionEvent{Kind: EventSequenceGap, Sequence: sequence, Expected: owner.lastInbound + 1})
	}
	owner.lastInbound = sequence
	owner.trimReplay(message.Header.AckSequence)
	owner.queueControl(Ack{Sequence: sequence})
	if pending := owner.byTID[message.Header.TransactionID]; pending != nil {
		owner.removePending(pending)
		pending.request.result <- submitResult{message: message}
		return
	}
	select {
	case owner.session.incoming <- message:
	default:
		owner.failTerminal(fmt.Errorf("%w: unsolicited message queue is full", ErrQueueSaturated))
	}
}

func (owner *sessionOwner) handleControl(payload any) {
	switch value := payload.(type) {
	case Ack:
		if !owner.readyControl("ack") {
			return
		}
		if !owner.acceptAcknowledgment(value.Sequence) {
			return
		}
		owner.trimReplay(value.Sequence)
		owner.emit(SessionEvent{Kind: EventAcknowledged, Sequence: value.Sequence})
	case Keepalive2:
		if !owner.readyControl("keepalive2") {
			return
		}
		owner.queueControl(Keepalive2Ack(value))
	case Keepalive2Ack:
		if !owner.readyControl("keepalive2 ack") {
			return
		}
		owner.emit(SessionEvent{Kind: EventKeepaliveAck, Time: value.Timestamp})
	case SessionReset:
		if !owner.transitionAllowed(StateReconnecting) {
			return
		}
		owner.handleReset(value.Full)
	case SessionRetry:
		if !owner.transitionAllowed(StateReconnecting) {
			return
		}
		if value.ConnectSequence == math.MaxUint64 {
			owner.failTerminal(ErrTransitionLimit)
			return
		}
		owner.connectSeq = value.ConnectSequence + 1
		owner.emit(SessionEvent{Kind: EventRetry, Sequence: owner.connectSeq})
		owner.sendReconnect()
	case SessionRetryGlobal:
		if !owner.transitionAllowed(StateReconnecting) {
			return
		}
		next, err := nextGlobalSequence(owner.config.GlobalSequenceSource, max(owner.globalSeq, value.GlobalSequence))
		if err != nil {
			owner.failTerminal(ErrTransitionLimit)
			return
		}
		owner.globalSeq = next
		owner.emit(SessionEvent{Kind: EventRetryGlobal, Sequence: owner.globalSeq})
		owner.sendReconnect()
	case Wait:
		if owner.state != StateConnecting && owner.state != StateReconnecting {
			owner.handleFault(fmt.Errorf("%w: wait in state %d", ErrMalformed, owner.state))
			return
		}
		owner.transitions++
		owner.setState(StateWait)
		owner.emit(SessionEvent{Kind: EventWait})
		owner.handleFault(ErrSessionDisconnected)
	case SessionReconnectOK:
		if !owner.transitionAllowed(StateReconnecting) {
			return
		}
		if !owner.acceptAcknowledgment(value.MessageSequence) {
			return
		}
		owner.trimReplay(value.MessageSequence)
		owner.prepareReplay()
		owner.partialReset = false
		owner.reconnectAttempts = 0
		owner.setState(StateReady)
		owner.emit(SessionEvent{Kind: EventReconnectOK, Sequence: value.MessageSequence})
		owner.completeRenewal()
	case ServerIdent:
		if owner.state != StateConnecting {
			owner.handleFault(fmt.Errorf("%w: server ident in state %d", ErrMalformed, owner.state))
			return
		}
		owner.transitions++
		if owner.transitions > owner.config.MaxHandshakeTransitions {
			owner.handleFault(ErrTransitionLimit)
			return
		}
		if unsupported := value.RequiredFeatures &^ owner.config.ClientIdent.SupportedFeatures; unsupported != 0 {
			owner.failTerminal(fmt.Errorf("%w: server requires unsupported features %#x", ErrUnsupportedFeature, unsupported))
			return
		}
		if missing := owner.config.ClientIdent.RequiredFeatures &^ value.SupportedFeatures; missing != 0 {
			owner.failTerminal(fmt.Errorf("%w: server lacks required features %#x", ErrUnsupportedFeature, missing))
			return
		}
		if !containsEntityEndpoint(value.Addresses, owner.config.ClientIdent.TargetAddress) {
			owner.handleFault(fmt.Errorf("%w: server ident does not contain target address", ErrMalformed))
			return
		}
		owner.serverCookie = value.Cookie
		owner.serverGlobalID = value.GlobalID
		owner.serverAddresses = cloneEntityAddresses(value.Addresses)
		owner.serverFeatures = value.SupportedFeatures
		owner.serverFlags = value.Flags
		owner.partialReset = false
		owner.reconnectAttempts = 0
		owner.failSentUnknown(ErrSessionDisconnected)
		owner.setState(StateReady)
		owner.completeRenewal()
	case IdentMissingFeatures:
		owner.failTerminal(fmt.Errorf("%w: server requires missing features %#x", ErrUnsupportedPayload, value.Features))
	default:
		owner.handleFault(fmt.Errorf("%w: unexpected session control %T", ErrUnsupportedPayload, payload))
	}
}

func (owner *sessionOwner) completeRenewal() {
	if !owner.renewalInProgress {
		return
	}
	owner.renewalInProgress = false
	owner.emitDiagnostic(DiagnosticCredentialRenewalCompleted)
}

func (owner *sessionOwner) readyControl(name string) bool {
	if owner.state == StateReady {
		return true
	}
	owner.handleFault(fmt.Errorf("%w: %s in state %d", ErrMalformed, name, owner.state))
	return false
}

func (owner *sessionOwner) acceptAcknowledgment(sequence uint64) bool {
	if !owner.sequenceExhausted && sequence >= owner.nextOutbound && sequence != 0 {
		owner.handleFault(fmt.Errorf("%w: acknowledgment %d exceeds highest outbound sequence", ErrMalformed, sequence))
		return false
	}
	return true
}

func cloneEntityAddresses(addresses protocol.EntityAddrVec) protocol.EntityAddrVec {
	cloned := make(protocol.EntityAddrVec, len(addresses))
	for index, address := range addresses {
		cloned[index] = address
		cloned[index].SocketData = append([]byte(nil), address.SocketData...)
	}
	return cloned
}

func (owner *sessionOwner) transitionAllowed(want SessionState) bool {
	if owner.state != want {
		owner.handleFault(fmt.Errorf("%w: transition in state %d", ErrMalformed, owner.state))
		return false
	}
	owner.transitions++
	if owner.transitions > owner.config.MaxHandshakeTransitions {
		owner.handleFault(ErrTransitionLimit)
		return false
	}
	return true
}

func (owner *sessionOwner) handleReset(full bool) {
	owner.emit(SessionEvent{Kind: EventSessionReset, Full: full})
	owner.serverCookie = 0
	owner.serverFlags = 0
	owner.connectSeq = 0
	owner.lastInbound = 0
	if full {
		if err := owner.refreshClientCookie(); err != nil {
			owner.failTerminal(err)
			return
		}
		owner.nextOutbound = 1
		owner.sequenceExhausted = false
		owner.nextTID = 1
		owner.tidExhausted = false
		owner.failAll(ErrSessionDisconnected)
		owner.replay = nil
		owner.retainedBytes = 0
		owner.partialReset = false
	} else {
		owner.partialReset = true
		owner.prepareReplay()
	}
	owner.setState(StateConnecting)
	owner.queueClientIdent()
}

func (owner *sessionOwner) queueClientIdent() {
	ident := owner.config.ClientIdent
	ident.Cookie = owner.clientCookie
	ident.GlobalSequence = owner.globalSeq
	owner.queueControl(ident)
}

func containsEntityEndpoint(addresses protocol.EntityAddrVec, target protocol.EntityAddr) bool {
	targetEndpoint, ok := target.AddrPort()
	if !ok {
		return false
	}
	for _, address := range addresses {
		if endpoint, ok := address.AddrPort(); ok && endpoint == targetEndpoint {
			return true
		}
	}
	return false
}

func (owner *sessionOwner) refreshClientCookie() error {
	source := owner.config.CookieSource
	if source == nil {
		source = randomCookieSource{}
	}
	cookie, err := source.Cookie()
	if err != nil {
		return fmt.Errorf("%w: generate client cookie: %v", ErrSessionDisconnected, err)
	}
	if cookie == 0 {
		return fmt.Errorf("%w: client cookie must be nonzero", ErrMalformed)
	}
	owner.clientCookie = cookie
	return nil
}

func (owner *sessionOwner) sendReconnect() {
	owner.controlQueue = nil
	owner.queueControl(SessionReconnect{
		Addresses:       owner.config.ClientIdent.Addresses,
		ClientCookie:    owner.clientCookie,
		ServerCookie:    owner.serverCookie,
		GlobalSequence:  owner.globalSeq,
		ConnectSequence: owner.connectSeq,
		MessageSequence: owner.lastInbound,
	})
}

func (owner *sessionOwner) queueControl(payload any) {
	frame, err := EncodeControl(payload, owner.config.Limits)
	if err != nil {
		owner.handleFault(err)
		return
	}
	if len(owner.controlQueue) >= owner.config.MaxQueuedMessages {
		owner.handleFault(ErrQueueSaturated)
		return
	}
	owner.controlQueue = append(owner.controlQueue, frame)
}

func (owner *sessionOwner) trimReplay(sequence uint64) {
	kept := owner.replay[:0]
	for _, pending := range owner.replay {
		if pending.seq > sequence {
			kept = append(kept, pending)
		}
	}
	owner.replay = kept
}

func (owner *sessionOwner) prepareReplay() {
	for _, pending := range owner.replay {
		if owner.byRequest[pending.request] != nil {
			pending.sent = false
		}
	}
}

func (owner *sessionOwner) handleFault(err error) {
	if owner.terminalErr != nil || owner.state == StateStopped || owner.state == StateDisconnected && owner.connectPending {
		return
	}
	owner.emit(SessionEvent{Kind: EventTransportFault, Err: err})
	if owner.transport != nil {
		_ = owner.transport.Close()
		owner.transport = nil
	}
	if owner.writeTasks != nil {
		close(owner.writeTasks)
	}
	owner.writeTasks = nil
	owner.writeBusy = false
	owner.controlQueue = nil
	if owner.serverFlags&ConnectionFlagLossy != 0 {
		owner.failSentUnknown(err)
		owner.resetForNewIdentity()
	} else if owner.config.ReconnectPolicy == FailPending {
		owner.failAll(fmt.Errorf("%w: %v", ErrSessionDisconnected, err))
	} else if owner.serverCookie == 0 {
		owner.failSentUnknown(err)
	} else {
		owner.prepareReplay()
	}
	owner.setState(StateDisconnected)
	owner.beginReconnect()
}

func (owner *sessionOwner) failTerminal(err error) {
	owner.terminalErr = err
	select {
	case owner.session.terminal <- err:
	default:
	}
	owner.emit(SessionEvent{Kind: EventTransportFault, Err: err})
	if owner.transport != nil {
		_ = owner.transport.Close()
		owner.transport = nil
	}
	if owner.writeTasks != nil {
		close(owner.writeTasks)
	}
	owner.writeTasks = nil
	owner.writeBusy = false
	owner.controlQueue = nil
	owner.connectPending = false
	owner.failAll(err)
	owner.setState(StateDisconnected)
}

func (owner *sessionOwner) beginReconnect() {
	if owner.config.MaxReconnectAttempts == 0 || owner.reconnectAttempts >= owner.config.MaxReconnectAttempts {
		owner.failTerminal(ErrReconnectExhausted)
		return
	}
	owner.reconnectAttempts++
	owner.connectPending = true
	owner.generation++
	request := connectRequest{generation: owner.generation, ctx: owner.connectorContext}
	owner.connectorRequests <- request
}

func (owner *sessionOwner) handleConnected(result connectResult) {
	if result.generation != owner.generation || !owner.connectPending {
		if result.transport != nil {
			_ = result.transport.Close()
		}
		return
	}
	owner.connectPending = false
	if result.err != nil || result.transport == nil {
		if result.err == nil {
			result.err = ErrSessionDisconnected
		}
		owner.emit(SessionEvent{Kind: EventTransportFault, Err: result.err})
		owner.beginReconnect()
		return
	}
	owner.terminalErr = nil
	owner.transitions = 0
	if owner.connectedOnce {
		next, err := nextGlobalSequence(owner.config.GlobalSequenceSource, owner.globalSeq)
		if err != nil {
			_ = result.transport.Close()
			owner.failTerminal(ErrTransitionLimit)
			return
		}
		owner.globalSeq = next
	}
	owner.connectedOnce = true
	identityChanged := false
	if authenticated, ok := result.transport.(AuthenticatedTransport); ok {
		globalID := authenticated.AuthenticatedGlobalID()
		if globalID > math.MaxInt64 {
			_ = result.transport.Close()
			owner.failTerminal(ErrMalformed)
			return
		}
		identityChanged = owner.authenticatedGlobalID != 0 && owner.authenticatedGlobalID != globalID
		owner.config.ClientIdent.GlobalID = int64(globalID)
		owner.authenticatedGlobalID = globalID
	}
	if identityChanged {
		owner.resetForNewIdentity()
	}
	if owner.serverCookie != 0 {
		if owner.connectSeq == math.MaxUint64 {
			_ = result.transport.Close()
			owner.failTerminal(ErrTransitionLimit)
			return
		}
		owner.connectSeq++
		owner.startTransport(result.transport, StateReconnecting)
		owner.sendReconnect()
	} else {
		if err := owner.refreshClientCookie(); err != nil {
			_ = result.transport.Close()
			owner.failTerminal(err)
			return
		}
		owner.connectSeq = 0
		owner.startTransport(result.transport, StateConnecting)
		owner.queueClientIdent()
	}
}

func (owner *sessionOwner) resetForNewIdentity() {
	owner.serverCookie = 0
	owner.serverFlags = 0
	owner.connectSeq = 0
	owner.lastInbound = 0
	owner.nextOutbound = 1
	owner.sequenceExhausted = false
	owner.nextTID = 1
	owner.tidExhausted = false
	owner.failAll(ErrSessionDisconnected)
	owner.partialReset = false
}

func (owner *sessionOwner) failSentUnknown(cause error) {
	for _, pending := range append([]*pendingRequest(nil), owner.pending...) {
		if !pending.sent {
			continue
		}
		owner.removePending(pending)
		pending.request.result <- submitResult{err: fmt.Errorf("%w: %w", ErrOutcomeUnknown, cause)}
	}
	owner.replay = nil
}

func (owner *sessionOwner) startTransport(transport Transport, state SessionState) {
	owner.transport = transport
	owner.generation++
	owner.writeTasks = make(chan writeTask)
	generation := owner.generation
	owner.pumpWG.Add(2)
	go owner.readPump(generation, transport)
	go owner.writePump(generation, transport, owner.writeTasks)
	if renewable, ok := transport.(RenewalTransport); ok && renewable.RenewalDue() != nil {
		owner.pumpWG.Add(1)
		go owner.renewalPump(generation, renewable.RenewalDue())
	}
	owner.setState(state)
}

func (owner *sessionOwner) renewalPump(generation uint64, due <-chan struct{}) {
	defer owner.pumpWG.Done()
	select {
	case <-due:
		select {
		case owner.renewals <- renewalDue{generation: generation}:
		case <-owner.session.done:
		}
	case <-owner.session.done:
	}
}

func (owner *sessionOwner) emitDiagnostic(kind SessionDiagnosticKind) {
	if owner.config.DiagnosticObserver == nil {
		return
	}
	owner.config.DiagnosticObserver(SessionDiagnostic{
		Kind:       kind,
		Service:    owner.config.DiagnosticService,
		ServiceID:  owner.config.DiagnosticServiceID,
		SessionID:  owner.config.DiagnosticSessionID,
		Generation: owner.generation,
		Timestamp:  owner.config.DiagnosticNow().UTC(),
	})
}

func (owner *sessionOwner) readPump(generation uint64, transport Transport) {
	defer owner.pumpWG.Done()
	for {
		frame, err := transport.ReadFrame()
		if err != nil {
			owner.reportFault(pumpFault{generation: generation, err: err})
			return
		}
		select {
		case owner.frames <- pumpFrame{generation: generation, frame: frame}:
		case <-owner.session.done:
			return
		}
	}
}

func (owner *sessionOwner) writePump(generation uint64, transport Transport, tasks <-chan writeTask) {
	defer owner.pumpWG.Done()
	for {
		select {
		case task, ok := <-tasks:
			if !ok {
				return
			}
			err := transport.WriteFrame(task.frame)
			select {
			case owner.writes <- pumpWriteResult{generation: generation, taskID: task.id, request: task.request, err: err}:
			case <-owner.session.done:
				return
			}
			if err != nil {
				return
			}
		case <-owner.session.done:
			return
		}
	}
}

func (owner *sessionOwner) reportFault(fault pumpFault) {
	select {
	case owner.faults <- fault:
	case <-owner.session.done:
	}
}

func (owner *sessionOwner) connectorPump(ctx context.Context, connector Connector) {
	defer owner.pumpWG.Done()
	for {
		select {
		case request := <-owner.connectorRequests:
			var transport Transport
			var err error
			if connector == nil {
				err = ErrSessionDisconnected
			} else {
				transport, err = connector.Connect(request.ctx)
			}
			select {
			case owner.connectorResults <- connectResult{generation: request.generation, transport: transport, err: err}:
			case <-ctx.Done():
				if transport != nil {
					_ = transport.Close()
				}
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func (owner *sessionOwner) stop(done chan struct{}) {
	owner.setState(StateStopped)
	owner.failAll(ErrSessionClosed)
	owner.connectorCancel()
	if owner.transport != nil {
		_ = owner.transport.Close()
	}
	close(owner.session.done)
	owner.pumpWG.Wait()
	close(owner.session.events)
	close(owner.session.incoming)
	close(done)
}

func (owner *sessionOwner) failAll(err error) {
	for _, pending := range owner.pending {
		resultErr := err
		if pending.mayHaveExecuted && !errors.Is(err, ErrOutcomeUnknown) {
			resultErr = fmt.Errorf("%w: %w", ErrOutcomeUnknown, err)
		}
		pending.request.result <- submitResult{err: resultErr}
	}
	owner.pending = nil
	owner.replay = nil
	clear(owner.byRequest)
	clear(owner.byTID)
	owner.retainedBytes = 0
}

func (owner *sessionOwner) removePending(target *pendingRequest) {
	for index, pending := range owner.pending {
		if pending == target {
			owner.pending = append(owner.pending[:index], owner.pending[index+1:]...)
			break
		}
	}
	for index, pending := range owner.replay {
		if pending == target {
			owner.replay = append(owner.replay[:index], owner.replay[index+1:]...)
			break
		}
	}
	delete(owner.byRequest, target.request)
	delete(owner.byTID, target.message.Header.TransactionID)
	owner.retainedBytes -= target.bytes
}

func (owner *sessionOwner) inFlightCount() int {
	count := 0
	for _, pending := range owner.pending {
		if pending.sent {
			count++
		}
	}
	return count
}

func (owner *sessionOwner) allocateSequence() (uint64, error) {
	if owner.sequenceExhausted {
		return 0, ErrTransitionLimit
	}
	sequence := owner.nextOutbound
	if sequence == 0 {
		sequence = 1
	}
	if sequence == math.MaxUint64 {
		owner.sequenceExhausted = true
		owner.nextOutbound = 0
	} else {
		owner.nextOutbound = sequence + 1
	}
	return sequence, nil
}

func (owner *sessionOwner) takeSequence() uint64 {
	sequence, _ := owner.allocateSequence()
	return sequence
}

func (owner *sessionOwner) takeTID() (uint64, error) {
	for !owner.tidExhausted {
		transactionID := owner.nextTID
		if transactionID == 0 {
			transactionID = 1
		}
		if transactionID == math.MaxUint64 {
			owner.tidExhausted = true
			owner.nextTID = 0
		} else {
			owner.nextTID = transactionID + 1
		}
		if _, exists := owner.byTID[transactionID]; !exists {
			return transactionID, nil
		}
	}
	return 0, ErrTransitionLimit
}

func (owner *sessionOwner) setState(state SessionState) {
	if owner.state == state {
		return
	}
	owner.state = state
	owner.emit(SessionEvent{Kind: EventStateChanged, State: state})
}

func (owner *sessionOwner) emit(event SessionEvent) {
	event.State = owner.state
	if owner.droppedEvents > owner.reportedDrops {
		overflow := SessionEvent{Kind: EventOverflow, State: owner.state, DroppedEvents: owner.droppedEvents}
		select {
		case owner.session.events <- overflow:
			owner.reportedDrops = owner.droppedEvents
		default:
		}
	}
	select {
	case owner.session.events <- event:
	default:
		owner.droppedEvents++
	}
}

func (owner *sessionOwner) snapshot() SessionSnapshot {
	queued := 0
	for _, pending := range owner.pending {
		if !pending.sent {
			queued++
		}
	}
	return SessionSnapshot{
		State:                 owner.state,
		AuthenticatedGlobalID: owner.authenticatedGlobalID,
		ServerGlobalID:        owner.serverGlobalID,
		ServerAddresses:       cloneEntityAddresses(owner.serverAddresses),
		ServerFeatures:        owner.serverFeatures,
		ServerFlags:           owner.serverFlags,
		NextOutboundSequence:  owner.nextOutbound,
		LastInboundSequence:   owner.lastInbound,
		NextTransactionID:     owner.nextTID,
		ClientCookie:          owner.clientCookie,
		ServerCookie:          owner.serverCookie,
		GlobalSequence:        owner.globalSeq,
		ConnectSequence:       owner.connectSeq,
		Queued:                queued,
		InFlight:              owner.inFlightCount(),
		Replay:                len(owner.replay),
		RetainedBytes:         owner.retainedBytes,
		ReconnectAttempts:     owner.reconnectAttempts,
		HandshakeTransitions:  owner.transitions,
		DroppedEvents:         owner.droppedEvents,
	}
}

func retainedMessageBytes(message Message) uint64 {
	return MessageHeaderSize + uint64(len(message.Front)) + uint64(len(message.Middle)) + uint64(len(message.Data))
}

func admissionMessageBytes(message Message, limits Limits) (uint64, error) {
	frontLength, err := checkedUint32Length(len(message.Front))
	if err != nil {
		return 0, err
	}
	middleLength, err := checkedUint32Length(len(message.Middle))
	if err != nil {
		return 0, err
	}
	dataLength, err := checkedUint32Length(len(message.Data))
	if err != nil {
		return 0, err
	}
	actual := MessageLengths{Front: frontLength, Middle: middleLength, Data: dataLength}
	if message.Lengths != actual {
		return 0, fmt.Errorf("%w: message lengths %+v do not match payloads %+v", ErrMalformed, message.Lengths, actual)
	}
	if message.Header.DataPrePaddingLength > dataLength {
		return 0, fmt.Errorf("%w: data pre-padding %d exceeds data length %d", ErrMalformed, message.Header.DataPrePaddingLength, dataLength)
	}
	var header [MessageHeaderSize]byte
	segments := []Segment{
		{Alignment: messageAlignments[0], Data: header[:]},
		{Alignment: messageAlignments[1], Data: message.Front},
		{Alignment: messageAlignments[2], Data: message.Middle},
		{Alignment: messageAlignments[3], Data: message.Data},
	}
	if err := validateMessageSegments(segments, limits); err != nil {
		return 0, err
	}
	return retainedMessageBytes(message), nil
}

func cloneMessage(message Message) Message {
	message.Front = append([]byte(nil), message.Front...)
	message.Middle = append([]byte(nil), message.Middle...)
	message.Data = append([]byte(nil), message.Data...)
	return message
}

func containsPending(items []*pendingRequest, target *pendingRequest) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}
