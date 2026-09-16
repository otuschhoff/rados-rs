package cephx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/otuschhoff/go-librados/internal/msgr"
	"github.com/otuschhoff/go-librados/internal/protocol"
)

var (
	ErrConnectConfig      = errors.New("invalid cephx connector configuration")
	ErrAuthHandshake      = errors.New("cephx authentication handshake failed")
	ErrPeerEntity         = errors.New("unexpected peer entity type")
	ErrPeerAddress        = errors.New("unexpected peer address")
	ErrAuthRejected       = errors.New("cephx authentication rejected")
	ErrAuthDowngrade      = errors.New("cephx auth downgrade rejected")
	ErrAuthSignature      = errors.New("cephx auth signature mismatch")
	ErrUnexpectedAuthFlow = errors.New("unexpected cephx auth flow")
)

type TicketMetadata struct {
	ServiceID   uint32
	SecretID    uint64
	Fingerprint [sha256.Size]byte
	ExpiresAt   time.Time
	RenewAfter  time.Time
}

type AuthMetadata struct {
	GlobalID uint64
	Method   uint32
	Mode     uint32
	Tickets  map[uint32]TicketMetadata
}

type MetadataTransport interface {
	msgr.Transport
	AuthMetadata() AuthMetadata
}

type ConnectorConfig struct {
	Network          string
	Address          string
	TargetAddress    protocol.EntityAddr
	ExpectedPeerType protocol.EntityType
	ClientEntityType protocol.EntityType
	Credential       Credential
	Dialer           *net.Dialer
	Dial             func(context.Context, string, string) (net.Conn, error)
	DialTimeout      time.Duration
	HandshakeTimeout time.Duration
	MaxBannerPayload uint16
	MessageLimits    msgr.Limits
	Limits           Limits
	GlobalID         uint64
	RequestedKeys    uint32
	AllowCRC         bool
	Now              func() time.Time
	Rand             io.Reader
	OldTicket        TicketBlob
}

type Connector struct {
	config      ConnectorConfig
	connectGate chan struct{}
	mu          sync.Mutex
	hooksMu     sync.Mutex
	state       connectorState
}

type connectorState struct {
	globalID uint64
	mode     uint32
	tickets  map[uint32]ServiceTicket
}

func NewConnector(config ConnectorConfig) (*Connector, error) {
	if config.DialTimeout < 0 || config.HandshakeTimeout < 0 {
		return nil, fmt.Errorf("%w: timeouts must not be negative", ErrConnectConfig)
	}
	config = config.withDefaults()
	if config.Credential.Entity() == "" {
		return nil, fmt.Errorf("%w: missing credential", ErrConnectConfig)
	}
	if config.Address == "" {
		return nil, fmt.Errorf("%w: missing target address", ErrConnectConfig)
	}
	if config.MessageLimits.MaxSegmentBytes == 0 || config.MessageLimits.MaxFrameBytes == 0 || config.MessageLimits.MaxAuthBytes == 0 {
		return nil, fmt.Errorf("%w: invalid messenger limits", ErrConnectConfig)
	}
	if config.MaxBannerPayload < 16 {
		return nil, fmt.Errorf("%w: max banner payload %d", ErrConnectConfig, config.MaxBannerPayload)
	}
	if config.ExpectedPeerType != protocol.EntityMonitor {
		return nil, fmt.Errorf("%w: expected peer type must be monitor", ErrConnectConfig)
	}
	return &Connector{config: config, connectGate: make(chan struct{}, 1)}, nil
}

// AuthMetadata returns a secret-free snapshot of retained authenticated state.
func (connector *Connector) AuthMetadata() AuthMetadata {
	connector.mu.Lock()
	defer connector.mu.Unlock()
	if connector.state.mode == 0 {
		return AuthMetadata{}
	}
	return AuthMetadata{GlobalID: connector.state.globalID, Method: AuthMethodCephX, Mode: connector.state.mode, Tickets: sanitizeTickets(connector.state.tickets)}
}

// NeedsRenewal reports whether a retained service ticket is absent, expired, or due for renewal.
func (connector *Connector) NeedsRenewal(serviceID uint32, now time.Time) bool {
	connector.mu.Lock()
	defer connector.mu.Unlock()
	ticket, ok := connector.state.tickets[serviceID]
	return !ok || ticket.ExpiresAt.IsZero() || !now.Before(ticket.RenewAfter)
}

// BuildServiceAuthorizer constructs an authorizer from a currently valid retained ticket.
func (connector *Connector) BuildServiceAuthorizer(serviceID uint32) (Authorizer, error) {
	_, _, authorizer, err := connector.serviceAuthorization(serviceID)
	return authorizer, err
}

func (connector *Connector) serviceAuthorization(serviceID uint32) (uint64, ServiceTicket, Authorizer, error) {
	now := connector.now()
	connector.mu.Lock()
	ticket, ok := connector.state.tickets[serviceID]
	if !ok {
		connector.mu.Unlock()
		return 0, ServiceTicket{}, Authorizer{}, ErrMissingTicket
	}
	if ticket.ExpiresAt.IsZero() || !now.Before(ticket.ExpiresAt) {
		if serviceID == uint32(protocol.EntityAuth) {
			connector.state = connectorState{}
		} else {
			delete(connector.state.tickets, serviceID)
		}
		connector.mu.Unlock()
		return 0, ServiceTicket{}, Authorizer{}, ErrExpiredTicket
	}
	globalID := connector.state.globalID
	ticket = cloneServiceTicket(ticket)
	connector.mu.Unlock()
	connector.hooksMu.Lock()
	defer connector.hooksMu.Unlock()
	authorizer, err := BuildAuthorizer(serviceID, globalID, ticket, now, connector.config.Rand, connector.config.Limits)
	return globalID, ticket, authorizer, err
}

func (connector *Connector) Connect(ctx context.Context) (msgr.Transport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case connector.connectGate <- struct{}{}:
		defer func() { <-connector.connectGate }()
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: wait for connector: %w", ErrAuthHandshake, ctx.Err())
	}
	cfg := connector.config.withDefaults()
	previousGlobalID, oldTicket, oldAuthKey := connector.renewalSnapshot(connector.now())
	if previousGlobalID != 0 {
		cfg.GlobalID = previousGlobalID
	}
	if oldTicket.Blob != nil {
		cfg.OldTicket = oldTicket
	}
	conn, err := cfg.dial(ctx)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()

	if err := cfg.applyHandshakeDeadline(conn, ctx); err != nil {
		return nil, err
	}
	stopCancelWatch := watchCancel(ctx, conn)
	defer stopCancelWatch()

	tap := newTranscriptConn(conn)
	codec := msgr.CRCCodec{WithDataCRC: true}

	if err := writeAll(tap, msgr.ClientBanner().Encode()); err != nil {
		return nil, handshakeError(ctx, "send banner", err)
	}
	peerBanner, err := msgr.ReadBanner(tap, cfg.MaxBannerPayload)
	if err != nil {
		return nil, handshakeError(ctx, "read banner", err)
	}
	if _, err := msgr.NegotiateBanner(msgr.ClientBanner(), peerBanner); err != nil {
		return nil, fmt.Errorf("%w: banner negotiation: %v", ErrAuthHandshake, err)
	}

	if err := cfg.validateRemoteAddress(conn.RemoteAddr()); err != nil {
		return nil, err
	}
	if err := writeControl(codec, tap, cfg.MessageLimits, msgr.Hello{EntityType: cfg.ClientEntityType, PeerAddress: cfg.TargetAddress}); err != nil {
		return nil, handshakeError(ctx, "send hello", err)
	}
	helloPayload, err := readControl(codec, tap, cfg.MessageLimits)
	if err != nil {
		return nil, handshakeError(ctx, "read hello", err)
	}
	hello, ok := helloPayload.(msgr.Hello)
	if !ok {
		return nil, fmt.Errorf("%w: hello payload %T", ErrUnexpectedAuthFlow, helloPayload)
	}
	if hello.EntityType != cfg.ExpectedPeerType {
		return nil, fmt.Errorf("%w: got %d want %d", ErrPeerEntity, hello.EntityType, cfg.ExpectedPeerType)
	}

	initial, err := BuildInitialPayload(cfg.Credential.Entity(), cfg.GlobalID, cfg.Limits)
	if err != nil {
		return nil, fmt.Errorf("%w: build initial payload: %v", ErrAuthHandshake, err)
	}
	authReq := msgr.AuthRequest{Method: AuthMethodCephX, PreferredModes: cfg.preferredModes(), AuthPayload: initial}
	if err := writeControl(codec, tap, cfg.MessageLimits, authReq); err != nil {
		return nil, handshakeError(ctx, "send auth request", err)
	}

	authReplyPayload, err := readControl(codec, tap, cfg.MessageLimits)
	if err != nil {
		return nil, handshakeError(ctx, "read auth reply", err)
	}
	authReplyMore, ok := authReplyPayload.(msgr.AuthReplyMore)
	if !ok {
		if bad, isBad := authReplyPayload.(msgr.AuthBadMethod); isBad {
			return nil, classifyAuthBadMethod(bad, cfg.preferredModes())
		}
		return nil, fmt.Errorf("%w: expected auth reply more, got %T", ErrUnexpectedAuthFlow, authReplyPayload)
	}

	serverChallenge, err := ParseServerChallenge(authReplyMore.AuthPayload, cfg.Limits)
	if err != nil {
		return nil, fmt.Errorf("%w: parse server challenge: %v", ErrAuthHandshake, err)
	}
	connector.hooksMu.Lock()
	morePayload, _, err := BuildChallengeRequestRandom(
		cfg.Credential,
		serverChallenge,
		cfg.OldTicket,
		cfg.RequestedKeys,
		cfg.Rand,
		cfg.Limits,
	)
	connector.hooksMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("%w: build challenge response: %v", ErrAuthHandshake, err)
	}
	if err := writeControl(codec, tap, cfg.MessageLimits, msgr.AuthRequestMore{AuthPayload: morePayload}); err != nil {
		return nil, handshakeError(ctx, "send auth request more", err)
	}

	donePayload, err := readControl(codec, tap, cfg.MessageLimits)
	if err != nil {
		return nil, handshakeError(ctx, "read auth done", err)
	}
	authDone, ok := donePayload.(msgr.AuthDone)
	if !ok {
		if bad, isBad := donePayload.(msgr.AuthBadMethod); isBad {
			return nil, classifyAuthBadMethod(bad, cfg.preferredModes())
		}
		return nil, fmt.Errorf("%w: expected auth done, got %T", ErrUnexpectedAuthFlow, donePayload)
	}
	if modeNotSupported(authDone.ConnectionMode, cfg.AllowCRC) {
		return nil, fmt.Errorf("%w: mode=%d", ErrAuthDowngrade, authDone.ConnectionMode)
	}
	if !validAuthenticatedGlobalID(authDone.GlobalID) {
		return nil, fmt.Errorf("%w: invalid authenticated global ID %d", ErrAuthHandshake, authDone.GlobalID)
	}

	now := connector.now()
	authReply, err := ParseAuthSessionReply(authDone.AuthPayload, cfg.Credential.Secret(), oldAuthKey, authDone.ConnectionMode, now, cfg.Limits)
	if err != nil {
		return nil, fmt.Errorf("%w: parse auth session reply: %v", ErrAuthHandshake, err)
	}
	transportCodec, err := selectTransportCodec(authDone.ConnectionMode, authReply.ConnectionSecret)
	if err != nil {
		return nil, err
	}

	clientSig := TranscriptSignature(authReply.AuthSessionKey, tap.rxBytes())
	tap.disableCapture()
	if err := writeControl(transportCodec, tap, cfg.MessageLimits, msgr.AuthSignature{Signature: clientSig}); err != nil {
		return nil, handshakeError(ctx, "send auth signature", err)
	}

	sigPayload, err := readControl(transportCodec, tap, cfg.MessageLimits)
	if err != nil {
		return nil, handshakeError(ctx, "read peer signature", err)
	}
	sigFrame, ok := sigPayload.(msgr.AuthSignature)
	if !ok {
		return nil, fmt.Errorf("%w: expected auth signature, got %T", ErrUnexpectedAuthFlow, sigPayload)
	}
	if !VerifyTranscriptSignature(authReply.AuthSessionKey, tap.txBytes(), sigFrame.Signature) {
		return nil, ErrAuthSignature
	}

	stopCancelWatch()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: final handoff: %w", ErrAuthHandshake, err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("%w: clear deadline: %w", ErrAuthHandshake, err)
	}
	baseTransport, err := msgr.NewConnTransport(conn, transportCodec, cfg.MessageLimits)
	if err != nil {
		return nil, err
	}
	connector.storeAuthenticated(authDone.GlobalID, authDone.ConnectionMode, authReply.Tickets)
	success = true
	metadata := AuthMetadata{
		GlobalID: authDone.GlobalID,
		Method:   AuthMethodCephX,
		Mode:     authDone.ConnectionMode,
		Tickets:  sanitizeTickets(authReply.Tickets),
	}
	return newAuthTransport(baseTransport, metadata, earliestRenewal(metadata.Tickets), now), nil
}

func validAuthenticatedGlobalID(globalID uint64) bool {
	return globalID != 0 && globalID <= math.MaxInt64
}

func (connector *Connector) now() time.Time {
	connector.hooksMu.Lock()
	defer connector.hooksMu.Unlock()
	return connector.config.Now()
}

func (connector *Connector) renewalSnapshot(now time.Time) (uint64, TicketBlob, *CryptoKey) {
	connector.mu.Lock()
	defer connector.mu.Unlock()
	authTicket, ok := connector.state.tickets[uint32(protocol.EntityAuth)]
	if !ok {
		return connector.state.globalID, connector.config.OldTicket, nil
	}
	if authTicket.ExpiresAt.IsZero() || !now.Before(authTicket.ExpiresAt) {
		connector.state = connectorState{}
		return 0, TicketBlob{}, nil
	}
	key := authTicket.SessionKey
	return connector.state.globalID, cloneTicketBlob(authTicket.Ticket), &key
}

func (connector *Connector) storeAuthenticated(globalID uint64, mode uint32, tickets map[uint32]ServiceTicket) {
	connector.mu.Lock()
	defer connector.mu.Unlock()
	connector.state.globalID = globalID
	connector.state.mode = mode
	connector.state.tickets = cloneTickets(tickets)
}

func cloneTickets(tickets map[uint32]ServiceTicket) map[uint32]ServiceTicket {
	if len(tickets) == 0 {
		return nil
	}
	cloned := make(map[uint32]ServiceTicket, len(tickets))
	for serviceID, ticket := range tickets {
		cloned[serviceID] = cloneServiceTicket(ticket)
	}
	return cloned
}

func cloneServiceTicket(ticket ServiceTicket) ServiceTicket {
	ticket.Ticket = cloneTicketBlob(ticket.Ticket)
	return ticket
}

func cloneTicketBlob(ticket TicketBlob) TicketBlob {
	return TicketBlob{SecretID: ticket.SecretID, Blob: append([]byte(nil), ticket.Blob...)}
}

type authTransport struct {
	msgr.Transport
	metadata   AuthMetadata
	closeOnce  sync.Once
	renewalDue chan struct{}
	timer      *time.Timer
}

func newAuthTransport(transport msgr.Transport, metadata AuthMetadata, renewAfter, now time.Time) *authTransport {
	authenticated := &authTransport{Transport: transport, metadata: copyMetadata(metadata), renewalDue: make(chan struct{})}
	if !renewAfter.IsZero() {
		delay := renewAfter.Sub(now)
		if delay < 0 {
			delay = 0
		}
		authenticated.timer = time.AfterFunc(delay, func() { close(authenticated.renewalDue) })
	}
	return authenticated
}

func (transport *authTransport) Close() error {
	if transport.timer != nil {
		transport.timer.Stop()
	}
	return transport.closeUnderlying()
}

func (transport *authTransport) closeUnderlying() error {
	var closeErr error
	transport.closeOnce.Do(func() { closeErr = transport.Transport.Close() })
	return closeErr
}

func (transport *authTransport) AuthenticatedGlobalID() uint64 {
	return transport.metadata.GlobalID
}

func (transport *authTransport) RenewalDue() <-chan struct{} { return transport.renewalDue }

func (transport *authTransport) AuthMetadata() AuthMetadata { return copyMetadata(transport.metadata) }

func earliestRenewal(tickets map[uint32]TicketMetadata) time.Time {
	var earliest time.Time
	for _, ticket := range tickets {
		if ticket.RenewAfter.IsZero() || !earliest.IsZero() && !ticket.RenewAfter.Before(earliest) {
			continue
		}
		earliest = ticket.RenewAfter
	}
	return earliest
}

func copyMetadata(metadata AuthMetadata) AuthMetadata {
	copied := metadata
	if metadata.Tickets == nil {
		return copied
	}
	copied.Tickets = make(map[uint32]TicketMetadata, len(metadata.Tickets))
	for serviceID, ticket := range metadata.Tickets {
		copied.Tickets[serviceID] = ticket
	}
	return copied
}

func sanitizeTickets(tickets map[uint32]ServiceTicket) map[uint32]TicketMetadata {
	if len(tickets) == 0 {
		return nil
	}
	metadata := make(map[uint32]TicketMetadata, len(tickets))
	for serviceID, ticket := range tickets {
		metadata[serviceID] = TicketMetadata{
			ServiceID:   ticket.ServiceID,
			SecretID:    ticket.Ticket.SecretID,
			Fingerprint: sha256.Sum256(ticket.Ticket.Blob),
			ExpiresAt:   ticket.ExpiresAt,
			RenewAfter:  ticket.RenewAfter,
		}
	}
	return metadata
}

func selectTransportCodec(mode uint32, connectionSecret []byte) (msgr.Codec, error) {
	switch mode {
	case ConModeSecure:
		codec, err := msgr.NewSecureCodec(connectionSecret, false)
		if err != nil {
			return nil, fmt.Errorf("%w: secure codec: %v", ErrAuthHandshake, err)
		}
		return codec, nil
	case ConModeCRC:
		return msgr.CRCCodec{WithDataCRC: true}, nil
	default:
		return nil, fmt.Errorf("%w: mode=%d", ErrUnsupportedMode, mode)
	}
}

func modeNotSupported(mode uint32, allowCRC bool) bool {
	if mode == ConModeSecure {
		return false
	}
	return !(allowCRC && mode == ConModeCRC)
}

func classifyAuthBadMethod(bad msgr.AuthBadMethod, preferredModes []uint32) error {
	methodAllowed := false
	for _, method := range bad.AllowedMethods {
		methodAllowed = methodAllowed || method == AuthMethodCephX
	}
	modeAllowed := false
	for _, allowed := range bad.AllowedModes {
		for _, preferred := range preferredModes {
			modeAllowed = modeAllowed || allowed == preferred
		}
	}
	kind := ErrAuthRejected
	if bad.Method != AuthMethodCephX || !methodAllowed || !modeAllowed {
		kind = ErrAuthDowngrade
	}
	return fmt.Errorf("%w: method=%d result=%d allowed_methods=%v allowed_modes=%v", kind, bad.Method, bad.Result, bad.AllowedMethods, bad.AllowedModes)
}

func writeControl(codec msgr.Codec, writer io.Writer, limits msgr.Limits, payload any) error {
	frame, err := msgr.EncodeControl(payload, limits)
	if err != nil {
		return err
	}
	wireFrame, err := codec.Encode(frame, limits)
	if err != nil {
		return err
	}
	return writeAll(writer, wireFrame)
}

func readControl(codec msgr.Codec, reader io.Reader, limits msgr.Limits) (any, error) {
	frame, err := codec.Read(reader, limits)
	if err != nil {
		return nil, err
	}
	if frame.Tag == msgr.TagMessage {
		return nil, fmt.Errorf("%w: unexpected message tag", msgr.ErrMalformed)
	}
	return msgr.DecodeControl(frame, limits)
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if written > 0 {
			data = data[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

type transcriptConn struct {
	net.Conn
	tx      bytes.Buffer
	rx      bytes.Buffer
	capture bool
}

func newTranscriptConn(conn net.Conn) *transcriptConn {
	return &transcriptConn{Conn: conn, capture: true}
}

func (conn *transcriptConn) Read(buffer []byte) (int, error) {
	count, err := conn.Conn.Read(buffer)
	if conn.capture && count > 0 {
		_, _ = conn.rx.Write(buffer[:count])
	}
	return count, err
}

func (conn *transcriptConn) Write(buffer []byte) (int, error) {
	count, err := conn.Conn.Write(buffer)
	if conn.capture && count > 0 {
		_, _ = conn.tx.Write(buffer[:count])
	}
	return count, err
}

func (conn *transcriptConn) disableCapture() { conn.capture = false }

func (conn *transcriptConn) txBytes() []byte { return append([]byte(nil), conn.tx.Bytes()...) }

func (conn *transcriptConn) rxBytes() []byte { return append([]byte(nil), conn.rx.Bytes()...) }

func watchCancel(ctx context.Context, conn net.Conn) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	var once sync.Once
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-stop:
		}
	}()
	return func() {
		once.Do(func() {
			close(stop)
			<-done
		})
	}
}

func handshakeError(ctx context.Context, stage string, err error) error {
	contextErr := ctx.Err()
	var networkErr net.Error
	if contextErr == nil && errors.As(err, &networkErr) && networkErr.Timeout() {
		if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
			contextErr = context.DeadlineExceeded
		}
	}
	if contextErr != nil {
		err = errors.Join(contextErr, err)
	}
	return fmt.Errorf("%w: %s: %w", ErrAuthHandshake, stage, err)
}

func (config ConnectorConfig) withDefaults() ConnectorConfig {
	if config.Network == "" {
		config.Network = "tcp"
	}
	if config.DialTimeout == 0 {
		config.DialTimeout = 10 * time.Second
	}
	if config.HandshakeTimeout == 0 {
		config.HandshakeTimeout = 15 * time.Second
	}
	if config.MaxBannerPayload == 0 {
		config.MaxBannerPayload = 64
	}
	if config.ExpectedPeerType == 0 {
		config.ExpectedPeerType = protocol.EntityMonitor
	}
	if config.ClientEntityType == 0 {
		config.ClientEntityType = protocol.EntityClient
	}
	if config.RequestedKeys == 0 {
		config.RequestedKeys = uint32(protocol.EntityAuth | protocol.EntityMonitor | protocol.EntityOSD | protocol.EntityManager)
	}
	config.Limits = config.Limits.withDefaults()
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	if config.Dial == nil {
		dialer := config.Dialer
		if dialer == nil {
			dialer = &net.Dialer{}
		}
		if dialer.Timeout == 0 {
			dialCopy := *dialer
			dialCopy.Timeout = config.DialTimeout
			dialer = &dialCopy
		}
		config.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		}
	}
	return config
}

func (config ConnectorConfig) dial(ctx context.Context) (net.Conn, error) {
	conn, err := config.Dial(ctx, config.Network, config.Address)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, fmt.Errorf("%w: dial returned nil connection", ErrAuthHandshake)
	}
	return conn, nil
}

func (config ConnectorConfig) applyHandshakeDeadline(conn net.Conn, ctx context.Context) error {
	deadline := time.Now().Add(config.HandshakeTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("%w: set handshake deadline: %v", ErrAuthHandshake, err)
	}
	return nil
}

func (config ConnectorConfig) preferredModes() []uint32 {
	if config.AllowCRC {
		return []uint32{ConModeSecure, ConModeCRC}
	}
	return []uint32{ConModeSecure}
}

func (config ConnectorConfig) validateRemoteAddress(remote net.Addr) error {
	target, ok := config.TargetAddress.AddrPort()
	if !ok {
		return nil
	}
	remoteTCP, ok := remote.(*net.TCPAddr)
	if !ok {
		return nil
	}
	remoteIP, ok := netip.AddrFromSlice(remoteTCP.IP)
	if !ok {
		return nil
	}
	remotePort := remoteTCP.Port
	if remotePort < 0 || remotePort > 65535 {
		return fmt.Errorf("%w: invalid remote port %d", ErrPeerAddress, remotePort)
	}
	remoteAddr := netip.AddrPortFrom(remoteIP.Unmap(), uint16(remotePort))
	if remoteAddr != target {
		return fmt.Errorf("%w: connected %s, target %s", ErrPeerAddress, remoteAddr, target)
	}
	return nil
}
