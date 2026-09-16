package cephx

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/otuschhoff/go-librados/internal/msgr"
	"github.com/otuschhoff/go-librados/internal/protocol"
)

type ServiceConnectorConfig struct {
	Authority        *Connector
	AuthoritySource  func() *Connector
	ServiceType      protocol.EntityType
	Network          string
	Address          string
	TargetAddress    protocol.EntityAddr
	Dialer           *net.Dialer
	Dial             func(context.Context, string, string) (net.Conn, error)
	DialTimeout      time.Duration
	HandshakeTimeout time.Duration
	MaxBannerPayload uint16
	MessageLimits    msgr.Limits
	AllowCRC         bool
}

type ServiceConnector struct {
	config ServiceConnectorConfig
}

func NewServiceConnector(config ServiceConnectorConfig) (*ServiceConnector, error) {
	if config.Authority == nil && config.AuthoritySource == nil || config.Address == "" || config.DialTimeout < 0 || config.HandshakeTimeout < 0 {
		return nil, fmt.Errorf("%w: invalid OSD service connector", ErrConnectConfig)
	}
	config = config.withDefaults()
	if config.ServiceType != protocol.EntityOSD && config.ServiceType != protocol.EntityManager {
		return nil, fmt.Errorf("%w: invalid service type %d", ErrConnectConfig, config.ServiceType)
	}
	if config.MaxBannerPayload < 16 || config.MessageLimits.MaxSegmentBytes == 0 || config.MessageLimits.MaxFrameBytes == 0 || config.MessageLimits.MaxAuthBytes == 0 {
		return nil, fmt.Errorf("%w: invalid OSD service connector limits", ErrConnectConfig)
	}
	return &ServiceConnector{config: config}, nil
}

func (connector *ServiceConnector) Connect(ctx context.Context) (msgr.Transport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg := connector.config
	authority := cfg.Authority
	if cfg.AuthoritySource != nil {
		authority = cfg.AuthoritySource()
	}
	if authority == nil {
		return nil, fmt.Errorf("%w: OSD authorizer: %w", ErrAuthHandshake, ErrMissingTicket)
	}
	serviceType := cfg.ServiceType
	globalID, ticket, authorizer, err := authority.serviceAuthorization(uint32(serviceType))
	if err != nil {
		return nil, fmt.Errorf("%w: service %d authorizer: %w", ErrAuthHandshake, serviceType, err)
	}
	conn, err := cfg.Dial(ctx, cfg.Network, cfg.Address)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, fmt.Errorf("%w: dial returned nil connection", ErrAuthHandshake)
	}
	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()
	transportConfig := ConnectorConfig{
		Address: cfg.Address, TargetAddress: cfg.TargetAddress, HandshakeTimeout: cfg.HandshakeTimeout,
		MessageLimits: cfg.MessageLimits, AllowCRC: cfg.AllowCRC,
	}
	if err := transportConfig.applyHandshakeDeadline(conn, ctx); err != nil {
		return nil, err
	}
	stopCancelWatch := watchCancel(ctx, conn)
	defer stopCancelWatch()

	tap := newTranscriptConn(conn)
	crcCodec := msgr.CRCCodec{WithDataCRC: true}
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
	if err := transportConfig.validateRemoteAddress(conn.RemoteAddr()); err != nil {
		return nil, err
	}
	if err := writeControl(crcCodec, tap, cfg.MessageLimits, msgr.Hello{EntityType: protocol.EntityClient, PeerAddress: cfg.TargetAddress}); err != nil {
		return nil, handshakeError(ctx, "send hello", err)
	}
	helloPayload, err := readControl(crcCodec, tap, cfg.MessageLimits)
	if err != nil {
		return nil, handshakeError(ctx, "read hello", err)
	}
	hello, ok := helloPayload.(msgr.Hello)
	if !ok || hello.EntityType != serviceType {
		return nil, fmt.Errorf("%w: service %d hello payload %T entity %d", ErrPeerEntity, serviceType, helloPayload, hello.EntityType)
	}
	if err := writeControl(crcCodec, tap, cfg.MessageLimits, msgr.AuthRequest{Method: AuthMethodCephX, PreferredModes: cfg.preferredModes(), AuthPayload: authorizer.Payload}); err != nil {
		return nil, handshakeError(ctx, "send OSD auth request", err)
	}
	authPayload, err := readControl(crcCodec, tap, cfg.MessageLimits)
	if err != nil {
		return nil, handshakeError(ctx, "read OSD auth reply", err)
	}
	if more, ok := authPayload.(msgr.AuthReplyMore); ok {
		authorizer, err = AddAuthorizerChallenge(authorizer, more.AuthPayload, ticket.SessionKey, authority.config.Limits)
		if err != nil {
			return nil, fmt.Errorf("%w: OSD authorizer challenge: %v", ErrAuthHandshake, err)
		}
		if err := writeControl(crcCodec, tap, cfg.MessageLimits, msgr.AuthRequestMore{AuthPayload: authorizer.Payload}); err != nil {
			return nil, handshakeError(ctx, "send OSD auth request more", err)
		}
		authPayload, err = readControl(crcCodec, tap, cfg.MessageLimits)
		if err != nil {
			return nil, handshakeError(ctx, "read OSD auth done", err)
		}
	}
	authDone, ok := authPayload.(msgr.AuthDone)
	if !ok {
		if bad, isBad := authPayload.(msgr.AuthBadMethod); isBad {
			return nil, classifyAuthBadMethod(bad, cfg.preferredModes())
		}
		return nil, fmt.Errorf("%w: expected OSD auth done, got %T", ErrUnexpectedAuthFlow, authPayload)
	}
	if authDone.GlobalID != globalID || !validAuthenticatedGlobalID(authDone.GlobalID) {
		return nil, fmt.Errorf("%w: OSD global ID %d does not match %d", ErrAuthHandshake, authDone.GlobalID, globalID)
	}
	if modeNotSupported(authDone.ConnectionMode, cfg.AllowCRC) {
		return nil, fmt.Errorf("%w: mode=%d", ErrAuthDowngrade, authDone.ConnectionMode)
	}
	connectionSecret, err := VerifyAuthorizerReply(authDone.AuthPayload, ticket.SessionKey, authorizer.Nonce, authority.config.Limits)
	if err != nil {
		return nil, fmt.Errorf("%w: verify OSD authorizer reply: %v", ErrAuthHandshake, err)
	}
	transportCodec, err := selectTransportCodec(authDone.ConnectionMode, connectionSecret)
	if err != nil {
		return nil, err
	}
	clientSignature := TranscriptSignature(ticket.SessionKey, tap.rxBytes())
	tap.disableCapture()
	if err := writeControl(transportCodec, tap, cfg.MessageLimits, msgr.AuthSignature{Signature: clientSignature}); err != nil {
		return nil, handshakeError(ctx, "send OSD auth signature", err)
	}
	signaturePayload, err := readControl(transportCodec, tap, cfg.MessageLimits)
	if err != nil {
		return nil, handshakeError(ctx, "read OSD auth signature", err)
	}
	signature, ok := signaturePayload.(msgr.AuthSignature)
	if !ok || !VerifyTranscriptSignature(ticket.SessionKey, tap.txBytes(), signature.Signature) {
		return nil, ErrAuthSignature
	}
	stopCancelWatch()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: final OSD handoff: %w", ErrAuthHandshake, err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("%w: clear OSD deadline: %v", ErrAuthHandshake, err)
	}
	baseTransport, err := msgr.NewConnTransport(conn, transportCodec, cfg.MessageLimits)
	if err != nil {
		return nil, err
	}
	success = true
	metadata := AuthMetadata{GlobalID: globalID, Method: AuthMethodCephX, Mode: authDone.ConnectionMode, Tickets: sanitizeTickets(map[uint32]ServiceTicket{uint32(serviceType): ticket})}
	return newAuthTransport(baseTransport, metadata, serviceRenewalTime(ticket), authority.now()), nil
}

func serviceRenewalTime(ticket ServiceTicket) time.Time {
	if ticket.RenewAfter.IsZero() || ticket.ExpiresAt.IsZero() || !ticket.RenewAfter.Before(ticket.ExpiresAt) {
		return ticket.RenewAfter
	}
	return ticket.RenewAfter.Add(ticket.ExpiresAt.Sub(ticket.RenewAfter) / 2)
}

func (config ServiceConnectorConfig) withDefaults() ServiceConnectorConfig {
	if config.ServiceType == 0 {
		config.ServiceType = protocol.EntityOSD
	}
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
	if config.Dial == nil {
		dialer := config.Dialer
		if dialer == nil {
			dialer = &net.Dialer{Timeout: config.DialTimeout}
		}
		config.Dial = dialer.DialContext
	}
	return config
}

func (config ServiceConnectorConfig) preferredModes() []uint32 {
	if config.AllowCRC {
		return []uint32{ConModeSecure, ConModeCRC}
	}
	return []uint32{ConModeSecure}
}
