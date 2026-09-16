package cephx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	wire "github.com/otuschhoff/go-librados/internal/encoding"
	"github.com/otuschhoff/go-librados/internal/protocol"
	krbcrypto "github.com/otuschhoff/gokrb5/v8/crypto"
)

const (
	AuthModeMon = 10

	AuthMethodCephX = 0x2

	ConModeCRC    = 0x1
	ConModeSecure = 0x2

	ConnectionSecretSizeSecure = 16 * 4

	CephAESIV     = "cephsageyudagreg"
	authEncMagic  = 0xff009cad8826aa55
	cephxCryptErr = 1

	cephxGetAuthSessionKey      = 0x0100
	cephxGetPrincipalSessionKey = 0x0200
	cephxGetRotatingKey         = 0x0400

	keyUsageAuthConnectionSecret = 0x03
	keyUsageTicketSessionKey     = 0x04
	keyUsageTicketBlob           = 0x05
	keyUsageAuthorize            = 0x10
	keyUsageAuthorizeChallenge   = 0x11
	keyUsageAuthorizeReply       = 0x12
)

var (
	ErrInvalidMode       = errors.New("invalid cephx mode")
	ErrInvalidMethod     = errors.New("invalid cephx auth method")
	ErrInvalidStatus     = errors.New("invalid cephx status")
	ErrInvalidVersion    = errors.New("invalid cephx version")
	ErrInvalidMagic      = errors.New("invalid cephx encrypted magic")
	ErrMalformedPayload  = errors.New("malformed cephx payload")
	ErrUnsupportedMode   = errors.New("unsupported cephx mode")
	ErrUnsupportedMethod = errors.New("unsupported cephx method")
	ErrUnsupportedType   = errors.New("unsupported cephx type")
	ErrMissingChallenge  = errors.New("missing cephx server challenge")
	ErrMissingTicket     = errors.New("missing cephx ticket")
	ErrExpiredTicket     = errors.New("expired cephx ticket")
	ErrChallengeMismatch = errors.New("cephx challenge mismatch")
	ErrNonceMismatch     = errors.New("cephx nonce mismatch")
)

type Limits struct {
	MaxAuthBytes             uint32
	MaxModes                 uint32
	MaxTickets               uint32
	MaxTicketBlobBytes       uint32
	MaxDecryptBytes          uint32
	MaxEncryptBytes          uint32
	MaxConnectionSecretBytes uint32
}

func DefaultLimits() Limits {
	return Limits{
		MaxAuthBytes:             1 << 20,
		MaxModes:                 64,
		MaxTickets:               64,
		MaxTicketBlobBytes:       1 << 20,
		MaxDecryptBytes:          1 << 20,
		MaxEncryptBytes:          1 << 20,
		MaxConnectionSecretBytes: ConnectionSecretSizeSecure,
	}
}

func (limits Limits) withDefaults() Limits {
	defaults := DefaultLimits()
	if limits.MaxAuthBytes == 0 {
		limits.MaxAuthBytes = defaults.MaxAuthBytes
	}
	if limits.MaxModes == 0 {
		limits.MaxModes = defaults.MaxModes
	}
	if limits.MaxTickets == 0 {
		limits.MaxTickets = defaults.MaxTickets
	}
	if limits.MaxTicketBlobBytes == 0 {
		limits.MaxTicketBlobBytes = defaults.MaxTicketBlobBytes
	}
	if limits.MaxDecryptBytes == 0 {
		limits.MaxDecryptBytes = defaults.MaxDecryptBytes
	}
	if limits.MaxEncryptBytes == 0 {
		limits.MaxEncryptBytes = defaults.MaxEncryptBytes
	}
	if limits.MaxConnectionSecretBytes == 0 {
		limits.MaxConnectionSecretBytes = defaults.MaxConnectionSecretBytes
	}
	return limits
}

type TicketBlob struct {
	SecretID uint64
	Blob     []byte
}

func (ticket TicketBlob) String() string {
	return fmt.Sprintf("cephx ticket secret_id=%d (redacted)", ticket.SecretID)
}

func (ticket TicketBlob) GoString() string { return ticket.String() }

type ServiceTicket struct {
	ServiceID  uint32
	Ticket     TicketBlob
	SessionKey CryptoKey
	ExpiresAt  time.Time
	RenewAfter time.Time
}

func (ticket ServiceTicket) String() string {
	return fmt.Sprintf("cephx service ticket service=%d expires=%s (redacted)", ticket.ServiceID, ticket.ExpiresAt.UTC().Format(time.RFC3339))
}

func (ticket ServiceTicket) GoString() string { return ticket.String() }

type AuthSessionReply struct {
	RequestType      uint16
	AuthSessionKey   CryptoKey
	ConnectionSecret []byte
	Tickets          map[uint32]ServiceTicket
}

func (reply AuthSessionReply) String() string {
	return fmt.Sprintf("cephx auth reply type=%d tickets=%d (redacted)", reply.RequestType, len(reply.Tickets))
}

func (reply AuthSessionReply) GoString() string { return reply.String() }

type Authorizer struct {
	Base      []byte
	Payload   []byte
	Nonce     uint64
	ServiceID uint32
}

func (authorizer Authorizer) String() string {
	return fmt.Sprintf("cephx authorizer service=%d (redacted)", authorizer.ServiceID)
}

func (authorizer Authorizer) GoString() string { return authorizer.String() }

func BuildInitialPayload(entity string, globalID uint64, limits Limits) ([]byte, error) {
	limits = limits.withDefaults()
	if !validClientEntity(entity) {
		return nil, ErrInvalidCredential
	}
	_, id, _ := strings.Cut(entity, ".")
	encoder := wire.NewEncoder(limits.MaxAuthBytes)
	encoder.Uint8(AuthModeMon)
	encoder.Uint32(uint32(protocol.EntityClient))
	encoder.String(id)
	encoder.Uint64(globalID)
	return encoder.BytesResult()
}

func ParseServerChallenge(payload []byte, limits Limits) (uint64, error) {
	limits = limits.withDefaults()
	if uint64(len(payload)) > uint64(limits.MaxAuthBytes) {
		return 0, wire.ErrLimitExceeded
	}
	decoder := wire.NewDecoder(payload, wire.Limits{MaxBytes: limits.MaxAuthBytes})
	structVersion := decoder.Uint8()
	challenge := decoder.Uint64()
	if err := decoder.Finish(); err != nil || decoder.Remaining() != 0 {
		return 0, ErrMalformedPayload
	}
	if structVersion != 1 {
		return 0, ErrInvalidVersion
	}
	return challenge, nil
}

func BuildChallengeRequestRandom(
	credential Credential,
	serverChallenge uint64,
	oldTicket TicketBlob,
	requestedKeys uint32,
	rng io.Reader,
	limits Limits,
) ([]byte, uint64, error) {
	if rng == nil {
		rng = rand.Reader
	}
	var challengeBytes [8]byte
	if _, err := io.ReadFull(rng, challengeBytes[:]); err != nil {
		return nil, 0, err
	}
	clientChallenge := binary.LittleEndian.Uint64(challengeBytes[:])
	request, err := BuildChallengeRequest(
		credential,
		serverChallenge,
		clientChallenge,
		oldTicket,
		requestedKeys,
		limits,
	)
	if err != nil {
		return nil, 0, err
	}
	return request, clientChallenge, nil
}

func BuildChallengeRequest(
	credential Credential,
	serverChallenge uint64,
	clientChallenge uint64,
	oldTicket TicketBlob,
	requestedKeys uint32,
	limits Limits,
) ([]byte, error) {
	limits = limits.withDefaults()
	if uint64(len(oldTicket.Blob)) > uint64(limits.MaxTicketBlobBytes) {
		return nil, wire.ErrLimitExceeded
	}
	challengeKey, err := calcClientServerChallenge(
		credential.Secret(),
		serverChallenge,
		clientChallenge,
		limits,
	)
	if err != nil {
		return nil, err
	}
	encoder := wire.NewEncoder(limits.MaxAuthBytes)
	encoder.Uint16(cephxGetAuthSessionKey)

	encoder.Uint8(3)
	encoder.Uint64(clientChallenge)
	encoder.Uint64(challengeKey)
	encodeTicketBlob(encoder, oldTicket)
	encoder.Uint32(requestedKeys)
	data, err := encoder.BytesResult()
	if err != nil {
		return nil, err
	}
	return data, nil
}

func BuildServiceTicketRequest(authorizer []byte, requestedKeys uint32, limits Limits) ([]byte, error) {
	limits = limits.withDefaults()
	if uint64(len(authorizer)) > uint64(limits.MaxAuthBytes) {
		return nil, wire.ErrLimitExceeded
	}
	encoder := wire.NewEncoder(limits.MaxAuthBytes)
	encoder.Uint16(cephxGetPrincipalSessionKey)
	encoder.Raw(authorizer)
	encoder.Uint8(1)
	encoder.Uint32(requestedKeys)
	return encoder.BytesResult()
}

func ParseAuthSessionReply(
	payload []byte,
	principalSecret CryptoKey,
	existingAuthKey *CryptoKey,
	connectionMode uint32,
	now time.Time,
	limits Limits,
) (AuthSessionReply, error) {
	limits = limits.withDefaults()
	if connectionMode != ConModeCRC && connectionMode != ConModeSecure {
		return AuthSessionReply{}, ErrUnsupportedMode
	}
	if uint64(len(payload)) > uint64(limits.MaxAuthBytes) {
		return AuthSessionReply{}, wire.ErrLimitExceeded
	}

	decoder := wire.NewDecoder(payload, wire.Limits{MaxBytes: limits.MaxAuthBytes})
	headerType := decoder.Uint16()
	status := decoder.Int32()
	if err := decoder.Finish(); err != nil {
		return AuthSessionReply{}, ErrMalformedPayload
	}
	if status != 0 {
		return AuthSessionReply{}, fmt.Errorf("%w: %d", ErrInvalidStatus, status)
	}
	if headerType != cephxGetAuthSessionKey {
		return AuthSessionReply{}, fmt.Errorf("%w: request_type=%d", ErrUnsupportedType, headerType)
	}

	tickets, err := parseServiceTicketReply(decoder, principalSecret, existingAuthKey, now, limits, limits.MaxTickets)
	if err != nil {
		return AuthSessionReply{}, err
	}
	if uint32(len(tickets)) > limits.MaxTickets {
		return AuthSessionReply{}, wire.ErrLimitExceeded
	}

	reply := AuthSessionReply{RequestType: headerType, Tickets: tickets}
	authTicket, ok := tickets[uint32(protocol.EntityAuth)]
	if !ok {
		return AuthSessionReply{}, ErrMissingTicket
	}
	reply.AuthSessionKey = authTicket.SessionKey

	if decoder.Remaining() == 0 {
		if err := decoder.Finish(); err != nil {
			return AuthSessionReply{}, ErrMalformedPayload
		}
		return reply, nil
	}

	connectionBlob := decoder.Bytes()
	extraTicketsBlob := decoder.Bytes()
	if err := decoder.Finish(); err != nil || decoder.Remaining() != 0 {
		return AuthSessionReply{}, ErrMalformedPayload
	}

	if !ok {
		return AuthSessionReply{}, ErrMissingTicket
	}
	if len(connectionBlob) > 0 {
		if connectionMode != ConModeSecure {
			return AuthSessionReply{}, ErrUnsupportedMode
		}
		secret, err := decryptStringEnvelope(authTicket.SessionKey, connectionBlob, keyUsageAuthConnectionSecret, limits)
		if err != nil {
			return AuthSessionReply{}, err
		}
		if uint64(len(secret)) > uint64(limits.MaxConnectionSecretBytes) {
			return AuthSessionReply{}, wire.ErrLimitExceeded
		}
		if len(secret) != ConnectionSecretSizeSecure {
			return AuthSessionReply{}, ErrMalformedPayload
		}
		reply.ConnectionSecret = secret
	}
	if len(extraTicketsBlob) > 0 {
		extraDecoder := wire.NewDecoder(extraTicketsBlob, wire.Limits{MaxBytes: limits.MaxAuthBytes})
		remainingTickets := limits.MaxTickets - uint32(len(reply.Tickets))
		extraTickets, err := parseServiceTicketReply(extraDecoder, authTicket.SessionKey, nil, now, limits, remainingTickets)
		if err != nil {
			return AuthSessionReply{}, err
		}
		if extraDecoder.Remaining() != 0 || extraDecoder.Finish() != nil {
			return AuthSessionReply{}, ErrMalformedPayload
		}
		for serviceID, ticket := range extraTickets {
			if _, duplicate := reply.Tickets[serviceID]; duplicate {
				return AuthSessionReply{}, ErrMalformedPayload
			}
			if uint32(len(reply.Tickets)) >= limits.MaxTickets {
				return AuthSessionReply{}, wire.ErrLimitExceeded
			}
			reply.Tickets[serviceID] = ticket
		}
	}

	return reply, nil
}

func BuildAuthorizer(
	serviceID uint32,
	globalID uint64,
	ticket ServiceTicket,
	now time.Time,
	rng io.Reader,
	limits Limits,
) (Authorizer, error) {
	limits = limits.withDefaults()
	if ticket.ServiceID != serviceID {
		return Authorizer{}, ErrMalformedPayload
	}
	if ticket.ExpiresAt.IsZero() || !now.Before(ticket.ExpiresAt) {
		return Authorizer{}, ErrExpiredTicket
	}
	if rng == nil {
		rng = rand.Reader
	}
	var nonceBytes [8]byte
	if _, err := io.ReadFull(rng, nonceBytes[:]); err != nil {
		return Authorizer{}, err
	}
	nonce := binary.LittleEndian.Uint64(nonceBytes[:])

	base := wire.NewEncoder(limits.MaxAuthBytes)
	base.Uint8(1)
	base.Uint64(globalID)
	base.Uint32(serviceID)
	encodeTicketBlob(base, ticket.Ticket)
	baseBytes, err := base.BytesResult()
	if err != nil {
		return Authorizer{}, err
	}

	authorize := wire.NewEncoder(limits.MaxAuthBytes)
	authorize.Uint8(2)
	authorize.Uint64(nonce)
	authorize.Bool(false)
	authorize.Uint64(0)
	authorizeBytes, err := authorize.BytesResult()
	if err != nil {
		return Authorizer{}, err
	}
	encryptedAuthorize, err := encodeEncryptEnvelopeUsage(ticket.SessionKey, authorizeBytes, keyUsageAuthorize, limits)
	if err != nil {
		return Authorizer{}, err
	}
	payload := append(append([]byte(nil), baseBytes...), encryptedAuthorize...)
	if uint64(len(payload)) > uint64(limits.MaxAuthBytes) {
		return Authorizer{}, wire.ErrLimitExceeded
	}
	return Authorizer{Base: baseBytes, Payload: payload, Nonce: nonce, ServiceID: serviceID}, nil
}

func AddAuthorizerChallenge(authorizer Authorizer, challenge []byte, sessionKey CryptoKey, limits Limits) (Authorizer, error) {
	limits = limits.withDefaults()
	challengePlaintext, err := decryptEncryptEnvelopeRawUsage(sessionKey, challenge, keyUsageAuthorizeChallenge, limits)
	if err != nil {
		return Authorizer{}, err
	}
	challengeDecoder := wire.NewDecoder(challengePlaintext, wire.Limits{MaxBytes: limits.MaxAuthBytes})
	challengeVersion := challengeDecoder.Uint8()
	serverChallenge := challengeDecoder.Uint64()
	if err := challengeDecoder.Finish(); err != nil || challengeDecoder.Remaining() != 0 {
		return Authorizer{}, ErrMalformedPayload
	}
	if challengeVersion != 1 {
		return Authorizer{}, ErrInvalidVersion
	}

	authorize := wire.NewEncoder(limits.MaxAuthBytes)
	authorize.Uint8(2)
	authorize.Uint64(authorizer.Nonce)
	authorize.Bool(true)
	authorize.Uint64(serverChallenge + 1)
	authorizeBytes, err := authorize.BytesResult()
	if err != nil {
		return Authorizer{}, err
	}
	encryptedAuthorize, err := encodeEncryptEnvelopeUsage(sessionKey, authorizeBytes, keyUsageAuthorize, limits)
	if err != nil {
		return Authorizer{}, err
	}
	payload := append(append([]byte(nil), authorizer.Base...), encryptedAuthorize...)
	if uint64(len(payload)) > uint64(limits.MaxAuthBytes) {
		return Authorizer{}, wire.ErrLimitExceeded
	}
	updated := authorizer
	updated.Payload = payload
	return updated, nil
}

func VerifyAuthorizerReply(payload []byte, sessionKey CryptoKey, nonce uint64, limits Limits) ([]byte, error) {
	limits = limits.withDefaults()
	decoder := wire.NewDecoder(payload, wire.Limits{MaxBytes: limits.MaxAuthBytes})
	encrypted := decoder.Bytes()
	if err := decoder.Finish(); err != nil || decoder.Remaining() != 0 {
		return nil, ErrMalformedPayload
	}
	plaintext, err := decryptEncryptEnvelopeRawUsage(sessionKey, encrypted, keyUsageAuthorizeReply, limits)
	if err != nil {
		return nil, err
	}

	reply := wire.NewDecoder(plaintext, wire.Limits{MaxBytes: limits.MaxAuthBytes})
	version := reply.Uint8()
	noncePlusOne := reply.Uint64()
	var secret []byte
	if version >= 2 {
		secret = reply.Bytes()
		if uint64(len(secret)) > uint64(limits.MaxConnectionSecretBytes) {
			return nil, wire.ErrLimitExceeded
		}
	}
	if err := reply.Finish(); err != nil || reply.Remaining() != 0 {
		return nil, ErrMalformedPayload
	}
	if version < 1 {
		return nil, ErrInvalidVersion
	}
	if noncePlusOne != nonce+1 {
		return nil, ErrNonceMismatch
	}
	return append([]byte(nil), secret...), nil
}

func TranscriptSignature(sessionKey CryptoKey, transcript []byte) [sha256.Size]byte {
	mac := hmac.New(sha256.New, sessionKey.secret[:sessionKey.size])
	_, _ = mac.Write(transcript)
	var out [sha256.Size]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func VerifyTranscriptSignature(sessionKey CryptoKey, transcript []byte, signature [sha256.Size]byte) bool {
	expected := TranscriptSignature(sessionKey, transcript)
	return hmac.Equal(expected[:], signature[:])
}

func decodeUtime(decoder *wire.Decoder) (time.Duration, error) {
	seconds := decoder.Uint32()
	nanoseconds := decoder.Uint32()
	if nanoseconds >= uint32(time.Second) {
		return 0, ErrMalformedPayload
	}
	maxSeconds := uint64(math.MaxInt64 / int64(time.Second))
	if uint64(seconds) > maxSeconds {
		return 0, wire.ErrLimitExceeded
	}
	return time.Duration(seconds)*time.Second + time.Duration(nanoseconds), nil
}

func decodeSecretKey(decoder *wire.Decoder, limits Limits) (CryptoKey, error) {
	var secret CryptoKey
	keyType := decoder.Uint16()
	_, err := decodeUtime(decoder)
	if err != nil {
		return secret, err
	}
	secretLength := decoder.Uint16()
	if !validKeyParameters(keyType, secretLength) {
		return secret, ErrUnsupportedType
	}
	if uint32(secretLength) > limits.MaxDecryptBytes {
		return secret, wire.ErrLimitExceeded
	}
	data := decoder.Raw(uint32(secretLength))
	secret.typeID = keyType
	secret.size = uint8(secretLength)
	copy(secret.secret[:], data)
	return secret, nil
}

func encodeTicketBlob(encoder *wire.Encoder, blob TicketBlob) {
	encoder.Uint8(1)
	encoder.Uint64(blob.SecretID)
	encoder.Bytes(blob.Blob)
}

func decodeTicketBlob(decoder *wire.Decoder, limits Limits) (TicketBlob, error) {
	version := decoder.Uint8()
	secretID := decoder.Uint64()
	blob := decoder.Bytes()
	if version != 1 {
		return TicketBlob{}, ErrInvalidVersion
	}
	if uint64(len(blob)) > uint64(limits.MaxTicketBlobBytes) {
		return TicketBlob{}, wire.ErrLimitExceeded
	}
	return TicketBlob{SecretID: secretID, Blob: blob}, nil
}

func parseServiceTicketReply(
	decoder *wire.Decoder,
	decryptKey CryptoKey,
	existingAuthKey *CryptoKey,
	now time.Time,
	limits Limits,
	maxTickets uint32,
) (map[uint32]ServiceTicket, error) {
	replyVersion := decoder.Uint8()
	count := decoder.Uint32()
	if replyVersion != 1 {
		return nil, ErrInvalidVersion
	}
	if count > maxTickets {
		return nil, wire.ErrLimitExceeded
	}
	tickets := make(map[uint32]ServiceTicket, count)
	for index := uint32(0); index < count; index++ {
		serviceID := decoder.Uint32()
		if _, duplicate := tickets[serviceID]; duplicate {
			return nil, ErrMalformedPayload
		}
		serviceTicketVersion := decoder.Uint8()
		if serviceTicketVersion != 1 {
			return nil, ErrInvalidVersion
		}

		serviceTicketPayload, err := decodeDecryptEnvelopeUsage(decryptKey, decoder, keyUsageTicketSessionKey, limits)
		if err != nil {
			return nil, err
		}

		serviceTicketDecoder := wire.NewDecoder(serviceTicketPayload, wire.Limits{MaxBytes: limits.MaxAuthBytes})
		serviceTicketVersion2 := serviceTicketDecoder.Uint8()
		if serviceTicketVersion2 != 1 {
			return nil, ErrInvalidVersion
		}
		sessionKey, err := decodeSecretKey(serviceTicketDecoder, limits)
		if err != nil {
			return nil, err
		}
		validity, err := decodeUtime(serviceTicketDecoder)
		if err != nil {
			return nil, err
		}
		if validity <= 0 {
			return nil, ErrExpiredTicket
		}
		if err := serviceTicketDecoder.Finish(); err != nil || serviceTicketDecoder.Remaining() != 0 {
			return nil, ErrMalformedPayload
		}

		ticketEncrypted := decoder.Uint8()
		var ticketPayload []byte
		switch ticketEncrypted {
		case 0:
			ticketPayload = decoder.Bytes()
		case 1:
			if existingAuthKey == nil {
				return nil, ErrMissingTicket
			}
			encryptedPayload, decryptErr := decodeDecryptEnvelopeUsage(*existingAuthKey, decoder, keyUsageTicketBlob, limits)
			if decryptErr != nil {
				return nil, decryptErr
			}
			encryptedDecoder := wire.NewDecoder(encryptedPayload, wire.Limits{MaxBytes: limits.MaxAuthBytes})
			ticketPayload = encryptedDecoder.Bytes()
			if encryptedDecoder.Finish() != nil || encryptedDecoder.Remaining() != 0 {
				return nil, ErrMalformedPayload
			}
		default:
			return nil, ErrMalformedPayload
		}

		ticketPayloadDecoder := wire.NewDecoder(ticketPayload, wire.Limits{MaxBytes: limits.MaxAuthBytes})
		ticketBlob, err := decodeTicketBlob(ticketPayloadDecoder, limits)
		if err != nil {
			return nil, err
		}
		if err := ticketPayloadDecoder.Finish(); err != nil || ticketPayloadDecoder.Remaining() != 0 {
			return nil, ErrMalformedPayload
		}

		ticket := ServiceTicket{
			ServiceID:  serviceID,
			SessionKey: sessionKey,
			Ticket:     ticketBlob,
		}
		ticket.ExpiresAt = now.Add(validity)
		ticket.RenewAfter = ticket.ExpiresAt.Add(-(validity / 4))
		if !now.Before(ticket.ExpiresAt) {
			return nil, ErrExpiredTicket
		}
		tickets[serviceID] = ticket
	}
	return tickets, nil
}

func decryptStringEnvelope(secret CryptoKey, payload []byte, usage uint32, limits Limits) ([]byte, error) {
	decoder := wire.NewDecoder(payload, wire.Limits{MaxBytes: limits.MaxAuthBytes})
	plaintext, err := decodeDecryptEnvelopeUsage(secret, decoder, usage, limits)
	if err != nil {
		return nil, err
	}
	if decoder.Remaining() != 0 {
		return nil, ErrMalformedPayload
	}
	stringDecoder := wire.NewDecoder(plaintext, wire.Limits{MaxBytes: limits.MaxConnectionSecretBytes})
	value := stringDecoder.Bytes()
	if err := stringDecoder.Finish(); err != nil || stringDecoder.Remaining() != 0 {
		return nil, ErrMalformedPayload
	}
	return value, nil
}

func decodeDecryptEnvelope(secret CryptoKey, decoder *wire.Decoder, limits Limits) ([]byte, error) {
	return decodeDecryptEnvelopeUsage(secret, decoder, 0, limits)
}

func decodeDecryptEnvelopeUsage(secret CryptoKey, decoder *wire.Decoder, usage uint32, limits Limits) ([]byte, error) {
	encrypted := decoder.Bytes()
	if err := decoder.Finish(); err != nil {
		return nil, ErrMalformedPayload
	}
	return decryptEncryptEnvelopeRawUsage(secret, encrypted, usage, limits)
}

func encodeEncryptEnvelope(secret CryptoKey, payload []byte, limits Limits) ([]byte, error) {
	return encodeEncryptEnvelopeUsage(secret, payload, 0, limits)
}

func encodeEncryptEnvelopeUsage(secret CryptoKey, payload []byte, usage uint32, limits Limits) ([]byte, error) {
	encrypted, err := encryptWithMagicUsage(secret, payload, usage, limits)
	if err != nil {
		return nil, err
	}
	encoder := wire.NewEncoder(limits.MaxAuthBytes)
	encoder.Bytes(encrypted)
	return encoder.BytesResult()
}

func encryptWithMagic(secret CryptoKey, payload []byte, limits Limits) ([]byte, error) {
	return encryptWithMagicUsage(secret, payload, 0, limits)
}

func encryptWithMagicUsage(secret CryptoKey, payload []byte, usage uint32, limits Limits) ([]byte, error) {
	limits = limits.withDefaults()
	encoder := wire.NewEncoder(limits.MaxEncryptBytes)
	encoder.Uint8(1)
	encoder.Uint64(authEncMagic)
	encoder.Raw(payload)
	plaintext, err := encoder.BytesResult()
	if err != nil {
		return nil, err
	}
	return encryptPayload(secret, plaintext, usage, limits)
}

func decryptEncryptEnvelopeRawUsage(secret CryptoKey, encrypted []byte, usage uint32, limits Limits) ([]byte, error) {
	limits = limits.withDefaults()
	plaintext, err := decryptPayload(secret, encrypted, usage, limits)
	if err != nil {
		return nil, err
	}
	decoder := wire.NewDecoder(plaintext, wire.Limits{MaxBytes: limits.MaxDecryptBytes})
	version := decoder.Uint8()
	magic := decoder.Uint64()
	payload := decoder.Raw(uint32(decoder.Remaining()))
	if err := decoder.Finish(); err != nil || decoder.Remaining() != 0 {
		return nil, ErrMalformedPayload
	}
	if version != 1 {
		return nil, ErrInvalidVersion
	}
	if magic != authEncMagic {
		return nil, ErrInvalidMagic
	}
	return payload, nil
}

func calcClientServerChallenge(secret CryptoKey, serverChallenge, clientChallenge uint64, limits Limits) (uint64, error) {
	challenge := wire.NewEncoder(limits.withDefaults().MaxEncryptBytes)
	challenge.Uint64(serverChallenge)
	challenge.Uint64(clientChallenge)
	challengeBytes, err := challenge.BytesResult()
	if err != nil {
		return 0, err
	}
	var folded []byte
	switch secret.typeID {
	case CryptoAES:
		folded, err = encodeEncryptEnvelope(secret, challengeBytes, limits)
	case CryptoAES256KRB5:
		mac := hmac.New(sha256.New, secret.secret[:secret.size])
		_, _ = mac.Write(challengeBytes)
		folded = mac.Sum(nil)
	default:
		return 0, ErrUnsupportedType
	}
	if err != nil {
		return 0, err
	}

	var key uint64
	for pos := 0; pos+8 <= len(folded); pos += 8 {
		key ^= binary.LittleEndian.Uint64(folded[pos : pos+8])
	}
	return key, nil
}

func encryptPayload(secret CryptoKey, plaintext []byte, usage uint32, limits Limits) ([]byte, error) {
	if secret.typeID == CryptoAES256KRB5 {
		limits = limits.withDefaults()
		if uint64(len(plaintext)) > uint64(limits.MaxEncryptBytes) {
			return nil, wire.ErrLimitExceeded
		}
		etype := krbcrypto.Aes256CtsHmacSha384192{}
		_, encrypted, err := etype.EncryptMessage(secret.secret[:secret.size], plaintext, usage)
		return encrypted, err
	}
	return encryptCBC(secret, plaintext, limits)
}

func decryptPayload(secret CryptoKey, ciphertext []byte, usage uint32, limits Limits) ([]byte, error) {
	if secret.typeID == CryptoAES256KRB5 {
		limits = limits.withDefaults()
		if len(ciphertext) < aes.BlockSize+24 {
			return nil, ErrMalformedPayload
		}
		if uint64(len(ciphertext)) > uint64(limits.MaxDecryptBytes)+aes.BlockSize+24 {
			return nil, wire.ErrLimitExceeded
		}
		etype := krbcrypto.Aes256CtsHmacSha384192{}
		plaintext, err := etype.DecryptMessage(secret.secret[:secret.size], ciphertext, usage)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformedPayload, err)
		}
		return plaintext, nil
	}
	return decryptCBC(secret, ciphertext, limits)
}

func encryptCBC(secret CryptoKey, plaintext []byte, limits Limits) ([]byte, error) {
	limits = limits.withDefaults()
	if uint64(len(plaintext)) > uint64(limits.MaxEncryptBytes) {
		return nil, wire.ErrLimitExceeded
	}
	padLength := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	if padLength == 0 {
		padLength = aes.BlockSize
	}
	if uint64(len(plaintext)) > math.MaxUint64-uint64(padLength) {
		return nil, wire.ErrLimitExceeded
	}
	padded := make([]byte, len(plaintext)+padLength)
	copy(padded, plaintext)
	for index := len(plaintext); index < len(padded); index++ {
		padded[index] = byte(padLength)
	}
	if uint64(len(padded)) > uint64(limits.MaxEncryptBytes)+aes.BlockSize {
		return nil, wire.ErrLimitExceeded
	}

	if secret.typeID != CryptoAES || secret.size != AESKeySize {
		return nil, ErrUnsupportedType
	}
	block, err := aes.NewCipher(secret.secret[:secret.size])
	if err != nil {
		return nil, err
	}
	result := make([]byte, len(padded))
	iv := [aes.BlockSize]byte{}
	copy(iv[:], []byte(CephAESIV))
	cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(result, padded)
	return result, nil
}

func decryptCBC(secret CryptoKey, ciphertext []byte, limits Limits) ([]byte, error) {
	limits = limits.withDefaults()
	if len(ciphertext) < aes.BlockSize || len(ciphertext)%aes.BlockSize != 0 {
		return nil, ErrMalformedPayload
	}
	if uint64(len(ciphertext)) > uint64(limits.MaxDecryptBytes)+aes.BlockSize {
		return nil, wire.ErrLimitExceeded
	}
	if secret.typeID != CryptoAES || secret.size != AESKeySize {
		return nil, ErrUnsupportedType
	}
	block, err := aes.NewCipher(secret.secret[:secret.size])
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	iv := [aes.BlockSize]byte{}
	copy(iv[:], []byte(CephAESIV))
	cipher.NewCBCDecrypter(block, iv[:]).CryptBlocks(plaintext, ciphertext)

	padLength := int(plaintext[len(plaintext)-1])
	if padLength == 0 || padLength > aes.BlockSize || padLength > len(plaintext) {
		return nil, ErrMalformedPayload
	}
	for _, value := range plaintext[len(plaintext)-padLength:] {
		if int(value) != padLength {
			return nil, ErrMalformedPayload
		}
	}
	return append([]byte(nil), plaintext[:len(plaintext)-padLength]...), nil
}

func DecodeAuthBadMethod(payload []byte, limits Limits) (method uint32, result int32, allowedMethods []uint32, allowedModes []uint32, err error) {
	limits = limits.withDefaults()
	if uint64(len(payload)) > uint64(limits.MaxAuthBytes) {
		return 0, 0, nil, nil, wire.ErrLimitExceeded
	}
	decoder := wire.NewDecoder(payload, wire.Limits{MaxBytes: limits.MaxAuthBytes})
	method = decoder.Uint32()
	result = decoder.Int32()
	allowedMethods, err = decodeUint32Slice(decoder, limits.MaxModes)
	if err != nil {
		return 0, 0, nil, nil, err
	}
	allowedModes, err = decodeUint32Slice(decoder, limits.MaxModes)
	if err != nil {
		return 0, 0, nil, nil, err
	}
	if err := decoder.Finish(); err != nil || decoder.Remaining() != 0 {
		return 0, 0, nil, nil, ErrMalformedPayload
	}
	return method, result, allowedMethods, allowedModes, nil
}

func decodeUint32Slice(decoder *wire.Decoder, maxCount uint32) ([]uint32, error) {
	count := decoder.Uint32()
	if count > maxCount {
		return nil, wire.ErrLimitExceeded
	}
	out := make([]uint32, count)
	for index := range out {
		out[index] = decoder.Uint32()
	}
	return out, nil
}
