package msgr

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

var ErrNilCodec = errors.New("messenger codec is nil")

// Codec encodes and decodes framed messenger traffic.
type Codec interface {
	Encode(Frame, Limits) ([]byte, error)
	Read(io.Reader, Limits) (Frame, error)
}

type connTransport struct {
	conn      net.Conn
	codec     Codec
	limits    Limits
	readMu    sync.Mutex
	writeMu   sync.Mutex
	closeOnce sync.Once
}

// NewConnTransport binds a network connection to one messenger codec.
func NewConnTransport(conn net.Conn, codec Codec, limits Limits) (Transport, error) {
	if conn == nil {
		return nil, fmt.Errorf("%w: nil connection", ErrMalformed)
	}
	if codec == nil {
		return nil, ErrNilCodec
	}
	return &connTransport{conn: conn, codec: codec, limits: limits}, nil
}

func (transport *connTransport) ReadFrame() (Frame, error) {
	transport.readMu.Lock()
	defer transport.readMu.Unlock()
	return transport.codec.Read(transport.conn, transport.limits)
}

func (transport *connTransport) WriteFrame(frame Frame) error {
	transport.writeMu.Lock()
	defer transport.writeMu.Unlock()
	wire, err := transport.codec.Encode(frame, transport.limits)
	if err != nil {
		return err
	}
	for len(wire) > 0 {
		written, writeErr := transport.conn.Write(wire)
		if written > 0 {
			wire = wire[written:]
		}
		if writeErr != nil {
			return writeErr
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

func (transport *connTransport) Close() error {
	var err error
	transport.closeOnce.Do(func() {
		err = transport.conn.Close()
	})
	return err
}
