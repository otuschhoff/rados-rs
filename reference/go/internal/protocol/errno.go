package protocol

import (
	"fmt"

	wire "github.com/otuschhoff/go-librados/internal/encoding"
)

// WireErrno is a signed Linux errno value carried by Ceph. Negative values are
// failures, zero is success, and positive values are retained without guessing.
type WireErrno int32

type ErrorClass uint8

const (
	ErrorUnknown ErrorClass = iota
	ErrorNotFound
	ErrorExists
	ErrorPermission
	ErrorUnsupported
	ErrorInvalid
	ErrorQuotaOrFull
	ErrorConflict
	ErrorTimeout
	ErrorCanceled
)

func (errno WireErrno) Error() string {
	return fmt.Sprintf("Ceph wire errno %d", errno)
}

func (errno WireErrno) Class() ErrorClass {
	switch errno {
	case -2:
		return ErrorNotFound
	case -17:
		return ErrorExists
	case -1, -13:
		return ErrorPermission
	case -38, -95:
		return ErrorUnsupported
	case -22:
		return ErrorInvalid
	case -28, -122:
		return ErrorQuotaOrFull
	case -11, -16, -35:
		return ErrorConflict
	case -110:
		return ErrorTimeout
	case -125:
		return ErrorCanceled
	default:
		return ErrorUnknown
	}
}

func (errno WireErrno) Encode(encoder *wire.Encoder) {
	encoder.Int32(int32(errno))
}

func DecodeWireErrno(decoder *wire.Decoder) WireErrno {
	return WireErrno(decoder.Int32())
}
