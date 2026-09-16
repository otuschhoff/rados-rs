// Package encoding implements bounded Ceph wire primitives.
package encoding

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

var (
	ErrLimitExceeded      = errors.New("encoding limit exceeded")
	ErrMalformed          = errors.New("malformed encoding")
	ErrUnsupportedVersion = errors.New("unsupported compatible version")
)

// Limits bounds input-derived memory use. Zero values reject variable-length
// values and must be replaced with explicit limits by each protocol owner.
type Limits struct {
	MaxBytes uint32
}

// Encoder accumulates one bounded wire value. Its first error is sticky.
type Encoder struct {
	buf []byte
	max uint64
	err error
}

// NewEncoder constructs an encoder whose total output cannot exceed maxBytes.
func NewEncoder(maxBytes uint32) *Encoder {
	return &Encoder{max: uint64(maxBytes)}
}

func (e *Encoder) reserve(size uint64) bool {
	if e.err != nil {
		return false
	}
	if size > e.max || uint64(len(e.buf)) > e.max-size {
		e.err = ErrLimitExceeded
		return false
	}
	return true
}

func (e *Encoder) Raw(value []byte) {
	if e.reserve(uint64(len(value))) {
		e.buf = append(e.buf, value...)
	}
}

func (e *Encoder) Uint8(value uint8) { e.Raw([]byte{value}) }

func (e *Encoder) Uint16(value uint16) {
	var data [2]byte
	binary.LittleEndian.PutUint16(data[:], value)
	e.Raw(data[:])
}

func (e *Encoder) Uint32(value uint32) {
	var data [4]byte
	binary.LittleEndian.PutUint32(data[:], value)
	e.Raw(data[:])
}

func (e *Encoder) Uint64(value uint64) {
	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], value)
	e.Raw(data[:])
}

func (e *Encoder) Int8(value int8)   { e.Uint8(uint8(value)) }
func (e *Encoder) Int16(value int16) { e.Uint16(uint16(value)) }
func (e *Encoder) Int32(value int32) { e.Uint32(uint32(value)) }
func (e *Encoder) Int64(value int64) { e.Uint64(uint64(value)) }

func (e *Encoder) Bool(value bool) {
	if value {
		e.Uint8(1)
		return
	}
	e.Uint8(0)
}

func (e *Encoder) Bytes(value []byte) {
	if uint64(len(value)) > math.MaxUint32 {
		e.err = ErrLimitExceeded
		return
	}
	e.Uint32(uint32(len(value)))
	e.Raw(value)
}

func (e *Encoder) String(value string) { e.Bytes([]byte(value)) }

// Versioned encodes a Ceph struct_v/struct_compat/payload_len envelope.
func (e *Encoder) Versioned(version, compat uint8, encode func(*Encoder)) {
	payload := NewEncoder(uint32(min(e.max, math.MaxUint32)))
	encode(payload)
	data, err := payload.BytesResult()
	if err != nil {
		e.err = err
		return
	}
	e.Uint8(version)
	e.Uint8(compat)
	e.Uint32(uint32(len(data)))
	e.Raw(data)
}

func (e *Encoder) BytesResult() ([]byte, error) {
	if e.err != nil {
		return nil, e.err
	}
	return append([]byte(nil), e.buf...), nil
}

// Decoder reads one bounded wire value without retaining caller-owned input.
type Decoder struct {
	data   []byte
	offset uint64
	limits Limits
	err    error
}

func NewDecoder(data []byte, limits Limits) *Decoder {
	return &Decoder{data: data, limits: limits}
}

func (d *Decoder) take(size uint64) []byte {
	if d.err != nil {
		return nil
	}
	if size > uint64(len(d.data))-d.offset {
		d.err = ErrMalformed
		return nil
	}
	start := d.offset
	d.offset += size
	return d.data[start:d.offset]
}

func (d *Decoder) Raw(size uint32) []byte {
	return append([]byte(nil), d.take(uint64(size))...)
}

func (d *Decoder) Uint8() uint8 {
	data := d.take(1)
	if data == nil {
		return 0
	}
	return data[0]
}

func (d *Decoder) Uint16() uint16 { return binary.LittleEndian.Uint16(d.fixed(2)) }
func (d *Decoder) Uint32() uint32 { return binary.LittleEndian.Uint32(d.fixed(4)) }
func (d *Decoder) Uint64() uint64 { return binary.LittleEndian.Uint64(d.fixed(8)) }
func (d *Decoder) Int8() int8     { return int8(d.Uint8()) }
func (d *Decoder) Int16() int16   { return int16(d.Uint16()) }
func (d *Decoder) Int32() int32   { return int32(d.Uint32()) }
func (d *Decoder) Int64() int64   { return int64(d.Uint64()) }
func (d *Decoder) Bool() bool     { return d.Uint8() != 0 }

func (d *Decoder) fixed(size uint64) []byte {
	data := d.take(size)
	if data != nil {
		return data
	}
	return make([]byte, size)
}

func (d *Decoder) Bytes() []byte {
	size := d.Uint32()
	if d.err != nil {
		return nil
	}
	if size > d.limits.MaxBytes {
		d.err = ErrLimitExceeded
		return nil
	}
	return d.Raw(size)
}

func (d *Decoder) String() string { return string(d.Bytes()) }

// Versioned returns a decoder restricted to one compatible envelope payload.
// Finishing the child skips unknown trailing fields without consuming bytes
// following the envelope in the parent.
func (d *Decoder) Versioned(localVersion uint8) (version uint8, payload *Decoder) {
	version = d.Uint8()
	compat := d.Uint8()
	size := d.Uint32()
	if d.err != nil {
		return 0, NewDecoder(nil, d.limits)
	}
	if localVersion < compat {
		d.err = fmt.Errorf("%w: local=%d required=%d", ErrUnsupportedVersion, localVersion, compat)
		return 0, NewDecoder(nil, d.limits)
	}
	if size > d.limits.MaxBytes {
		d.err = ErrLimitExceeded
		return 0, NewDecoder(nil, d.limits)
	}
	data := d.take(uint64(size))
	if data == nil {
		return 0, NewDecoder(nil, d.limits)
	}
	return version, NewDecoder(data, d.limits)
}

func (d *Decoder) Remaining() uint64 { return uint64(len(d.data)) - d.offset }

// Position returns the number of bytes consumed from this decoder's input.
func (d *Decoder) Position() uint64 { return d.offset }

func (d *Decoder) Finish() error { return d.err }
