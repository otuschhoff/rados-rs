package msgr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

const (
	PreambleSize       = 32
	MaxSegments        = 4
	DefaultAlignment   = 8
	PageAlignment      = 4096
	LateStatusAborted  = 0x01
	LateStatusComplete = 0x0e
)

var (
	ErrIntegrity = errors.New("messenger integrity check failed")
	ErrAborted   = errors.New("messenger frame aborted")
)

type Tag uint8

const (
	TagHello Tag = iota + 1
	TagAuthRequest
	TagAuthBadMethod
	TagAuthReplyMore
	TagAuthRequestMore
	TagAuthDone
	TagAuthSignature
	TagClientIdent
	TagServerIdent
	TagIdentMissingFeatures
	TagSessionReconnect
	TagSessionReset
	TagSessionRetry
	TagSessionRetryGlobal
	TagSessionReconnectOK
	TagWait
	TagMessage
	TagKeepalive2
	TagKeepalive2Ack
	TagAck
	TagCompressionRequest
	TagCompressionDone
)

type Limits struct {
	MaxSegmentBytes uint32
	MaxFrameBytes   uint64
	MaxAddresses    uint32
	MaxAuthBytes    uint32
}

type Segment struct {
	Alignment uint16
	Data      []byte
}

type Frame struct {
	Tag      Tag
	Segments []Segment
}

type CRCCodec struct {
	WithDataCRC bool
}

type segmentDescriptor struct {
	length    uint32
	alignment uint16
}

func EncodeCRC(frame Frame, limits Limits) ([]byte, error) {
	return (CRCCodec{WithDataCRC: true}).Encode(frame, limits)
}

func (codec CRCCodec) Encode(frame Frame, limits Limits) ([]byte, error) {
	segments, err := normalizeSegments(frame.Segments)
	if err != nil {
		return nil, err
	}
	if !validTag(frame.Tag) {
		return nil, fmt.Errorf("%w: tag %d", ErrMalformed, frame.Tag)
	}
	descriptors := make([]segmentDescriptor, len(segments))
	total := uint64(PreambleSize)
	for index, segment := range segments {
		if len(segment.Data) > math.MaxUint32 || uint64(len(segment.Data)) > uint64(limits.MaxSegmentBytes) {
			return nil, ErrLimitExceeded
		}
		if !validAlignment(segment.Alignment) {
			return nil, fmt.Errorf("%w: segment %d alignment %d", ErrMalformed, index, segment.Alignment)
		}
		descriptors[index] = segmentDescriptor{uint32(len(segment.Data)), segment.Alignment}
		var addition uint64 = uint64(len(segment.Data))
		if index == 0 && len(segment.Data) > 0 {
			addition += 4
		}
		if total > math.MaxUint64-addition {
			return nil, ErrLimitExceeded
		}
		total += addition
	}
	if len(segments) > 1 {
		total += 13
	}
	if total > limits.MaxFrameBytes || total > uint64(maxInt()) {
		return nil, ErrLimitExceeded
	}

	preamble := encodePreamble(frame.Tag, descriptors)
	result := bytes.NewBuffer(make([]byte, 0, int(total)))
	result.Write(preamble[:])
	for index, segment := range segments {
		result.Write(segment.Data)
		if index == 0 && len(segment.Data) > 0 {
			crc := uint32(0)
			if codec.WithDataCRC {
				crc = cephCRC32C(math.MaxUint32, segment.Data)
			}
			writeUint32(result, crc)
		}
	}
	if len(segments) > 1 {
		result.WriteByte(LateStatusComplete)
		for index := 1; index < MaxSegments; index++ {
			crc := uint32(0)
			if codec.WithDataCRC && index < len(segments) {
				crc = cephCRC32C(math.MaxUint32, segments[index].Data)
			}
			writeUint32(result, crc)
		}
	}
	return result.Bytes(), nil
}

func ReadCRC(reader io.Reader, limits Limits) (Frame, error) {
	return (CRCCodec{WithDataCRC: true}).Read(reader, limits)
}

func (codec CRCCodec) Read(reader io.Reader, limits Limits) (Frame, error) {
	var preamble [PreambleSize]byte
	if _, err := io.ReadFull(reader, preamble[:]); err != nil {
		return Frame{}, fmt.Errorf("%w: preamble: %v", ErrMalformed, err)
	}
	tag, descriptors, err := decodePreamble(preamble)
	if err != nil {
		return Frame{}, err
	}
	total := uint64(PreambleSize)
	for index, descriptor := range descriptors {
		if descriptor.length > limits.MaxSegmentBytes || !validAlignment(descriptor.alignment) {
			return Frame{}, ErrLimitExceeded
		}
		addition := uint64(descriptor.length)
		if index == 0 && descriptor.length > 0 {
			addition += 4
		}
		if total > math.MaxUint64-addition {
			return Frame{}, ErrLimitExceeded
		}
		total += addition
	}
	if len(descriptors) > 1 {
		total += 13
	}
	if total > limits.MaxFrameBytes || total > uint64(maxInt()) {
		return Frame{}, ErrLimitExceeded
	}

	segments := make([]Segment, len(descriptors))
	for index, descriptor := range descriptors {
		data := make([]byte, descriptor.length)
		if _, err := io.ReadFull(reader, data); err != nil {
			return Frame{}, fmt.Errorf("%w: segment %d: %v", ErrMalformed, index, err)
		}
		if index == 0 && descriptor.length > 0 {
			var encoded [4]byte
			if _, err := io.ReadFull(reader, encoded[:]); err != nil {
				return Frame{}, fmt.Errorf("%w: segment 0 crc: %v", ErrMalformed, err)
			}
			if got, want := cephCRC32C(math.MaxUint32, data), binary.LittleEndian.Uint32(encoded[:]); codec.WithDataCRC && got != want {
				return Frame{}, fmt.Errorf("%w: segment 0 crc", ErrIntegrity)
			}
		}
		segments[index] = Segment{Alignment: descriptor.alignment, Data: data}
	}
	if len(descriptors) > 1 {
		var epilogue [13]byte
		if _, err := io.ReadFull(reader, epilogue[:]); err != nil {
			return Frame{}, fmt.Errorf("%w: epilogue: %v", ErrMalformed, err)
		}
		switch epilogue[0] & 0x0f {
		case LateStatusComplete:
		case LateStatusAborted:
			return Frame{}, ErrAborted
		default:
			return Frame{}, fmt.Errorf("%w: late status %#x", ErrMalformed, epilogue[0])
		}
		for index := 1; index < len(descriptors); index++ {
			want := binary.LittleEndian.Uint32(epilogue[1+(index-1)*4:])
			if got := cephCRC32C(math.MaxUint32, segments[index].Data); codec.WithDataCRC && got != want {
				return Frame{}, fmt.Errorf("%w: segment %d crc", ErrIntegrity, index)
			}
		}
	}
	return Frame{Tag: tag, Segments: segments}, nil
}

func encodePreamble(tag Tag, descriptors []segmentDescriptor) [PreambleSize]byte {
	var preamble [PreambleSize]byte
	preamble[0] = byte(tag)
	preamble[1] = byte(len(descriptors))
	for index, descriptor := range descriptors {
		offset := 2 + index*6
		binary.LittleEndian.PutUint32(preamble[offset:], descriptor.length)
		binary.LittleEndian.PutUint16(preamble[offset+4:], descriptor.alignment)
	}
	binary.LittleEndian.PutUint32(preamble[28:], cephCRC32C(0, preamble[:28]))
	return preamble
}

func decodePreamble(preamble [PreambleSize]byte) (Tag, []segmentDescriptor, error) {
	if got, want := cephCRC32C(0, preamble[:28]), binary.LittleEndian.Uint32(preamble[28:]); got != want {
		return 0, nil, fmt.Errorf("%w: preamble crc calculated=%#x encoded=%#x", ErrIntegrity, got, want)
	}
	tag := Tag(preamble[0])
	if !validTag(tag) {
		return 0, nil, fmt.Errorf("%w: tag %d", ErrMalformed, tag)
	}
	count := int(preamble[1])
	if count < 1 || count > MaxSegments {
		return 0, nil, fmt.Errorf("%w: segment count %d", ErrMalformed, count)
	}
	if preamble[26] != 0 || preamble[27] != 0 {
		return 0, nil, fmt.Errorf("%w: flags or reserved byte", ErrMalformed)
	}
	descriptors := make([]segmentDescriptor, count)
	for index := range MaxSegments {
		offset := 2 + index*6
		descriptor := segmentDescriptor{
			length:    binary.LittleEndian.Uint32(preamble[offset:]),
			alignment: binary.LittleEndian.Uint16(preamble[offset+4:]),
		}
		if index < count {
			descriptors[index] = descriptor
		} else if descriptor != (segmentDescriptor{}) {
			return 0, nil, fmt.Errorf("%w: nonzero unused descriptor", ErrMalformed)
		}
	}
	if count > 1 && descriptors[count-1].length == 0 {
		return 0, nil, fmt.Errorf("%w: trailing empty segment", ErrMalformed)
	}
	return tag, descriptors, nil
}

func normalizeSegments(segments []Segment) ([]Segment, error) {
	if len(segments) < 1 || len(segments) > MaxSegments {
		return nil, fmt.Errorf("%w: segment count %d", ErrMalformed, len(segments))
	}
	end := len(segments)
	for end > 1 && len(segments[end-1].Data) == 0 {
		end--
	}
	result := make([]Segment, end)
	for index := range end {
		result[index] = Segment{Alignment: segments[index].Alignment, Data: append([]byte(nil), segments[index].Data...)}
	}
	return result, nil
}

func validTag(tag Tag) bool { return tag >= TagHello && tag <= TagAck }

func validAlignment(alignment uint16) bool {
	return alignment != 0 && alignment&(alignment-1) == 0
}

func writeUint32(writer io.Writer, value uint32) {
	var data [4]byte
	binary.LittleEndian.PutUint32(data[:], value)
	_, _ = writer.Write(data[:])
}

func maxInt() int { return int(^uint(0) >> 1) }
