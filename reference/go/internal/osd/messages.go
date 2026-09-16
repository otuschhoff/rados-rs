// Package osd implements the read-only Ceph OSD protocol and request lifecycle.
package osd

import (
	"errors"
	"fmt"
	"math"

	wire "github.com/otuschhoff/go-librados/internal/encoding"
	"github.com/otuschhoff/go-librados/internal/maps"
	"github.com/otuschhoff/go-librados/internal/msgr"
	"github.com/otuschhoff/go-librados/internal/protocol"
)

var ErrMalformedReply = errors.New("malformed OSD reply")

const (
	OpRead                = uint16(0x1201)
	OpStat                = uint16(0x1202)
	OpSparseRead          = uint16(0x1205)
	OpNotify              = uint16(0x1206)
	OpNotifyAck           = uint16(0x1207)
	OpListWatchers        = uint16(0x1209)
	OpAssertVer           = uint16(0x1208)
	OpOmapGetKeys         = uint16(0x1211)
	OpOmapGetValues       = uint16(0x1212)
	OpOmapGetHeader       = uint16(0x1213)
	OpOmapGetValuesByKeys = uint16(0x1214)
	OpOmapCompare         = uint16(0x1219)
	OpChecksum            = uint16(0x121f)
	OpCompareExtent       = uint16(0x1220)
	OpGetXattr            = uint16(0x1301)
	OpGetXattrs           = uint16(0x1302)
	OpCompareXattr        = uint16(0x1303)
	OpCall                = uint16(0x1401)
	OpPGList              = uint16(0x1501)
	OpPGNList             = uint16(0x1505)
	OpScrubList           = uint16(0x1507)
	OpWrite               = uint16(0x2201)
	OpWriteFull           = uint16(0x2202)
	OpTruncate            = uint16(0x2203)
	OpZero                = uint16(0x2204)
	OpDelete              = uint16(0x2205)
	OpAppend              = uint16(0x2206)
	OpWatch               = uint16(0x220f)
	OpCreate              = uint16(0x220d)
	OpRollback            = uint16(0x220e)
	OpOmapSetValues       = uint16(0x2215)
	OpOmapSetHeader       = uint16(0x2216)
	OpOmapClear           = uint16(0x2217)
	OpOmapRemoveKeys      = uint16(0x2218)
	OpCopyFrom            = uint16(0x221a)
	OpSetAllocationHint   = uint16(0x2223)
	OpWriteSame           = uint16(0x2226)
	OpCopyFrom2           = uint16(0x222d)
	OpOmapRemoveRange     = uint16(0x222c)
	OpSetXattr            = uint16(0x2301)
	OpRemoveXattr         = uint16(0x2304)

	OpFlagExclusive = uint32(0x0001)
	OpFlagFailOK    = uint32(0x0002)

	CopyFromFlagTruncateSequence = uint8(1 << 5)

	FlagAck           = uint32(0x0001)
	FlagWrite         = uint32(0x0020)
	FlagOnDisk        = uint32(0x0004)
	FlagRead          = uint32(0x0010)
	FlagRetry         = uint32(0x0008)
	FlagPGOp          = uint32(0x0400)
	FlagIgnoreCache   = uint32(0x8000)
	FlagIgnoreOverlay = uint32(0x20000)
	FlagRedirected    = uint32(0x200000)
	FlagReturnVector  = uint32(0x04000000)

	NoSnap                  = ^uint64(1)
	operationDescriptorSize = uint64(38)
)

type Operation struct {
	Code               uint16
	Flags              uint32
	Offset             uint64
	Length             uint64
	PatternLength      uint64
	ChecksumType       uint8
	ChunkSize          uint32
	ExpectedObjectSize uint64
	ExpectedWriteSize  uint64
	AllocationFlags    uint32
	XattrNameLength    uint32
	XattrValueLength   uint32
	CompareOperator    uint8
	CompareMode        uint8
	ClassNameLength    uint8
	MethodNameLength   uint8
	ClassInputLength   uint32
	WatchCookie        uint64
	WatchVersion       uint64
	WatchOperation     uint8
	WatchGeneration    uint32
	WatchTimeout       uint32
	AssertVersion      uint64
	SnapshotID         uint64
	SourceSnapshotID   uint64
	SourceVersion      uint64
	CopyFlags          uint8
	SourceFadviseFlags uint32
	ListCount          uint64
	ListStartEpoch     uint32
	PayloadLength      uint32
	Data               []byte
}

type Request struct {
	MapEpoch          uint32
	PG                maps.PG
	Shard             int8
	Sharded           bool
	ObjectHash        uint32
	PoolID            int64
	Object            string
	Locator           string
	Namespace         string
	Snapshot          uint64
	SnapshotSequence  uint64
	WriteSnapshots    []uint64
	TransactionID     uint64
	ClientGlobalID    uint64
	ClientIncarnation int32
	Retry             int32
	Flags             uint32
	Features          uint64
	Operations        []Operation
}

type OperationResult struct {
	Operation uint16
	Code      int32
	Data      []byte
}

type Redirect struct {
	Pool      int64
	Locator   string
	Namespace string
	Object    string
}

type Reply struct {
	Object     string
	PG         maps.PG
	Flags      int64
	Result     int32
	MapEpoch   uint32
	Retry      int32
	Version    uint64
	Redirect   *Redirect
	Operations []OperationResult
}

type Limits struct {
	MaxBytes      uint32
	MaxOperations uint32
}

func EncodeRequest(request Request, limits Limits) (msgr.Message, error) {
	if limits.MaxBytes == 0 || limits.MaxOperations == 0 || len(request.Operations) == 0 || uint64(len(request.Operations)) > uint64(limits.MaxOperations) || len(request.Operations) > int(^uint16(0)) || len(request.WriteSnapshots) > int(^uint32(0)) || request.PoolID < 0 {
		return msgr.Message{}, wire.ErrLimitExceeded
	}
	if !validSnapshotContext(request.SnapshotSequence, request.WriteSnapshots) {
		return msgr.Message{}, wire.ErrMalformed
	}
	mutation := false
	dataLength := uint64(0)
	for index := range request.Operations {
		operation := &request.Operations[index]
		if !supportedOperation(operation.Code) {
			return msgr.Message{}, fmt.Errorf("%w: operation %#x", wire.ErrUnsupportedVersion, operation.Code)
		}
		if isMutation(operation.Code) {
			mutation = true
		}
		if len(operation.Data) > int(^uint32(0)) {
			return msgr.Message{}, wire.ErrLimitExceeded
		}
		if operation.PayloadLength != 0 && operation.PayloadLength != uint32(len(operation.Data)) {
			return msgr.Message{}, wire.ErrMalformed
		}
		if err := validateOperation(*operation); err != nil {
			return msgr.Message{}, err
		}
		operation.PayloadLength = uint32(len(operation.Data))
		dataLength += uint64(len(operation.Data))
		if dataLength > uint64(limits.MaxBytes) {
			return msgr.Message{}, wire.ErrLimitExceeded
		}
	}
	encoder := wire.NewEncoder(limits.MaxBytes)
	shard := int8(-1)
	if request.Sharded {
		shard = request.Shard
	}
	encodeSPGWithShard(encoder, request.PG, shard)
	encoder.Uint32(request.ObjectHash)
	encoder.Uint32(request.MapEpoch)
	flags := FlagRead
	if mutation || request.Flags&FlagWrite != 0 {
		flags = FlagWrite | FlagOnDisk
	}
	encoder.Uint32(flags | request.Flags)
	encodeRequestID(encoder, request.ClientGlobalID, request.TransactionID, request.ClientIncarnation)
	encodeTrace(encoder)
	encoder.Int32(request.ClientIncarnation)
	encodeUTime(encoder, 0, 0)
	encodeLocator(encoder, request.PoolID, request.Locator, request.Namespace)
	encoder.String(request.Object)
	encoder.Uint16(uint16(len(request.Operations)))
	for _, operation := range request.Operations {
		encodeOperation(encoder, operation)
	}
	encoder.Uint64(request.Snapshot)
	encoder.Uint64(request.SnapshotSequence)
	encoder.Uint32(uint32(len(request.WriteSnapshots)))
	for _, snapshot := range request.WriteSnapshots {
		encoder.Uint64(snapshot)
	}
	encoder.Int32(request.Retry)
	encoder.Uint64(request.Features)
	front, err := encoder.BytesResult()
	if err != nil {
		return msgr.Message{}, err
	}
	if uint64(len(front))+dataLength > uint64(limits.MaxBytes) {
		return msgr.Message{}, wire.ErrLimitExceeded
	}
	data := make([]byte, 0, dataLength)
	for _, operation := range request.Operations {
		data = append(data, operation.Data...)
	}
	return msgr.Message{Header: msgr.MessageHeader{TransactionID: request.TransactionID, Type: protocol.MessageOSDOp, Version: 8, CompatVersion: 3}, Front: front, Data: data, Lengths: msgr.MessageLengths{Front: uint32(len(front)), Data: uint32(len(data))}}, nil
}

func validSnapshotContext(sequence uint64, snapshots []uint64) bool {
	for index, snapshot := range snapshots {
		if snapshot > sequence || index > 0 && snapshot >= snapshots[index-1] {
			return false
		}
	}
	return true
}

func supportedOperation(code uint16) bool {
	switch code {
	case OpRead, OpStat, OpSparseRead, OpNotify, OpNotifyAck, OpListWatchers, OpAssertVer, OpOmapGetKeys, OpOmapGetValues,
		OpOmapGetValuesByKeys, OpOmapGetHeader, OpOmapCompare, OpChecksum, OpCompareExtent,
		OpGetXattr, OpGetXattrs, OpCompareXattr, OpCall, OpPGList, OpPGNList, OpScrubList,
		OpWrite, OpWriteFull, OpTruncate, OpZero, OpDelete, OpAppend, OpWatch, OpCreate, OpRollback,
		OpOmapSetValues, OpOmapSetHeader, OpOmapClear, OpOmapRemoveKeys, OpCopyFrom,
		OpSetAllocationHint, OpWriteSame, OpCopyFrom2, OpOmapRemoveRange, OpSetXattr, OpRemoveXattr:
		return true
	default:
		return false
	}
}

func validateOperation(operation Operation) error {
	switch operation.Code {
	case OpChecksum:
		seedSize, validType := ChecksumSize(operation.ChecksumType)
		if !validType {
			return wire.ErrMalformed
		}
		if uint64(len(operation.Data)) != seedSize || operation.Length > math.MaxInt32 || operation.Length > math.MaxUint64-operation.Offset || (operation.ChunkSize != 0 && (operation.Length == 0 || operation.Length%uint64(operation.ChunkSize) != 0)) {
			return wire.ErrMalformed
		}
	case OpSetAllocationHint:
		if operation.Flags != OpFlagFailOK || len(operation.Data) != 0 {
			return wire.ErrMalformed
		}
	case OpWriteSame:
		if operation.PatternLength == 0 || operation.PatternLength != uint64(len(operation.Data)) || operation.Length == 0 || operation.Length%operation.PatternLength != 0 || operation.Offset > ^uint64(0)-operation.Length {
			return wire.ErrMalformed
		}
	case OpCopyFrom:
		if operation.CopyFlags != 0 || len(operation.Data) == 0 {
			return wire.ErrMalformed
		}
	case OpCopyFrom2:
		if operation.CopyFlags != 0 || len(operation.Data) == 0 {
			return wire.ErrMalformed
		}
	case OpPGNList:
		if operation.ListCount == 0 || len(operation.Data) == 0 {
			return wire.ErrMalformed
		}
	case OpScrubList:
		if len(operation.Data) == 0 {
			return wire.ErrMalformed
		}
	case OpGetXattr, OpRemoveXattr:
		if operation.XattrValueLength != 0 || uint64(operation.XattrNameLength) != uint64(len(operation.Data)) {
			return wire.ErrMalformed
		}
	case OpSetXattr, OpCompareXattr:
		if uint64(operation.XattrNameLength)+uint64(operation.XattrValueLength) != uint64(len(operation.Data)) {
			return wire.ErrMalformed
		}
	case OpCall:
		if operation.ClassNameLength == 0 || operation.MethodNameLength == 0 ||
			uint64(operation.ClassNameLength)+uint64(operation.MethodNameLength)+uint64(operation.ClassInputLength) != uint64(len(operation.Data)) {
			return wire.ErrMalformed
		}
	case OpWatch:
		if operation.WatchCookie == 0 || (operation.WatchOperation != WatchOperationUnwatch && operation.WatchOperation != WatchOperationRegister && operation.WatchOperation != WatchOperationReconnect && operation.WatchOperation != WatchOperationPing) || len(operation.Data) != 0 {
			return wire.ErrMalformed
		}
	case OpNotify, OpNotifyAck:
		if operation.WatchCookie == 0 || len(operation.Data) == 0 {
			return wire.ErrMalformed
		}
	}
	return nil
}

func isMutation(code uint16) bool { return code&0x2000 != 0 }

func DecodeReply(message msgr.Message, limits Limits) (Reply, error) {
	if limits.MaxBytes == 0 || limits.MaxOperations == 0 || message.Header.Type != protocol.MessageOSDOpReply || message.Header.Version < 4 || message.Header.CompatVersion > 8 || uint64(len(message.Front))+uint64(len(message.Middle))+uint64(len(message.Data)) > uint64(limits.MaxBytes) {
		return Reply{}, ErrMalformedReply
	}
	decoder := wire.NewDecoder(message.Front, wire.Limits{MaxBytes: limits.MaxBytes})
	reply := Reply{Object: decoder.String()}
	var err error
	reply.PG, err = decodePG(decoder)
	if err != nil {
		return Reply{}, err
	}
	reply.Flags = decoder.Int64()
	reply.Result = decoder.Int32()
	decodeEVersion(decoder)
	reply.MapEpoch = decoder.Uint32()
	count := decoder.Uint32()
	if err := decoder.Finish(); err != nil {
		return Reply{}, err
	}
	if count > limits.MaxOperations || uint64(count)*operationDescriptorSize > decoder.Remaining() {
		return Reply{}, wire.ErrLimitExceeded
	}
	reply.Operations = make([]OperationResult, count)
	lengths := make([]uint32, count)
	for index := range lengths {
		reply.Operations[index].Operation, lengths[index] = decodeOperation(decoder)
	}
	reply.Retry = decoder.Int32()
	for index := range reply.Operations {
		reply.Operations[index].Code = decoder.Int32()
	}
	decodeEVersion(decoder)
	reply.Version = decoder.Uint64()
	if message.Header.Version == 6 {
		return Reply{}, fmt.Errorf("%w: legacy redirect encoding", wire.ErrUnsupportedVersion)
	}
	if message.Header.Version >= 7 {
		if decoder.Bool() {
			redirect, err := decodeRedirect(decoder)
			if err != nil {
				return Reply{}, err
			}
			reply.Redirect = &redirect
		}
	}
	if message.Header.Version >= 8 {
		if err := decodeTrace(decoder); err != nil {
			return Reply{}, err
		}
	}
	if err := decoder.Finish(); err != nil {
		return Reply{}, fmt.Errorf("%w: front: %v", ErrMalformedReply, err)
	}
	if decoder.Remaining() != 0 {
		return Reply{}, fmt.Errorf("%w: %d trailing front bytes", ErrMalformedReply, decoder.Remaining())
	}
	offset := uint64(0)
	for index, length := range lengths {
		if uint64(length) > uint64(len(message.Data))-offset {
			return Reply{}, fmt.Errorf("%w: operation %d needs %d data bytes after offset %d", ErrMalformedReply, index, length, offset)
		}
		reply.Operations[index].Data = append([]byte(nil), message.Data[offset:offset+uint64(length)]...)
		offset += uint64(length)
	}
	if offset != uint64(len(message.Data)) {
		return Reply{}, fmt.Errorf("%w: %d trailing data bytes for operation lengths %v", ErrMalformedReply, uint64(len(message.Data))-offset, lengths)
	}
	return reply, nil
}

func encodePG(encoder *wire.Encoder, pg maps.PG) {
	encoder.Uint8(1)
	encoder.Uint64(pg.Pool)
	encoder.Uint32(pg.Seed)
	encoder.Int32(-1)
}

func decodePG(decoder *wire.Decoder) (maps.PG, error) {
	if decoder.Uint8() != 1 {
		return maps.PG{}, wire.ErrUnsupportedVersion
	}
	pg := maps.PG{Pool: decoder.Uint64(), Seed: decoder.Uint32(), Preferred: decoder.Int32()}
	return pg, decoder.Finish()
}

func encodeOperation(encoder *wire.Encoder, operation Operation) {
	encoder.Uint16(operation.Code)
	encoder.Uint32(operation.Flags)
	switch operation.Code {
	case OpGetXattr, OpGetXattrs, OpCompareXattr, OpSetXattr, OpRemoveXattr:
		encoder.Uint32(operation.XattrNameLength)
		encoder.Uint32(operation.XattrValueLength)
		encoder.Uint8(operation.CompareOperator)
		encoder.Uint8(operation.CompareMode)
		encoder.Raw(make([]byte, 18))
	case OpAssertVer:
		encoder.Uint64(0)
		encoder.Uint64(operation.AssertVersion)
		encoder.Raw(make([]byte, 12))
	case OpCall:
		encoder.Uint8(operation.ClassNameLength)
		encoder.Uint8(operation.MethodNameLength)
		encoder.Uint8(0)
		encoder.Uint32(operation.ClassInputLength)
		encoder.Raw(make([]byte, 21))
	case OpWatch:
		encoder.Uint64(operation.WatchCookie)
		encoder.Uint64(operation.WatchVersion)
		encoder.Uint8(operation.WatchOperation)
		encoder.Uint32(operation.WatchGeneration)
		encoder.Uint32(operation.WatchTimeout)
		encoder.Raw(make([]byte, 3))
	case OpNotify, OpNotifyAck:
		encoder.Uint64(operation.WatchCookie)
		encoder.Raw(make([]byte, 20))
	case OpPGList, OpPGNList:
		encoder.Uint64(operation.ListCount)
		encoder.Uint32(operation.ListStartEpoch)
		encoder.Raw(make([]byte, 16))
	case OpSetAllocationHint:
		encoder.Uint64(operation.ExpectedObjectSize)
		encoder.Uint64(operation.ExpectedWriteSize)
		encoder.Uint32(operation.AllocationFlags)
		encoder.Raw(make([]byte, 8))
	case OpWriteSame:
		encoder.Uint64(operation.Offset)
		encoder.Uint64(operation.Length)
		encoder.Uint64(operation.PatternLength)
		encoder.Uint32(0)
	case OpChecksum:
		encoder.Uint64(operation.Offset)
		encoder.Uint64(operation.Length)
		encoder.Uint32(operation.ChunkSize)
		encoder.Uint8(operation.ChecksumType)
		encoder.Raw(make([]byte, 7))
	case OpCopyFrom, OpCopyFrom2:
		encoder.Uint64(operation.SourceSnapshotID)
		encoder.Uint64(operation.SourceVersion)
		encoder.Uint8(operation.CopyFlags)
		encoder.Uint32(operation.SourceFadviseFlags)
		encoder.Raw(make([]byte, 7))
	case OpRollback:
		encoder.Uint64(operation.SnapshotID)
		encoder.Raw(make([]byte, 20))
	default:
		encoder.Uint64(operation.Offset)
		encoder.Uint64(operation.Length)
		encoder.Uint64(0)
		encoder.Uint32(0)
	}
	encoder.Uint32(operation.PayloadLength)
}

func EncodeCopyFromSource(object string, poolID int64, locator, namespace string, truncateSequence uint32, truncateSize uint64, includeTruncate bool, maxBytes uint32) ([]byte, error) {
	if maxBytes == 0 || object == "" || poolID < 0 {
		return nil, wire.ErrMalformed
	}
	encoder := wire.NewEncoder(maxBytes)
	encoder.String(object)
	encoder.Versioned(6, 3, func(payload *wire.Encoder) {
		payload.Int64(poolID)
		payload.Int32(-1)
		payload.String(locator)
		payload.String(namespace)
		payload.Int64(-1)
	})
	if includeTruncate {
		encoder.Uint32(truncateSequence)
		encoder.Uint64(truncateSize)
	}
	return encoder.BytesResult()
}

func decodeOperation(decoder *wire.Decoder) (uint16, uint32) {
	code := decoder.Uint16()
	decoder.Uint32()
	decoder.Raw(28)
	return code, decoder.Uint32()
}

func encodeLocator(encoder *wire.Encoder, pool int64, key, namespace string) {
	encoder.Versioned(6, 3, func(payload *wire.Encoder) {
		payload.Int64(pool)
		payload.Int32(-1)
		payload.String(key)
		payload.String(namespace)
		payload.Int64(-1)
	})
}

func decodeRedirect(decoder *wire.Decoder) (Redirect, error) {
	version, payload := decoder.Versioned(1)
	if err := decoder.Finish(); err != nil {
		return Redirect{}, err
	}
	if version != 1 {
		return Redirect{}, wire.ErrUnsupportedVersion
	}
	locatorVersion, locator := payload.Versioned(6)
	if err := payload.Finish(); err != nil {
		return Redirect{}, err
	}
	if locatorVersion < 3 {
		return Redirect{}, wire.ErrUnsupportedVersion
	}
	redirect := Redirect{Pool: locator.Int64()}
	locator.Int32()
	redirect.Locator = locator.String()
	redirect.Namespace = locator.String()
	if locatorVersion >= 6 {
		locator.Int64()
	}
	if err := locator.Finish(); err != nil || locator.Remaining() != 0 {
		return Redirect{}, ErrMalformedReply
	}
	redirect.Object = payload.String()
	legacyLength := payload.Uint32()
	if uint64(legacyLength) > payload.Remaining() {
		return Redirect{}, ErrMalformedReply
	}
	payload.Raw(legacyLength)
	if err := payload.Finish(); err != nil || payload.Remaining() != 0 {
		return Redirect{}, ErrMalformedReply
	}
	return redirect, nil
}

func encodeRequestID(encoder *wire.Encoder, globalID, transactionID uint64, incarnation int32) {
	encoder.Versioned(2, 2, func(requestID *wire.Encoder) {
		requestID.Uint8(uint8(protocol.EntityClient))
		requestID.Uint64(globalID)
		requestID.Uint64(transactionID)
		requestID.Int32(incarnation)
	})
}

func encodeEVersion(encoder *wire.Encoder, epoch uint32, version uint64) {
	encoder.Uint32(epoch)
	encoder.Uint64(version)
}

func decodeEVersion(decoder *wire.Decoder) {
	decoder.Uint32()
	decoder.Uint64()
}

func encodeUTime(encoder *wire.Encoder, seconds, nanoseconds uint32) {
	encoder.Uint32(seconds)
	encoder.Uint32(nanoseconds)
}

func decodeTrace(decoder *wire.Decoder) error {
	decoder.Int64()
	decoder.Int64()
	decoder.Int64()
	return decoder.Finish()
}

func encodeTrace(encoder *wire.Encoder) {
	encoder.Int64(0)
	encoder.Int64(0)
	encoder.Int64(0)
}
