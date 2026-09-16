// Package objecter routes and executes bounded Ceph object requests.
package objecter

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/otuschhoff/go-librados/internal/cephx"
	wire "github.com/otuschhoff/go-librados/internal/encoding"
	"github.com/otuschhoff/go-librados/internal/maps"
	"github.com/otuschhoff/go-librados/internal/msgr"
	"github.com/otuschhoff/go-librados/internal/osd"
	"github.com/otuschhoff/go-librados/internal/protocol"
)

var (
	ErrClosed           = errors.New("objecter closed")
	ErrNoPrimary        = errors.New("object has no acting primary")
	ErrRecovery         = errors.New("read recovery exhausted")
	ErrMalformedStat    = errors.New("malformed stat result")
	ErrStaleMap         = errors.New("OSD supplied a newer map")
	ErrNoSortBitwise    = errors.New("OSD map does not enable SORTBITWISE")
	ErrWatchInterrupted = errors.New("watch interrupted; events may have been lost")
)

const readReplyFrontBytes = uint64(144)

type MapSource interface {
	OSDMap() *maps.OSDMap
	RefreshOSDMap(context.Context, uint32) error
}

type Route struct {
	Epoch     uint32
	PG        maps.PG
	RawHash   uint32
	Primary   int32
	Shard     int8
	Sharded   bool
	Addresses protocol.EntityAddrVec
}

type Router interface {
	Route(Target) (Route, error)
}

type rawHashRouter interface {
	RouteRawHash(int64, uint32) (Route, error)
}

type Target struct {
	PoolID           int64
	Object           string
	Locator          string
	Namespace        string
	Snapshot         uint64
	SnapshotSequence uint64
	WriteSnapshots   []uint64
}

type Result struct {
	Data             []byte
	Size             uint64
	ModificationTime time.Time
	Version          uint64
	Operations       []OperationResult
}

type SparseReadResult struct {
	Extents []osd.SparseExtent
	Version uint64
}

type OperationResult struct {
	Data []byte
	Code int32
}

type EnumerationResult struct {
	Entries []osd.ListEntry
	Next    osd.HObject
}

type session interface {
	Submit(context.Context, msgr.Message) (msgr.Message, error)
	Stop()
}

type notificationSession interface {
	Notifications() <-chan osd.WatchNotification
	NotificationError() error
}

type backoffWaiter interface {
	Wait(context.Context, maps.PG, osd.HObject) error
}

type targetSubmitter interface {
	SubmitTarget(context.Context, maps.PG, osd.HObject, msgr.Message) (msgr.Message, error)
}

type SessionFactory func(int32, protocol.EntityAddrVec) (session, error)

type Config struct {
	Maps              MapSource
	Router            Router
	Authority         *cephx.Connector
	AuthoritySource   func() *cephx.Connector
	ServiceConnector  cephx.ServiceConnectorConfig
	Session           msgr.SessionConfig
	ClientAddresses   protocol.EntityAddrVec
	MessageLimits     osd.Limits
	MaxAttempts       int
	RefreshWait       time.Duration
	MaxMutations      int
	MaxMutationBytes  uint64
	ClientIncarnation int32
	SessionFactory    SessionFactory
}

type Client struct {
	config                Config
	mu                    sync.Mutex
	done                  chan struct{}
	sessions              map[int32]sessionEntry
	closed                bool
	closeDone             chan struct{}
	mutationClosed        bool
	nextTransaction       uint64
	nextMutation          uint64
	pendingMutations      map[uint64]uint64
	retainedMutationBytes uint64
	unknownMutation       uint64
	mutationChanged       chan struct{}
	watches               map[uint64]*Watch
	notifies              map[uint64]chan notifyCompletion
	workers               sync.WaitGroup
}

type notifyCompletion struct {
	notification osd.WatchNotification
	err          error
}

type sessionEntry struct {
	address string
	session session
}

func (client *Client) MaxEnumerationEntries() uint64 {
	return uint64(client.config.MessageLimits.MaxBytes / 12)
}

func New(config Config) (*Client, error) {
	if config.Maps == nil || config.MessageLimits.MaxBytes == 0 || config.MessageLimits.MaxOperations == 0 || config.MaxAttempts <= 0 || config.RefreshWait <= 0 {
		return nil, wire.ErrLimitExceeded
	}
	if config.Router == nil {
		config.Router = mapRouter{source: config.Maps}
	}
	if config.MaxMutations == 0 {
		config.MaxMutations = 64
	}
	if config.MaxMutationBytes == 0 {
		config.MaxMutationBytes = uint64(config.MessageLimits.MaxBytes) * uint64(config.MaxMutations)
	}
	if config.MaxMutations < 0 || config.MaxMutationBytes == 0 {
		return nil, wire.ErrLimitExceeded
	}
	if config.ClientIncarnation == 0 {
		var value [4]byte
		if _, err := rand.Read(value[:]); err != nil {
			return nil, err
		}
		config.ClientIncarnation = int32(binary.LittleEndian.Uint32(value[:])&math.MaxInt32 | 1)
	}
	if config.SessionFactory == nil {
		if config.AuthoritySource == nil {
			config.AuthoritySource = func() *cephx.Connector { return config.Authority }
		}
		if config.AuthoritySource() == nil || len(config.ClientAddresses) == 0 {
			return nil, wire.ErrMalformed
		}
		config.SessionFactory = productionSessionFactory(config)
	}
	config.ClientAddresses = cloneAddresses(config.ClientAddresses)
	return &Client{config: config, done: make(chan struct{}), sessions: make(map[int32]sessionEntry), nextTransaction: 1, pendingMutations: make(map[uint64]uint64), mutationChanged: make(chan struct{}), watches: make(map[uint64]*Watch), notifies: make(map[uint64]chan notifyCompletion)}, nil
}

func (client *Client) Read(ctx context.Context, target Target, offset, length uint64) (Result, error) {
	minimumReplyBytes := readReplyFrontBytes + uint64(len(target.Object))
	if length > math.MaxUint64-offset || minimumReplyBytes > uint64(client.config.MessageLimits.MaxBytes) || length > uint64(client.config.MessageLimits.MaxBytes)-minimumReplyBytes {
		return Result{}, wire.ErrLimitExceeded
	}
	return client.execute(ctx, target, osd.Operation{Code: osd.OpRead, Offset: offset, Length: length})
}

func (client *Client) SparseRead(ctx context.Context, target Target, offset, length uint64) (SparseReadResult, error) {
	if length > math.MaxInt32 || length > math.MaxUint64-offset {
		return SparseReadResult{}, wire.ErrLimitExceeded
	}
	result, err := client.execute(ctx, target, osd.Operation{Code: osd.OpSparseRead, Offset: offset, Length: length})
	if err != nil {
		return SparseReadResult{}, err
	}
	extents, err := osd.DecodeSparseRead(result.Data, offset, length, client.config.MessageLimits.MaxBytes, client.config.MessageLimits.MaxBytes/16)
	if err != nil {
		return SparseReadResult{}, err
	}
	return SparseReadResult{Extents: extents, Version: result.Version}, nil
}

func (client *Client) Checksum(ctx context.Context, target Target, kind uint8, seed []byte, offset, length, chunk uint64) ([]byte, error) {
	if chunk > math.MaxUint32 {
		return nil, wire.ErrLimitExceeded
	}
	result, err := client.execute(ctx, target, osd.Operation{Code: osd.OpChecksum, Offset: offset, Length: length, ChunkSize: uint32(chunk), ChecksumType: kind, Data: seed})
	if err != nil {
		return nil, err
	}
	return osd.DecodeChecksum(result.Data, kind, client.config.MessageLimits.MaxBytes)
}

func (client *Client) Stat(ctx context.Context, target Target) (Result, error) {
	result, err := client.execute(ctx, target, osd.Operation{Code: osd.OpStat})
	if err != nil {
		return Result{}, err
	}
	if len(result.Data) != 16 {
		return Result{}, ErrMalformedStat
	}
	result.Size = binary.LittleEndian.Uint64(result.Data[:8])
	seconds := binary.LittleEndian.Uint32(result.Data[8:12])
	nanoseconds := binary.LittleEndian.Uint32(result.Data[12:])
	if nanoseconds >= 1_000_000_000 {
		return Result{}, ErrMalformedStat
	}
	result.ModificationTime = time.Unix(int64(seconds), int64(nanoseconds)).UTC()
	result.Data = nil
	return result, nil
}

func (client *Client) ReadOperations(ctx context.Context, target Target, operations []osd.Operation) (Result, error) {
	if len(operations) == 0 {
		return Result{}, wire.ErrMalformed
	}
	classCall := false
	for _, operation := range operations {
		if !isReadOperation(operation.Code) && operation.Code != osd.OpCall {
			return Result{}, wire.ErrMalformed
		}
		classCall = classCall || operation.Code == osd.OpCall
	}
	if classCall {
		return client.ClassOperations(ctx, target, operations)
	}
	return client.executeOperations(ctx, target, operations, 0, false)
}

func isReadOperation(code uint16) bool {
	switch code {
	case osd.OpRead, osd.OpStat, osd.OpSparseRead, osd.OpAssertVer, osd.OpOmapGetKeys, osd.OpOmapGetValues,
		osd.OpOmapGetValuesByKeys, osd.OpOmapGetHeader, osd.OpOmapCompare,
		osd.OpChecksum, osd.OpCompareExtent, osd.OpGetXattr, osd.OpGetXattrs, osd.OpCompareXattr, osd.OpListWatchers, osd.OpScrubList:
		return true
	default:
		return false
	}
}

func (client *Client) execute(ctx context.Context, target Target, operation osd.Operation) (Result, error) {
	return client.executeOperation(ctx, target, operation, 0, false)
}

func (client *Client) executeTrackedOutcomeSensitive(ctx context.Context, target Target, operation osd.Operation) (Result, error) {
	sequence, transactionID, operation, err := client.admitMutation(ctx, operation)
	if err != nil {
		return Result{}, err
	}
	result, err := client.executeRoutedOperations(ctx, target, []osd.Operation{operation}, transactionID, true, false, 0, client.config.Router.Route)
	client.completeMutation(sequence, err)
	return result, err
}

func (client *Client) executeOperation(ctx context.Context, target Target, operation osd.Operation, transactionID uint64, mutation bool) (Result, error) {
	return client.executeOperations(ctx, target, []osd.Operation{operation}, transactionID, mutation)
}

func (client *Client) executeOperations(ctx context.Context, target Target, operations []osd.Operation, transactionID uint64, mutation bool) (Result, error) {
	return client.executeRoutedOperations(ctx, target, operations, transactionID, mutation, mutation, 0, client.config.Router.Route)
}

func (client *Client) executeRoutedOperations(ctx context.Context, target Target, operations []osd.Operation, transactionID uint64, outcomeSensitive, durable bool, initialFlags uint32, routeTarget func(Target) (Route, error)) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if transactionID == 0 {
		var err error
		transactionID, err = client.takeTransactionID()
		if err != nil {
			return Result{}, err
		}
	}
	if len(operations) == 0 || uint64(len(operations)) > uint64(client.config.MessageLimits.MaxOperations) {
		return Result{}, wire.ErrLimitExceeded
	}
	currentTarget := target
	requestFlags := initialFlags
	if len(operations) > 1 {
		requestFlags |= osd.FlagReturnVector
	}
	var lastErr error
	for attempt := 0; attempt < client.config.MaxAttempts; attempt++ {
		route, err := routeTarget(currentTarget)
		if err != nil {
			return Result{}, preserveOutcomeUnknown(lastErr, err)
		}
		if route.Primary < 0 || len(route.Addresses) == 0 {
			return Result{}, preserveOutcomeUnknown(lastErr, ErrNoPrimary)
		}
		if attempt > 0 {
			requestFlags |= osd.FlagRetry
		}
		active, err := client.getSession(route.Primary, route.Addresses)
		if err != nil {
			return Result{}, preserveOutcomeUnknown(lastErr, err)
		}
		var clientGlobalID uint64
		if client.config.AuthoritySource != nil {
			if authority := client.config.AuthoritySource(); authority != nil {
				clientGlobalID = authority.AuthMetadata().GlobalID
			}
		}
		request, err := osd.EncodeRequest(osd.Request{
			MapEpoch: route.Epoch, PG: route.PG, ObjectHash: route.RawHash, Shard: route.Shard, Sharded: route.Sharded,
			PoolID: currentTarget.PoolID, Object: currentTarget.Object, Locator: currentTarget.Locator,
			Namespace: currentTarget.Namespace, Snapshot: currentTarget.Snapshot, SnapshotSequence: currentTarget.SnapshotSequence,
			WriteSnapshots: currentTarget.WriteSnapshots, TransactionID: transactionID, ClientGlobalID: clientGlobalID, ClientIncarnation: client.config.ClientIncarnation, Retry: int32(attempt), Flags: requestFlags,
			Features: uint64(protocol.FeatureOSDClient), Operations: operations,
		}, client.config.MessageLimits)
		if err != nil {
			return Result{}, preserveOutcomeUnknown(lastErr, err)
		}
		object := osd.HObject{Key: currentTarget.Locator, Object: currentTarget.Object, Snapshot: currentTarget.Snapshot, Hash: route.RawHash, Namespace: currentTarget.Namespace, Pool: currentTarget.PoolID}
		var message msgr.Message
		if submitter, ok := active.(targetSubmitter); ok {
			message, err = submitter.SubmitTarget(ctx, route.PG, object, request)
		} else {
			if waiter, ok := active.(backoffWaiter); ok {
				if err := waiter.Wait(ctx, route.PG, object); err != nil {
					if ctx.Err() != nil {
						return Result{}, preserveOutcomeUnknown(lastErr, ctx.Err())
					}
					lastErr = preserveOutcomeUnknown(lastErr, err)
					client.invalidate(route.Primary, active)
					client.refresh(ctx, route.Epoch)
					continue
				}
			}
			message, err = active.Submit(ctx, request)
		}
		if err != nil {
			if errors.Is(err, msgr.ErrQueueSaturated) {
				return Result{}, preserveOutcomeUnknown(lastErr, err)
			}
			if outcomeSensitive && errors.Is(err, msgr.ErrOutcomeUnknown) {
				lastErr = preserveOutcomeUnknown(lastErr, err)
				client.invalidate(route.Primary, active)
				if !errors.Is(err, msgr.ErrReconnectExhausted) && !errors.Is(err, ErrStaleMap) {
					changed, refreshErr := client.waitForPrimaryChange(ctx, currentTarget, route)
					if !changed {
						return Result{}, errors.Join(err, refreshErr)
					}
				} else {
					client.refresh(ctx, route.Epoch)
				}
				continue
			}
			if ctx.Err() != nil {
				return Result{}, preserveOutcomeUnknown(lastErr, ctx.Err())
			}
			lastErr = preserveOutcomeUnknown(lastErr, err)
			client.invalidate(route.Primary, active)
			client.refresh(ctx, route.Epoch)
			continue
		}
		reply, err := osd.DecodeReply(message, client.config.MessageLimits)
		if err != nil {
			client.invalidate(route.Primary, active)
			if outcomeSensitive {
				return Result{}, fmt.Errorf("%w: %v", msgr.ErrOutcomeUnknown, err)
			}
			return Result{}, fmt.Errorf("%w: %v", osd.ErrMalformedReply, err)
		}
		if reply.Object != currentTarget.Object || reply.PG != route.PG {
			client.invalidate(route.Primary, active)
			if outcomeSensitive {
				return Result{}, fmt.Errorf("%w: %v", msgr.ErrOutcomeUnknown, osd.ErrMalformedReply)
			}
			return Result{}, osd.ErrMalformedReply
		}
		if reply.Retry >= 0 && reply.Retry != int32(attempt) {
			client.invalidate(route.Primary, active)
			if outcomeSensitive {
				return Result{}, fmt.Errorf("%w: %v", msgr.ErrOutcomeUnknown, osd.ErrMalformedReply)
			}
			return Result{}, osd.ErrMalformedReply
		}
		if reply.Redirect != nil {
			currentTarget.PoolID = reply.Redirect.Pool
			if reply.Redirect.Object != "" {
				currentTarget.Object = reply.Redirect.Object
			}
			currentTarget.Locator = reply.Redirect.Locator
			currentTarget.Namespace = reply.Redirect.Namespace
			requestFlags |= osd.FlagRedirected | osd.FlagIgnoreCache | osd.FlagIgnoreOverlay
			lastErr = errors.New("OSD redirected read")
			if outcomeSensitive {
				transactionID, err = client.takeTransactionID()
				if err != nil {
					return Result{}, err
				}
			}
			continue
		}
		if reply.Result == -11 {
			lastErr = protocol.WireErrno(reply.Result)
			client.refresh(ctx, route.Epoch)
			if outcomeSensitive {
				transactionID, err = client.takeTransactionID()
				if err != nil {
					return Result{}, err
				}
			}
			continue
		}
		if len(reply.Operations) != len(operations) {
			client.invalidate(route.Primary, active)
			if outcomeSensitive {
				return Result{}, fmt.Errorf("%w: %v", msgr.ErrOutcomeUnknown, osd.ErrMalformedReply)
			}
			return Result{}, osd.ErrMalformedReply
		}
		retry := reply.Result == -11
		for index := range operations {
			if reply.Operations[index].Operation != operations[index].Code {
				client.invalidate(route.Primary, active)
				if outcomeSensitive {
					return Result{}, fmt.Errorf("%w: %v", msgr.ErrOutcomeUnknown, osd.ErrMalformedReply)
				}
				return Result{}, osd.ErrMalformedReply
			}
			retry = retry || reply.Operations[index].Code == -11
		}
		if retry {
			lastErr = protocol.WireErrno(-11)
			client.refresh(ctx, route.Epoch)
			if outcomeSensitive {
				transactionID, err = client.takeTransactionID()
				if err != nil {
					return Result{}, err
				}
			}
			continue
		}
		if durable && reply.Result == 0 && uint64(reply.Flags)&uint64(osd.FlagOnDisk) == 0 {
			client.invalidate(route.Primary, active)
			return Result{}, fmt.Errorf("%w: mutation reply is not durable", msgr.ErrOutcomeUnknown)
		}
		result := Result{Version: reply.Version, Operations: make([]OperationResult, len(reply.Operations))}
		for index, operationResult := range reply.Operations {
			if operations[index].Code == osd.OpRead && uint64(len(operationResult.Data)) > operations[index].Length {
				client.invalidate(route.Primary, active)
				return Result{}, osd.ErrMalformedReply
			}
			result.Operations[index] = OperationResult{Data: append([]byte(nil), operationResult.Data...), Code: operationResult.Code}
		}
		result.Data = append([]byte(nil), result.Operations[0].Data...)
		if reply.Result < 0 {
			return result, protocol.WireErrno(reply.Result)
		}
		for index, operationResult := range result.Operations {
			if operationResult.Code < 0 && operations[index].Flags&osd.OpFlagFailOK == 0 {
				return result, protocol.WireErrno(operationResult.Code)
			}
		}
		return result, nil
	}
	return Result{}, fmt.Errorf("%w: %w", ErrRecovery, lastErr)
}

func (client *Client) PGNLS(ctx context.Context, poolID int64, namespace string, cursor osd.HObject, count uint64) (osd.ListPage, error) {
	if count == 0 || (!cursor.IsMin() && (cursor.Pool != poolID || cursor.Snapshot != osd.NoSnap || cursor.IsMax())) {
		return osd.ListPage{}, wire.ErrMalformed
	}
	route, err := client.routeRawHash(poolID, cursor.Hash)
	if err != nil {
		return osd.ListPage{}, err
	}
	operation, err := osd.EncodePGNLSOperation(cursor, count, route.Epoch, client.config.MessageLimits.MaxBytes)
	if err != nil {
		return osd.ListPage{}, err
	}
	first := true
	routeTarget := func(Target) (Route, error) {
		if first {
			first = false
			return route, nil
		}
		return client.routeRawHash(poolID, cursor.Hash)
	}
	result, err := client.executeRoutedOperations(ctx, Target{PoolID: poolID, Namespace: namespace, Snapshot: osd.NoSnap}, []osd.Operation{operation}, 0, false, false, osd.FlagPGOp|osd.FlagIgnoreOverlay, routeTarget)
	if err != nil {
		return osd.ListPage{}, err
	}
	return osd.DecodePGNLSPage(result.Data, client.config.MessageLimits.MaxBytes, client.config.MessageLimits.MaxBytes/12)
}

func (client *Client) Enumerate(ctx context.Context, poolID int64, namespace string, start, end osd.HObject, limit uint64) (EnumerationResult, error) {
	if limit == 0 || limit > client.MaxEnumerationEntries() || start.IsMax() || (!end.IsMax() && osd.CompareHObject(start, end) > 0) {
		return EnumerationResult{}, wire.ErrMalformed
	}
	return enumeratePages(poolID, start, end, limit, func(cursor osd.HObject, count uint64) (osd.ListPage, []osd.HObject, error) {
		page, err := client.PGNLS(ctx, poolID, namespace, cursor, count)
		if err != nil {
			return osd.ListPage{}, nil, err
		}
		entryCursors, err := client.enumerationEntryCursors(poolID, namespace, page.Entries)
		return page, entryCursors, err
	})
}

func enumeratePages(poolID int64, start, end osd.HObject, limit uint64, fetch func(osd.HObject, uint64) (osd.ListPage, []osd.HObject, error)) (EnumerationResult, error) {
	if osd.CompareHObject(start, end) == 0 {
		return EnumerationResult{Next: end}, nil
	}
	result := EnumerationResult{Entries: make([]osd.ListEntry, 0, limit), Next: start}
	for uint64(len(result.Entries)) < limit && osd.CompareHObject(result.Next, end) < 0 {
		remaining := limit - uint64(len(result.Entries))
		page, entryCursors, err := fetch(result.Next, remaining)
		if err != nil {
			return EnumerationResult{}, err
		}
		if len(entryCursors) != len(page.Entries) {
			return EnumerationResult{}, osd.ErrMalformedReply
		}
		if err := validateEnumerationPage(poolID, result.Next, page.Next, entryCursors); err != nil {
			return EnumerationResult{}, err
		}
		next := page.Next
		entryCount := len(page.Entries)
		if osd.CompareHObject(next, end) > 0 {
			next = end
			for entryCount > 0 && osd.CompareHObject(entryCursors[entryCount-1], end) >= 0 {
				entryCount--
			}
		}
		available := int(limit - uint64(len(result.Entries)))
		if entryCount > available {
			next = entryCursors[available]
			entryCount = available
		}
		result.Entries = append(result.Entries, page.Entries[:entryCount]...)
		result.Next = next
	}
	return result, nil
}

func (client *Client) enumerationEntryCursors(poolID int64, namespace string, entries []osd.ListEntry) ([]osd.HObject, error) {
	osdMap := client.config.Maps.OSDMap()
	if osdMap == nil {
		return nil, ErrNoPrimary
	}
	if _, ok := osdMap.PoolByID(poolID); !ok {
		return nil, protocol.WireErrno(-2)
	}
	result := make([]osd.HObject, len(entries))
	for index, entry := range entries {
		if namespace != "\x01" && entry.Namespace != namespace {
			return nil, osd.ErrMalformedReply
		}
		placement, err := osdMap.MapObject(poolID, entry.Object, entry.Locator, entry.Namespace)
		if err != nil {
			return nil, err
		}
		result[index] = osd.HObject{Key: entry.Locator, Object: entry.Object, Snapshot: osd.NoSnap, Hash: placement.RawHash, Namespace: entry.Namespace, Pool: poolID}
	}
	return result, nil
}

func validateEnumerationPage(poolID int64, start, next osd.HObject, entries []osd.HObject) error {
	if !next.IsMax() && (next.IsMin() || next.Snapshot != osd.NoSnap || next.Pool != poolID) {
		return osd.ErrMalformedReply
	}
	previous := start
	for _, entry := range entries {
		if osd.CompareHObject(entry, previous) < 0 || (!next.IsMax() && osd.CompareHObject(entry, next) >= 0) {
			return osd.ErrMalformedReply
		}
		previous = entry
	}
	if !next.IsMax() && osd.CompareHObject(next, start) <= 0 {
		return osd.ErrMalformedReply
	}
	return nil
}

func (client *Client) routeRawHash(poolID int64, hash uint32) (Route, error) {
	if router, ok := client.config.Router.(rawHashRouter); ok {
		return router.RouteRawHash(poolID, hash)
	}
	osdMap := client.config.Maps.OSDMap()
	if osdMap == nil {
		return Route{}, ErrNoPrimary
	}
	return mapRouter{source: client.config.Maps}.RouteRawHash(poolID, hash)
}

func preserveOutcomeUnknown(previous, current error) error {
	if errors.Is(previous, msgr.ErrOutcomeUnknown) {
		return errors.Join(previous, current)
	}
	return current
}

type mapRouter struct{ source MapSource }

func (router mapRouter) Route(target Target) (Route, error) {
	osdMap := router.source.OSDMap()
	if osdMap == nil {
		return Route{}, ErrNoPrimary
	}
	placement, err := osdMap.PlaceObject(target.PoolID, target.Object, target.Locator, target.Namespace)
	if err != nil {
		return Route{}, err
	}
	addresses, ok := osdMap.OSDClientAddresses(placement.ActingPrimary)
	if !ok {
		return Route{}, ErrNoPrimary
	}
	return Route{Epoch: osdMap.Epoch(), PG: placement.PG, RawHash: placement.RawHash, Primary: placement.ActingPrimary, Shard: placement.PrimaryShard, Sharded: placement.Sharded, Addresses: addresses}, nil
}

func (router mapRouter) RouteRawHash(poolID int64, hash uint32) (Route, error) {
	osdMap := router.source.OSDMap()
	if osdMap == nil {
		return Route{}, ErrNoPrimary
	}
	if !osdMap.SortBitwise() {
		return Route{}, ErrNoSortBitwise
	}
	if _, ok := osdMap.PoolByID(poolID); !ok {
		return Route{}, protocol.WireErrno(-2)
	}
	placement, err := osdMap.PlaceRawHash(poolID, hash)
	if err != nil {
		return Route{}, err
	}
	addresses, ok := osdMap.OSDClientAddresses(placement.ActingPrimary)
	if !ok {
		return Route{}, ErrNoPrimary
	}
	return Route{Epoch: osdMap.Epoch(), PG: placement.PG, RawHash: placement.RawHash, Primary: placement.ActingPrimary, Shard: placement.PrimaryShard, Sharded: placement.Sharded, Addresses: addresses}, nil
}

func (client *Client) refresh(ctx context.Context, epoch uint32) {
	refreshCtx, cancel := context.WithTimeout(ctx, client.config.RefreshWait)
	defer cancel()
	_ = client.config.Maps.RefreshOSDMap(refreshCtx, epoch)
}

func (client *Client) waitForPrimaryChange(ctx context.Context, target Target, failed Route) (bool, error) {
	epoch := failed.Epoch
	var lastErr error
	for range client.config.MaxAttempts {
		refreshCtx, cancel := context.WithTimeout(ctx, client.config.RefreshWait)
		err := client.config.Maps.RefreshOSDMap(refreshCtx, epoch)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			lastErr = err
			continue
		}
		refreshed, err := client.config.Router.Route(target)
		if err != nil {
			return false, err
		}
		if refreshed.Primary != failed.Primary {
			return true, nil
		}
		if refreshed.Epoch <= epoch {
			lastErr = fmt.Errorf("OSD map did not advance past epoch %d", epoch)
			continue
		}
		epoch = refreshed.Epoch
	}
	if lastErr != nil {
		return false, fmt.Errorf("OSD map refresh after epoch %d with acting primary %d unchanged: %w", epoch, failed.Primary, lastErr)
	}
	return false, fmt.Errorf("acting primary %d unchanged through epoch %d", failed.Primary, epoch)
}

func (client *Client) getSession(osdID int32, addresses protocol.EntityAddrVec) (session, error) {
	address, ok := selectAddress(addresses)
	if !ok {
		return nil, ErrNoPrimary
	}
	client.mu.Lock()
	if client.closed {
		client.mu.Unlock()
		return nil, ErrClosed
	}
	var interrupted []*Watch
	if existing, ok := client.sessions[osdID]; ok {
		if existing.address == address {
			client.mu.Unlock()
			return existing.session, nil
		}
		delete(client.sessions, osdID)
		interrupted = client.watchesForPrimaryLocked(osdID)
		existing.session.Stop()
	}
	created, err := client.config.SessionFactory(osdID, addresses)
	if err != nil {
		client.mu.Unlock()
		for _, watch := range interrupted {
			watch.interrupt(msgr.ErrSessionClosed)
		}
		return nil, err
	}
	client.sessions[osdID] = sessionEntry{address: address, session: created}
	if notifications, ok := created.(notificationSession); ok {
		client.workers.Add(1)
		go func() {
			defer client.workers.Done()
			client.dispatchNotifications(osdID, created, notifications)
		}()
	}
	client.mu.Unlock()
	for _, watch := range interrupted {
		watch.interrupt(msgr.ErrSessionClosed)
	}
	return created, nil
}

func (client *Client) invalidate(osdID int32, failed session) {
	client.mu.Lock()
	var interrupted []*Watch
	removed := false
	if existing, ok := client.sessions[osdID]; ok && existing.session == failed {
		delete(client.sessions, osdID)
		interrupted = client.watchesForPrimaryLocked(osdID)
		removed = true
	}
	client.mu.Unlock()
	if !removed {
		return
	}
	failed.Stop()
	for _, watch := range interrupted {
		watch.interrupt(msgr.ErrSessionClosed)
	}
}

func (client *Client) watchesForPrimaryLocked(osdID int32) []*Watch {
	watches := make([]*Watch, 0)
	for _, watch := range client.watches {
		if watch.primaryOSD() == osdID {
			watches = append(watches, watch)
		}
	}
	return watches
}

func (client *Client) Close() {
	client.mu.Lock()
	if client.closed {
		closeDone := client.closeDone
		client.mu.Unlock()
		if closeDone != nil {
			<-closeDone
		}
		return
	}
	client.closed = true
	client.closeDone = make(chan struct{})
	closeDone := client.closeDone
	client.mutationClosed = true
	client.notifyMutationWaitersLocked()
	sessions := client.sessions
	client.sessions = nil
	watches := client.watches
	notifies := client.notifies
	client.watches = nil
	client.notifies = nil
	if client.done != nil {
		close(client.done)
	}
	client.mu.Unlock()
	for _, watch := range watches {
		watch.stop(ErrClosed)
	}
	for _, completion := range notifies {
		select {
		case completion <- notifyCompletion{err: errors.Join(msgr.ErrOutcomeUnknown, ErrClosed)}:
		default:
		}
	}
	for _, entry := range sessions {
		entry.session.Stop()
	}
	for _, watch := range watches {
		watch.wait()
	}
	client.workers.Wait()
	close(closeDone)
}

func productionSessionFactory(config Config) SessionFactory {
	return func(osdID int32, addresses protocol.EntityAddrVec) (session, error) {
		selected, ok := selectEntityAddress(addresses)
		if !ok {
			return nil, ErrNoPrimary
		}
		endpoint, _ := selected.AddrPort()
		serviceConfig := config.ServiceConnector
		if config.AuthoritySource() == nil {
			return nil, cephx.ErrMissingTicket
		}
		serviceConfig.Authority = nil
		serviceConfig.AuthoritySource = config.AuthoritySource
		serviceConfig.Address = endpoint.String()
		serviceConfig.TargetAddress = selected
		connector, err := cephx.NewServiceConnector(serviceConfig)
		if err != nil {
			return nil, err
		}
		sessionConfig := config.Session
		sessionConfig.ClientIdent.Addresses = cloneAddresses(config.ClientAddresses)
		sessionConfig.ClientIdent.TargetAddress = selected
		sessionConfig.ClientIdent.SupportedFeatures = uint64(protocol.FeatureOSDClient)
		sessionConfig.ClientIdent.RequiredFeatures = uint64(protocol.FeatureOSDReplyMux | protocol.FeaturePGID64 | protocol.FeatureNewOSDOpReplyEncoding | protocol.FeatureMessageAddress2)
		sessionConfig.ReconnectPolicy = msgr.ReplayPending
		sessionConfig.DiagnosticService = "osd"
		sessionConfig.DiagnosticServiceID = osdID
		raw, err := msgr.NewSession(nil, connector, sessionConfig)
		if err != nil {
			return nil, err
		}
		return newOSDSession(raw, config.MessageLimits, config.RefreshWait), nil
	}
}

func selectAddress(addresses protocol.EntityAddrVec) (string, bool) {
	address, ok := selectEntityAddress(addresses)
	if !ok {
		return "", false
	}
	endpoint, ok := address.AddrPort()
	return endpoint.String(), ok
}

func selectEntityAddress(addresses protocol.EntityAddrVec) (protocol.EntityAddr, bool) {
	for _, address := range addresses {
		if address.Type != protocol.AddressV2 {
			continue
		}
		if endpoint, ok := address.AddrPort(); ok && endpoint.Port() != 0 {
			return address, true
		}
	}
	return protocol.EntityAddr{}, false
}

func cloneAddresses(addresses protocol.EntityAddrVec) protocol.EntityAddrVec {
	cloned := make(protocol.EntityAddrVec, len(addresses))
	for index, address := range addresses {
		cloned[index] = address
		cloned[index].SocketData = append([]byte(nil), address.SocketData...)
	}
	return cloned
}
