# Frozen v1 Public API Design

Status: approved signature contract. Types and methods are implemented only in
the phase that can test their behavior. Additive options may be introduced;
changing these signatures requires an explicit design revision.

```go
package rados

// Configuration and lifecycle.
type SecurityMode uint8
const (
    SecurityModeSecure SecurityMode = iota
    SecurityModeCRC
)
type Config struct {
    Monitors []string
    Entity, ClusterFSID string
    Key []byte
    SecurityMode SecurityMode
    DialTimeout, HandshakeTimeout, OperationTimeout time.Duration
}
func DefaultConfig() Config
func ParseConfig(data []byte) (Config, error)
func LoadConfig(path string) (Config, error)
func LoadKeyring(path, entity string) ([]byte, error)
func (config Config) WithOption(name, value string) (Config, error)
func (config Config) Option(name string) (string, bool)
func (config Config) ParseArgs(arguments []string) (Config, []string, error)
func (config Config) ParseEnv(name string) (Config, error)
func New(config Config) (*Client, error)
func (c *Client) Connect(ctx context.Context) error
func (c *Client) Flush(ctx context.Context) error
func (c *Client) Shutdown(ctx context.Context) error
func (c *Client) Close() error
func (c *Client) FSID() string
func (c *Client) InstanceID() uint64

// Immutable object views and core results.
type Pool struct{}
type ObjectRef struct{}
type ObjectInfo struct { Size uint64; ModTime time.Time; Version uint64 }
type OpResult struct { Version uint64; Results []SubOpResult }
type SubOpResult struct { Data []byte; Value uint64; Err error }
func (c *Client) OpenPool(ctx context.Context, name string) (Pool, error)
func (c *Client) OpenPoolByID(ctx context.Context, id int64) (Pool, error)
func (p Pool) ID() int64
func (p Pool) Name() string
func (p Pool) WithNamespace(namespace string) Pool
func (p Pool) WithLocator(locator string) Pool
func (p Pool) WithReadSnapshot(id uint64) Pool
func (p Pool) Object(name string) ObjectRef
func (o ObjectRef) Read(ctx context.Context, offset, length uint64) ([]byte, ObjectInfo, error)
func (o ObjectRef) Stat(ctx context.Context) (ObjectInfo, error)
func (o ObjectRef) Write(ctx context.Context, offset uint64, data []byte) (OpResult, error)
func (o ObjectRef) WriteFull(ctx context.Context, data []byte) (OpResult, error)
func (o ObjectRef) Append(ctx context.Context, data []byte) (OpResult, error)
func (o ObjectRef) Truncate(ctx context.Context, size uint64) (OpResult, error)
func (o ObjectRef) Zero(ctx context.Context, offset, length uint64) (OpResult, error)
func (o ObjectRef) Remove(ctx context.Context) (OpResult, error)
func (o ObjectRef) Create(ctx context.Context, exclusive bool) (OpResult, error)

// Metadata and server-side class calls.
type XAttr struct { Name string; Value []byte }
type OMAPEntry struct { Key, Value []byte }
type Page[T any] struct { Values []T; More bool }
func (o ObjectRef) GetXAttr(ctx context.Context, name string) ([]byte, error)
func (o ObjectRef) SetXAttr(ctx context.Context, name string, value []byte) (OpResult, error)
func (o ObjectRef) RemoveXAttr(ctx context.Context, name string) (OpResult, error)
func (o ObjectRef) ListXAttrs(ctx context.Context) ([]XAttr, error)
func (o ObjectRef) ListOMAP(ctx context.Context, after string, limit uint64) (Page[OMAPEntry], error)
func (o ObjectRef) Exec(ctx context.Context, class, method string, input []byte) ([]byte, error)

// Atomic operation builders. Builders are single-use and freeze on execute.
type ReadOp struct{}
type WriteOp struct{}
func NewReadOp() *ReadOp
func NewWriteOp() *WriteOp
func (op *ReadOp) Read(offset, length uint64) int
func (op *ReadOp) Stat() int
func (op *ReadOp) AssertExists()
func (op *ReadOp) AssertVersion(version uint64)
func (op *ReadOp) GetXAttr(name string) int
func (op *ReadOp) ListOMAP(after string, limit uint64) int
func (op *ReadOp) Exec(class, method string, input []byte) int
func (op *WriteOp) Create(exclusive bool)
func (op *WriteOp) Write(offset uint64, data []byte)
func (op *WriteOp) WriteFull(data []byte)
func (op *WriteOp) Append(data []byte)
func (op *WriteOp) Truncate(size uint64)
func (op *WriteOp) Zero(offset, length uint64)
func (op *WriteOp) Remove()
func (op *WriteOp) AssertVersion(version uint64)
func (op *WriteOp) CompareExtent(offset uint64, data []byte) int
func (op *WriteOp) SetXAttr(name string, value []byte)
func (op *WriteOp) RemoveXAttr(name string)
func (op *WriteOp) SetOMAP(values []OMAPEntry)
func (op *WriteOp) RemoveOMAP(keys [][]byte)
func (op *WriteOp) ClearOMAP()
func (op *WriteOp) SetOMAPHeader(value []byte)
func (op *WriteOp) CompareOMAP(key, value []byte) int
func (op *WriteOp) Exec(class, method string, input []byte) int
func (o ObjectRef) ExecuteRead(ctx context.Context, op *ReadOp) (OpResult, error)
func (o ObjectRef) ExecuteWrite(ctx context.Context, op *WriteOp) (OpResult, error)

// Enumeration.
type ObjectEntry struct { Name, Namespace, Locator string }
type ObjectCursor struct { poolID int64; value string; end bool }
type ObjectPage struct { Values []ObjectEntry; Next ObjectCursor; More bool }
func (p Pool) BeginObjectCursor() ObjectCursor
func (p Pool) EndObjectCursor() ObjectCursor
func (p Pool) ListObjects(ctx context.Context, after ObjectCursor, limit uint64) (ObjectPage, error)
func (p Pool) SplitCursor(begin, end ObjectCursor, partitions uint32) ([]ObjectCursor, error)
func CompareObjectCursors(left, right ObjectCursor) (int, error)
func (cursor ObjectCursor) IsEnd() bool

// Watches and locks.
type WatchEvent struct { NotifyID, Cookie uint64; Notifier uint64; Data []byte }
type NotifyReply struct { Acknowledged []uint64; TimedOut []uint64 }
type Watch struct{}
type Watcher struct { Client, Address string; Cookie uint64; Timeout time.Duration }
type LockMode uint8
type LockOptions struct { Cookie, Description string; Duration time.Duration; Renew bool }
type Locker struct { Client, Cookie, Address string }
func (o ObjectRef) Watch(ctx context.Context, queue uint32) (*Watch, <-chan WatchEvent, error)
func (w *Watch) Ack(ctx context.Context, notifyID uint64, data []byte) error
func (w *Watch) Close(ctx context.Context) error
func (o ObjectRef) Notify(ctx context.Context, data []byte) (NotifyReply, error)
func (o ObjectRef) ListWatchers(ctx context.Context) ([]Watcher, error)
func (o ObjectRef) Lock(ctx context.Context, name string, mode LockMode, options LockOptions) error
func (o ObjectRef) Unlock(ctx context.Context, name, cookie string) error
func (o ObjectRef) ListLockers(ctx context.Context, name string) ([]Locker, error)
func (o ObjectRef) BreakLock(ctx context.Context, name, client, cookie string) error

// Snapshots.
type Snapshot struct { ID uint64; Name string; CreatedAt time.Time }
type SnapshotContext struct { Sequence uint64; Snapshots []uint64 }
func (p Pool) CreateSnapshot(ctx context.Context, name string) error
func (p Pool) RemoveSnapshot(ctx context.Context, name string) error
func (p Pool) ListSnapshots(ctx context.Context) ([]Snapshot, error)
func (p Pool) LookupSnapshot(ctx context.Context, name string) (Snapshot, error)
func (p Pool) CreateSelfManagedSnapshot(ctx context.Context) (uint64, error)
func (p Pool) RemoveSelfManagedSnapshot(ctx context.Context, id uint64) error
func (p Pool) WithReadSnapshot(id uint64) Pool
func (p Pool) WithWriteSnapshot(context SnapshotContext) Pool
func (p Pool) UsesSelfManagedSnapshots(ctx context.Context) (bool, error)
func (o ObjectRef) RollbackToSnapshot(ctx context.Context, name string) (OpResult, error)
func (o ObjectRef) RollbackToSelfManagedSnapshot(ctx context.Context, id uint64) (OpResult, error)

// Administration and specialized I/O.
type ClusterStats struct { KB, KBUsed, KBAvailable, Objects uint64 }
type PoolStats struct { BytesUsed, Objects, ReadBytes, WriteBytes uint64 }
type CommandResult struct { Output []byte; Status string }
type SparseExtent struct { Offset uint64; Data []byte }
type ChecksumType uint8
type InconsistentObject struct { Object string; Shards []int; Errors []string }
type InconsistentPG struct { PG string; Errors []string }
func (c *Client) ListPools(ctx context.Context) ([]string, error)
func (c *Client) SessionAddresses() []string
func (c *Client) ClusterStats(ctx context.Context) (ClusterStats, error)
func (p Pool) Stats(ctx context.Context) (PoolStats, error)
func (p Pool) IsErasureCoded(ctx context.Context) (bool, error)
func (p Pool) RequiresAlignment(ctx context.Context) (bool, error)
func (p Pool) RequiredAlignment(ctx context.Context) (uint64, error)
func (c *Client) MonitorCommand(ctx context.Context, command []byte, input []byte) (CommandResult, error)
func (c *Client) ManagerCommand(ctx context.Context, command []byte, input []byte) (CommandResult, error)
func (c *Client) OSDCommand(ctx context.Context, id int, command []byte, input []byte) (CommandResult, error)
func (c *Client) PGCommand(ctx context.Context, pg string, command []byte, input []byte) (CommandResult, error)
func (c *Client) CreatePool(ctx context.Context, name string) error
func (c *Client) DeletePool(ctx context.Context, name string) error
func (c *Client) Blocklist(ctx context.Context, address string, duration time.Duration) error
func (p Pool) EnableApplication(ctx context.Context, name string, force bool) error
func (p Pool) ListApplications(ctx context.Context) ([]string, error)
func (p Pool) GetApplicationMetadata(ctx context.Context, application, key string) (string, error)
func (p Pool) SetApplicationMetadata(ctx context.Context, application, key, value string) error
func (p Pool) RemoveApplicationMetadata(ctx context.Context, application, key string) error
func (p Pool) ListApplicationMetadata(ctx context.Context, application string) (map[string]string, error)
func (c *Client) ListInconsistentPGs(ctx context.Context, poolID int64) ([]InconsistentPG, error)
func (c *Client) ListInconsistentObjects(ctx context.Context, pg string) ([]InconsistentObject, error)
func (o ObjectRef) SparseRead(ctx context.Context, offset, length uint64) ([]SparseExtent, ObjectInfo, error)
func (o ObjectRef) WriteSame(ctx context.Context, offset, length uint64, pattern []byte) (OpResult, error)
func (o ObjectRef) Checksum(ctx context.Context, kind ChecksumType, seed []byte, offset, length, chunk uint64) ([]byte, error)
func (o ObjectRef) CopyFrom(ctx context.Context, source ObjectRef, sourceVersion uint64) (OpResult, error)
func (o ObjectRef) CopyFrom2(ctx context.Context, source ObjectRef, sourceVersion uint64, truncateSequence uint32, truncateSize uint64) (OpResult, error)
func (o ObjectRef) SetAllocationHint(ctx context.Context, expectedObjectSize, expectedWriteSize uint64) (OpResult, error)
```

Configuration transformations are value-oriented. `DefaultConfig` supplies
`client.admin`, secure mode, and finite 10 second dial, 15 second handshake,
and 30 second operation timeouts without consulting files, arguments, or the
environment. `ParseConfig` and `LoadConfig` accept only the bounded
configuration subset documented in `docs/p04/configuration.md`; `ParseEnv` is
an explicit overlay, and `WithOption`/`ParseArgs` are the final explicit
overlay. Returned monitor slices, key bytes, and option state do not alias the
input configuration. Unknown programmatic options remain observable through
`Option` but have no effect on `New`.

Administrative command arguments are one bounded JSON object passed as one
Ceph command-vector element. Returned output and status are caller-owned and
remain available when the server returns a negative errno. Manager commands
follow the active daemon published by `MgrMap`; manager absence does not gate
connection setup or ordinary object I/O. Targeted monitor/manager variants and
pool creation with an explicit CRUSH rule are not part of the frozen v1 API.

Pool creation/deletion and application metadata mutations wait for the
resulting OSD map to become visible before returning. `Blocklist` accepts a
complete Ceph entity address with an optional `v1:`, `v2:`, or `any:` prefix,
optional port, and optional 32-bit nonce; durations are whole seconds in the
native unsigned 32-bit range. It also waits for a newer OSD map. Session
addresses are copied from the nonce-bearing messenger identity and returned as
new Go strings.

Administrative methods require the corresponding Ceph monitor, manager, or
OSD capabilities. A client used only for ordinary object I/O does not require
manager capabilities or manager availability. Pool deletion and blocklisting
are intentionally explicit and must only be used against resources whose
ownership the application has established.

Iteration pages are bounded and cursors are opaque. Begin/end cursors come from
the owning pool; the zero cursor is invalid. Cursors may be stored and reused
while that pool ID exists, but using one with another pool or comparing cursors
from different pools returns `ErrInvalidArgument`. `SplitCursor` accepts the
full range returned by `BeginObjectCursor` and `EndObjectCursor`; partitions are
ordered, non-overlapping half-open ranges. Enumeration is not a global snapshot
and is not globally sorted under concurrent mutation. Unsupported pool or
feature combinations return `ErrUnsupported`; methods never emulate atomic
server operations with client-side read-modify-write sequences.
