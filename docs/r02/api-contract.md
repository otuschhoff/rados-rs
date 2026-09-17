# R02 Rust API Contract

R02 freezes locally testable ownership and lifecycle contracts without claiming
network connectivity. `Client::new` validates and owns configuration without
starting a runtime or performing I/O. `Client`, `Pool`, and `ObjectRef` are
cheaply cloned handles; pool and object derivation copies byte identities and
never mutates siblings. `close` is synchronous, shared, and idempotent.

`connect`, `open_pool`, and `flush` are async signatures and return
`ErrorKind::NotConnected` until their transport-owning phases. `shutdown`
performs the complete R02 local transition: it checks cancellation/deadline,
closes every clone, and returns. Repeated shutdown calls succeed unless that
call's options are already canceled or expired. Adding transport behavior must
preserve these signatures and local checks.

Object names, namespaces, and locator keys are bounded owned bytes, not UTF-8
paths. Authentication keys are copied and their `Debug` representation is
redacted; every owned key allocation is zeroized on drop. Returned operation,
class, metadata, cursor, watch/notify, lock, snapshot, sparse-read, checksum and
administrative values own their buffers. `OpResult` is the canonical short name
for `OperationResult`, and `SubOperationResult` preserves both signed result
codes and structured errors. Read and write builders consume themselves and
reject sub-operation, retained-byte, and offset/length overflow before
submission.

`Watch` is an opaque ownership handle and `ObjectCursor` is an opaque,
pool-scoped position. R02 freezes these types without constructors or network
methods; their transport-backed creation and lifecycle methods are added only
in their owning phases. This keeps R02 honest rather than exposing methods that
can only fail before messenger and objecter support exists.

`OperationOptions` accepts an absolute monotonic deadline and a clonable
explicit cancellation token. An unpolled future has no side effects. Dropping a
future after future transport admission will not promise cancellation; the
implementation must retain admitted work and report ambiguity through
`ErrorKind::OutcomeUnknown`. External timeout wrappers follow that dropped-
future rule.

`Error` preserves the original signed Ceph/Linux errno and classifies it without
calling the host OS errno namespace. It may match both `OutcomeUnknown` and its
preserved timeout/cancellation cause.

The compile-checked example is [`examples/r02_contract.rs`](../../examples/r02_contract.rs).