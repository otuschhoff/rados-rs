# API Inventory Coverage

This document summarizes classification of the public librados API extracted
from the pinned Ceph headers. It describes inventory coverage only; it is not a
release-readiness claim.

The generated inventory contains 623 rows: 243 C APIs and 380 C++ operations.

| Disposition | Count |
| --- | ---: |
| implemented | 338 |
| go-native | 153 |
| intentional-omission | 113 |
| deferred | 19 |
| planned | 0 |
| review-required | 0 |

`implemented` means an actual Go method or operation preserves the relevant
synchronous behavior. It does not mean that a similarly named method was
counted based on naming alone. Configuration and lifecycle map to typed
`Config` values and context-aware `Client` methods; discovery maps to client
and immutable pool methods; namespace and locator mutation maps to immutable
pool views; read/stat and mutation operations map to their `ObjectRef`
equivalents.

`go-native` records adaptations where exposing the C or C++ shape would be
misleading. Constructors and copy ownership use Go construction and value
ownership. AIO completion allocation, callback registration, completion
polling, cancellation, and last-version access are represented by
`context.Context`, direct operation results, versioned `OpResult` values, and
`Client.Flush`. Async read/stat and mutation duplicates therefore do not add a
second public operation family.

Native `cct`, cluster, and ioctx handle access is intentionally omitted because
the implementation has a pure-Go boundary. The librados version API,
minimum-compatible-release diagnostics, direct monitor ping, explicit
wait-for-latest-map calls, public hash-position diagnostics, and
`PlacementGroup::parse` are intentionally omitted because they are absent from
the frozen v1 public API and do not provide distinct v1-required behavior.
Other intentional omissions are deprecated, legacy, or non-frozen variants
identified by their owning phase. Deferred rows remain outside the v1 scope
defined by `SPEC.md` and retain explicit prerequisites and future
qualification tests in the generated inventory.