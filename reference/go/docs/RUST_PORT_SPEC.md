# Native Rust RADOS Client: Port Design and Execution Spec

Status: proposed; implementation is not started by this document.
Design date: 2026-09-16.

## 1. Decision and Objective

Build a native Rust client for unmodified Ceph, porting the completed Go client's behavior and using this project's accumulated protocol knowledge, fixtures, differential drivers, fault scenarios and qualification machinery. Do not rediscover Ceph from its C API alone, and do not mechanically translate Go goroutines and mutexes into Rust tasks and locks.

The result must be usable as a Rust library without a Go runtime, native librados, Ceph development packages, language bridge, subprocess, gateway or proxy. Production transport, authentication, codecs and placement execute in Rust. Go and native Ceph remain development-only reference implementations.

Adopt an async-first Tokio API, safe Rust for project-owned production code, and small private modules inside one initial library crate. Reuse language-neutral evidence directly; adapt language-bound probes and validators incrementally. Require independent Ceph evidence as well as Go/Rust parity, because a port can reproduce its reference implementation's mistakes.

Treat the Go feature set as complete for planning, as requested. This does not import Go release approval into Rust: checked-in P12 documentation still records outstanding qualification/review gates. No Go release status is changed by this document.

## 2. Scope and Baseline

### 2.1 Freeze the Reference Before Porting

The inspected repository HEAD is `061df4d7eab779eee2bb7c069ad43aec3e455981`, but the inspected working tree also contains modified and untracked implementation, configuration and P12 tooling files. That commit alone is therefore **not** a complete reference for this design.

R00 must select an approved immutable Go source snapshot that includes the intended completed implementation. Record commit and relevant content hashes, or a content-addressed source archive with dirty-tree provenance if a commit is not yet approved. Do not auto-commit unrelated work to create a baseline. A missing final snapshot blocks baseline certification, not reading or inventory work.

Use the existing [P00 evidence manifest](p00/evidence.json), not newly guessed versions:

- Ceph source-semantics baseline: v20.2.0, commit `69f84cc2651aa259a15bc192ddaabd3baba07489`.
- Current qualification server: v20.2.4, commit `7f793731f1b39eb4f465e960113d2363c311b964`.
- Container architecture digests and native compiler/development-package pins: inherit from the evidence manifest after validating availability.
- Go oracle toolchains: read the frozen project's manifests/contracts; do not substitute the host's default Go.
- Rust: choose an available stable toolchain, edition and MSRV in R00; pin toolchain/component versions and record `rustc -Vv`, Cargo version and target triples. Do not invent a future Rust version.

"Ceph v20+" means the same finite, tested capability policy as Go, not unconditional support for later releases. Initially qualify Ceph 20.2.4 on the inherited replicated and EC profiles. Add other versions through explicit future qualification.

### 2.2 Feature Parity

Rust v1 targets every implemented, non-deferred public Go behavior and every native API mapping represented by that behavior. Use the [native API inventory](p00/api-inventory.csv), [Go public API contract](p01/public-api.md), [P12 API coverage](p12/api-coverage.md), exported Go source and tests together. Historical inventory counts alone are not a parity metric.

Create a Rust mapping ledger keyed by stable semantic operation ID, with columns for native symbol(s), Go symbol(s), Rust API, baseline evidence, phase, supported pool/features, deliberate language adaptation, test IDs and status. C memory-management functions and duplicated sync/aio entry points map to Rust ownership/async semantics rather than redundant methods. Inspect exported Go declarations as well as the native inventory so Go-specific configuration and lifecycle helpers cannot be missed.

Required families:

| Family | Rust Target |
| --- | --- |
| Connection and configuration | Explicit config, supported file/keyring/argument/environment loaders, precedence, credential handling, secure default, monitor discovery/failover and FSID pinning |
| Protocol | Messenger v2.1 CRC/secure, implemented authentication methods and service authorization, map updates, exact supported CRUSH/PG/primary routing |
| Core object I/O | Create/exclusive create, stat/version, reads, writes, append, write-full, truncate, zero, remove, immutable namespace/locator views |
| Metadata and atomic operations | Xattrs, binary OMAP operations/headers/ranges, assertions, extent/version comparisons, single-object compounds, flags and sub-results |
| Enumeration | Object and namespace pagination, supported cursor/range partition behavior |
| Lifecycle and errors | Bounded concurrent I/O, operation deadlines, cancellation, outcome unknown, flush watermark, close and graceful shutdown |
| Coordination | Class execution, shared/exclusive locks, renew/list/break, watch/notify/ack, timeout partial results and recovery |
| Snapshots and specialized I/O | Named/self-managed snapshots and write contexts, rollback, sparse/extent queries, checksums, writesame, hints, clone/copy/inconsistency APIs present in Go |
| Administration | Monitor/manager/OSD/PG commands, cluster/pool stats, pool/application metadata administration, addresses/blocklisting and manager failover |
| EC | Same operation-specific certified profile as Go, including explicit failures and alignment/overwrite constraints |

Read the frozen configuration implementation and [configuration contract](p04/configuration.md) before fixing the parity ledger: current README passages and implementation-era documentation need not have identical freshness. Do not omit file loading just because an older summary says it is absent. Similarly, inventory actual auth negotiation and dependencies; do not infer the supported method set from the `cephx` package name alone.

Inherit the Go limitations unless changed by an explicit design decision and new tests: no RBD, CephFS, RGW/S3, client-side EC, multi-object transactions, new caching semantics, unsupported CRUSH profiles, old messenger revisions, automatic secure-to-CRC downgrade or implicit wire compression. No C ABI and no source compatibility with Rust librados FFI wrappers is required. A blocking Rust facade, Windows and runtime abstraction are deferred, not v1 prerequisites.

## 3. Reuse the Assembled Knowledge

### 3.1 Reuse Map

All links in this table point to existing assets. Their future Rust equivalents are deliverables, not already available commands.

| Existing Asset | Reuse Strategy | Required Adaptation |
| --- | --- | --- |
| [Protocol source index](p00/protocol-sources.md), phase tasks and handoffs | Read exact Ceph/Go symbols and recorded decisions before each task | Add Rust symbols and evidence links; preserve source revisions |
| [Fixture policy](../testdata/README.md), [manifest schema](../testdata/manifest.schema.json), P01-P05 fixtures | Consume original bytes, expected values, source hashes and synthetic-secret provenance | Rust loaders with checked bounds; no fixture regeneration merely to match Rust output |
| [Encoding](../internal/encoding/codec.go), [wire types](../internal/protocol/address.go), adjacent tests | Reference semantic contracts and edge cases | Explicit Rust byte parsing; do not expose wire structs as public API |
| [Messenger framing](../internal/msgr/frame.go), [secure framing](../internal/msgr/secure.go), [session core](../internal/msgr/session.go) | Reuse transcripts, frame vectors and transition tests | Tokio I/O/task ownership, cancellation-safe writes and request registration |
| [Authentication](../internal/cephx/core.go), [connector](../internal/cephx/connector.go), [service connector](../internal/cephx/service_connector.go) | Reuse challenge/ticket/authorizer vectors and live denial/renewal cases | Audited Rust crypto and credential lifetime design |
| [Map placement](../internal/maps/placement.go), [CRUSH](../internal/crush/place.go), [integer logarithm](../internal/crush/ln.go) | Reuse whole object-to-primary corpus, not just CRUSH outputs | Exact wrapping arithmetic, widths, signed comparisons and integer math |
| [Mutation ownership/flush](../internal/objecter/mutation.go), [routing engine](../internal/objecter/client.go) | Preserve request identity, retained payloads, ambiguity and watermark invariants | Owned request records that outlive dropped Rust futures |
| [OSD operations](../internal/osd/messages.go) and adjacent metadata/lock/watch modules | Reuse opcode/result semantics, compound payloads and tests | Typed consuming builders and byte-preserving Rust identities |
| [Integration infrastructure](../integration/README.md), P03-P11 runners/probes/native drivers | Keep cluster topology, safety checks, native environment and scenario meaning | Add a Rust probe adapter per phase; retain Go path and reports |
| [P12 qualification contract](../internal/p12qualcontract/contract.go), [qualifier](../tools/p12-qualify/main.go) | Copy the evidence discipline and fixed-gate model | Rust-specific command, target, dependency and artifact contract; not string replacement |
| [P12 endurance runner](../integration/p12/reproduce.sh), [report schema](../integration/p12/report.schema.json) | Reuse scenarios, renewal/churn requirements and benchmark shape | Rust candidate/report namespace and worker/process invocation |
| [Review contract](p12/human-review.md), [signature verifier](../tools/p12-verify/review_signature_test.go) | Reuse role separation, exact-candidate binding and negative tests | Fresh Rust approvals and artifact hashes; never reuse Go signatures |

P01-P05 binary fixtures are the primary cross-language starting point. Go fuzz corpora contain Go-specific serialization in some cases: decode their container format into typed cases or raw payloads, preserve origin hashes, and retain their regression intent. Do not feed an encoded Go fuzz-file header to a Rust wire decoder and call it parity coverage.

Keep fixture generators and native helpers in their existing languages. Rewriting a working oracle in Rust adds common-mode failure risk without improving the shipped library. Go-based schema/provenance validators may remain host tools if their assumptions are explicit and Rust artifacts are bound correctly.

### 3.2 Harness Boundary

The current Makefile, shell runners and P12 contracts explicitly invoke Go probes and Go-specific source/dependency/toolchain checks. They do not already support a interchangeable Rust binary. R01 must establish the smallest adapter boundary, beginning with one fixture and one phase scenario, before extending it across the suite.

Prefer additive test-only adapters over a repository-wide harness rewrite. Select the client runner explicitly as `go`, `rust` or `native`; never silently fall back to Go when the Rust probe is missing. Where a native driver already has an operation format, retain it behind an adapter rather than changing its independent semantics.

Define a versioned, bounded JSON Lines contract for test-only requests/results and scenario events:

- Stable case ID, implementation ID, operation, opaque object identity, pool/namespace/locator/snapshot context and options.
- Base64 for arbitrary bytes; decimal strings for 64-bit IDs, offsets and versions where JSON tooling could lose precision. Define absent, null and empty separately.
- Canonical result classification, original signed wire result, sub-results, comparison offsets, object bytes/digests and timestamp precision.
- Local request correlation and fault-injection markers separate from protocol request IDs. No requirement that independent clients produce identical random nonces or transaction counters.
- Bounded records/output; bulk data may use hashed temporary artifacts. Secrets arrive through protected files/descriptors or the existing scoped credential mechanism, never logged JSON, command arguments or committed reports.

Use persistent probes for sessions, watches and concurrency; one process per operation cannot test those contracts. The controller owns pool creation/cleanup and permits only validated disposable-cluster FSIDs. Run Go and Rust over equivalent isolated object histories, plus intentional mixed-client cases; sequential execution against the same already-mutated object is not a valid general comparison.

Go's `internal` package boundary matters: a Go reference helper importing private codecs must live under the Go module, for example a test-only helper under `tools/`. An external Rust process cannot import those packages. Keep helpers out of production library dependencies, and ensure `cargo test` for ordinary Rust unit tests does not require Go, Docker or Ceph.

### 3.3 Evidence Hierarchy

For every claim identify whether evidence is a synthetic unit test, Go differential result, upstream/native vector, or live Ceph observation. Go/Rust agreement alone is insufficient for security, placement or mutation replay.

If sources disagree, record a minimal reproducer and resolve against the pinned Ceph implementation and observed behavior. Do not silently adopt a Go defect or opportunistically fix Go in the Rust task. Record an explicit Rust adaptation/correction and a separate Go issue when necessary.

Reports must bind the Rust source and build features, lockfile, compiler/target, Go oracle snapshot, Ceph image, fixture hashes, controller/driver hashes, actual commands, timestamps, exit codes and output hashes. Use separate Rust report paths; never overwrite P03-P12 Go evidence or relax existing Go verifiers to make Rust pass. Schema-valid is not synonymous with passed. Missing infrastructure is blocked or failed, never fabricated success.

## 4. Rust Architecture

### 4.1 Repository and Crate Layout

Use a separate private Git repository, provisionally `rust-librados`, with its own root Cargo workspace, CI, dependency policy and release history. Do not use a long-lived Rust branch or a `rust/` workspace inside the Go repository. Use ordinary short-lived task/phase branches within the Rust repository. R00 establishes this repository boundary and its evidence-import contract before R01 scaffolds Cargo. Do not create or publish a repository or crate as part of writing this spec. R00 selects an available package name; use `rados` as the conceptual library import name, not a claim that a registry name is available.

The Rust repository owns `src/`, `tests/`, `testdata/`, `integration/`, `tools/`, `docs/` and `reference/`. Record the pinned Go snapshot in `reference/go-baseline.json` and each imported asset's original repository, commit or archive digest, path, content hash, local destination and license/provenance. Copy selected language-neutral fixtures and native drivers unchanged; adapt runners and translate language-specific probes/checks only when needed. Retain useful Go generators/reference helpers in a pinned Go checkout rather than rewriting independent oracles in Rust. Never import historical Go passes or approvals as Rust qualification evidence.

No submodule or third shared-conformance repository is required initially. A sibling Go checkout is a development convenience, not a build or test path contract. Opt-in differential CI fetches the exact Go snapshot into a temporary checkout; ordinary Rust unit tests consume local fixtures without Go or network access. When transferring this spec, rewrite Go-source links to pinned upstream URLs or provenance-tracked local imports so they do not depend on a sibling checkout.

Import only the reviewed evidence needed for the next phases. Keep imported fixtures separate from Rust-specific cases, with explicit update PRs showing upstream changes, provenance and conformance results for both implementations where applicable. Never auto-refresh from moving Go HEAD. Consider extracting shared conformance infrastructure only after both clients use a proven stable runner contract.

Initially one production crate is sufficient. Use private modules `encoding`, `protocol`, `msgr`, `auth`, `maps`, `crush`, `mon`, `osd`, `objecter` and `mgr`, with public API modules organized by operation family. Match the actual Go `internal/osd` and objecter boundaries instead of the older speculative package layout in the original spec. Separate pure codec/placement functions from I/O so they can be fuzzed without a runtime.

Add a test-only conformance/probe binary and tooling crate only when R01 needs them. Keep them out of the published library package. Add a pinned `rust-toolchain.toml`, lockfile, feature/dependency policy and package include list during scaffolding. Do not create empty modules for all phases at once. The separate repository must preserve imported notices, fixture provenance and pinned references from its first evidence import.

### 4.2 Runtime and Ownership

- Tokio is the sole initial async runtime. Applications own the runtime; library construction starts no hidden runtime and performs no network I/O. Connecting requires an active runtime and returns typed errors on invalid setup.
- Use an `Arc`-backed client handle and immutable pool/object views. Clone handles cheaply; do not hold mutex guards across `.await`. Prefer a small explicit session/request supervisor over tasks with unclear ownership.
- One reader and one serialized writer per connection own framing state, secure sequence counters and stream progress. Every worker is tracked and receives shutdown signals. No unbounded detached per-request tasks.
- Bound admission by both request count and retained bytes. Acquire owned permits before retaining payloads and keep them until request state is terminal. Bound waiting submissions as well as the writer queue; a bounded channel alone does not bound copied payloads in blocked senders.
- Use owned immutable payloads, such as `bytes::Bytes`, for queued/replayable operations. Borrowed convenience methods copy into owned memory at admission. Never extend a borrow with unsafe code to satisfy a spawned task's `'static` requirement.
- Publish immutable map snapshots via `Arc` plus a short lock; add a specialized atomic snapshot crate only after measurement. Keep old snapshots valid while requests reference them and bound retained history.
- Application callbacks do not run in the connection reader. Expose watches as bounded event receivers with explicit acknowledgment and terminal error/loss reporting. Avoid `Arc` cycles between clients, watches and worker tasks.

### 4.3 Dependency Policy

Prefer standard Rust for collections, checked arithmetic, ownership, I/O-independent logic and error sources. Adopt maintained crates for established mechanisms, not Ceph-specific algorithms:

| Need | Initial Choice/Policy |
| --- | --- |
| Async networking, timers, bounded channels | `tokio` with only required features; `tokio-util` cancellation/task support if useful |
| Owned packet buffers | `bytes`; measure before adding buffer pools |
| Error implementation | Concrete public errors, optionally `thiserror`; no public `anyhow::Error` contract |
| AES-GCM, CephX AES modes, HMAC/hash/KDF | Compatible maintained RustCrypto crates such as `aes`, `aes-gcm`, `cbc`, `hmac`, `sha2`, and `cipher`, selecting only primitives the pinned implementation actually uses |
| Credentials and secrets | `zeroize` and optionally `secrecy`; redacted `Debug`, no unbounded secret copies |
| Secure randomness | Maintained OS-backed `getrandom`/`rand_core` integration; never deterministic production RNG |
| CRC and object checksum variants | Maintained Rust implementations with explicit polynomial, seed and finalization vector tests |
| Test reports and configuration tooling | `serde`/`serde_json`, `base64` as needed; not as Ceph binary wire encoding |
| Diagnostics | Optional `tracing` events with no installed global subscriber or exporter |
| Tests | `proptest`, `cargo-fuzz`, `loom` and Miri where appropriate, dev/tooling only |

These are selection candidates, not verified version pins. R00/R01 audit compatible releases, MSRV, license, feature graph, maintenance and transitive dependencies. Port required authentication mechanisms from actual source evidence; any extra method needing a maintained Rust implementation is a separately gated dependency decision, not a silent reduction to CephX-only parity.

No OpenSSL/native TLS backend, librados-sys, Go FFI or runtime dynamic loading in the shipped path. Messenger secure mode is not TLS; Rustls is not a replacement for it. OS calls through Rust's standard library/runtime dependencies and audited Rust intrinsics are permitted; do not define "native Rust" as banning the platform C ABI itself. Reject C/C++-compiled protocol/crypto dependencies. Review build scripts, target-specific and unified Cargo features, not only package names or `links` metadata. Separate test-only native drivers from this audit.

Set `#![forbid(unsafe_code)]` for project-owned production Rust code. Audited third-party unsafe code and standard runtime internals are allowed with a recorded policy. Do not weaken this rule to translate Go buffer tricks. Never implement cryptographic primitives by hand; even use of audited primitives still requires protocol-level review.

## 5. Public API and Semantic Contracts

R02 freezes signatures in compilable examples before building high-level features. Prefer `Client`, `Config`, `Pool`, `ObjectRef`, `ReadOp`, `WriteOp`, `OperationOptions`, `ObjectInfo`, `OpResult`, `Watch` and a structured error type. Constructors/builders validate locally; network methods return `Future<Output = Result<...>>` through `async fn`.

Use byte-preserving object/namespace/locator/key types, not mandatory UTF-8 `String`. Provide convenient validated conversions from strings and byte slices. Keep filesystem paths as `Path`/`PathBuf`, sizes/offsets and wire IDs explicitly sized, wire times at their original precision and host conversions fallible. Use checked arithmetic for lengths/allocations and explicit wrapping arithmetic only where CRUSH/protocol math requires it. Never use floating-point replacements for CRUSH integer approximations or generic consistent hashing for placement.

Consume operation builders on submission. Return versions and per-sub-operation results with the request; no shared "last version" field. Preserve positive class results, comparison mismatch offsets, partial notify results and signed wire errno values. A Ceph/Linux wire errno is not a Darwin `io::Error::from_raw_os_error` value; map explicitly. Preserve compound operations as one server-side request and expose unsupported operations rather than client-side non-atomic emulation.

### 5.1 Cancellation Is a Port-Critical Contract

Go call cancellation returns an error; Rust callers can destroy a future without observing any result. A naive use of `tokio::select!`, `timeout`, or task abortion can lose request ownership, strand a flush watermark or interrupt a frame midway.

Required design:

1. A future not yet polled has no side effects. Before admission, cancellation leaves no registered request, retained payload or submitted mutation.
2. Admission atomically registers an owned request, local mutation sequence, wire identity, resource permits and completion bookkeeping. Requests remain supervised independently of the caller's response receiver.
3. Cancellation of admitted but provably unsent work removes it from dispatch and completes its accounting. If transmission races with cancellation, classify conservatively as potentially submitted.
4. Once any relevant mutation transmission may have occurred, cancellation cannot promise rollback. An explicit cancellation/deadline API returns outcome unknown when no definitive OSD result is available, preserving the cancellation cause. Dropping a future has no result channel: document this fact and preserve ambiguity/completion in internal state and the flush/shutdown outcome.
5. The writer either finishes the frame with owned buffers or closes the connection and enters recovery. Do not cancel `write_all` midway and then reuse the stream for a new frame. Reader cancellation likewise preserves parse progress or discards the connection. Session tasks must not be aborted per caller request.
6. A dropped caller cannot strand permits, transaction registrations, mutation watermarks or retained keys/buffers. Terminal transitions execute once, including panics/task failure in the supervised worker boundary.
7. Retry/reconnect/remap preserve Ceph identity and deduplication limits. Never issue a fresh request identity to hide an ambiguous append, class call or concurrent write. Messenger ACK is not OSD commit. No exactly-once promise across arbitrary failures.

Expose an explicit cancellation token/deadline in operation options for callers that need an observed outcome. Deadlines use a monotonic clock and include admission, resolution, reconnect and retry work; do not restart the timeout each attempt. External `tokio::time::timeout` drops the future and therefore follows the dropped-future contract. Rustdoc and a compiled example must make the distinction clear.

Model the race points between admission, dispatch, first transmitted bytes, ACK, OSD reply, cancellation and completion. Port the tests around [Go mutation admission and flush](../internal/objecter/mutation.go), and add Rust-only tests that repeatedly poll/drop futures at each boundary. Validate the dispatch/replay rules against [messenger transport](../internal/msgr/transport.go) and [OSD sessions](../internal/objecter/osd_session.go), not the wrapper alone.

### 5.2 Close, Flush and Shared Handles

`flush(options).await` captures an admission watermark and waits for relevant earlier mutations. It cannot silently report success over a retained unknown outcome. Preserve the frozen Go contract for definitive operation failures versus unknown outcomes; a flush is not necessarily an aggregate result for every failed call, and that distinction needs conformance tests.

`close()` is idempotent, nonblocking and initiates termination of the shared client for all clones. `shutdown(options).await` stops admission, drains to a defined watermark within its deadline, then stops and joins workers and reports errors/ambiguity. Repeated or concurrent shutdown calls must be bounded and consistent.

Dropping one clone does not close other handles. Last-owner drop performs best-effort cancellation only, never network I/O, blocking or async flush. Design worker ownership so background tasks cannot keep the public owner alive forever. Only explicit successful async shutdown guarantees drained work and observed worker termination. Dropping the runtime cannot guarantee completed writes and must be documented.

Watches require explicit asynchronous unregister/drain for deterministic cleanup; `Drop` is only best effort. Slow receivers, missed notifications and re-registration errors are surfaced. Locks preserve Ceph owner/cookie/renewal semantics and do not claim fencing against unrelated writes.

## 6. Verification and Release Contract

### 6.1 Three-Way Conformance

Use Rust versus frozen Go versus native Ceph for every supported family. At wire level compare deterministic encodings and authenticated synthetic transcripts. At behavior level compare object state, error class/wire code, atomicity, versions within the same history and operation results; normalize only justified nondeterminism such as independently allocated IDs or timestamps.

Required mixed-client histories include Go-write/Rust-read and reverse, native-write/Rust-read and reverse, native/Go/Rust conditional-write contention, cross-language locks/notifications, and snapshot reads after another client's mutations. Placement requires zero mismatches across original P05 corpora plus qualified later fixtures, including full/incremental maps, CRUSH choices and effective primary/shard overrides.

Port negative tests, not just happy paths: corrupt/truncated frames, allocation attacks, forbidden downgrade, nonce rollover, renewal/reclaim, stale maps, denied caps, partial writes, lost mutation replies, backoff, blocklisting, EC rejection, dropped futures, full queues and shared-handle shutdown. Timing assertions use deterministic clocks where possible and a bounded tolerant live protocol, not sleeps guessed from a laptop.

### 6.2 Tool Gates

R01 implements exact commands in the separate repository's Rust CI targets. The following are intended Cargo gates run from that repository's root once its `Cargo.toml` exists, not commands already available in this Go repository:

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo test --workspace --release --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo doc --no-deps --locked
```

Also require tests at the pinned MSRV and latest selected stable, rustdoc examples, feature combinations, default/no-default feature builds as applicable, warning-free docs, `cargo audit`/`cargo deny` with pinned tools/policy, and `cargo metadata`/`cargo tree -e features` dependency review. Define supported feature sets explicitly; do not assume an all-features build is a sufficient matrix. Async runtime support is a core requirement, not a misleading optional feature.

Use targeted Loom models for admission/completion/close races, Miri for pure parser/ownership tests that support it, and `cargo-fuzz` for parsers, framing and scripted transitions. These tools supplement real concurrency/cluster tests, not a claim that the type system or Loom proves the whole client race-free. Dev-only fuzz/sanitizer toolchains may use native instrumentation without relaxing the shipped library requirement.

Run affected fuzz targets for at least 60 seconds during task validation and a fixed certifying campaign of at least 10 minutes per enumerated target before the release candidate. Bind target list, corpus, budget, compiler and output to source hashes; an interrupted campaign is failed evidence. Pin nightly separately where fuzz/Miri require it and do not raise production MSRV to match test tooling.

Initially build and execute on Linux x86_64/aarch64 and macOS x86_64/aarch64. Compile on appropriate native CI runners to avoid assuming Apple SDK or cross-linker availability. Record emulation explicitly. Build success is not runtime certification. Inspect final example/probe linkage and execute representative clients in environments without Go or Ceph client libraries installed; ordinary OS libraries are allowed. The Ceph server image containing librados is not by itself proof of library independence.

### 6.3 Qualification and Packaging

Reuse the P12 fixed-matrix approach with Rust-specific contracts. Do not call `make qualify-p12` and label its Go checks a Rust pass, change Go source hashes to Rust hashes in an old report, or copy Go review approvals.

R08 records Rust/Go/native performance on the same cluster and transport modes; preserve the existing workload shape and benchmark operation semantics. Record payload size, concurrency, throughput, latency percentiles, CPU, allocations/retained bytes and resident memory. Ratify numeric budgets from these measurements before R13. No claimed speedup or parity without measurements; no optimization that weakens protocol or completion guarantees.

Before Rust v1: all parity-ledger requirements and certified profile tests pass; zero known unresolved critical/high security or data-integrity findings; bounded-resource and failure tests pass; a reproducible 24-hour soak covers renewal, reconnection, map churn and mixed-client I/O. Smoke/quick runs remain non-certifying. Missing a runtime or review is a blocked release gate, not an allowed skip.

Use a separate immutable Rust candidate, report schemas, source/artifact hashes and accountable approvals for security, distributed systems, license/notices and release ownership, following [the existing review model](p12/human-review.md). Review signatures bind the exact Rust candidate; private signing keys remain external to tooling and the LLM. Candidate production must not depend on a signature over itself, and reports must avoid self-referential hash cycles.

Package verification includes the actual Cargo package contents, dependency/license notices, examples/docs, checksums and reproducibility for a fixed toolchain/target. Tests or includes must not depend on unpublished fixture paths or a sibling Go checkout after packaging: keep repository-only fixture suites in test tooling, or include the specifically reviewed subset required for package tests. `cargo package` verification runs from the packaged source, not just the Rust working tree. Publishing/tagging requires separate user approval.

### 6.4 Licensing

The project currently declares LGPL-2.1-only in [its license](../LICENSE) and [dependency audit](p12/dependencies.md). The Rust port is expected to adapt Go code and upstream-derived implementations, not constitute a clean-room rewrite. Preserve applicable notices and per-file provenance; do not relabel it MIT/Apache merely because that is common for Rust crates.

R00 and the release review must address LGPL obligations for Rust distribution, including static linking, modified library source, relinking/replacement mechanisms and any dependency-specific terms. An `rlib` label or publication of source alone is not evidence that every consumer's distribution complies. Obtain accountable license review before distribution and explain consumer obligations without claiming legal certification. Any desired license change requires rights-holder approval outside the port task.

## 7. Phased LLM Implementation

Phases are milestones, not one-shot prompts. Each numbered item is split into tasks owning one codec, transition, operation or bounded tooling change. Preserve the Go implementation and its test expectations; do not run destructive integration tests during spec writing or as an implicit unit-test dependency.

### R00: Freeze Knowledge and Scope

Dependencies: none.

1. Record the separate-private-repository decision from Section 4.1 in an architecture decision record, including owner/name, default branch, independent CI/releases and short-lived task branches. Establish the Rust repository under explicit repository-creation/publication authorization; do not use a long-lived Go branch, monorepo workspace or submodule. Transfer this spec with resolved source links, preserving the Go repository and its existing work.
2. Select the immutable completed Go snapshot, validate Ceph/image pins, and record Rust toolchain/MSRV, target and package-name decisions in the baseline manifest.
3. Define the asset import/update manifest and the copy/adapt/translate/retain disposition for fixtures, native drivers, runners, Go generators and probes. Import the minimal reviewed evidence bundle for R00-R02 with notices and verified hashes. Specify temporary pinned Go checkouts for differential CI, no sibling-path dependency for ordinary Rust tests, and reviewable future import PRs; leave a third shared repository deferred.
4. Produce the semantic Go/native/Rust mapping ledger and source/fixture index; resolve stale documentation against source/tests and record supported authentication/configuration behavior.
5. Review dependency feasibility, LGPL port/distribution policy and test cluster prerequisites; record missing access rather than constructing fake evidence.

Exit gate: the separate private Rust repository and recorded repository decision exist, the pinned Go baseline and initial asset imports have reproducible provenance/hashes, and the import/update and differential-checkout contracts require no sibling layout or submodule. Missing repository authorization/access blocks this gate rather than causing an in-tree fallback. Every implemented public behavior has a Rust disposition, and protocol/licensing/dependency unknowns have explicit owners and blockers. No broad "v20+" certification is inferred.

### R01: Rust Workspace and Evidence Bridge

Dependencies: R00.

1. Add the minimal root Cargo workspace in the R00 Rust repository, MSRV/toolchain/lockfile, no-unsafe policy, initial CI and test-only probe boundaries.
2. Load an existing P01 fixture without changing it; validate its provenance with reused tooling and independently compare its decoded fields with the Go/native expectation.
3. Specify/implement the bounded probe protocol and controller adapter with an explicit Rust runner; add Rust report schema and positive/negative verifier tests for stale hashes, missing probes and wrong implementation IDs.

Exit gate: ordinary Cargo tests run without Go/Ceph installed; the opt-in bridge round-trips a real existing test case; missing Rust execution fails rather than invoking Go. Existing Go unit/tooling tests remain unchanged and passing for touched shared tooling.

### R02: API Contracts and Bounded Wire Types

Dependencies: R01.

1. Freeze public byte identities, errors, options, result/ownership types and lifecycle signatures with compiled examples and docs.
2. Port primitives, versioned envelopes, addresses, features, signed wire errors and CRC handling, one family per task.
3. Port P01 vectors, fuzz regressions and malformed/limit tests in debug and release profiles.

Exit gate: exact fixture bytes/decoded values match; allocation/overflow/truncation tests pass; public errors preserve wire values independent of host OS. No network code is needed to validate this phase.

### R03: Messenger Codecs and Session State Machine

Dependencies: R02.

1. Port banner/control/message and v2.1 CRC frame codecs, then secure framing using synthetic secrets and original P02 upstream vectors.
2. Port explicit session states, sequence/ACK/reset/reconnect rules and transcript inputs as testable transition logic.
3. Add bounded Tokio reader/writer supervision, admission and fault-script transport; test fragmented frames and drop/cancel during partial I/O.

Exit gate: Go/native-derived deterministic transcripts match, invalid secure data is never dispatched, and cancellation cannot desynchronize a reused stream. All session/frame fuzz smoke tests pass; this phase does not yet claim live authentication.

### R04: Authentication and Live Secure Session

Dependencies: R03.

1. Port credential/keyring parsing primitives and each negotiated auth mechanism in the frozen scope, CephX challenge/ticket/authorizer handling first.
2. Integrate transcript checks, connection secrets, secure mode and service authorization; port P03 vectors without changing expected outputs.
3. Run the adapted P03 live probe for credentials, downgrade rejection, ticket expiry/renewal, identity reclaim and reconnection.

Exit gate: Rust authenticates to the pinned monitor in secure v2.1; Go/native auth vectors and denial/renewal cases pass. Crypto/transcript dependency and code review resolves any unverified construction before object I/O work.

### R05: Monitor, Configuration and Maps

Dependencies: R04.

1. Port public supported config/file/environment/argument behavior with frozen precedence and byte/path semantics; add tests for documented exclusions.
2. Port monitor bootstrap, DNS/address bounds, FSID enforcement, subscriptions and failover.
3. Port monmap/full/incremental OSDMap/pool data and manager map types, with immutable publication and bounded history; consume P04 fixtures.

Exit gate: Rust lists the expected pools, observes map updates and survives monitor loss; full/incremental decoding converges and wrong FSIDs fail. Config parity is tested against the actual frozen Go implementation.

### R06: Exact Placement

Dependencies: R05.

1. Port object/namespace/locator hashing and PG mapping, explicitly preserving integer wrap and sentinel behavior.
2. Port supported CRUSH algorithms/tunables/choose arguments and integer approximations incrementally.
3. Port temp/upmap/primary/shard overrides and unsupported-profile rejection; consume P05 and later placement corpora through the differential bridge.

Exit gate: zero full object-to-PG/acting-primary/shard mismatches in Rust/Go/native cases across the certified maps and transitions. No generic hashing replacement or float approximation is accepted.

### R07: Read-Only Object Client

Dependencies: R06.

1. Port OSD service session integration, request/reply codecs and correlation, with bounded owned request state.
2. Expose stat/version and ranged reads through immutable object views; handle missing/empty objects, binary identities and limits.
3. Port read remap/redirect/backoff/deadline behavior and the P06 fault scenarios; verify dropped callers free resources without disrupting other calls.

Exit gate: Rust reads Go/native-written objects and matches results/errors in the live pinned cluster. Read recovery and shutdown are bounded; no mutation retry logic is assumed proven by read tests.

### R08: Mutations and Async Cancellation Correctness

Dependencies: R07.

1. Port create/write/write-full/append/truncate/zero/remove individually, preserving request identity and OSD completion flags.
2. Implement admitted-request ownership, explicit cancellation/deadlines, dropped-future behavior, unknown outcomes, flush watermarks and close/shutdown.
3. Port P07 lost-reply/remap cases, add Loom models and poll/drop tests at every admission/send/completion boundary, then collect the first Rust/Go/native performance baseline.

Exit gate: cross-client CRUD matches, append is not duplicated by retry, no dropped future strands a watermark/permit, and ACK cannot masquerade as commit. Human distributed-systems review of cancellation/replay invariants is required before broadening writes.

### R09: Metadata, Atomic Builders and Enumeration

Dependencies: R08.

1. Port xattrs and OMAP data/header/range operations with binary keys, ordering, limits and partial results.
2. Add consuming compound builders, comparisons/assertions and flags with server-side atomicity and per-sub-operation results.
3. Port namespace/object listing and cursors, then adapt P08 cross-client contention and iteration cases.

Exit gate: native/Go/Rust conditional updates and compound-failure atomicity pass; metadata and cursor behavior match the frozen profile under supported mutation/map-change scenarios.

### R10: Classes, Locks and Watches

Dependencies: R09.

1. Port generic class execution/results and conservative retry classification, then lock encodings and lifecycle.
2. Implement bounded watch receiver, explicit notify acknowledgment, partial timeout results, status and re-registration.
3. Adapt P09 scenarios to persistent Rust probes; add dropped receiver, queue overflow, lease expiry and explicit unregister/drain tests.

Exit gate: native/Go/Rust lock and notification interoperability passes during remap/restart; loss is observable and no worker survives successful shutdown. No automatic retry of unknown class mutations or implicit lock fencing is introduced.

### R11: Snapshots, EC and Specialized Operations

Dependencies: R10.

1. Port named and self-managed snapshot metadata/contexts, reads, rollback and removal with validated ordering/sequence rules.
2. Qualify the inherited EC profile and per-operation restrictions; add snapshot/EC negative cases independently from replicated I/O.
3. Port remaining specialized operations from the mapping ledger, including checksum, sparse/extent, writesame, hints, copy/clone and applicable inconsistency behaviors.

Exit gate: P10-equivalent histories match Go/native, including rejected operations; every specialized operation has a reference case. No silent fragmentation or client-side emulation changes atomicity.

### R12: Administration and Parity Closure

Dependencies: R11.

1. Port manager sessions/failover and command transports for each target, retaining structured outputs and method-specific error behavior.
2. Port stats, pool/application operations, addresses/blocklisting and remaining inventoried administrative queries; adapt P11 scenarios.
3. Close every mapping-ledger row and compile migration/examples for all public families. Record deliberate Rust language adaptations and inherited unsupported cases.

Exit gate: all target Go/native behaviors have passing Rust evidence or an explicitly approved scope revision; ordinary I/O works with least privilege and does not depend on a healthy manager. Destructive tests stay scoped to disposable resources.

### R13: Rust Production Qualification

Dependencies: R12.

1. Complete the Rust fixed feature/toolchain/runtime matrix, fuzz campaign, dependency/linkage/license checks and packaged-source verification.
2. Run adapted endurance, churn and fault suites for 24 hours, compare against approved R08 performance/resource budgets and fix findings in their owning modules.
3. Produce an immutable Rust candidate, signed accountable reviews, compatibility/migration documentation, notices and reproducible artifacts. Publish only with separate authorization.

Exit gate: all Rust gates in Section 6 pass for the exact candidate, with fresh Rust-specific signatures. Go approvals, quick runs, skipped platforms and stale reports cannot satisfy this gate.

### R14: Maintain Both Implementations

Dependencies: R13.

1. Track Go/Ceph changes by semantic ID, source diff, fixture provenance and versioned bridge contract; triage protocol fixes for both clients.
2. Add future Ceph releases, CRUSH profiles, optional features or a blocking Rust facade through separate scoped decisions and independent conformance cases.
3. Re-run previously supported profiles and newly claimed/mixed-version upgrade scenarios before extending the published matrix.

Exit gate: each new claim has Rust/Go/native evidence as applicable and old-profile regression coverage. Neither implementation becomes a moving, unpinned oracle for the other.

## 8. Per-Task LLM Contract

Use a task packet like this, storing completed evidence and handoffs outside the protocol code:

```text
Task: Rxx-Tyy
Behavior: one codec, operation, transition or harness adapter
Dependencies: completed task IDs; required toolchain/cluster access
Reference: frozen Go snapshot, Go symbols/tests, Ceph symbols/revision
Fixtures: IDs, provenance, expected bytes/results; no new guessed oracle
Scope: allowed Rust files and explicitly allowed shared-tooling changes
Rust contract: ownership, Send/Sync, admission, cancel/drop, errors, resource limits
Hypothesis: one falsifiable local behavior
First check: exact smallest failing test or independent fixture comparison
Deliverables: implementation, regression tests, ledger and task-note updates
Acceptance: focused Cargo test; differential/fuzz/live gates where applicable
Stop conditions: ambiguous wire contract, missing reference, license/review blocker
Handoff: changes, actual commands/results, evidence hashes, unresolved risks
```

Execution rules:

1. Start at the Go code that decides the behavior and its test, then the relevant Ceph/fixture anchor. Avoid remapping the entire repository in each session.
2. Translate invariants into a failing Rust test before implementation; ordinary codec round trips are not independent evidence. Run the narrow check immediately after the first behavioral edit.
3. Keep tasks small enough for one reviewable result. Split a phase at each codec family, request transition and API operation; do not ask an LLM to port a whole messenger or objecter in one prompt.
4. Never alter expected fixtures, replay rules, source hashes, feature advertisements or report pass flags merely to get green output. Minimize a discrepancy and resolve it against the frozen references.
5. Do not port Go's concurrency syntax literally. Every spawned task needs an owner and shutdown rule; every `.await` needs a cancellation/lock/payload-lifetime argument where it can affect request state.
6. No production placeholders that report success, guessed enum discriminants, FFI fallback, unrestricted `unsafe`, or detached error-swallowing task. Do not use `unwrap`/`expect` on untrusted input or ordinary failure paths.
7. Keep Go production changes out of scope. Shared harness edits require regression tests preserving Go behavior and additive Rust evidence paths. User changes and untracked phase artifacts are not disposable.
8. Report tests actually executed and identify synthetic versus live evidence. Tool, cluster or review absence is an explicit blocker. Never claim a human review or create a signing identity on a reviewer's behalf.
9. Freeze fixture/probe/public-type contracts before parallel work. Independent codec readers or operation families may be delegated when authorized; session/auth/replay changes with shared state require serialized integration and review.
10. End each task with the ledger updated, source/evidence links, a concise handoff and the next unblocked task. Re-estimate after R04 live auth, R08 cancellation/replay proof and R12 parity closure, not by wrapper count.

## 9. Completion Definition

The Rust port is functionally complete when the frozen Go/native mapping ledger is closed with independent tests and all deliberate language adaptations are documented. It is release-qualified only after R13's Rust-specific candidate, runtime, soak, fuzz, package and accountable review gates pass.

The main advantage of this project is its assembled knowledge: known encodings, exact placement fixtures, explicit error/replay decisions, working native drivers and strict evidence contracts. The main new risk is Rust async ownership and cancellation. Spend implementation effort on that distinction and on independent conformance, rather than rebuilding Ceph discovery tooling or copying the Go release reports.