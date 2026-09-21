# R13 Performance

Status: **budget is landed; no certifying benchmark evidence exists yet**.
The performance surface for R13 is a conservative floor derived from R08's
mutation qualification evidence, not a parity or speedup claim. Passing the
R13 gate records that Rust stays within the R08-derived budget against a
native librados baseline on the pinned matrix.

## Non-goals

R13 makes **no** claim about:

- Rust performance parity with native librados.
- Any Rust throughput or latency speedup versus the frozen Go
  `github.com/otuschhoff/go-librados` P12 client.
- Absolute IOPS, throughput, or tail-latency numbers on user hardware.
- Behaviour outside the pinned 3-OSD replicated `r13-data` profile with
  `size=2 min_size=1 pg_num=16`, 900 s auth ticket TTL, and the secure/CRC
  transport pair.

The Rust R13 benchmark is a **budget floor**, not a headline number. It is
intentionally loose enough to survive real-world OS scheduling jitter and
tight enough to catch regressions of practical concern.

## Benchmark matrix

Source of truth: [`BENCH_SIZES`, `BENCH_CONCURRENCIES`, `BENCH_WORKLOADS`,
`BENCH_ROWS_PER_RUN`, `BENCH_RUNS_PER_CANDIDATE`](../../tools/r13/src/constants.rs).

- Payload sizes: `4096`, `65536`, `1_048_576`, `4_194_304` bytes (4 KiB,
  64 KiB, 1 MiB, 4 MiB).
- Concurrencies: `1`, `16`, `64` parallel Tokio tasks.
- Workloads: `read`, `write`, `mixed`.
- Rows per run: `4 * 3 * 3 = 36`.
- Runs per certifying candidate: `4` — two transports (`secure`, `crc`) ×
  two implementations (`rust`, `native`).

Every certifying benchmark row is `2 * concurrency` operations. The
producer records `operations`, `bytes`, `elapsed_ns`,
`throughput_bytes_per_second`, `iops`, and `p50_ns / p95_ns / p99_ns`
latency samples per row.

## R08-derived budget

Frozen in
[`BENCH_MIN_NATIVE_THROUGHPUT_RATIO`, `BENCH_MAX_NATIVE_P99_RATIO`,
`BENCH_MAX_RSS_BYTES`, `BENCH_MAX_ALLOCATIONS`,
`BENCH_MAX_ALLOCATED_BYTES`](../../tools/r13/src/constants.rs). Enforced
per benchmark run by
[`tools/r13/src/budget.rs`](../../tools/r13/src/budget.rs).

| Constraint | Threshold | Rationale |
| --- | --- | --- |
| Rust / native throughput ratio (per row) | `>= 0.10` | Rust must sustain at least 10 % of the native baseline per row. Chosen from the R08 write-full baseline evidence in [`docs/r08/live-qualification-report.json`](../r08/live-qualification-report.json), which observed the Rust R08 client comfortably above this margin at 4 KiB payload. |
| Rust / native p99 latency ratio (per row) | `<= 8.0` | Rust p99 must stay within 8× the native baseline. Chosen conservatively to survive Tokio scheduler wakes on macOS runners. |
| Rust peak RSS (per run) | `<= 2 684 354 560` bytes (2.5 GiB) | Caps process memory including the runtime, Tokio, and the client working set. |
| Rust allocations (per run) | `<= 1 000 000` (native only; optional for Rust) | Enforced for the native implementation; the Rust implementation forbids `unsafe_code` so no custom `GlobalAlloc` can honestly report allocations. The `allocations` field is `null` for Rust. |
| Rust allocated bytes (per run) | `<= 42 949 672 960` bytes (40 GiB, native only; optional for Rust) | Same rationale as allocations. |

The verifier
[`budget::evaluate_budget`](../../tools/r13/src/budget.rs) enforces the
optional/required split honestly: when a `rust` row reports `allocations
= None`, the budget check is not enforced; when `native` reports `None`,
verification fails.

## Reference values from R08

The single reference performance evidence available to R13 today is the
R08 `performance` array in
[`docs/r08/live-qualification-report.json`](../r08/live-qualification-report.json).
That evidence covers one workload (`write-full-baseline-v1`) at a single
payload (`4096` bytes) and concurrency (`1`) for `128` operations. It is
sufficient to anchor the conservative budget floor but does not by itself
cover the full 4×3×3 matrix; R13 introduces the full matrix and the
paired Rust/native producers to close that gap.

R13 has NOT re-run the R08 evidence. It uses R08's frozen numbers as the
anchor for the budget, which is why the throughput floor is 10 % and the
p99 headroom is 8×.

## Rust vs native implementation

- **Rust producer**: [`tools/r13/src/bin/rados-r13-bench.rs`](../../tools/r13/src/bin/rados-r13-bench.rs).
  Uses only the public `rados` crate types. Runs the 4×3×3 matrix per
  transport. Rejects `--implementation native`; the label is fixed to
  `rust`.
- **Native producer**: [`tools/r13/native-bench/bench.cpp`](../../tools/r13/native-bench/bench.cpp),
  compiled inside a Docker image parameterised by `--build-arg
  CEPH_IMAGE=<amd64|arm64 pin>`. The image reuses the pinned
  `librados-devel-20.2.4` and `libradospp-devel-20.2.4` RPMs used by the
  R08 native probe. Emits the same `benchmark_run` JSON shape with
  `implementation = "native"`.

Both producers write to the same schema
([`integration/r13/report.schema.json`](../../integration/r13/report.schema.json))
and are byte-compared per row by the strict R13 candidate verifier.

## Honesty caveats

- The Rust producer honestly reports `allocations` and `allocated_bytes`
  as `null`. It cannot pretend to know allocation counters without a
  custom `GlobalAlloc`, which would require the workspace-wide forbidden
  `unsafe_code`. This is *not* an artefact of the harness: any allocation
  reporter would need `unsafe`.
- Sample buckets are bounded by `CANDIDATE_PROBE_MAX_SAMPLES = 2000`
  (probe module) so long soaks do not silently allocate unbounded memory
  for telemetry. When the bound is reached the producer stops sampling
  and records `maximum_configured_sample_count`.
- `session_renewals` and `credential_renewals` are `null` in every probe
  observation. The public `rados` API does not expose completed renewal
  generation numbers; the R13 candidate verifier requires the null and a
  sentinel string
  (`RENEWAL_MEASUREMENT_SENTINEL`) in the probe report so the reader
  cannot mistake the omission for a zero-count observation.
- `inflight` sample counts are `null` for the same reason
  (`INFLIGHT_MEASUREMENT_SENTINEL`).

## Reproducing the benchmark

The Rust and native benchmarks run under the endurance reproducer, not
standalone:

```sh
# Full certifying benchmark matrix. Requires 24 h of host time, a
# reachable pinned Ceph amd64+arm64 image, and the pinned compiler image.
integration/r13/reproduce.sh
```

The reproducer cross-compiles the Rust probe/bench inside the pinned
compiler image, builds the native benchmark image with `--build-arg
CEPH_IMAGE=<pinned>`, and executes each of the four benchmark runs under
`docker run --platform <platform>`. The final report is written to
`integration/r13/report.json` only after `rados-r13-candidate --verify`
accepts every budget row and the release-artefact byte-compare succeeds.

The `--quick` variant is deliberately non-certifying: it does not run
the benchmarks, records an empty `benchmark.runs` array, and refuses to
be promoted into a candidate.
