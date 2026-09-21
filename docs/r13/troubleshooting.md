# R13 Troubleshooting

Status: **failure-mode reference for R13 producers and verifiers**. Every
mode below is reproducible from the checked-in source; no attempt is made
to guess at causes that are not diagnosed by an actual R13 verifier or
producer message.

If you hit a mode not listed here, prefer reading the strict error message
from the tool over guessing. The R13 verifiers report the exact rule that
failed.

## Environment

The producers require the pinned tool set from
[`dependencies.md`](dependencies.md#server-container-and-reproduction-dependencies):

- `docker` with a running daemon that can reach the pinned Ceph images.
- `jq`, `shasum`, `git`, `tar`, `gzip`, `cargo`, `sh` on `$PATH`.
- Rust `1.98.0` toolchain (`rust-toolchain.toml` selects it automatically
  when `rustup` is installed).
- Nightly `nightly-2026-09-01` + `cargo-fuzz 0.13.2` for the fuzz gate.

Offline checks (`--verify-shape`, `--check-inventory`,
`--print-source-digest`, `cargo test`) never require Docker or Ceph.

## Automated qualification (`integration/r13/qualify.sh`,
## `rados-r13-qualify`)

### `expected >=24 check ids, got N`

Cause: `rados-r13-qualify --print-checks` returned fewer than the 24
canonical check ids because the binary was not up to date. Rebuild with
`cargo build -p rados-r13-tools` and re-run.

### `docker probe failed for <platform>: ...`

Cause: the Docker daemon rejected `--platform` for one of the four
required native runtimes. On macOS hosts, `linux/amd64` requires
Rosetta; `linux/arm64` runs natively on Apple Silicon; `darwin/*`
platforms cannot be observed from a Linux host. The producer marks the
overall status as `failed` and emits the failure evidence at
`docs/r13/qualification-report.failed.json`. This is intentional. Do
**not** hand-edit the failed evidence into the pass path.

### `R13 qualify: no runtime available for darwin/<arch>`

Cause: neither the host nor Docker can provide the darwin runtime for one
of the two required platforms. There is no substitute; the R13 verifier
requires observations for every entry in `KNOWN_PLATFORMS`. Use a
darwin/amd64 host (native or Rosetta) plus a darwin/arm64 host (Apple
Silicon) to close the four-platform matrix.

### `inventory summary output malformed`

Cause: `rados-r13-qualify --check-inventory` failed to print the expected
`native_rows=... ledger_rows=...` summary. Re-run
`cargo run -p rados-r13-tools --bin rados-r13-qualify -- --check-inventory
--root .` directly to see the strict error message.

### `parity ledger has N rows, expected 905`

Cause: the parity ledger drifted from the frozen row count. This is a
contract violation; R13 refuses to run until it is resolved. Check the
row that was added or removed, and either revert or update the
`PARITY_LEDGER_ROWS` constant with matching ledger evidence.

### `parity ledger row N has unresolved status "..."`

Cause: a ledger row carries a status not on
[`LEDGER_ALLOWED_STATUSES`](../../tools/r13/src/constants.rs). Only the
allow-list statuses are legal; add the new disposition to the constant
only if a phase document supports it, and update the R13 documentation
accordingly.

## Fuzz (`integration/r13/validate-fuzz.sh`, `rados-r13-fuzz`)

### `cargo-fuzz version mismatch (need cargo-fuzz 0.13.2, saw ...)`

Cause: the host has a different `cargo-fuzz`. Install the pin with
`cargo install cargo-fuzz --version 0.13.2 --locked`.

### `R13 fuzz: source changed during campaign`

Cause: the source digest observed at the start of the campaign disagrees
with the digest at the end. Rerun with a clean tree; do not run fuzz over
a work-in-progress branch.

### `R13 fuzz: certifying campaign <target> ended with status <status>`

Cause: a certifying campaign was interrupted (`SIGINT`/`SIGTERM`, exit
130/143) or failed (non-zero exit). The report is recorded with the
observed status; the R13 verifier refuses to accept it as certifying.
Restart the failed campaign after fixing the underlying cause; do not
edit the report.

### `R13 fuzz: cargo-fuzz version mismatch` on macOS

Cause: `cargo fuzz` on macOS silently uses an older nightly if the pinned
one is not installed. Force `rustup toolchain install nightly-2026-09-01`
before invoking the validator.

### Corpus tree hash drift

Cause: libFuzzer wrote a new interesting input into the seed corpus. R13
prevents this by pointing libFuzzer at
`$temporary/work-corpus/<target>/` as its writable output while passing
`fuzz/corpus/<target>/` as a read-only secondary. If you invoked
`cargo fuzz run` directly against `fuzz/corpus/<target>/` without the
harness, the seed tree is now dirty. Restore from git.

## Endurance (`integration/r13/reproduce.sh`, `rados-r13-candidate`)

### `R13 requires docker` / `R13 requires a running Docker daemon`

Cause: the reproducer needs the daemon. Start Docker (or the
Rosetta-emulated daemon on macOS) and re-run.

### `R13 supports only amd64 and arm64 Docker daemons (got <arch>)`

Cause: only `linux/amd64` and `linux/arm64` are pinned. Cross-arch
emulation via `qemu-user-static` is possible in principle but not
supported by R13 constants; use a native host.

### `certifying churn must touch every OSD`

Cause: the churn loop did not restart every OSD before the probes
finished. Increase the probe duration or shorten the churn interval so
the round-robin covers all three OSDs. Do not edit the report to claim
otherwise.

### `R13 probe (<transport>) exited <code>; diagnostics under
### `docs/r13/failure-diagnostics/`

Cause: one of the two live probes returned non-zero. Container logs are
retained under `docs/r13/failure-diagnostics/probe-<transport>.log`. Read
the last frames for the underlying error (usually a mons transient or a
BlueStore initialisation failure) and re-run.

### `benchmark row <coord> throughput ratio < 0.10` /
### `p99 ratio > 8.0` /
### `peak RSS > 2.5 GiB`

Cause: the run breached the R08-derived budget. The verifier reports the
exact row coordinate. Investigate the offending platform/workload;
running a fresh benchmark is the only accepted resolution — hand-editing
`integration/r13/report.json` fails the strict verifier signature.

### `release artefact byte comparison failed`

Cause: two consecutive `rados-r13-release` runs produced non-identical
outputs. That is a determinism bug, not a transient. Report to the
release owner; do not paper over it. The verifier refuses the report.

## Detached review (`rados-r13-verify`)

### `automated tooling cannot approve human review`

Cause: someone (or an automated pipeline) tried to promote
`docs/r13/human-review.json` from `pending` to `approved` without four
detached signatures. The verifier is *designed* to refuse this.

### `pending review must not claim a candidate or reviews`

Cause: the pending human-review envelope was edited to reference a
candidate or add empty review records. Restore the canonical pending
document — the R13 verifier will not accept a partially populated pending
form.

### `unresolved reviewer role: <role>`

Cause: a role is missing from the review record set or from the
`reviewer-trust.json` active-key list. Each of `security`,
`distributed-systems`, `license/notices`, and `release-owner` must be
present exactly once, with an active enrolled key.

### Signature verification failure

Cause: the detached Ed25519 signature does not verify against the
declared reviewer public key over the canonical payload. Re-run
`rados-r13-verify print-review-payload <role>` on the exact candidate
report bytes and re-sign. Externally held private keys are the reviewer's
responsibility; the R13 verifier prints the payload but never signs.

## Deterministic release (`rados-r13-release`)

### `invalid release version "..."`

Cause: version string does not match `vX.Y.Z` (optionally with `-pre` /
`+build`). Use a semver-shaped identifier; the R13 gate does not authorize
a tag.

### `symbolic link ... not permitted`

Cause: the enumerator refuses symlinks by design. Remove or dereference
the symlink under the workspace, or exclude the offending path.

### `release output already exists`

Cause: `--output` points at a non-empty directory. Choose a fresh path
or remove the existing artefacts.

## When in doubt

- Reproduce the failure with the smallest possible invocation.
- Read the strict verifier's error message. R13 verifiers are terse but
  exact.
- Do not edit an evidence report to make it pass. Every verifier binds
  the report to on-disk content-addressed evidence; hand edits fail
  content binding.
- Consult [`STATUS.md`](STATUS.md) for the current landed remediations
  before assuming a bug.
