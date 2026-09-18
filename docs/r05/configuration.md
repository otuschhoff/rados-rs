# R05 Configuration Contract

The deterministic bridge compares the actual Rust `Config` implementation with
the actual pinned Go `Config` implementation. Neither probe contains a second
configuration parser.

Defaults are cluster `ceph`, entity `client.admin`, secure messenger mode, and
10 s/15 s/30 s dial, handshake, and operation timeouts. Configuration files
apply `[global]` first and the resulting exact entity section second. Unknown
file options are ignored, while unknown programmatic options are retained and
queryable. `include` and `include_dir` are explicitly rejected.

Environment loading is opt-in through an explicit prefix; ordinary constructors
do not read process state. Arguments accept recognized long options in separate
or `--name=value` form, preserve unknown and positional arguments, and preserve
the `--` marker and following remainder. `--id=x` selects `client.x`.

Direct keys take precedence when key and keyring arguments are both present.
When only a keyring is selected it is loaded for the effective entity after
expanding `$cluster` and `$name`. Evidence publishes only the SHA-256 of the
canonical encoded key and normalizes the fixture-root path; no secret bytes are
written to the report.

Durations follow Go `time.ParseDuration` units and formatting, including
compound and decimal values (`1h2m3.004005006s`, `250ms`, and `1us`/`1µs`).
Values must be positive and fit the Go signed 64-bit nanosecond range. Monitor
seeds split on commas, semicolons, or whitespace, discard messenger-v1 entries,
retain v2/bare ordering, and reject empty results or more than 64 entries.