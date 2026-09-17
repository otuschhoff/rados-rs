# R03 Session Contract

The private session machine has `Disconnected`, `Connecting`, `Reconnecting`,
`Ready`, `Wait` and `Stopped` states. `step` is deterministic and side-effect
free apart from its owned state; all I/O is represented by returned effects.

Each connection attempt advances a checked generation. Connector results,
transport frames and write completions from older generations are ignored or
closed. Handshake transitions and reconnect attempts are bounded, and terminal
failure closes the active transport.

Admission assigns checked request and transaction identities and retains the
message within queue, byte and in-flight limits. Dispatch assigns outbound
sequence numbers. ACKs advance monotonically and release replay state;
duplicate inbound messages are dropped and sequence gaps are reported before
the sequence advances, matching the pinned Go transition contract. Replies can
complete only requests that have been dispatched. One-way and reply-bearing
operations have distinct completion rules.

On disconnect, `ReplayPending` retains only operations that can be replayed
without violating execution ambiguity. `FailPending` completes pending work.
An operation whose bytes may have executed but cannot be safely accounted for
returns `OutcomeUnknown`. Caller-future drop does not cancel admitted work; an
explicit cancellation request still cannot promise cancellation after dispatch
or permit reuse of a partially written stream.

Reset, retry, retry-global, reconnect-ok, wait and keepalive controls are
validated against state and generation. Full reset clears session identity and
replay state. Replacement cookies and reconnect sequences are bounded.

Credential renewal records the initial connector-provided identity, drains the
active generation and reconnects. Renewal completes only when the connector
returns a different concrete credential identity; `None` is unknown, not proof
of change. Unchanged or missing identity retries within the normal reconnect
bound and eventually fails terminally. R04 supplies the real authenticated
identity and credential lifecycle.
