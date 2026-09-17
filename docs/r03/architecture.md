# R03 Messenger Architecture

R03 remains entirely behind the public API boundary. `Client::connect` and
transport-backed public operations still return `ErrorKind::NotConnected`; no
public connection behavior or live authentication is claimed.

## Layers

1. `banner`, `frame`, `control`, `message` and `secure` own bounded wire parsing
   and encoding. A frame is dispatched only after its CRC or GCM integrity,
   shape, alignment and size checks succeed.
2. `session` is a pure state machine. Inputs carry a connection generation;
   effects describe connects, closes, writes, completions and observable events.
3. `transport` owns one reader task and one writer task per stream. Its write
   queue is bounded. A write error after any bytes may have reached the peer
   faults and discards the stream.
4. `supervisor` is the sole mutable owner of the machine and active transport.
   It serializes commands, transport events and connector completion, rejects
   stale generations, reaps connector tasks and translates connector panics
   into bounded connection failure.

## Ownership And Failure

Only the owner task mutates session state. Request futures receive admission
and completion through one-shot channels; dropping a caller after admission
does not abandon the owner-held operation. Depending on reconnect policy and
whether bytes may have executed, faults replay retained requests or complete
them with `OutcomeUnknown`.

Reader and writer shutdown is explicit and interruptible. Invalid CRC, invalid
GCM tags, malformed padding/status, sequence violations and impossible control
or message shapes become faults before application dispatch. A terminal state
emits `CloseTransport`, completes retained work and prevents a live stream from
outlasting the machine.

Queues, frame bytes, segment bytes, address/auth collections, retained request
bytes, in-flight transactions, reconnect attempts, handshake transitions and
event channels all have explicit bounds. Event-channel overflow is sticky and
reported cumulatively as `EventsDropped` rather than silently disappearing.

## Authentication Boundary

`ConnectionSetup` can carry an authenticated global ID and a digest-like
credential identity supplied by a future connector. Renewal drains the current
generation and only completes after a connector supplies positively changed
credentials. Missing or unchanged identity causes another bounded reconnect
attempt. R03 does not parse credentials, derive CephX keys or authenticate a
network peer; those are R04 responsibilities.
