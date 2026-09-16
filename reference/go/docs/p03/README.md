# P03: CephX and Secure Session Integration

P03 implements bounded CephX credential parsing, authentication, ticket and
authorizer processing, transcript authentication, and secure messenger v2.1
connection establishment. Production configuration advertises secure mode
only unless `AllowCRC` is explicitly enabled.

The implementation supports Ceph type-1 AES-128 keys and type-2
AES256-CTS-HMAC-SHA384-192 keys. Type-2 cryptography uses
`github.com/otuschhoff/gokrb5/v8` at `v8.5.3`; Ceph-specific key usages remain
explicit in `internal/cephx`. The supported keyring subset accepts canonical
Ceph-generated lengths only: 16 bytes for type 1 and 32 bytes for type 2.

Run `make verify-p03` for local deterministic gates, `make integration-p03` for
the disposable pinned-monitor gate, and `make verify-p03-all` for the complete
quality, reproduction, integration, and fuzz suite.

P03 deliberately stops after authenticated `ClientIdent`/`ServerIdent`.
Monitor discovery, map subscriptions, map decoding, and failover belong to P04.
