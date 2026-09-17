# R04 Execution And Handoff

R04 implements private CephX authentication and live secure monitor-session
qualification. Public client connection, monitor discovery/configuration and
map consumption remain outside this phase.

## Delivered

- Canonical type-1 and type-2 credential/keyring parsing with redacted secret
  values and zeroized owned buffers.
- Ceph-compatible AES-128-CBC and RFC 8009 AES256-CTS-HMAC-SHA384-192
  encryption, challenge, ticket, authorizer and transcript processing.
- Exact P03 fixture checks and an eleven-case pinned Rust/Go differential
  bridge with bounded subprocesses, source binding and negative verifier tests.
- Transactional monitor and OSD/manager service connectors with secure default,
  explicit CRC opt-in, deadline/cancellation bounds, global-ID reclaim, ticket
  rotation and expiry.
- Generation-tagged credential renewal integrated with the R03 session owner.
- Four production-source CephX fuzz targets and a reproducible seed generator.
- A digest-pinned Ceph 20.2.4 monitor harness covering authentication, identity,
  renewal, expiry, reconnect, wrong-key rejection and downgrade rejection.

## Evidence Boundaries

Ordinary workspace tests require neither Go nor Docker. The differential bridge
is an opt-in clean-tree gate against Go commit
`c8bb148a1379b51ef87256c27f366a05f8da4dc4` and tree
`c5039b6b50a05b942a902f70dc2fcb090463e8c7`. The live report binds every Rust
source file, build manifest, lockfile and live harness input by SHA-256; its
verifier requires that exact artifact set.

The live harness proves monitor authentication only. OSD and manager service
authorization are covered by deterministic and scripted connector tests, not a
live daemon. The feature-gated live probe is qualification infrastructure and
does not expose or activate a production public connection API.

Fuzz campaign records are task-validation evidence rather than certification.
Generated mutations and raw logs remain disposable; the tracked corpus script,
source hashes, seed hashes and final statistics make the campaigns repeatable.

## R05 Handoff

R05 owns public configuration precedence and file/environment loading, monitor
bootstrap and failover, FSID enforcement, subscriptions, monmap/OSDMap/manager
map decoding and publication, and the public-client connection boundary. It
must preserve R04's secure default, transactional credential state and bounded
session ownership. Live service authorization should be exercised when R05 has
real map-derived OSD or manager endpoints.