# Initial Compatibility Matrix

Only rows marked **selected** are targets. A target becomes certified only
after its phase-specific integration report exists; selection is not a claim
of current client support.

| Dimension | Selected | Deferred or rejected |
| --- | --- | --- |
| Ceph source semantics | 20.2.0 | Earlier majors |
| Integration server | 20.2.4 | Future 20.x and later majors until separately certified |
| Authentication | CephX | none authentication outside synthetic tests |
| Messenger | v2.1 secure; explicit CRC | v1, v2.0, compression, automatic downgrade |
| Client OS | Linux, macOS | Windows |
| Client architecture | amd64, arm64 | Other architectures |
| Server OS | Linux container host | macOS/Windows daemons |
| Replicated pool | size 3/min_size 2, 32 PG, `p00-replicated-rule`, OSD failure domain | cache tiers and production host/rack failure domains until a multi-host runner is added |
| EC pool | `k=2 m=1`, jerasure Reed-Solomon, OSD failure domain, overwrite enabled | Other plugins/profiles until qualified |
| CRUSH | straw2, OSD failure domain, default Tentacle tunables | straw1/tree/uniform/list; choose-args and device classes until encountered and qualified |
| Addressing | IPv4 and IPv6 vectors | msgr1-only address vectors |

## Explicit Unsupported Features

The initial v1 excludes messenger v1/v2.0, wire compression, cache-tier and
legacy tmap behavior, service registration/status beacons, cluster-log
subscriptions, deprecated aliases without distinct behavior, and unqualified
CRUSH algorithms or profiles. Each matching public API is marked deferred or
intentionally omitted in `api-inventory.csv`.

Ordinary I/O identities use least privilege. Separate generated identities are
required for read-only, read/write, namespace-restricted and administrative
tests. Destructive administrative tests require both the disposable-cluster
guard and a matching FSID recorded at bootstrap.