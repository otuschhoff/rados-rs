# Initial Threat Model

## Assets and Trust Boundaries

Assets are CephX keys/tickets, messenger session secrets, object bytes and
metadata, cluster FSID and maps, request identities, completion state, and
administrative authority. Trust boundaries exist between callers and the Go
API, configuration/keyring files and the process, DNS/network peers and the
client, monitor/manager/OSD sessions, and test infrastructure versus production
clusters.

Ceph daemons are authenticated peers, not memory-safe inputs. Network frames,
maps, commands and class responses remain hostile until authenticated, bounded
and decoded. The local caller may misuse the API but must not trigger panics,
secret disclosure or unbounded allocation.

## Threats and Required Controls

| Threat | Required control and verification |
| --- | --- |
| Credential or payload disclosure | Never log secrets/payloads; redact identifiers; secret-scanning tests and log review |
| Peer spoofing or wrong cluster | CephX plus explicit FSID pin; reject mismatches before map/object use |
| Downgrade to CRC/no-auth | Secure by default; CRC requires explicit policy; no production no-auth surface |
| Frame tampering/replay | Transcript authentication, AEAD verification before dispatch, directional sequence/nonce checks |
| Malformed allocation/overflow | Pre-allocation bounds, checked arithmetic, fuzz and corruption fixtures |
| Stale/malicious maps | Atomic epoch/FSID validation, no rollback, bounded history, fail closed on required features |
| Mutation duplication/false success | Explicit request state and identity; no blind retry; outcome-unknown errors |
| Resource exhaustion | Global/per-session inflight, byte, retry, connection and event-queue limits |
| Cross-client data leak | Immutable namespace/locator/snapshot views; capability and namespace tests |
| Callback deadlock | Dispatch outside receive loop with bounded queues and observable overflow |
| Destructive test against production | Explicit guard token, Linux-host checks, generated FSID marker and no external config default |
| Supply-chain substitution | Commit, image digest and toolchain checksum pins; manifest validator |

## Review Gates

P02/P03 require independent security review of framing, transcript and CephX.
P05 requires placement-math review. P07 requires distributed-systems review of
replay and completion. P12 requires a full security review. LLM self-review is
supplementary and cannot satisfy these gates.