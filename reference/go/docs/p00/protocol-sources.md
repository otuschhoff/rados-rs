# Protocol Source Index

All paths refer to Ceph commit
`69f84cc2651aa259a15bc192ddaabd3baba07489` unless a task explicitly records a
new qualification commit.

| Area | Primary implementation evidence | Independent evidence | Owning phase |
| --- | --- | --- | --- |
| Public behavior | `src/include/rados/librados.h`, `librados.hpp`, `src/librados/librados_c.cc` | native reference driver, `src/test/librados` | P01-P11 |
| Binary encoding | `src/include/encoding.h`, `buffer.h`, relevant type headers | `ceph-dencoder` fixtures | P01 |
| Messenger 2.1 | `src/msg/async/ProtocolV2.cc`, `frames_v2.h` | `doc/dev/msgr2.rst`, frame captures/vectors | P02 |
| CephX | `src/auth/cephx`, `src/auth/AuthClientHandler.cc` | real monitor negative tests | P03 |
| Monitor | `src/mon/MonClient.cc`, monitor messages | `ceph mon dump`, failover tests | P04 |
| Maps | `src/osd/OSDMap.cc`, map type headers | full/incremental convergence fixtures | P04 |
| Placement | `src/crush`, `OSDMap::object_locator_to_pg`, `pg_to_up_acting_osds` | `ceph osd map` corpus | P05 |
| OSD operations | `src/osdc/Objecter.cc`, `Objecter.h`, `OSDOp.h`, `src/messages/MOSDOp*` | native operation histories | P06-P10 |
| Completion/replay | `Objecter`, `src/librados/IoCtxImpl.cc`, `RadosClient.cc` | lost-reply failure tests | P07 |
| Classes/locks | `src/cls/lock`, class client headers | mixed native/Go tests | P09 |
| Manager/admin | `src/mgr`, command message definitions | Ceph CLI JSON results | P11 |

## Unresolved Questions and Owners

These are intentionally open and do not block P00. They must block their owning
phase if not answered with pinned source plus independent evidence.

| Question | Owner/review | Due |
| --- | --- | --- |
| Exact v2.1 secure nonce, direction and rollover invariants | security reviewer | P02/P03 |
| Modern commit/complete meaning and replay identity retention | distributed-systems reviewer | P07 |
| Full supported Ceph config/keyring grammar | API/config reviewer | P04 |
| Exact CRUSH feature subset encountered by selected profiles | placement reviewer | P05 |
| EC operation restrictions for the selected overwrite profile | storage semantics reviewer | P10 |

Required human reviewers are roles, not yet named people. A release gate cannot
be passed until an accountable person is recorded for each required review.