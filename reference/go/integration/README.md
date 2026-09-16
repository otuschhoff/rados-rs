# Integration Infrastructure

Integration code is isolated from the shipped Go module. It may use native Ceph
tools and librados; production code and ordinary unit tests may not.

## P00 host requirements

Use a disposable Linux VM with systemd, root access, Docker, at least 4 CPUs,
12 GiB RAM and 40 GiB free disk. Python 3 and an SSH daemon listening on port 22
are required for cephadm host management. Every exposed block device must have
a usable udev database record so `ceph-volume` can inventory the host; Linux
containers that cannot process virtual-disk udev events are not sufficient. The
runner creates three 6 GiB loop devices, bootstraps Ceph services and destroys
them on exit. Never run it on a Ceph host or a machine containing valuable
`/var/lib/ceph` state. Run from a clean, committed worktree so the report's
repository commit identifies the exact code under test.

macOS is supported as a future client platform, but Docker Desktop is not a
sufficient cephadm host because its Linux VM does not expose the required
systemd/raw-device lifecycle. Start a dedicated Linux VM and run:

The host must also resolve the numeric Ceph UID and GID embedded in the pinned
image. Some recent distributions require a local `ceph` system account for
cephadm's numeric ownership operations; the runner checks this before bootstrap
and reports the required IDs.

```sh
sudo env P00_DISPOSABLE_CLUSTER=I_UNDERSTAND_THIS_DESTROYS_DATA make p00-smoke
```

Successful reports are written to `integration/reports/` and contain no keys.
The report must validate against `integration/manifest.schema.json`.

## P06 through P09 host requirements

The P06 read-path gate runs on macOS or Linux with Docker, Go, `jq`, Python 3,
`shasum`, and network access to the pinned multi-architecture Ceph image. Docker
must support privileged containers, bridge networks with fixed addresses, and
managed volumes. Allow at least 4 CPUs, 8 GiB RAM, and 8 GiB free disk for three
ephemeral BlueStore OSDs. The workflow does not access host block devices or an
existing Ceph installation; it removes its containers, volumes, network, keys,
and temporary data on exit.

P07 uses 8 GiB sparse devices per OSD and additionally compiles isolated native
librados differential and benchmark drivers inside the pinned image. Allow at
least 12 GiB free disk and enough time for the complete 144-row Go/native,
secure/CRC baseline matrix. No native Ceph library is linked into shipped Go
code.

P08 reuses the three-OSD, 8 GiB BlueStore topology without the benchmark
matrix. It compiles an isolated, dynamically loaded native driver and proves
binary metadata interoperability, single-request compound atomicity,
cross-client version contention, namespace isolation, and cursor-based
enumeration. Both clients use the pool-scoped `client.p08` identity.

P09 reuses the same topology for class execution, locks, and watch/notify
coordination, including partial-timeout reporting, remap-triggered
watch re-registration, and bounded shutdown. The native differential
driver remains isolated through dynamic symbol loading and is not linked
into production Go binaries.

Run the latest serialized quality, real-cluster, semantic-verifier,
cross-build, and fuzz gates with:

```sh
make verify-p09-all
```