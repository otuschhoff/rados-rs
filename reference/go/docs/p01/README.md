# P01 Minimal Module and Binary Primitives

Status: implementation complete; qualification is recorded in `task-handoff.md`.

P01 initializes the pure-Go module and establishes the bounded binary foundation
for later messenger work. It does not connect to Ceph and makes no
interoperability claim.

## Delivered

- Root `rados` package with a structured public error taxonomy.
- Bounded little-endian primitives and Ceph version/compat envelopes.
- Separate global and messenger feature namespaces.
- Entity names, Linux-shaped IPv4/IPv6 addresses, feature-dependent address
  vectors, and host-independent Ceph wire errno values.
- Six native-oracle byte fixtures generated in the pinned Ceph 20.2.4 image,
  with strict provenance sidecars and human redistribution review.
- Fuzz targets for primitive, envelope, address, and address-vector decoders.
- cgo-disabled test/build, pinned-toolchain vet, race, vulnerability, module,
  dependency, provenance, scheduled fuzz, and cross-build gates.

## Records

- `api-contract.md`: public ownership, timeout, cancellation, concurrency, and
  lifecycle decisions.
- `public-api.md`: reviewed v1 exported type and method signatures.
- `provenance.md`: independently implemented source facts and fixture oracle.
- `tasks.md`: P01 task packets and acceptance status.
- `task-handoff.md`: exact completed validation and the P02 boundary.

Run the complete local phase gate, including race, pinned analyzers, dependency
checks, and four 60-second fuzz campaigns, with:

```sh
make verify-p01-all
```

For a faster non-fuzzing development gate, run `make verify-p01`. Run only the
required fuzz smoke with:

```sh
make fuzz-p01
```
