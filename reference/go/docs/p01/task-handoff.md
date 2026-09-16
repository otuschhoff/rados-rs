# P01 Handoff

Status: **P01 complete**.

## Qualification

- `CGO_ENABLED=0 go test ./...`: passed.
- `CGO_ENABLED=0 go build ./...`: passed.
- `go vet ./...`: passed.
- `go mod verify`: passed.
- Linux/macOS amd64/arm64 cgo-disabled cross-builds: passed.
- P00 verification: passed.
- Six pinned fixture hashes and manifests: passed.
- All six fixtures reproduced through the pinned image and byte-compared: passed.
- Four fuzz targets, 60 seconds each: passed with no panic or bound violation.

No deterministic clock or fake transport was added because P01 owns no timing
or transport behavior. P02 must introduce those interfaces with the first
scripted session consumer, not as unused scaffolding.

## P02 Boundary

Begin with messenger v2.1 banner and feature negotiation. Reuse bounded codecs
and preserve the internal/public boundary: wire values stay internal, while
public lifecycle contracts remain as recorded in `api-contract.md`. P02 must add
fixture vectors for each frame family and deterministic fake-peer fragmentation
before any connectivity claim.
