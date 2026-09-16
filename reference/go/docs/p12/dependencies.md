# Dependency and License Audit

Status: production import graph audited on 2026-09-16 from `go.mod` using Go
1.27.1. This is a technical inventory, not legal advice or a final release
approval.

Project SPDX identity: `LGPL-2.1-only`. The canonical license text is in the
repository root `LICENSE` file.

`go list -deps` for the root package reaches exactly these non-standard-library
modules:

| Module | Selected version | Reachable purpose | License found in selected module | cgo/FFI |
| --- | --- | --- | --- | --- |
| `github.com/otuschhoff/gokrb5/v8` | v8.5.3 | CephX Kerberos/RFC 8009 primitives and types | Apache-2.0 | None found |
| `github.com/jcmturner/aescts/v2` | v2.0.0 | AES ciphertext stealing used by gokrb5 | Apache-2.0 | None found |
| `github.com/jcmturner/gofork` | v1.7.6 | Go-derived crypto helpers used by gokrb5 | BSD-3-Clause | None found |
| `golang.org/x/crypto` | v0.56.0 | Supplemental Go cryptography used by gokrb5 | BSD-3-Clause | None found |

The broader `go list -m all` graph contains test/support modules inherited from
dependency module files; they are not reachable from the shipped root package
and are not represented above as production dependencies. Re-run the reachable
graph audit whenever imports or selected versions change.

## Audit Commands

```sh
CGO_ENABLED=0 GOTOOLCHAIN=go1.27.1 go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}}{{end}}{{end}}' . | sort -u
CGO_ENABLED=0 GOTOOLCHAIN=go1.27.1 go list -deps -f '{{if .CgoFiles}}{{.ImportPath}} {{join .CgoFiles ","}}{{end}}' ./...
CGO_ENABLED=0 GOTOOLCHAIN=go1.27.1 go mod verify
```

The cgo query produced no package entries during this review. `go mod verify`
must still pass on the final release candidate. Source distributions and binary
release bundles must retain the project license and applicable third-party
notices. Ceph images, tools, and native oracles are qualification infrastructure,
not shipped module dependencies; their upstream licenses still govern their own
redistribution.

The generated API inventory contains factual signatures derived from
LGPL-covered Ceph headers. The project license decision does not remove the
need to preserve provenance and applicable notices for inventory, fixtures, and
native oracle sources.