# Frozen Go Reference

go-baseline.json binds a compressed snapshot of the supplied dirty Go working
tree, original HEAD/status, included files, modes and hashes. imports.json binds
unchanged selected copies. go-public-api.json is AST-derived public scope, not
implemented Rust. Archived historical Go reports do not certify Rust.

Verify from the rados-rs root without the original checkout:

```sh
GO111MODULE=off go run ./tools/r00/main.go -root . -verify
GO111MODULE=off go test ./tools/r00 -count=1
```

For opt-in differential work, verify first, then extract into temporary storage:

```sh
reference_dir=$(mktemp -d)
archive=$(jq -r .archive reference/go-baseline.json)
tar -xzf "$archive" -C "$reference_dir"
```

Use pinned Go commands inside the extracted module. Original HEAD alone lacks
captured work. The archive has no Git metadata; legacy verifiers requiring a
clean Git tree need an explicit adapter, not a manufactured commit presented
as upstream. Do not change old report pass flags to bypass this boundary.

Unchanged local go/ documents retain original Go-relative links; navigate the
complete extracted archive for those links. The main Rust spec has adapted
links to imported copies. Copied scripts are reference-only; original modes
are recorded in the archive. Execute generators in the complete environment.

No submodule, sibling path or Go dependency belongs in ordinary Rust tests or
the published crate. Explicit import updates require a new manifest/archive,
reviewed source/fixture/license diffs and regression evidence for both clients
where applicable. The capture tool refuses to overwrite an existing baseline.

Observer and native fixture runner also refuse to overwrite reports. Preserve
previous results under distinct filenames before rerunning. Registry raw bodies
are not retained; URLs and response hashes accompany extracted metadata.
Availability observations are time-bound, not reservations.