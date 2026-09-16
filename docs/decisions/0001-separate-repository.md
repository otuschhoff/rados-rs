# ADR 0001: Separate Private Rust Repository

Status: accepted repository decision, authorized by the project owner's request
to execute R00 and commit the port spec to a project named rados-rs.

Repository: https://github.com/otuschhoff/rados-rs
Default branch: main. Visibility: private.

Use a separate repository, not a long-lived Go branch, a Go monorepo workspace,
or a submodule. Rust owns its Cargo layout, CI, dependencies, API and releases.
Use short-lived task branches when needed; R00 is the initial main commit.
Do not create a third shared-conformance repository until two clients exercise
a stable runner contract.

Freeze the completed Go working tree as a content-addressed archive with its
original HEAD, dirty status and every included file's digest. This is a source
reference, not evidence of a clean Go commit or a passed Go release gate. Do
not commit or reset the owner's Go changes to manufacture a baseline.

Copy selected fixtures and native drivers unchanged with provenance; adapt
runners and translate only language-bound probes/checks. Retain useful Go
generators and private-package helpers inside an extracted pinned Go module.
The archive is a development-only reference, not a production dependency.

Import updates require explicit review of source versions, hashes, notices and
behavior. Do not auto-follow moving Go HEAD. Imported expected fixture values
must not be changed merely to match Rust output. Keep Rust-specific cases apart.

Differential CI extracts the verified snapshot into temporary storage, never a
required sibling checkout. Ordinary Rust unit tests use local imported fixtures.
Rust evidence and future approvals remain separate from historical Go reports.

Only the spec and R00 assets are committed now. No Cargo scaffolding, cluster
mutation, crate publication, fabricated review signature or release tag is
authorized by this decision.