# Artifact Chain

`ironport apply` emits a release bundle that is meant to be verified as a unit, not file by file in isolation.

## Produced Files

- `<artifact>`
- `<artifact>.sig`
- `<artifact>.prov`
- `<artifact>.intoto.json`
- `<artifact>.slsa.json`
- `<artifact>.spdx.json`

## What Each File Means

### `<artifact>`

The payload that the client ultimately wants to consume.

### `<artifact>.sig`

Detached signature data for the artifact payload. Verification is context-bound to the artifact, not treated as a generic blob.

### `<artifact>.prov`

Build provenance sidecar. The important operational invariant is that `build_hash` must equal the artifact SHA-256.

### `<artifact>.intoto.json`

In-toto attestation describing the build or transformation subject.

### `<artifact>.slsa.json`

SLSA provenance statement for the same artifact subject.

### `<artifact>.spdx.json`

SPDX SBOM document tied to the artifact subject hash.

## Repository Metadata

`ironport-repo` serves dynamic TUF-style metadata at:

- `/metadata/root.json`
- `/metadata/targets.json`
- `/metadata/snapshot.json`
- `/metadata/timestamp.json`

Each metadata document also has a `.sig` sibling endpoint.

## Verification Rules

The client should only accept the artifact if all of the following hold:

- artifact payload matches the detached signature in artifact context
- `.prov` `build_hash` equals the artifact SHA-256
- `.intoto.json`, `.slsa.json`, and `.spdx.json` all bind to the same artifact SHA-256 subject
- TUF-style metadata verifies and is fresh
- locally stored rollback state is not regressing

## Rollback Protection

`ironport-client` stores last-seen snapshot and timestamp versions under `.ironport-client/`. A lower version is rejected as rollback.

## Operational Advice

- Publish the artifact and all sidecars together.
- Verify from a clean client state before calling a release accepted.
- Treat metadata freshness failures as release blockers, not warnings.
- Keep signer rotation and revocation procedures rehearsed.
