# Operations Guide

## Who This Guide Is For

This guide is for the team that owns:

- build and release
- CI and verification
- Linux validation hardware
- signing keys or external signers

It is written as an execution checklist, not a tutorial.

## Build Matrix

### Core Validation

```bash
cargo test
cargo check --all-targets --all-features
```

### Linux Host Validation Surface

```bash
cargo check --tests --target x86_64-unknown-linux-gnu --features "std alloc linux-host"
```

### Miri

```bash
cargo miri test --features "std alloc"
```

### Kani

```bash
cargo kani --features "std alloc kani"
```

### Fuzz Build

```bash
cargo fuzz build
```

## Release Inputs

Before publishing an artifact set, confirm:

- manifests validate cleanly
- revocation feed is up to date
- the artifact hash is stable
- provenance sidecars are generated
- the repository metadata is refreshed
- rollback state is not regressing

## Artifact Publication Flow

1. Build the artifact.
2. Run `ironport apply` to emit the transformed artifact and sidecars.
3. Publish through `ironport-repo`.
4. Verify from a clean client state with `ironport-client`.
5. Record the accepted artifact hash and metadata version.

The sidecars and metadata roles are described in [Artifact Chain](ARTIFACT_CHAIN.md).

## Linux Lab Validation

The lab lane should be treated like a gate, not a smoke show.

### Required Surfaces

- at least one SPDM-capable DOE device if device attestation is part of the acceptance policy
- at least one SR-IOV-capable device if VF budgeting matters
- a kernel exposing `iommufd` and VFIO char devices if DMA isolation is validated through host bindings
- AER/DPC-capable topology if containment decisions are part of release acceptance

### Execution Inputs

- `IRONSHIM_LIVE_SPDM_BDF`
- `IRONSHIM_LIVE_VFIO_CDEV`
- `IRONSHIM_LIVE_PASID` when needed
- `IRONSHIM_LIVE_DPC_BDF`
- `IRONSHIM_LIVE_DPC_RECOVER=1` only on sacrificial hardware
- `IRONSHIM_LIVE_SRIOV_BDF`

See [Live Validation Guide](LIVE_VALIDATION.md) for per-test commands.

## CI

Two workflow lanes matter:

- `.github/workflows/ci.yml`
- `.github/workflows/advanced-verification.yml`

The second lane is where Miri, Kani, fuzz builds, and Linux host compile checks live.

## Incident Handling

When a validation step fails:

1. decide whether the failure is build, policy, artifact, or hardware
2. keep the failing artifact hash
3. store the exact metadata versions involved
4. preserve the DPC/AER or SPDM transcript data if available
5. do not publish a "mostly fine" release

## Recommended Release Gate

A release should not be called accepted unless all of the following are true:

- `cargo test` passes
- `cargo check --all-targets --all-features` passes
- Miri lane passes
- Kani lane passes
- fuzz targets build
- `ironport-client` accepts the artifact set from a clean state
- the required live Linux lab runs pass for the devices you claim to support

## Team Notes

- Keep the signer and verifier commands externally configurable.
- Treat lab hardware as inventory, not as an afterthought.
- Keep rollback state under source-controlled operational procedures.
- Rehearse key revocation before you need it.
