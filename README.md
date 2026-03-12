# IronShim-rs

IronShim-rs is a hardening-first `no_std` Rust micro-shim for untrusted drivers. It is built for bare-metal operating systems that want explicit capability boundaries, deterministic lifecycle control, signed resource manifests, and a host-side validation lane for real PCIe hardware.

![no_std](https://img.shields.io/badge/no__std-yes-blue)
![Rust 2021](https://img.shields.io/badge/rust-2021-orange)
![License](https://img.shields.io/badge/license-AGPL--3.0--only-green)

**Language Hubs**
- [English Docs](docs/README.en.md)
- [Turkce Dokumantasyon](docs/README.tr.md)

## Why This Exists

Most driver interfaces are still built around trust, ambient authority, and huge amounts of implied kernel behavior. IronShim-rs takes the opposite position:

- hardware access is granted explicitly
- manifests are scoped to a concrete driver identity and IOMMU domain
- interrupts are budgeted and can be quarantined
- artifact delivery is signed, versioned, and rollback-aware
- Linux can be used as a validation harness without collapsing the bare-metal model

This crate is meant for teams that want a small isolation core, not a hand-wavy framework.

## What You Get

### Core Library

- Fail-closed `ResourcePolicy` defaults for MMIO and Port I/O.
- `ResourceManifest` with canonical serialization, SHA-256 hashing, signature hooks, revocation, and scope binding.
- Typed DMA handles and scatter lists with manifest-bounded access.
- Driver lifecycle state machine with explicit transitions and quarantine semantics.
- Interrupt budgeting, deferred work queues, and telemetry/audit hooks.
- ABI compatibility checks for version, features, and layout correctness.

### Platform And Attestation Surface

- Isolation descriptors for mapped DMA and shared virtual addressing.
- Virtual-function budgeting and containment decisions for AER/DPC faults.
- Device attestation and measured-boot data models for release gating.
- Optional Linux host backend for DOE/SPDM, SR-IOV, AER/DPC, `iommufd`, and VFIO lab validation.

### Tooling

- `ironport` transformation and signing pipeline.
- `ironport-repo` serving dynamic TUF-style metadata.
- `ironport-client` verifying artifact signatures, provenance, subject hashes, and rollback state.
- Kani proof harnesses, cargo-fuzz targets, and Miri automation.

## Repository Map

- `src/lib.rs`: public surface and feature gates
- `src/resource.rs`: manifest model, policy, signatures, PCI parsing
- `src/dma.rs`: DMA allocator traits, handles, constraints, scatter-gather
- `src/driver.rs`: lifecycle and sandbox profile
- `src/interrupt.rs`: IRQ budgets, quarantine, telemetry
- `src/platform.rs`: isolation, attestation, measured boot, containment decisions
- `src/linux_backend.rs`: Linux DOE/SPDM, SR-IOV, AER/DPC, `iommufd`, VFIO backend
- `src/verification.rs`: Kani proofs
- `src/bin/ironport.rs`: artifact transformation and signing
- `src/bin/ironport_repo.rs`: repository service
- `src/bin/ironport_client.rs`: verified download client
- `fuzz/`: fuzz targets

## Documentation Map

- [Architecture Deep Dive](docs/ARCHITECTURE.md)
- [Security Model](docs/SECURITY_MODEL.md)
- [Operations Guide](docs/OPERATIONS.md)
- [Artifact Chain](docs/ARTIFACT_CHAIN.md)
- [Live Validation Guide](docs/LIVE_VALIDATION.md)

## Quick Start

Library validation:

```bash
cargo test
```

Full host-facing compile sweep:

```bash
cargo check --all-targets --all-features
cargo check --tests --target x86_64-unknown-linux-gnu --features "std alloc linux-host"
```

Toolchain example:

```bash
ironport extract linux.c ported.c v1 pattern.toml
ironport apply pattern.toml input.c output.c
ironport-repo 127.0.0.1:8080 repo_dir
ironport-client 127.0.0.1:8080 get-verified output.c out.c
```

## Feature Matrix

| Feature | Purpose |
| --- | --- |
| `std` | Enables host-side helpers and richer testing support |
| `alloc` | Enables heap-backed structures used by host tooling and verification helpers |
| `linux-host` | Enables Linux DOE/SPDM, SR-IOV, AER/DPC, `iommufd`, and VFIO backend |
| `loom` | Concurrency-model exploration hooks |
| `fuzzing` | Fuzz entry points for manifest and PCI parsing |
| `kani` | Kani proof harnesses |

## Security Snapshot

IronShim-rs assumes drivers are not trusted with raw hardware ownership.

- MMIO and Port I/O are denied unless a policy grants access.
- Manifest scope binds driver identity, IOMMU domain, and nonce.
- Signature validation rejects revoked keys and hash mismatches.
- Interrupt abuse is budgeted and can trigger quarantine.
- AER/DPC faults are mapped into containment decisions.
- Measured boot can block release when host trust is degraded.
- Artifact distribution is provenance-aware and rollback-resistant.

The longer version lives in [Security Model](docs/SECURITY_MODEL.md).

## Linux Host Validation

The `linux-host` feature is not a portability escape hatch. It is a lab lane for validating the same security model against real devices and kernel interfaces.

It includes:

- DOE mailbox access for SPDM
- SPDM requester flows for version, capabilities, algorithms, certificate retrieval, challenge, measurements, key exchange, and finish
- SR-IOV inventory and VF control through sysfs
- AER counter ingestion and DPC containment/recovery helpers
- `iommufd` IOAS and stage-1 page-table hooks
- VFIO device binding and hardware page-table attach/detach

Live execution instructions are documented in [Live Validation Guide](docs/LIVE_VALIDATION.md).

## Verification Story

This repo is built to support multiple confidence lanes instead of one giant "trust me" claim.

- Unit tests cover isolation, manifests, ABI checks, attestation freshness, and interrupt behavior.
- Kani proofs target manifest encoding, lifecycle constraints, DMA windows, containment mapping, and boot gating.
- cargo-fuzz targets manifest and PCI parsing.
- Miri is wired into CI for UB-sensitive paths.
- GitHub Actions run the advanced verification lanes on a schedule.

## Current Boundaries

IronShim-rs is opinionated, but not magical.

- Bare-metal integration still requires your kernel to implement allocator, IRQ, policy, and audit hooks.
- Linux live validation still requires access to a Linux host with the relevant devices and kernel support.
- Hardware certification is outside the scope of the crate itself.

## License

This project is licensed under the GNU Affero General Public License v3.0 only. See [LICENSE](LICENSE).
