# IronShim-rs Documentation (EN)

This directory is the operator and integrator map for IronShim-rs.

## Start Here

- [Project README](../README.md)
- [Architecture Deep Dive](ARCHITECTURE.md)
- [Security Model](SECURITY_MODEL.md)
- [Operations Guide](OPERATIONS.md)
- [Artifact Chain](ARTIFACT_CHAIN.md)
- [Live Validation Guide](LIVE_VALIDATION.md)
- [Turkish Documentation Index](README.tr.md)

## Reading Order

### If You Are Embedding The Library

1. [Architecture Deep Dive](ARCHITECTURE.md)
2. [Security Model](SECURITY_MODEL.md)

### If You Own Build And Release

1. [Operations Guide](OPERATIONS.md)
2. [Artifact Chain](ARTIFACT_CHAIN.md)

### If You Own Real Hardware Validation

1. [Live Validation Guide](LIVE_VALIDATION.md)
2. [Operations Guide](OPERATIONS.md)

## Documentation Scope

These docs describe the repository as it exists today:

- fail-closed resource policy
- canonical manifest hashing and signature hooks
- lifecycle and interrupt containment
- TUF-style artifact publication and rollback-aware client verification
- Linux DOE/SPDM, SR-IOV, AER/DPC, `iommufd`, and VFIO validation surface
- Kani, fuzzing, and Miri assurance lanes

## License

IronShim-rs is licensed under AGPL-3.0-only. See [LICENSE](../LICENSE).
