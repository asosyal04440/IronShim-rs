# Live Validation Guide

This guide documents the Linux host-assisted smoke tests that exercise the real backend under the `linux-host` feature.

## Build Surface

Use a Linux host with a recent kernel that exposes:

- PCIe config space through `/sys/bus/pci/devices`
- DOE mailbox support on the target device for SPDM
- `iommufd` and VFIO character devices for attach/map testing
- SR-IOV sysfs controls where applicable

Compile the validation surface with:

```bash
cargo check --tests --target x86_64-unknown-linux-gnu --features "std alloc linux-host"
```

## Live Test Entry Points

The live smoke tests are env-gated inside `src/linux_backend.rs` and remain inert unless the corresponding variables are set.

### SPDM over DOE

- `IRONSHIM_LIVE_SPDM_BDF`: PCI BDF of the device exposing DOE/SPDM

Triggered test path:

- open DOE mailbox
- fetch SPDM versions
- fetch capabilities
- negotiate algorithms
- fetch digests
- fetch certificate chain
- optionally run challenge and measurements when the target supports them

Example:

```bash
IRONSHIM_LIVE_SPDM_BDF=0000:5e:00.0 cargo test --features "std alloc linux-host" live_spdm_smoke_if_requested -- --nocapture
```

### IOMMUFD and VFIO

- `IRONSHIM_LIVE_VFIO_CDEV`: VFIO character device path
- `IRONSHIM_LIVE_PASID`: optional PASID for stage-1 hardware page-table attach

Triggered test path:

- open `iommufd`
- allocate IOAS
- bind VFIO device to `iommufd`
- allocate a stage-1 hardware page table
- attach hardware page table
- map and unmap a userspace buffer
- detach hardware page table

Example:

```bash
IRONSHIM_LIVE_VFIO_CDEV=/dev/vfio/devices/vfio0 cargo test --features "std alloc linux-host" live_iommufd_vfio_roundtrip_if_requested -- --nocapture
```

### DPC and AER Recovery

- `IRONSHIM_LIVE_DPC_BDF`: PCI BDF for the downstream port or device
- `IRONSHIM_LIVE_DPC_RECOVER=1`: opt in to a recovery attempt when reset is required

Triggered test path:

- read DPC status block
- derive containment decision
- convert DPC state into AER-style severity
- optionally trigger reset-based recovery through sysfs

Example:

```bash
IRONSHIM_LIVE_DPC_BDF=0000:5d:00.0 IRONSHIM_LIVE_DPC_RECOVER=1 cargo test --features "std alloc linux-host" live_dpc_recovery_if_requested -- --nocapture
```

### SR-IOV Inventory

- `IRONSHIM_LIVE_SRIOV_BDF`: PCI BDF for the PF device

Triggered test path:

- inspect total and enabled VF counts
- enumerate current VF symlinks

Example:

```bash
IRONSHIM_LIVE_SRIOV_BDF=0000:86:00.0 cargo test --features "std alloc linux-host" live_sriov_inventory_if_requested -- --nocapture
```

## Operational Notes

- These tests are smoke tests, not destructive conformance loops.
- Recovery and VF provisioning can affect live devices; run only on sacrificial or lab hardware.
- SPDM support varies by device and firmware. Challenge and measurement steps may legitimately be unsupported on some targets.
- On non-Linux hosts, use `cargo check` for compile validation and run live tests only on a native Linux machine.

## Release Gate Recommendation

For release acceptance, require:

- `cargo test`
- `cargo check --all-targets --all-features`
- `cargo miri test --features "std alloc"`
- `cargo fuzz build`
- `cargo kani --features "std alloc kani"`
- at least one successful lab run for each enabled live backend surface in this document
