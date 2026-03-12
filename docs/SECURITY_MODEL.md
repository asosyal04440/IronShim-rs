# Security Model

## Goal

IronShim-rs is built to reduce driver authority from "can touch the machine" to "can touch only what the manifest and runtime policy allow."

The project assumes that:

- drivers may be buggy
- drivers may be malicious
- build artifacts may be tampered with
- devices may report fault or attestation signals that matter for trust decisions

## Trust Boundaries

### Trusted

- the embedding kernel or monitor
- the manifest signing authority
- the revocation feed
- telemetry and audit sinks
- the trusted update and acceptance path

### Conditionally Trusted

- the Linux validation host
- device firmware and attestation responses
- measured-boot records

### Untrusted

- the driver payload
- transformed source inputs until verified
- downloaded artifacts until signature and metadata checks pass

## Security Invariants

### 1. Hardware Access Is Explicit

The driver never receives raw ambient access to MMIO, Port I/O, or DMA. Access only exists through handles derived from a validated manifest.

### 2. Policy Defaults Deny

`ResourcePolicy` returns `AccessDenied` by default for MMIO and Port I/O operations. If the embedding system wants access, it must say so explicitly.

### 3. Manifest Identity Is Bound

`ResourceScope` binds a manifest to:

- `driver_id`
- `iommu_domain`
- `binding_nonce`

This prevents a "same resource list, different context" replay from looking identical.

### 4. Signatures Cover Canonical State

`ResourceManifest` computes a canonical SHA-256 hash over:

- scope fields
- MMIO descriptors
- Port I/O descriptors
- revocation state

Signature validation rejects hash mismatch and revoked keys.

### 5. Lifecycle Is Bounded

Drivers are not allowed arbitrary state transitions. Invalid transitions fail with `InvalidState`, which keeps error handling crisp and auditable.

### 6. Interrupt Abuse Is Contained

Interrupt budgets let the kernel clamp a driver that floods IRQ handling. The resulting quarantine reason is explicit and can feed both local policy and telemetry.

### 7. Platform Faults Become Decisions

PCIe AER and DPC data are mapped into a small decision surface:

- observe
- quarantine
- reset required

That mapping keeps downstream policy code simple and predictable.

### 8. Release Acceptance Can Use Host Trust

Measured boot and device attestation are modeled as release gates. A degraded or untrusted boot state can reject or rate-limit acceptance of a build or device binding.

## Attack Classes And Responses

## Driver Reads Outside Granted MMIO

Response:

- `ResourcePolicy` denies by default
- `MmioRegion::check` rejects out-of-bounds access
- driver receives `AccessDenied` or `OutOfBounds`

## Driver Tries To Reuse Another Driver's Manifest

Response:

- scope mismatch changes canonical hash
- signature validation fails if the manifest is replayed under a new context

## Revoked Signing Key Still Used

Response:

- `RevocationList` check rejects the signature before acceptance

## Interrupt Storm

Response:

- budget overrun is recorded
- driver can be quarantined
- telemetry and audit sinks see the event

## Artifact Rollback

Response:

- `ironport-client` stores and compares previously seen repository metadata versions
- older snapshot or timestamp state is rejected

## Faulty Or Suspicious Device State

Response:

- AER and DPC surface is translated into containment decisions
- release or runtime policy can quarantine or reset the device

## Stale Device Attestation

Response:

- `DeviceAttestationReport::validate_freshness` rejects reports outside the allowed age window

## Non-Goals

IronShim-rs does not claim to solve:

- full kernel memory isolation by itself
- trusted boot implementation
- remote key custody
- hardware certification
- side-channel resistance against every microarchitectural class

It provides hooks and structure for those systems; it is not those systems.

## Operational Expectations

To keep the security model intact, the embedding environment must:

- validate manifests before activation
- keep revocation data current
- map DMA through trusted platform allocators and mappers
- wire telemetry and audit sinks into systems that someone actually reads
- treat live hardware validation as a release activity, not a marketing bullet

## License Note

This repository is licensed under AGPL-3.0-only. If you expose modified network-facing services built from these tools, the license obligations follow the AGPL network interaction clause. This is a project policy note, not legal advice.
