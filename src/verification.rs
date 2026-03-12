#[cfg(kani)]
mod proofs {
    use crate::{
        containment_decision, validate_abi_range, AbiVersionRange, AerEvent, AerSeverity,
        BootTrust, ContainmentDecision, DmaIsolationWindow, DriverLifecycle, DriverState,
        MeasuredBootRecord, MeasuredBootState, MmioDesc, ResourceManifest, ResourceScope,
    };

    struct DriverTag;

    #[kani::proof]
    fn manifest_canonical_size_matches_write() {
        let manifest = ResourceManifest::<DriverTag, 1, 1>::new(
            ResourceScope {
                driver_id: 7,
                iommu_domain: 9,
                binding_nonce: 11,
            },
            [MmioDesc {
                base: 0x1000,
                size: 0x2000,
            }],
            1,
            [crate::IoPortDesc {
                port: 0x3f8,
                count: 8,
            }],
            1,
        )
        .unwrap();
        let mut buf = [0u8; 64];
        let written = manifest.write_canonical(&mut buf).unwrap();
        assert_eq!(written, manifest.canonical_len());
    }

    #[kani::proof]
    fn dma_window_accepts_exact_range() {
        let window = DmaIsolationWindow {
            base: 0x4000,
            size: 0x2000,
        };
        assert!(window.contains(0x4000, 0x2000).is_ok());
        assert!(window.contains(0x5fff, 2).is_err());
    }

    #[kani::proof]
    fn containment_mapping_is_stable() {
        assert_eq!(
            containment_decision(AerEvent {
                severity: AerSeverity::Correctable,
                source_id: 0,
                status: 0,
                header_log: [0; 4],
            }),
            ContainmentDecision::Observe
        );
        assert_eq!(
            containment_decision(AerEvent {
                severity: AerSeverity::Fatal,
                source_id: 0,
                status: 0,
                header_log: [0; 4],
            }),
            ContainmentDecision::ResetRequired
        );
    }

    #[kani::proof]
    fn measured_boot_gate_blocks_untrusted() {
        let state = MeasuredBootState::<1> {
            trust: BootTrust::Untrusted,
            records: [MeasuredBootRecord {
                pcr: 7,
                digest: [0u8; 32],
            }],
            record_count: 1,
        };
        assert!(state.release_gate().is_err());
    }

    #[kani::proof]
    fn driver_lifecycle_allows_nominal_sequence() {
        let lifecycle = DriverLifecycle::new();
        assert!(lifecycle.transition(DriverState::Initialized).is_ok());
        assert!(lifecycle.transition(DriverState::Running).is_ok());
        assert!(lifecycle.transition(DriverState::Suspended).is_ok());
        assert!(lifecycle.transition(DriverState::Running).is_ok());
        assert!(lifecycle.transition(DriverState::Shutdown).is_ok());
    }

    #[kani::proof]
    fn driver_lifecycle_rejects_invalid_shortcuts() {
        let lifecycle = DriverLifecycle::new();
        assert!(lifecycle.transition(DriverState::Running).is_err());
        assert_eq!(lifecycle.state(), DriverState::Created);
    }

    #[kani::proof]
    fn manifest_constructor_rejects_zero_scope() {
        let manifest = ResourceManifest::<DriverTag, 1, 0>::new(
            ResourceScope {
                driver_id: 0,
                iommu_domain: 0,
                binding_nonce: 1,
            },
            [MmioDesc {
                base: 0x1000,
                size: 0x100,
            }],
            1,
            [],
            0,
        );
        assert!(manifest.is_err());
    }

    #[kani::proof]
    fn abi_range_stays_closed_outside_bounds() {
        assert!(validate_abi_range(3, AbiVersionRange { min: 4, max: 8 }).is_err());
        assert!(validate_abi_range(6, AbiVersionRange { min: 4, max: 8 }).is_ok());
    }
}
