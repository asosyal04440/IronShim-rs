use crate::{Error, PhysAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciIsolationCaps {
    pub ats: bool,
    pub pri: bool,
    pub pasid: bool,
    pub sva: bool,
}

impl PciIsolationCaps {
    pub const fn iommu_fallback() -> Self {
        Self {
            ats: false,
            pri: false,
            pasid: false,
            sva: false,
        }
    }

    pub const fn shared_virtual_addressing() -> Self {
        Self {
            ats: true,
            pri: true,
            pasid: true,
            sva: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationMode {
    MappedDma,
    SharedVirtualAddressing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsolationBinding {
    pub driver_id: u64,
    pub iommu_domain: u32,
    pub pasid: Option<u32>,
    pub mode: IsolationMode,
    pub caps: PciIsolationCaps,
}

impl IsolationBinding {
    pub fn validate(&self) -> Result<(), Error> {
        if self.driver_id == 0 || self.iommu_domain == 0 {
            return Err(Error::InvalidState);
        }
        match self.mode {
            IsolationMode::MappedDma => Ok(()),
            IsolationMode::SharedVirtualAddressing => {
                if !self.caps.ats || !self.caps.pri || !self.caps.pasid || !self.caps.sva {
                    return Err(Error::Unsupported);
                }
                if self.pasid.is_none() {
                    return Err(Error::InvalidState);
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaIsolationWindow {
    pub base: PhysAddr,
    pub size: usize,
}

impl DmaIsolationWindow {
    pub fn contains(&self, addr: PhysAddr, bytes: usize) -> Result<(), Error> {
        if self.base == 0 || self.size == 0 || bytes == 0 {
            return Err(Error::InvalidAddress);
        }
        let end = addr.checked_add(bytes).ok_or(Error::OutOfBounds)?;
        let window_end = self.base.checked_add(self.size).ok_or(Error::OutOfBounds)?;
        if addr < self.base || end > window_end {
            return Err(Error::OutOfBounds);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VfResourceBudget {
    pub max_dma_bytes: usize,
    pub max_mmio_bytes: usize,
    pub max_interrupts_per_sec: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualFunctionBinding {
    pub physical_function: u16,
    pub virtual_function: u16,
    pub iommu_domain: u32,
    pub budget: VfResourceBudget,
}

impl VirtualFunctionBinding {
    pub fn validate(&self) -> Result<(), Error> {
        if self.iommu_domain == 0 {
            return Err(Error::InvalidState);
        }
        if self.budget.max_dma_bytes == 0 || self.budget.max_mmio_bytes == 0 {
            return Err(Error::InvalidState);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AerSeverity {
    Correctable,
    NonFatal,
    Fatal,
    DpcContainment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AerEvent {
    pub severity: AerSeverity,
    pub source_id: u16,
    pub status: u32,
    pub header_log: [u32; 4],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainmentDecision {
    Observe,
    Quarantine,
    ResetRequired,
}

pub fn containment_decision(event: AerEvent) -> ContainmentDecision {
    match event.severity {
        AerSeverity::Correctable => ContainmentDecision::Observe,
        AerSeverity::NonFatal => ContainmentDecision::Quarantine,
        AerSeverity::Fatal | AerSeverity::DpcContainment => ContainmentDecision::ResetRequired,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpdmMeasurement {
    pub slot: u8,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceAttestationReport<const N: usize> {
    pub generated_at: u64,
    pub nonce: [u8; 32],
    pub transcript_hash: [u8; 32],
    pub measurements: [SpdmMeasurement; N],
    pub measurement_count: usize,
}

impl<const N: usize> DeviceAttestationReport<N> {
    pub fn measurement(&self, slot: u8) -> Option<[u8; 32]> {
        for index in 0..self.measurement_count.min(N) {
            let measurement = self.measurements[index];
            if measurement.slot == slot {
                return Some(measurement.digest);
            }
        }
        None
    }

    pub fn validate_freshness(&self, now: u64, max_age_secs: u64) -> Result<(), Error> {
        if self.generated_at > now {
            return Err(Error::InvalidState);
        }
        if now.saturating_sub(self.generated_at) > max_age_secs {
            return Err(Error::Timeout);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeasuredBootRecord {
    pub pcr: u8,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootTrust {
    Trusted,
    Degraded,
    Untrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeasuredBootState<const N: usize> {
    pub trust: BootTrust,
    pub records: [MeasuredBootRecord; N],
    pub record_count: usize,
}

impl<const N: usize> MeasuredBootState<N> {
    pub fn release_gate(&self) -> Result<(), Error> {
        match self.trust {
            BootTrust::Trusted => Ok(()),
            BootTrust::Degraded => Err(Error::RateLimited),
            BootTrust::Untrusted => Err(Error::AccessDenied),
        }
    }
}
