use core::marker::PhantomData;
use core::ptr::{read_volatile, write_volatile};

use crate::crypto::Sha256;
use crate::{AuditEvent, AuditSink, Error, NotSendSync, TelemetryEvent, TelemetrySink};

pub trait PortIo {
    fn inb(&self, port: u16) -> u8;
    fn inw(&self, port: u16) -> u16;
    fn inl(&self, port: u16) -> u32;
    fn outb(&self, port: u16, value: u8);
    fn outw(&self, port: u16, value: u16);
    fn outl(&self, port: u16, value: u32);
}

pub trait ResourcePolicy {
    fn mmio_read(&self, _base: usize, _offset: usize, _size: usize) -> Result<(), Error> {
        Err(Error::AccessDenied)
    }
    fn mmio_write(&self, _base: usize, _offset: usize, _size: usize) -> Result<(), Error> {
        Err(Error::AccessDenied)
    }
    fn port_read(&self, _base: u16, _offset: u16, _size: u16) -> Result<(), Error> {
        Err(Error::AccessDenied)
    }
    fn port_write(&self, _base: u16, _offset: u16, _size: u16) -> Result<(), Error> {
        Err(Error::AccessDenied)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MmioDesc {
    pub base: usize,
    pub size: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct IoPortDesc {
    pub port: u16,
    pub count: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceScope {
    pub driver_id: u64,
    pub iommu_domain: u32,
    pub binding_nonce: u32,
}

pub struct MmioRegion<DriverTag> {
    base: usize,
    size: usize,
    _tag: PhantomData<DriverTag>,
    _nosend: NotSendSync,
}

pub struct IoPortRange<DriverTag> {
    base: u16,
    count: u16,
    _tag: PhantomData<DriverTag>,
    _nosend: NotSendSync,
}

pub struct ResourceManifest<DriverTag, const MMIO: usize = 8, const PORTS: usize = 8> {
    scope: ResourceScope,
    mmio: [MmioDesc; MMIO],
    mmio_len: usize,
    ports: [IoPortDesc; PORTS],
    ports_len: usize,
    mmio_revoked: [bool; MMIO],
    ports_revoked: [bool; PORTS],
    _tag: PhantomData<DriverTag>,
    _nosend: NotSendSync,
}

impl<DriverTag, const MMIO: usize, const PORTS: usize> ResourceManifest<DriverTag, MMIO, PORTS> {
    /// Invariant: all regions are non-empty and indices are within fixed capacity.
    pub fn new(
        scope: ResourceScope,
        mmio: [MmioDesc; MMIO],
        mmio_len: usize,
        ports: [IoPortDesc; PORTS],
        ports_len: usize,
    ) -> Result<Self, Error> {
        if scope.driver_id == 0 || scope.iommu_domain == 0 {
            return Err(Error::InvalidState);
        }
        if mmio_len > MMIO || ports_len > PORTS {
            return Err(Error::InvalidAddress);
        }
        for idx in 0..mmio_len {
            if mmio[idx].size == 0 {
                return Err(Error::InvalidAddress);
            }
        }
        for idx in 0..ports_len {
            if ports[idx].count == 0 {
                return Err(Error::InvalidAddress);
            }
        }
        Ok(Self {
            scope,
            mmio,
            mmio_len,
            ports,
            ports_len,
            mmio_revoked: [false; MMIO],
            ports_revoked: [false; PORTS],
            _tag: PhantomData,
            _nosend: NotSendSync::new(),
        })
    }

    pub fn scope(&self) -> ResourceScope {
        self.scope
    }

    /// Invariant: returned region is bounded to the manifest whitelist.
    pub fn mmio_region(&self, index: usize) -> Result<MmioRegion<DriverTag>, Error> {
        if index >= self.mmio_len {
            return Err(Error::ResourceNotGranted);
        }
        if self.mmio_revoked[index] {
            return Err(Error::Revoked);
        }
        let desc = self.mmio[index];
        Ok(MmioRegion {
            base: desc.base,
            size: desc.size,
            _tag: PhantomData,
            _nosend: NotSendSync::new(),
        })
    }

    /// Invariant: returned port range is bounded to the manifest whitelist.
    pub fn io_port_range(&self, index: usize) -> Result<IoPortRange<DriverTag>, Error> {
        if index >= self.ports_len {
            return Err(Error::ResourceNotGranted);
        }
        if self.ports_revoked[index] {
            return Err(Error::Revoked);
        }
        let desc = self.ports[index];
        Ok(IoPortRange {
            base: desc.port,
            count: desc.count,
            _tag: PhantomData,
            _nosend: NotSendSync::new(),
        })
    }

    pub fn revoke_mmio(&mut self, index: usize) -> Result<(), Error> {
        if index >= self.mmio_len {
            return Err(Error::ResourceNotGranted);
        }
        self.mmio_revoked[index] = true;
        Ok(())
    }

    pub fn regrant_mmio(&mut self, index: usize) -> Result<(), Error> {
        if index >= self.mmio_len {
            return Err(Error::ResourceNotGranted);
        }
        self.mmio_revoked[index] = false;
        Ok(())
    }

    pub fn revoke_ports(&mut self, index: usize) -> Result<(), Error> {
        if index >= self.ports_len {
            return Err(Error::ResourceNotGranted);
        }
        self.ports_revoked[index] = true;
        Ok(())
    }

    pub fn regrant_ports(&mut self, index: usize) -> Result<(), Error> {
        if index >= self.ports_len {
            return Err(Error::ResourceNotGranted);
        }
        self.ports_revoked[index] = false;
        Ok(())
    }

    pub fn add_mmio(&mut self, desc: MmioDesc) -> Result<usize, Error> {
        if self.mmio_len >= MMIO || desc.size == 0 {
            return Err(Error::OutOfMemory);
        }
        let index = self.mmio_len;
        self.mmio[index] = desc;
        self.mmio_revoked[index] = false;
        self.mmio_len += 1;
        Ok(index)
    }

    pub fn remove_mmio(&mut self, index: usize) -> Result<(), Error> {
        if index >= self.mmio_len {
            return Err(Error::ResourceNotGranted);
        }
        self.mmio_revoked[index] = true;
        Ok(())
    }

    pub fn add_port_range(&mut self, desc: IoPortDesc) -> Result<usize, Error> {
        if self.ports_len >= PORTS || desc.count == 0 {
            return Err(Error::OutOfMemory);
        }
        let index = self.ports_len;
        self.ports[index] = desc;
        self.ports_revoked[index] = false;
        self.ports_len += 1;
        Ok(index)
    }

    pub fn remove_port_range(&mut self, index: usize) -> Result<(), Error> {
        if index >= self.ports_len {
            return Err(Error::ResourceNotGranted);
        }
        self.ports_revoked[index] = true;
        Ok(())
    }
}

impl<DriverTag> MmioRegion<DriverTag> {
    fn check(&self, offset: usize, size: usize) -> Result<usize, Error> {
        let end = offset.checked_add(size).unwrap_or(usize::MAX);
        if size == 0 || end > self.size {
            return Err(Error::OutOfBounds);
        }
        self.base.checked_add(offset).ok_or(Error::InvalidAddress)
    }

    pub fn read_u32<P: ResourcePolicy>(&self, policy: &P, offset: usize) -> Result<u32, Error> {
        policy.mmio_read(self.base, offset, core::mem::size_of::<u32>())?;
        let addr = self.check(offset, core::mem::size_of::<u32>())?;
        // SAFETY: `check` guarantees the address is within the granted MMIO window and aligned
        // for a `u32` access as provided by the caller's manifest region contract.
        Ok(unsafe { read_volatile(addr as *const u32) })
    }

    pub fn write_u32<P: ResourcePolicy>(
        &self,
        policy: &P,
        offset: usize,
        value: u32,
    ) -> Result<(), Error> {
        policy.mmio_write(self.base, offset, core::mem::size_of::<u32>())?;
        let addr = self.check(offset, core::mem::size_of::<u32>())?;
        // SAFETY: `check` guarantees the address is within the granted MMIO window and points to
        // writable MMIO that the manifest exposes for this driver.
        unsafe { write_volatile(addr as *mut u32, value) };
        Ok(())
    }
}

impl<DriverTag> IoPortRange<DriverTag> {
    fn port(&self, offset: u16) -> Result<u16, Error> {
        if offset >= self.count {
            return Err(Error::OutOfBounds);
        }
        self.base.checked_add(offset).ok_or(Error::InvalidAddress)
    }

    pub fn inb<P: PortIo, R: ResourcePolicy>(
        &self,
        io: &P,
        policy: &R,
        offset: u16,
    ) -> Result<u8, Error> {
        policy.port_read(self.base, offset, 1)?;
        Ok(io.inb(self.port(offset)?))
    }

    pub fn inw<P: PortIo, R: ResourcePolicy>(
        &self,
        io: &P,
        policy: &R,
        offset: u16,
    ) -> Result<u16, Error> {
        policy.port_read(self.base, offset, 2)?;
        Ok(io.inw(self.port(offset)?))
    }

    pub fn inl<P: PortIo, R: ResourcePolicy>(
        &self,
        io: &P,
        policy: &R,
        offset: u16,
    ) -> Result<u32, Error> {
        policy.port_read(self.base, offset, 4)?;
        Ok(io.inl(self.port(offset)?))
    }

    pub fn outb<P: PortIo, R: ResourcePolicy>(
        &self,
        io: &P,
        policy: &R,
        offset: u16,
        value: u8,
    ) -> Result<(), Error> {
        policy.port_write(self.base, offset, 1)?;
        io.outb(self.port(offset)?, value);
        Ok(())
    }

    pub fn outw<P: PortIo, R: ResourcePolicy>(
        &self,
        io: &P,
        policy: &R,
        offset: u16,
        value: u16,
    ) -> Result<(), Error> {
        policy.port_write(self.base, offset, 2)?;
        io.outw(self.port(offset)?, value);
        Ok(())
    }

    pub fn outl<P: PortIo, R: ResourcePolicy>(
        &self,
        io: &P,
        policy: &R,
        offset: u16,
        value: u32,
    ) -> Result<(), Error> {
        policy.port_write(self.base, offset, 4)?;
        io.outl(self.port(offset)?, value);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestSignature {
    pub key_id: u64,
    pub timestamp: u64,
    pub manifest_hash: [u8; 32],
    pub provenance_hash: Option<[u8; 32]>,
    pub device_attestation_hash: Option<[u8; 32]>,
}

pub trait ManifestValidator {
    fn validate(&self, signature: &ManifestSignature) -> Result<(), Error>;
}

pub trait RevocationList {
    fn is_revoked(&self, key_id: u64) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciInfo {
    pub vendor_id: u16,
    pub device_id: u16,
    pub function: u8,
    pub sriov_vfs: u16,
    pub msix_vectors: u16,
    pub msi_vectors: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciBar {
    pub raw: u32,
    pub base: u64,
    pub is_io: bool,
    pub is_64: bool,
    pub prefetchable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciFunctionDesc {
    pub info: PciInfo,
    pub bars: [PciBar; 6],
    pub bar_len: usize,
}

pub trait PciConfigAccess {
    fn read_u32(&self, bus: u8, device: u8, function: u8, offset: u8) -> u32;
    fn read_u16(&self, bus: u8, device: u8, function: u8, offset: u8) -> u16 {
        let word = self.read_u32(bus, device, function, offset & !0x3);
        let shift = ((offset & 0x2) as u32) * 8;
        ((word >> shift) & 0xffff) as u16
    }
    fn read_u8(&self, bus: u8, device: u8, function: u8, offset: u8) -> u8 {
        let word = self.read_u32(bus, device, function, offset & !0x3);
        let shift = ((offset & 0x3) as u32) * 8;
        ((word >> shift) & 0xff) as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciAddress {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

pub trait PciTopology {
    fn for_each_function(&self, f: &mut dyn FnMut(PciAddress));
}

pub struct FullPciScan;

impl PciTopology for FullPciScan {
    fn for_each_function(&self, f: &mut dyn FnMut(PciAddress)) {
        for bus in 0u8..=255 {
            for device in 0u8..32 {
                for function in 0u8..8 {
                    f(PciAddress {
                        bus,
                        device,
                        function,
                    });
                }
            }
        }
    }
}

pub trait KernelPciBridge {
    fn config(&self) -> &dyn PciConfigAccess;
    fn topology(&self) -> &dyn PciTopology;
}

pub fn discover_pci_functions<
    A: PciConfigAccess + ?Sized,
    T: PciTopology + ?Sized,
    const N: usize,
>(
    access: &A,
    topology: &T,
    out: &mut [PciFunctionDesc; N],
) -> Result<usize, Error> {
    let mut count = 0;
    topology.for_each_function(&mut |addr| {
        if count >= N {
            return;
        }
        if let Ok(desc) = parse_pci_function(access, addr.bus, addr.device, addr.function) {
            out[count] = desc;
            count += 1;
        }
    });
    if count == 0 {
        return Err(Error::ResourceNotGranted);
    }
    Ok(count)
}

pub fn discover_pci_topology<B: KernelPciBridge, const N: usize>(
    bridge: &B,
    out: &mut [PciFunctionDesc; N],
) -> Result<usize, Error> {
    discover_pci_functions(bridge.config(), bridge.topology(), out)
}

pub fn parse_pci_function<A: PciConfigAccess + ?Sized>(
    access: &A,
    bus: u8,
    device: u8,
    function: u8,
) -> Result<PciFunctionDesc, Error> {
    let id = access.read_u32(bus, device, function, 0x00);
    let vendor_id = (id & 0xffff) as u16;
    if vendor_id == 0xffff {
        return Err(Error::ResourceNotGranted);
    }
    let device_id = (id >> 16) as u16;
    let status = access.read_u16(bus, device, function, 0x06);
    let header = access.read_u8(bus, device, function, 0x0e);
    let header_type = header & 0x7f;
    let mut bars = [PciBar {
        raw: 0,
        base: 0,
        is_io: false,
        is_64: false,
        prefetchable: false,
    }; 6];
    let mut bar_len = if header_type == 0 { 6 } else { 2 };
    let mut index = 0;
    let mut bar_slot = 0;
    while index < bar_len && bar_slot < 6 {
        let offset = 0x10 + (index * 4) as u8;
        let raw = access.read_u32(bus, device, function, offset);
        if raw == 0 {
            bars[bar_slot] = PciBar {
                raw,
                base: 0,
                is_io: (raw & 0x1) == 0x1,
                is_64: false,
                prefetchable: false,
            };
            index += 1;
            bar_slot += 1;
            continue;
        }
        if (raw & 0x1) == 0x1 {
            bars[bar_slot] = PciBar {
                raw,
                base: (raw & 0xffff_fffc) as u64,
                is_io: true,
                is_64: false,
                prefetchable: false,
            };
            index += 1;
            bar_slot += 1;
            continue;
        }
        let mem_type = (raw >> 1) & 0x3;
        let is_64 = mem_type == 0x2;
        let prefetchable = (raw & 0x8) != 0;
        let mut base = (raw & 0xffff_fff0) as u64;
        if is_64 && index + 1 < bar_len {
            let hi = access.read_u32(bus, device, function, offset + 4);
            base |= (hi as u64) << 32;
            index += 2;
        } else {
            index += 1;
        }
        bars[bar_slot] = PciBar {
            raw,
            base,
            is_io: false,
            is_64,
            prefetchable,
        };
        bar_slot += 1;
    }
    bar_len = bar_slot;
    let mut msix_vectors = 0u16;
    let mut msi_vectors = 0u16;
    if (status & 0x10) != 0 {
        let mut cap_ptr = access.read_u8(bus, device, function, 0x34);
        let mut guard = 0;
        while cap_ptr >= 0x40 && guard < 32 {
            let cap_id = access.read_u8(bus, device, function, cap_ptr);
            let next = access.read_u8(bus, device, function, cap_ptr + 1);
            if cap_id == 0x05 {
                let ctrl = access.read_u16(bus, device, function, cap_ptr + 2);
                let exp = ((ctrl >> 1) & 0x7) as u16;
                msi_vectors = 1u16 << exp;
            } else if cap_id == 0x11 {
                let ctrl = access.read_u16(bus, device, function, cap_ptr + 2);
                msix_vectors = (ctrl & 0x7ff).saturating_add(1);
            }
            if next == 0 {
                break;
            }
            cap_ptr = next;
            guard += 1;
        }
    }
    Ok(PciFunctionDesc {
        info: PciInfo {
            vendor_id,
            device_id,
            function,
            sriov_vfs: 0,
            msix_vectors,
            msi_vectors,
        },
        bars,
        bar_len,
    })
}

pub fn parse_pci_functions<A: PciConfigAccess, const N: usize>(
    access: &A,
    bus: u8,
    device: u8,
    out: &mut [PciFunctionDesc; N],
) -> Result<usize, Error> {
    let mut count = 0;
    let header = access.read_u8(bus, device, 0, 0x0e);
    let multifunction = (header & 0x80) != 0;
    let functions = if multifunction { 8 } else { 1 };
    for function in 0..functions {
        if count >= N {
            break;
        }
        if let Ok(desc) = parse_pci_function(access, bus, device, function) {
            out[count] = desc;
            count += 1;
        }
    }
    if count == 0 {
        return Err(Error::ResourceNotGranted);
    }
    Ok(count)
}

impl<DriverTag, const MMIO: usize, const PORTS: usize> ResourceManifest<DriverTag, MMIO, PORTS> {
    pub fn canonical_len(&self) -> usize {
        8 + 4 + 4 + 2 + 2 + (self.mmio_len * 17) + (self.ports_len * 5)
    }

    pub fn write_canonical(&self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < self.canonical_len() {
            return Err(Error::OutOfMemory);
        }
        let mut cursor = 0;
        out[cursor..cursor + 8].copy_from_slice(&self.scope.driver_id.to_le_bytes());
        cursor += 8;
        out[cursor..cursor + 4].copy_from_slice(&self.scope.iommu_domain.to_le_bytes());
        cursor += 4;
        out[cursor..cursor + 4].copy_from_slice(&self.scope.binding_nonce.to_le_bytes());
        cursor += 4;
        out[cursor..cursor + 2].copy_from_slice(&(self.mmio_len as u16).to_le_bytes());
        cursor += 2;
        out[cursor..cursor + 2].copy_from_slice(&(self.ports_len as u16).to_le_bytes());
        cursor += 2;
        for idx in 0..self.mmio_len {
            out[cursor..cursor + 8].copy_from_slice(&(self.mmio[idx].base as u64).to_le_bytes());
            cursor += 8;
            out[cursor..cursor + 8].copy_from_slice(&(self.mmio[idx].size as u64).to_le_bytes());
            cursor += 8;
            out[cursor] = self.mmio_revoked[idx] as u8;
            cursor += 1;
        }
        for idx in 0..self.ports_len {
            out[cursor..cursor + 2].copy_from_slice(&self.ports[idx].port.to_le_bytes());
            cursor += 2;
            out[cursor..cursor + 2].copy_from_slice(&self.ports[idx].count.to_le_bytes());
            cursor += 2;
            out[cursor] = self.ports_revoked[idx] as u8;
            cursor += 1;
        }
        Ok(cursor)
    }

    pub fn compute_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.scope.driver_id.to_le_bytes());
        hasher.update(&self.scope.iommu_domain.to_le_bytes());
        hasher.update(&self.scope.binding_nonce.to_le_bytes());
        hasher.update(&(self.mmio_len as u16).to_le_bytes());
        hasher.update(&(self.ports_len as u16).to_le_bytes());
        for idx in 0..self.mmio_len {
            hasher.update(&(self.mmio[idx].base as u64).to_le_bytes());
            hasher.update(&(self.mmio[idx].size as u64).to_le_bytes());
            hasher.update(&[self.mmio_revoked[idx] as u8]);
        }
        for idx in 0..self.ports_len {
            hasher.update(&self.ports[idx].port.to_le_bytes());
            hasher.update(&self.ports[idx].count.to_le_bytes());
            hasher.update(&[self.ports_revoked[idx] as u8]);
        }
        hasher.finalize()
    }

    pub fn validate_signature<V: ManifestValidator, R: RevocationList>(
        &self,
        signature: &ManifestSignature,
        validator: &V,
        revoked: &R,
    ) -> Result<(), Error> {
        if revoked.is_revoked(signature.key_id) {
            return Err(Error::SignatureInvalid);
        }
        let expected = self.compute_hash();
        if expected != signature.manifest_hash {
            return Err(Error::SignatureInvalid);
        }
        validator.validate(signature)
    }

    pub fn validate_signature_with_hooks<
        V: ManifestValidator,
        R: RevocationList,
        T: TelemetrySink,
        A: AuditSink,
    >(
        &self,
        signature: &ManifestSignature,
        validator: &V,
        revoked: &R,
        telemetry: &T,
        audit: &A,
    ) -> Result<(), Error> {
        if revoked.is_revoked(signature.key_id) {
            telemetry.record(TelemetryEvent::Error(Error::SignatureInvalid));
            audit.record(AuditEvent::ManifestRejected);
            return Err(Error::SignatureInvalid);
        }
        let expected = self.compute_hash();
        if expected != signature.manifest_hash {
            telemetry.record(TelemetryEvent::Error(Error::SignatureInvalid));
            audit.record(AuditEvent::ManifestRejected);
            return Err(Error::SignatureInvalid);
        }
        validator.validate(signature)?;
        audit.record(AuditEvent::ManifestValidated);
        Ok(())
    }
}

pub fn parse_manifest_blob<DriverTag, const MMIO: usize, const PORTS: usize>(
    bytes: &[u8],
) -> Result<ResourceManifest<DriverTag, MMIO, PORTS>, Error> {
    if bytes.len() < 24 || &bytes[..4] != b"ISM2" {
        return Err(Error::InvalidAddress);
    }
    let driver_id = u64::from_le_bytes([
        bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
    ]);
    let iommu_domain = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let binding_nonce = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let mmio_len = u16::from_le_bytes([bytes[20], bytes[21]]) as usize;
    let ports_len = u16::from_le_bytes([bytes[22], bytes[23]]) as usize;
    let mut cursor = 24;
    if mmio_len > MMIO || ports_len > PORTS {
        return Err(Error::InvalidAddress);
    }
    let mut mmio = [MmioDesc { base: 0, size: 0 }; MMIO];
    for idx in 0..mmio_len {
        if cursor + 16 > bytes.len() {
            return Err(Error::InvalidAddress);
        }
        let base = u64::from_le_bytes([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
            bytes[cursor + 4],
            bytes[cursor + 5],
            bytes[cursor + 6],
            bytes[cursor + 7],
        ]) as usize;
        let size = u64::from_le_bytes([
            bytes[cursor + 8],
            bytes[cursor + 9],
            bytes[cursor + 10],
            bytes[cursor + 11],
            bytes[cursor + 12],
            bytes[cursor + 13],
            bytes[cursor + 14],
            bytes[cursor + 15],
        ]) as usize;
        mmio[idx] = MmioDesc { base, size };
        cursor += 16;
    }
    let mut ports = [IoPortDesc { port: 0, count: 0 }; PORTS];
    for idx in 0..ports_len {
        if cursor + 4 > bytes.len() {
            return Err(Error::InvalidAddress);
        }
        let port = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]);
        let count = u16::from_le_bytes([bytes[cursor + 2], bytes[cursor + 3]]);
        ports[idx] = IoPortDesc { port, count };
        cursor += 4;
    }
    ResourceManifest::new(
        ResourceScope {
            driver_id,
            iommu_domain,
            binding_nonce,
        },
        mmio,
        mmio_len,
        ports,
        ports_len,
    )
}
