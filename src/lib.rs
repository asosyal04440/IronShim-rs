#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

mod dma;
mod driver;
mod interrupt;
mod resource;

use core::marker::PhantomData;
use core::mem::{align_of, size_of};
#[cfg(feature = "alloc")]
use alloc::rc::Rc;
#[cfg(not(feature = "alloc"))]
use core::cell::Cell;

pub type PhysAddr = usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    OutOfMemory,
    InvalidAddress,
    ResourceNotGranted,
    InterruptInUse,
    AccessDenied,
    OutOfBounds,
    BudgetExceeded,
    Quarantined,
    Revoked,
    InvalidState,
    SignatureInvalid,
    RateLimited,
    Timeout,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    Recoverable,
    Fatal,
}

impl Error {
    pub fn class(&self) -> ErrorClass {
        match self {
            Error::OutOfMemory
            | Error::InvalidAddress
            | Error::InterruptInUse
            | Error::SignatureInvalid
            | Error::Unsupported => ErrorClass::Fatal,
            Error::ResourceNotGranted
            | Error::AccessDenied
            | Error::OutOfBounds
            | Error::BudgetExceeded
            | Error::Quarantined
            | Error::Revoked
            | Error::InvalidState
            | Error::RateLimited
            | Error::Timeout => ErrorClass::Recoverable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryEvent {
    Error(Error),
    Quarantine(u32),
    BudgetExceeded(u32),
    Revocation(u32),
}

pub trait TelemetrySink {
    fn record(&self, event: TelemetryEvent);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEvent {
    ManifestValidated,
    ManifestRejected,
    PatternApplied,
    UpdateRejected,
    WorkQueueOverflow,
    SyscallDenied(u32),
    SyscallAllowed(u32),
}

pub trait AuditSink {
    fn record(&self, event: AuditEvent);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallRequest {
    pub number: u32,
    pub args: [usize; 6],
}

pub trait SyscallPolicy {
    fn check(&self, request: &SyscallRequest) -> Result<(), Error>;
}

pub fn enforce_syscall<P: SyscallPolicy, A: AuditSink>(
    policy: &P,
    audit: &A,
    request: &SyscallRequest,
) -> Result<(), Error> {
    match policy.check(request) {
        Ok(()) => {
            audit.record(AuditEvent::SyscallAllowed(request.number));
            Ok(())
        }
        Err(err) => {
            audit.record(AuditEvent::SyscallDenied(request.number));
            Err(err)
        }
    }
}

pub const ABI_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbiFeatures {
    pub bits: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverAbiDescriptor {
    pub version: u32,
    pub features: AbiFeatures,
    pub struct_size: usize,
    pub struct_align: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbiVersionRange {
    pub min: u32,
    pub max: u32,
}

pub trait DriverAbi {
    const VERSION: u32;
    const FEATURES: AbiFeatures;
}

pub fn validate_abi<T: DriverAbi>(expected_version: u32, required: AbiFeatures) -> Result<(), Error> {
    if T::VERSION != expected_version {
        return Err(Error::InvalidState);
    }
    if (T::FEATURES.bits & required.bits) != required.bits {
        return Err(Error::Unsupported);
    }
    Ok(())
}

pub fn validate_layout(actual_size: usize, actual_align: usize, expected_size: usize, expected_align: usize) -> Result<(), Error> {
    if actual_size != expected_size || actual_align != expected_align {
        return Err(Error::InvalidAddress);
    }
    Ok(())
}

pub fn validate_bindgen_layout<T>(expected_size: usize, expected_align: usize) -> Result<(), Error> {
    validate_layout(size_of::<T>(), align_of::<T>(), expected_size, expected_align)
}

pub fn validate_driver_abi<T: DriverAbi>(descriptor: DriverAbiDescriptor) -> Result<(), Error> {
    validate_abi::<T>(descriptor.version, descriptor.features)?;
    validate_bindgen_layout::<T>(descriptor.struct_size, descriptor.struct_align)?;
    Ok(())
}

pub fn validate_abi_range(version: u32, range: AbiVersionRange) -> Result<(), Error> {
    if version < range.min || version > range.max {
        return Err(Error::InvalidState);
    }
    Ok(())
}

pub fn validate_driver_abi_compat<T: DriverAbi>(
    descriptor: DriverAbiDescriptor,
    range: AbiVersionRange,
    required: AbiFeatures,
) -> Result<(), Error> {
    validate_abi::<T>(descriptor.version, required)?;
    validate_abi_range(descriptor.version, range)?;
    validate_bindgen_layout::<T>(descriptor.struct_size, descriptor.struct_align)?;
    Ok(())
}

#[cfg(feature = "alloc")]
pub(crate) struct NotSendSync(PhantomData<Rc<()>>);

#[cfg(not(feature = "alloc"))]
pub(crate) struct NotSendSync(PhantomData<Cell<()>>);

impl NotSendSync {
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

pub use dma::{
    DmaAllocator, DmaConstraints, DmaHandle, DmaMapper, DmaMemoryType, DmaPin, DmaScatterList,
    DmaSync, ScatterEntry,
};
pub use driver::{Driver, DriverContext, DriverLifecycle, DriverState, SandboxProfile};
pub use interrupt::{
    DeferredWork, InterruptBudget, InterruptHandler, InterruptMetrics, InterruptRegistry, WorkQueue,
};
pub use resource::{
    discover_pci_functions, discover_pci_topology, parse_manifest_blob, parse_pci_function,
    parse_pci_functions, AllowAllPolicy, FullPciScan, IoPortDesc, IoPortRange, KernelPciBridge,
    ManifestSignature, ManifestValidator, MmioDesc, MmioRegion, PciAddress, PciBar,
    PciConfigAccess, PciFunctionDesc, PciInfo, PciTopology, PortIo, ResourceManifest,
    ResourcePolicy, RevocationList,
};

#[cfg(feature = "fuzzing")]
pub mod fuzzing {
    use crate::parse_manifest_blob;

    pub fn manifest(bytes: &[u8]) {
        let _ = parse_manifest_blob::<(), 8, 8>(bytes);
    }

    struct ByteConfig<'a> {
        data: &'a [u8],
    }

    impl<'a> crate::PciConfigAccess for ByteConfig<'a> {
        fn read_u32(&self, bus: u8, device: u8, function: u8, offset: u8) -> u32 {
            if self.data.is_empty() {
                return 0;
            }
            let idx = bus as usize ^ (device as usize).wrapping_shl(8) ^ (function as usize).wrapping_shl(4);
            let base = idx.wrapping_add(offset as usize) % self.data.len();
            let mut buf = [0u8; 4];
            for (i, slot) in buf.iter_mut().enumerate() {
                *slot = self.data[(base + i) % self.data.len()];
            }
            u32::from_le_bytes(buf)
        }
    }

    pub fn pci(bytes: &[u8]) {
        let cfg = ByteConfig { data: bytes };
        let _ = crate::parse_pci_function(&cfg, 0, 0, 0);
    }
}

pub mod crypto {
    pub struct Sha256 {
        state: [u32; 8],
        buffer: [u8; 64],
        buffer_len: usize,
        total_len: u64,
    }

    impl Sha256 {
        pub fn new() -> Self {
            Self {
                state: [
                    0x6a09e667,
                    0xbb67ae85,
                    0x3c6ef372,
                    0xa54ff53a,
                    0x510e527f,
                    0x9b05688c,
                    0x1f83d9ab,
                    0x5be0cd19,
                ],
                buffer: [0; 64],
                buffer_len: 0,
                total_len: 0,
            }
        }

        pub fn update(&mut self, data: &[u8]) {
            let mut offset = 0;
            self.total_len = self.total_len.wrapping_add(data.len() as u64);
            if self.buffer_len > 0 {
                let remaining = 64 - self.buffer_len;
                let take = remaining.min(data.len());
                self.buffer[self.buffer_len..self.buffer_len + take]
                    .copy_from_slice(&data[..take]);
                self.buffer_len += take;
                offset += take;
                if self.buffer_len == 64 {
                    compress(&mut self.state, &self.buffer);
                    self.buffer_len = 0;
                }
            }
            while offset + 64 <= data.len() {
                compress(&mut self.state, &data[offset..offset + 64]);
                offset += 64;
            }
            if offset < data.len() {
                let remaining = data.len() - offset;
                self.buffer[..remaining].copy_from_slice(&data[offset..]);
                self.buffer_len = remaining;
            }
        }

        pub fn finalize(mut self) -> [u8; 32] {
            let bit_len = self.total_len.wrapping_mul(8);
            self.buffer[self.buffer_len] = 0x80;
            self.buffer_len += 1;
            if self.buffer_len > 56 {
                for b in self.buffer[self.buffer_len..].iter_mut() {
                    *b = 0;
                }
                compress(&mut self.state, &self.buffer);
                self.buffer_len = 0;
            }
            for b in self.buffer[self.buffer_len..56].iter_mut() {
                *b = 0;
            }
            self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
            compress(&mut self.state, &self.buffer);
            let mut out = [0u8; 32];
            for (i, chunk) in out.chunks_mut(4).enumerate() {
                chunk.copy_from_slice(&self.state[i].to_be_bytes());
            }
            out
        }

        pub fn digest(data: &[u8]) -> [u8; 32] {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize()
        }
    }

    pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut key_block = [0u8; 64];
        if key.len() > 64 {
            let digest = Sha256::digest(key);
            key_block[..32].copy_from_slice(&digest);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for i in 0..64 {
            ipad[i] ^= key_block[i];
            opad[i] ^= key_block[i];
        }
        let mut inner = Sha256::new();
        inner.update(&ipad);
        inner.update(data);
        let inner_hash = inner.finalize();
        let mut outer = Sha256::new();
        outer.update(&opad);
        outer.update(&inner_hash);
        outer.finalize()
    }

    fn compress(state: &mut [u32; 8], block: &[u8]) {
        let mut w = [0u32; 64];
        for (i, chunk) in block.chunks(4).enumerate().take(16) {
            w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    const K: [u32; 64] = [
        0x428a2f98,
        0x71374491,
        0xb5c0fbcf,
        0xe9b5dba5,
        0x3956c25b,
        0x59f111f1,
        0x923f82a4,
        0xab1c5ed5,
        0xd807aa98,
        0x12835b01,
        0x243185be,
        0x550c7dc3,
        0x72be5d74,
        0x80deb1fe,
        0x9bdc06a7,
        0xc19bf174,
        0xe49b69c1,
        0xefbe4786,
        0x0fc19dc6,
        0x240ca1cc,
        0x2de92c6f,
        0x4a7484aa,
        0x5cb0a9dc,
        0x76f988da,
        0x983e5152,
        0xa831c66d,
        0xb00327c8,
        0xbf597fc7,
        0xc6e00bf3,
        0xd5a79147,
        0x06ca6351,
        0x14292967,
        0x27b70a85,
        0x2e1b2138,
        0x4d2c6dfc,
        0x53380d13,
        0x650a7354,
        0x766a0abb,
        0x81c2c92e,
        0x92722c85,
        0xa2bfe8a1,
        0xa81a664b,
        0xc24b8b70,
        0xc76c51a3,
        0xd192e819,
        0xd6990624,
        0xf40e3585,
        0x106aa070,
        0x19a4c116,
        0x1e376c08,
        0x2748774c,
        0x34b0bcb5,
        0x391c0cb3,
        0x4ed8aa4a,
        0x5b9cca4f,
        0x682e6ff3,
        0x748f82ee,
        0x78a5636f,
        0x84c87814,
        0x8cc70208,
        0x90befffa,
        0xa4506ceb,
        0xbef9a3f7,
        0xc67178f2,
    ];
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
