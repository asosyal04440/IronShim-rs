use crate::mock::{MockDmaAllocator, MockInterruptRegistry};
use crate::{
    crypto::{hmac_sha256, Sha256},
    enforce_syscall, AuditEvent, AuditSink, AllowAllPolicy, AbiFeatures, AbiVersionRange,
    DmaAllocator, DmaConstraints, DmaScatterList, DriverAbiDescriptor, Error, InterruptBudget,
    InterruptHandler, InterruptRegistry, MmioDesc, ResourceManifest, ResourcePolicy,
    SyscallPolicy, SyscallRequest,
};
use std::string::String;
use std::boxed::Box;
use std::sync::atomic::{AtomicU32, Ordering};
use std::vec;

struct DriverTag;

struct DenyPolicy;

impl ResourcePolicy for DenyPolicy {
    fn mmio_read(&self, _base: usize, _offset: usize, _size: usize) -> Result<(), Error> {
        Err(Error::AccessDenied)
    }
}

#[test]
fn patched_driver_unauthorized_mmio_is_blocked() {
    let mut mmio = vec![0u32; 4];
    let base = mmio.as_mut_ptr() as usize;
    let manifest = ResourceManifest::<DriverTag, 1, 0>::new(
        [MmioDesc { base, size: 16 }],
        1,
        [],
        0,
    )
    .unwrap();

    let region = manifest.mmio_region(0).unwrap();
    let result = region.read_u32(&DenyPolicy, 0);
    assert_eq!(result, Err(Error::AccessDenied));
}

#[test]
fn dma_alloc_and_write() {
    let allocator = MockDmaAllocator::new(1024, 0x1000_0000);
    let mut handle = allocator.alloc::<u32>(4).unwrap();
    handle[0] = 10;
    handle[3] = 42;
    assert_eq!(handle.phys(), 0x1000_0000);
    assert_eq!(handle[3], 42);
}

#[test]
fn dma_scatter_list_collects_segments() {
    let allocator = MockDmaAllocator::new(1024, 0x2000_0000);
    let handle_a = allocator.alloc::<u32>(2).unwrap();
    let handle_b = allocator.alloc::<u32>(4).unwrap();
    let constraints = DmaConstraints {
        alignment: 4,
        max_segments: 4,
        boundary_mask: 0,
        max_bytes: 64,
    };
    let mut list: DmaScatterList<'_, u32, _, 4> = DmaScatterList::with_constraints(constraints);
    list.push(handle_a).unwrap();
    list.push(handle_b).unwrap();
    assert_eq!(list.len(), 2);
    let first = list.segment(0).unwrap();
    let second = list.segment(1).unwrap();
    assert_eq!(first.phys, 0x2000_0000);
    assert_eq!(second.count, 4);
}

static SEEN: AtomicU32 = AtomicU32::new(0);

struct TestHandler;

impl InterruptHandler for TestHandler {
    fn handle(&mut self, irq: u32) -> Result<(), Error> {
        SEEN.store(irq, Ordering::SeqCst);
        Ok(())
    }
}

#[test]
fn interrupt_registry_triggers_handler() {
    let registry = MockInterruptRegistry::new(8);
    let handler = Box::leak(Box::new(TestHandler));

    registry
        .register_with_budget(3, handler, InterruptBudget { max_ticks: 10, max_calls: 2 })
        .unwrap();
    registry.trigger_with_budget(3, 1).unwrap();
    assert_eq!(SEEN.load(Ordering::SeqCst), 3);
}

#[test]
fn interrupt_budget_quarantines_on_overuse() {
    let registry = MockInterruptRegistry::new(4);
    let handler = Box::leak(Box::new(TestHandler));
    registry
        .register_with_budget(1, handler, InterruptBudget { max_ticks: 1, max_calls: 1 })
        .unwrap();
    assert!(registry.trigger_with_budget(1, 1).is_ok());
    assert_eq!(registry.trigger_with_budget(1, 1), Err(Error::BudgetExceeded));
}

#[test]
fn mmio_access_with_allow_policy() {
    let mut mmio = vec![0u32; 4];
    let base = mmio.as_mut_ptr() as usize;
    let manifest = ResourceManifest::<DriverTag, 1, 0>::new(
        [MmioDesc { base, size: 16 }],
        1,
        [],
        0,
    )
    .unwrap();
    let region = manifest.mmio_region(0).unwrap();
    assert!(region.write_u32(&AllowAllPolicy, 0, 5).is_ok());
    let value = region.read_u32(&AllowAllPolicy, 0).unwrap();
    assert_eq!(value, 5);
}

#[test]
fn abi_range_rejects_out_of_bounds() {
    struct TestAbi;
    impl crate::DriverAbi for TestAbi {
        const VERSION: u32 = 3;
        const FEATURES: AbiFeatures = AbiFeatures { bits: 0 };
    }
    let descriptor = DriverAbiDescriptor {
        version: 3,
        features: AbiFeatures { bits: 0 },
        struct_size: 8,
        struct_align: 8,
    };
    let range = AbiVersionRange { min: 1, max: 2 };
    let result = crate::validate_driver_abi_compat::<TestAbi>(descriptor, range, AbiFeatures { bits: 0 });
    assert_eq!(result, Err(Error::InvalidState));
}

#[test]
fn sha256_and_hmac_are_deterministic() {
    let digest = Sha256::digest(b"abc");
    let hex = to_hex(&digest);
    assert_eq!(
        hex,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let key = [0x0b; 20];
    let sig = hmac_sha256(&key, b"Hi There");
    let sig_hex = to_hex(&sig);
    assert_eq!(
        sig_hex,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
}

struct DenyOddSyscalls;

impl SyscallPolicy for DenyOddSyscalls {
    fn check(&self, request: &SyscallRequest) -> Result<(), Error> {
        if request.number % 2 == 1 {
            Err(Error::AccessDenied)
        } else {
            Ok(())
        }
    }
}

struct CountingAudit {
    allowed: AtomicU32,
    denied: AtomicU32,
}

impl CountingAudit {
    fn new() -> Self {
        Self {
            allowed: AtomicU32::new(0),
            denied: AtomicU32::new(0),
        }
    }
}

impl AuditSink for CountingAudit {
    fn record(&self, event: AuditEvent) {
        match event {
            AuditEvent::SyscallAllowed(_) => {
                self.allowed.fetch_add(1, Ordering::SeqCst);
            }
            AuditEvent::SyscallDenied(_) => {
                self.denied.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
    }
}

#[test]
fn syscall_policy_records_audit() {
    let policy = DenyOddSyscalls;
    let audit = CountingAudit::new();
    let even = SyscallRequest {
        number: 2,
        args: [0; 6],
    };
    let odd = SyscallRequest {
        number: 3,
        args: [0; 6],
    };
    assert!(enforce_syscall(&policy, &audit, &even).is_ok());
    assert_eq!(
        enforce_syscall(&policy, &audit, &odd),
        Err(Error::AccessDenied)
    );
    assert_eq!(audit.allowed.load(Ordering::SeqCst), 1);
    assert_eq!(audit.denied.load(Ordering::SeqCst), 1);
}

#[cfg(miri)]
#[test]
fn miri_manifest_parsing_is_total() {
    let bytes = [0u8; 64];
    let _ = crate::parse_manifest_blob::<DriverTag, 1, 1>(&bytes);
}

fn to_hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(feature = "loom")]
mod loom_tests {
    use loom::sync::atomic::{AtomicU32, Ordering};
    use loom::sync::Arc;
    use loom::thread;

    #[test]
    fn loom_budget_visibility() {
        loom::model(|| {
            let shared = Arc::new(AtomicU32::new(0));
            let shared_worker = Arc::clone(&shared);
            let t = thread::spawn(move || {
                shared_worker.store(u32::MAX, Ordering::SeqCst);
            });
            t.join().unwrap();
            assert_eq!(shared.load(Ordering::SeqCst), u32::MAX);
        });
    }
}
