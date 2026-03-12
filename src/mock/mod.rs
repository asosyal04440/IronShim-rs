use core::cell::Cell;
use core::ptr::NonNull;

use crate::{
    DmaAllocator, DmaHandle, Error, InterruptBudget, InterruptHandler, InterruptMetrics,
    InterruptRegistry, PhysAddr, QuarantineReason, ResourcePolicy,
};

use std::boxed::Box;
use std::cell::RefCell;
use std::vec;
use std::vec::Vec;

pub struct MockDmaAllocator {
    buffer: Box<[u8]>,
    cursor: Cell<usize>,
    phys_base: PhysAddr,
}

impl MockDmaAllocator {
    pub fn new(size: usize, phys_base: PhysAddr) -> Self {
        Self {
            buffer: vec![0u8; size].into_boxed_slice(),
            cursor: Cell::new(0),
            phys_base,
        }
    }

    fn align_up(value: usize, align: usize) -> usize {
        let mask = align - 1;
        (value + mask) & !mask
    }
}

impl DmaAllocator for MockDmaAllocator {
    fn alloc<T>(&self, count: usize) -> Result<DmaHandle<'_, T, Self>, Error> {
        let size = core::mem::size_of::<T>()
            .checked_mul(count)
            .ok_or(Error::OutOfMemory)?;
        let align = core::mem::align_of::<T>().max(1);
        let offset = Self::align_up(self.cursor.get(), align);
        let end = offset.checked_add(size).ok_or(Error::OutOfMemory)?;
        if end > self.buffer.len() {
            return Err(Error::OutOfMemory);
        }
        self.cursor.set(end);
        // SAFETY: `offset..end` has been bounds-checked against `buffer`, and the returned pointer
        // is used as an owned DMA allocation with `count * size_of::<T>()` bytes.
        let ptr = unsafe { self.buffer.as_ptr().add(offset) as *mut T };
        let phys = self.phys_base + offset;
        DmaHandle::from_raw(self, ptr, phys, count)
    }

    fn free<T>(&self, _phys: PhysAddr, _count: usize) {}
}

pub struct AllowAllPolicy;

impl ResourcePolicy for AllowAllPolicy {
    fn mmio_read(&self, _base: usize, _offset: usize, _size: usize) -> Result<(), Error> {
        Ok(())
    }

    fn mmio_write(&self, _base: usize, _offset: usize, _size: usize) -> Result<(), Error> {
        Ok(())
    }

    fn port_read(&self, _base: u16, _offset: u16, _size: u16) -> Result<(), Error> {
        Ok(())
    }

    fn port_write(&self, _base: u16, _offset: u16, _size: u16) -> Result<(), Error> {
        Ok(())
    }
}

pub struct MockInterruptRegistry {
    table: RefCell<Vec<InterruptSlot>>,
}

#[derive(Clone, Copy)]
struct InterruptSlot {
    handler: Option<NonNull<dyn InterruptHandler>>,
    budget: InterruptBudget,
    calls: u32,
    quarantined: bool,
    metrics: InterruptMetrics,
}

impl MockInterruptRegistry {
    pub fn new(size: usize) -> Self {
        Self {
            table: RefCell::new(vec![
                InterruptSlot {
                    handler: None,
                    budget: InterruptBudget::unlimited(),
                    calls: 0,
                    quarantined: false,
                    metrics: InterruptMetrics {
                        latency_ticks: 0,
                        missed: 0,
                        irq_calls: 0,
                        deferred_runs: 0,
                        dma_map_ops: 0,
                        dma_unmap_ops: 0,
                        budget_violations: 0,
                        quarantine_reason: None,
                    },
                };
                size
            ]),
        }
    }
}

impl InterruptRegistry for MockInterruptRegistry {
    fn register(&self, irq: u32, handler: &'static mut dyn InterruptHandler) -> Result<(), Error> {
        self.register_with_budget(irq, handler, InterruptBudget::unlimited())
    }

    fn register_with_budget(
        &self,
        irq: u32,
        handler: &'static mut dyn InterruptHandler,
        budget: InterruptBudget,
    ) -> Result<(), Error> {
        let mut table = self.table.borrow_mut();
        let index = irq as usize;
        if index >= table.len() {
            return Err(Error::InvalidAddress);
        }
        if table[index].handler.is_some() {
            return Err(Error::InterruptInUse);
        }
        table[index].handler = Some(NonNull::from(handler));
        table[index].budget = budget;
        table[index].calls = 0;
        table[index].quarantined = false;
        Ok(())
    }

    fn unregister(&self, irq: u32) -> Result<(), Error> {
        let mut table = self.table.borrow_mut();
        let index = irq as usize;
        if index >= table.len() {
            return Err(Error::InvalidAddress);
        }
        table[index].handler = None;
        Ok(())
    }

    fn trigger(&self, irq: u32) -> Result<(), Error> {
        self.trigger_with_budget(irq, 0)
    }

    fn trigger_with_budget(&self, irq: u32, elapsed_ticks: u32) -> Result<(), Error> {
        let mut table = self.table.borrow_mut();
        let index = irq as usize;
        if index >= table.len() {
            return Err(Error::InvalidAddress);
        }
        let slot = &mut table[index];
        if slot.quarantined {
            return Err(Error::Quarantined);
        }
        if slot.calls >= slot.budget.max_calls || elapsed_ticks > slot.budget.max_ticks {
            slot.quarantined = true;
            slot.metrics.budget_violations = slot.metrics.budget_violations.saturating_add(1);
            slot.metrics.quarantine_reason = Some(if elapsed_ticks > slot.budget.max_ticks {
                QuarantineReason::TimeoutFault
            } else {
                QuarantineReason::BudgetExceeded
            });
            return Err(Error::BudgetExceeded);
        }
        let mut handler = slot.handler.ok_or(Error::ResourceNotGranted)?;
        // SAFETY: the slot stores the unique leaked handler pointer registered for this IRQ and we
        // borrow it mutably only for the duration of this dispatch.
        let result = unsafe { handler.as_mut().handle(irq) };
        slot.calls = slot.calls.saturating_add(1);
        slot.metrics.irq_calls = slot.metrics.irq_calls.saturating_add(1);
        slot.metrics.latency_ticks = elapsed_ticks;
        if result.is_err() {
            slot.quarantined = true;
            slot.metrics.quarantine_reason = Some(QuarantineReason::HandlerFault);
            return Err(Error::Quarantined);
        }
        Ok(())
    }

    fn unquarantine(&self, irq: u32) -> Result<(), Error> {
        let mut table = self.table.borrow_mut();
        let index = irq as usize;
        if index >= table.len() {
            return Err(Error::InvalidAddress);
        }
        table[index].quarantined = false;
        table[index].calls = 0;
        table[index].metrics.quarantine_reason = None;
        Ok(())
    }

    fn metrics(&self, irq: u32) -> Result<InterruptMetrics, Error> {
        let table = self.table.borrow();
        let index = irq as usize;
        if index >= table.len() {
            return Err(Error::InvalidAddress);
        }
        Ok(table[index].metrics)
    }
}
