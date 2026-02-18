use core::ptr::NonNull;

use crate::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptBudget {
    pub max_ticks: u32,
    pub max_calls: u32,
}

impl InterruptBudget {
    pub const fn unlimited() -> Self {
        Self {
            max_ticks: u32::MAX,
            max_calls: u32::MAX,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptMetrics {
    pub latency_ticks: u32,
    pub missed: u32,
    pub budget_violations: u32,
}

pub trait InterruptHandler {
    /// Invariant: handler must not escape into kernel IDT without registry checks.
    fn handle(&mut self, irq: u32) -> Result<(), Error>;
}

pub trait InterruptRegistry {
    /// Invariant: a given IRQ can be registered by only one handler.
    fn register(&self, irq: u32, handler: &'static mut dyn InterruptHandler) -> Result<(), Error>;
    fn register_with_budget(
        &self,
        irq: u32,
        handler: &'static mut dyn InterruptHandler,
        budget: InterruptBudget,
    ) -> Result<(), Error>;
    /// Invariant: unregister only affects the specified IRQ slot.
    fn unregister(&self, irq: u32) -> Result<(), Error>;
    /// Invariant: trigger dispatches only if a handler is registered for the IRQ.
    fn trigger(&self, irq: u32) -> Result<(), Error>;
    fn trigger_with_budget(&self, irq: u32, elapsed_ticks: u32) -> Result<(), Error>;
    fn unquarantine(&self, irq: u32) -> Result<(), Error>;
    fn metrics(&self, irq: u32) -> Result<InterruptMetrics, Error>;
}

pub trait DeferredWork {
    fn run(&mut self);
}

pub struct WorkQueue<'a, const N: usize> {
    queue: [Option<NonNull<dyn DeferredWork + 'a>>; N],
    head: usize,
    tail: usize,
    len: usize,
}

impl<'a, const N: usize> WorkQueue<'a, N> {
    pub const fn new() -> Self {
        Self {
            queue: [None; N],
            head: 0,
            tail: 0,
            len: 0,
        }
    }

    pub fn enqueue(&mut self, work: &'a mut dyn DeferredWork) -> Result<(), Error> {
        if self.len >= N {
            return Err(Error::OutOfMemory);
        }
        self.queue[self.tail] = Some(NonNull::from(work));
        self.tail = (self.tail + 1) % N;
        self.len += 1;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn process_one(&mut self) -> Result<(), Error> {
        if self.len == 0 {
            return Err(Error::ResourceNotGranted);
        }
        let item = self.queue[self.head].take();
        self.head = (self.head + 1) % N;
        self.len -= 1;
        if let Some(mut work) = item {
            unsafe { work.as_mut().run() };
            Ok(())
        } else {
            Err(Error::ResourceNotGranted)
        }
    }

    pub fn process_all(&mut self) -> usize {
        let mut processed = 0;
        while self.len > 0 {
            if self.process_one().is_ok() {
                processed += 1;
            }
        }
        processed
    }
}
