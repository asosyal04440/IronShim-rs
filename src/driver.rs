use core::cell::Cell;

use crate::{AuditSink, DmaAllocator, Error, InterruptRegistry, SyscallPolicy, TelemetrySink};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverState {
    Created,
    Initialized,
    Running,
    Suspended,
    Shutdown,
    Quarantined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxProfile {
    pub max_dma_bytes: usize,
    pub max_mmio_bytes: usize,
    pub max_irqs_per_sec: u32,
    pub dma_max_segments: usize,
    pub dma_alignment: usize,
    pub dma_boundary_mask: usize,
    pub interrupt_budget_ticks: u32,
}

impl SandboxProfile {
    pub const fn minimal() -> Self {
        Self {
            max_dma_bytes: 0,
            max_mmio_bytes: 0,
            max_irqs_per_sec: 0,
            dma_max_segments: 0,
            dma_alignment: 1,
            dma_boundary_mask: 0,
            interrupt_budget_ticks: 0,
        }
    }
}

pub struct DriverLifecycle {
    state: Cell<DriverState>,
}

impl DriverLifecycle {
    pub const fn new() -> Self {
        Self {
            state: Cell::new(DriverState::Created),
        }
    }

    pub fn state(&self) -> DriverState {
        self.state.get()
    }

    pub fn transition(&self, next: DriverState) -> Result<(), Error> {
        let current = self.state.get();
        let valid = matches!(
            (current, next),
            (DriverState::Created, DriverState::Initialized)
                | (DriverState::Initialized, DriverState::Running)
                | (DriverState::Running, DriverState::Suspended)
                | (DriverState::Suspended, DriverState::Running)
                | (DriverState::Running, DriverState::Shutdown)
                | (DriverState::Suspended, DriverState::Shutdown)
                | (_, DriverState::Quarantined)
        );
        if !valid {
            return Err(Error::InvalidState);
        }
        self.state.set(next);
        Ok(())
    }
}

pub struct DriverContext<
    'a,
    A: DmaAllocator,
    R: InterruptRegistry,
    T: TelemetrySink,
    U: AuditSink,
    S: SyscallPolicy,
> {
    pub dma: &'a A,
    pub interrupts: &'a R,
    pub telemetry: &'a T,
    pub audit: &'a U,
    pub syscalls: &'a S,
    pub profile: SandboxProfile,
    pub lifecycle: &'a DriverLifecycle,
}

pub struct NoopLifecycleHooks;

impl NoopLifecycleHooks {
    pub fn start<A, R, T, U, S>(_ctx: &DriverContext<A, R, T, U, S>) -> Result<(), Error>
    where
        A: DmaAllocator,
        R: InterruptRegistry,
        T: TelemetrySink,
        U: AuditSink,
        S: SyscallPolicy,
    {
        Ok(())
    }

    pub fn suspend<A, R, T, U, S>(_ctx: &DriverContext<A, R, T, U, S>) -> Result<(), Error>
    where
        A: DmaAllocator,
        R: InterruptRegistry,
        T: TelemetrySink,
        U: AuditSink,
        S: SyscallPolicy,
    {
        Ok(())
    }

    pub fn resume<A, R, T, U, S>(_ctx: &DriverContext<A, R, T, U, S>) -> Result<(), Error>
    where
        A: DmaAllocator,
        R: InterruptRegistry,
        T: TelemetrySink,
        U: AuditSink,
        S: SyscallPolicy,
    {
        Ok(())
    }
}

pub struct NoopInterruptHook;

impl NoopInterruptHook {
    pub fn handle<A, R, T, U, S>(
        _irq: u32,
        _ctx: &DriverContext<A, R, T, U, S>,
    ) -> Result<(), Error>
    where
        A: DmaAllocator,
        R: InterruptRegistry,
        T: TelemetrySink,
        U: AuditSink,
        S: SyscallPolicy,
    {
        Ok(())
    }
}

pub trait Driver<
    A: DmaAllocator,
    R: InterruptRegistry,
    T: TelemetrySink,
    U: AuditSink,
    S: SyscallPolicy,
>
{
    fn init(&mut self, ctx: &DriverContext<A, R, T, U, S>) -> Result<(), Error>;
    fn start(&mut self, ctx: &DriverContext<A, R, T, U, S>) -> Result<(), Error>;
    fn suspend(&mut self, ctx: &DriverContext<A, R, T, U, S>) -> Result<(), Error>;
    fn resume(&mut self, ctx: &DriverContext<A, R, T, U, S>) -> Result<(), Error>;
    fn shutdown(&mut self, ctx: &DriverContext<A, R, T, U, S>);
    fn handle_interrupt(
        &mut self,
        irq: u32,
        ctx: &DriverContext<A, R, T, U, S>,
    ) -> Result<(), Error>;
}
