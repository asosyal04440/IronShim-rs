use core::mem::{size_of, MaybeUninit};
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;
use core::slice;

use crate::{Error, NotSendSync, PhysAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaConstraints {
    pub alignment: usize,
    pub max_segments: usize,
    pub boundary_mask: usize,
    pub max_bytes: usize,
}

impl DmaConstraints {
    pub const fn relaxed() -> Self {
        Self {
            alignment: 1,
            max_segments: usize::MAX,
            boundary_mask: 0,
            max_bytes: usize::MAX,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaMemoryType {
    Coherent,
    Streaming,
}

pub trait DmaAllocator {
    /// Invariant: allocator returns a DMA buffer with verified physical address, never 0.
    fn alloc<T>(&self, count: usize) -> Result<DmaHandle<'_, T, Self>, Error>
    where
        Self: Sized;
    fn alloc_constrained<T>(
        &self,
        count: usize,
        constraints: DmaConstraints,
    ) -> Result<DmaHandle<'_, T, Self>, Error>
    where
        Self: Sized,
    {
        let handle = self.alloc::<T>(count)?;
        handle.validate_constraints(constraints)?;
        Ok(handle)
    }
    /// Invariant: phys/count must match a prior successful allocation.
    fn free<T>(&self, phys: PhysAddr, count: usize);
}

pub trait DmaMapper {
    fn map(&self, phys: PhysAddr, bytes: usize) -> Result<PhysAddr, Error>;
    fn unmap(&self, iova: PhysAddr, bytes: usize) -> Result<(), Error>;
}

pub trait DmaSync {
    fn sync_for_device(&self, phys: PhysAddr, bytes: usize) -> Result<(), Error>;
    fn sync_for_cpu(&self, phys: PhysAddr, bytes: usize) -> Result<(), Error>;
}

pub trait DmaPin {
    fn pin(&self, phys: PhysAddr, bytes: usize) -> Result<(), Error>;
    fn unpin(&self, phys: PhysAddr, bytes: usize) -> Result<(), Error>;
}

pub struct DmaHandle<'a, T, A: DmaAllocator> {
    virt: NonNull<T>,
    phys: PhysAddr,
    count: usize,
    allocator: &'a A,
    mem_type: DmaMemoryType,
    zeroize_on_drop: bool,
    _nosend: NotSendSync,
}

impl<'a, T, A: DmaAllocator> DmaHandle<'a, T, A> {
    /// Invariant: virt is non-null, phys is verified non-zero, count > 0.
    pub fn from_raw(
        allocator: &'a A,
        virt: *mut T,
        phys: PhysAddr,
        count: usize,
    ) -> Result<Self, Error> {
        if virt.is_null() || phys == 0 || count == 0 {
            return Err(Error::InvalidAddress);
        }
        let virt = NonNull::new(virt).ok_or(Error::InvalidAddress)?;
        Ok(Self {
            virt,
            phys,
            count,
            allocator,
            mem_type: DmaMemoryType::Coherent,
            zeroize_on_drop: false,
            _nosend: NotSendSync::new(),
        })
    }

    /// Invariant: returned phys is the verified DMA address for this buffer.
    pub fn phys(&self) -> PhysAddr {
        self.phys
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn bytes(&self) -> usize {
        size_of::<T>().saturating_mul(self.count)
    }

    /// Invariant: pointer covers exactly `count` elements.
    pub fn as_ptr(&self) -> *mut T {
        self.virt.as_ptr()
    }

    pub fn memory_type(&self) -> DmaMemoryType {
        self.mem_type
    }

    pub fn set_memory_type(&mut self, mem_type: DmaMemoryType) {
        self.mem_type = mem_type;
    }

    pub fn enable_zeroize_on_drop(&mut self) {
        self.zeroize_on_drop = true;
    }

    pub fn map<M: DmaMapper>(&self, mapper: &M) -> Result<PhysAddr, Error> {
        mapper.map(self.phys, self.bytes())
    }

    pub fn unmap<M: DmaMapper>(&self, mapper: &M, iova: PhysAddr) -> Result<(), Error> {
        mapper.unmap(iova, self.bytes())
    }

    pub fn sync_for_device<S: DmaSync>(&self, sync: &S) -> Result<(), Error> {
        sync.sync_for_device(self.phys, self.bytes())
    }

    pub fn sync_for_cpu<S: DmaSync>(&self, sync: &S) -> Result<(), Error> {
        sync.sync_for_cpu(self.phys, self.bytes())
    }

    pub fn pin<P: DmaPin>(&self, pin: &P) -> Result<(), Error> {
        pin.pin(self.phys, self.bytes())
    }

    pub fn unpin<P: DmaPin>(&self, pin: &P) -> Result<(), Error> {
        pin.unpin(self.phys, self.bytes())
    }

    pub fn validate_constraints(&self, constraints: DmaConstraints) -> Result<(), Error> {
        let bytes = self.bytes();
        if bytes > constraints.max_bytes {
            return Err(Error::OutOfBounds);
        }
        if self.phys % constraints.alignment != 0 {
            return Err(Error::InvalidAddress);
        }
        if constraints.boundary_mask != 0 {
            let start = self.phys & !constraints.boundary_mask;
            let end = (self.phys + bytes.saturating_sub(1)) & !constraints.boundary_mask;
            if start != end {
                return Err(Error::OutOfBounds);
            }
        }
        Ok(())
    }
}

impl<'a, T, A: DmaAllocator> Deref for DmaHandle<'a, T, A> {
    type Target = [T];

    /// Invariant: slice length equals allocation count; no out-of-bounds access.
    fn deref(&self) -> &Self::Target {
        // SAFETY: `from_raw` validates the pointer/count pair and the handle owns that allocation
        // for the lifetime of `self`.
        unsafe { slice::from_raw_parts(self.virt.as_ptr(), self.count) }
    }
}

impl<'a, T, A: DmaAllocator> DerefMut for DmaHandle<'a, T, A> {
    /// Invariant: slice length equals allocation count; no out-of-bounds access.
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: `from_raw` validates the pointer/count pair and `&mut self` guarantees unique
        // access to the backing DMA allocation for this call.
        unsafe { slice::from_raw_parts_mut(self.virt.as_ptr(), self.count) }
    }
}

impl<'a, T, A: DmaAllocator> Drop for DmaHandle<'a, T, A> {
    /// Invariant: frees only allocations produced by this allocator.
    fn drop(&mut self) {
        if self.zeroize_on_drop {
            // SAFETY: `virt` points to `bytes()` writable bytes owned by this handle; zeroization
            // happens before the allocator reclaims the buffer.
            unsafe {
                core::ptr::write_bytes(self.virt.as_ptr() as *mut u8, 0, self.bytes());
            }
        }
        self.allocator.free::<T>(self.phys, self.count);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScatterEntry {
    pub phys: PhysAddr,
    pub count: usize,
}

pub struct DmaScatterList<'a, T, A: DmaAllocator, const N: usize> {
    entries: [MaybeUninit<DmaHandle<'a, T, A>>; N],
    len: usize,
    constraints: DmaConstraints,
    _nosend: NotSendSync,
}

impl<'a, T, A: DmaAllocator, const N: usize> DmaScatterList<'a, T, A, N> {
    pub fn new() -> Self {
        Self {
            entries: [const { MaybeUninit::uninit() }; N],
            len: 0,
            constraints: DmaConstraints::relaxed(),
            _nosend: NotSendSync::new(),
        }
    }

    pub fn with_constraints(constraints: DmaConstraints) -> Self {
        Self {
            entries: [const { MaybeUninit::uninit() }; N],
            len: 0,
            constraints,
            _nosend: NotSendSync::new(),
        }
    }

    /// Invariant: each handle owns a verified non-zero physical segment.
    pub fn push(&mut self, handle: DmaHandle<'a, T, A>) -> Result<(), Error> {
        if self.len >= N {
            return Err(Error::OutOfMemory);
        }
        if self.len >= self.constraints.max_segments {
            return Err(Error::OutOfBounds);
        }
        handle.validate_constraints(self.constraints)?;
        self.entries[self.len].write(handle);
        self.len += 1;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.len
    }

    /// Invariant: segments are derived only from owned DMA handles.
    pub fn segment(&self, index: usize) -> Option<ScatterEntry> {
        if index >= self.len {
            return None;
        }
        // SAFETY: `index < len` guarantees the slot was initialized by `push` and has not been
        // dropped yet because the scatter list still owns it.
        let handle = unsafe { self.entries[index].assume_init_ref() };
        Some(ScatterEntry {
            phys: handle.phys(),
            count: handle.len(),
        })
    }
}

impl<'a, T, A: DmaAllocator, const N: usize> Drop for DmaScatterList<'a, T, A, N> {
    /// Invariant: drops all owned handles, triggering allocator reclamation.
    fn drop(&mut self) {
        for index in 0..self.len {
            // SAFETY: entries in `0..len` were initialized by `push`; each is dropped exactly once
            // here when the scatter list releases ownership.
            unsafe { self.entries[index].assume_init_drop() };
        }
    }
}
