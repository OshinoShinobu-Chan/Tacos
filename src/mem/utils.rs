mod list;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

pub use self::list::{InMemList, IterMut};

use crate::device::virtio::SECTOR_SIZE;
use crate::fs::disk::Swap;
use crate::fs::disk::DISKFS;
use crate::fs::File;
use crate::mem::layout::VM_OFFSET;
use crate::sync::{Intr, Lazy, Mutex};

pub const PG_SHIFT: usize = 12;
pub const PG_MASK: usize = (1 << PG_SHIFT) - 1;
pub const PG_SIZE: usize = 1 << PG_SHIFT;

/// Physical Address
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysAddr(usize);

impl PhysAddr {
    pub fn value(&self) -> usize {
        self.0
    }

    /// Physical page number
    pub fn ppn(&self) -> usize {
        self.0 >> PG_SHIFT
    }

    /// Translates physical address to virtual address.
    pub fn into_va(&self) -> usize {
        self.0 + VM_OFFSET
    }

    pub fn from_pa(pa: usize) -> Self {
        Self(pa)
    }
}

// Convert a virtual address(stored in usize) to a physical address.
impl From<usize> for PhysAddr {
    fn from(va: usize) -> Self {
        assert!(in_kernel_space(va));
        Self(va - VM_OFFSET)
    }
}

// Convert a pointer(in virtual address) to a physical address.
impl<T> From<*const T> for PhysAddr {
    fn from(pa: *const T) -> Self {
        PhysAddr::from(pa as usize)
    }
}

// Convert a pointer(in virtual address) to a physical address.
impl<T> From<*mut T> for PhysAddr {
    fn from(pa: *mut T) -> Self {
        PhysAddr::from(pa as usize)
    }
}

/// Checks if a virtual memory address is valid (lies in the kernel space)
/// Contains kernel, sbi, mmio and plic memory.
pub fn in_kernel_space(va: usize) -> bool {
    va & VM_OFFSET == VM_OFFSET
}

pub const fn div_round_up(n: usize, align: usize) -> usize {
    assert!(align.is_power_of_two());
    round_up(n, align) / align
}

pub const fn round_up(n: usize, align: usize) -> usize {
    assert!(align.is_power_of_two());
    (n + align - 1) & !(align - 1)
}

pub const fn round_down(n: usize, align: usize) -> usize {
    assert!(align.is_power_of_two());
    n & !(align - 1)
}

pub const fn prev_power_of_two(num: usize) -> usize {
    1 << (64 - num.leading_zeros() as usize - 1)
}

/// Aligned to page boundary.
pub trait PageAlign: Copy + Eq + Sized {
    fn floor(self) -> Self;

    fn ceil(self) -> Self;

    fn is_aligned(self) -> bool {
        self.floor() == self
    }
}

impl PageAlign for usize {
    fn floor(self) -> Self {
        (self >> PG_SHIFT) << PG_SHIFT
    }

    fn ceil(self) -> Self {
        ((self + PG_SIZE - 1) >> PG_SHIFT) << PG_SHIFT
    }
}

impl PageAlign for PhysAddr {
    fn floor(self) -> Self {
        PhysAddr(self.0.floor())
    }

    fn ceil(self) -> Self {
        PhysAddr(self.0.ceil())
    }
}

#[derive(Clone)]
pub enum PageType {
    /// offset
    Swap(Option<usize>),
    /// (offset, readsize)
    Code((File, usize, usize)),
    /// (file, offset)
    Mmap((File, usize)),
}

unsafe impl Sync for PageType {}
unsafe impl Send for PageType {}

pub struct SupplementalPageTable {
    list: Vec<Option<PageType>>,
    recycled_slot: VecDeque<usize>,
}

pub static SUPPLEMENTAL_PAGETABLE: Lazy<Mutex<SupplementalPageTable, Intr>> =
    Lazy::new(|| Mutex::new(SupplementalPageTable::new()));

impl SupplementalPageTable {
    pub fn new() -> Self {
        Self {
            list: Vec::new(),
            recycled_slot: VecDeque::new(),
        }
    }

    pub fn push(&mut self, pagetype: PageType) -> usize {
        if !self.recycled_slot.is_empty() {
            let index = self.recycled_slot.pop_back().unwrap();
            self.list[index] = Some(pagetype);
            index
        } else {
            self.list.push(Some(pagetype));
            self.list.len() - 1
        }
    }

    pub fn remove(&mut self, index: usize) {
        assert!(index < self.list.len());
        assert!(self.list[index].is_some());
        // TODO: if page is Swap, free the disk
        // if let PageType::Swap(Some(offset)) = self.list[index].clone().unwrap() {
        //     let swap = Swap::lock();
        //     let start_sector = swap.start();
        //     let aim_sector = start_sector + offset / SECTOR_SIZE;
        //     DISKFS.free_map.lock().reset(aim_sector as u32);
        // }
        self.list[index] = None;
        self.recycled_slot.push_front(index);
    }

    pub fn get(&self, index: usize) -> Option<PageType> {
        self.list.get(index).unwrap().clone()
    }

    pub fn replace(&mut self, index: usize, pagetype: PageType) {
        self.list[index].replace(pagetype);
    }

    /// alloc a page lazily, don't really alloc a page in physical memory,
    /// return index, map this to va using map first and the evict
    pub fn lazy_alloc(&mut self, pagetype: PageType) -> usize {
        // push the entry to table
        self.push(pagetype)
    }
}
