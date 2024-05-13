//! Manages kernel and user page tables.
//!
//! ## Risc-v Pagetable Scheme
//! The risc-v Sv39 scheme has three levels of page-table pages.
//! A page-table page contains 512 64-bit PTEs.
//! A 64-bit virtual address is split into five fields:
//!   39..63 -- each be the same to bit 38.
//!   30..38 -- 9 bits of level-2 index.
//!   21..29 -- 9 bits of level-1 index.
//!   12..20 -- 9 bits of level-0 index.
//!    0..11 -- 12 bits of byte offset within the page.
//! ref: <https://five-embeddev.com/riscv-isa-manual/latest/supervisor.html#sec:sv39>
//!
//! ## Design
//! The struct [`PageTable`] holds reference to a in-momory Sv39 page table. And
//! [`KernelPgTable`], which has only one instance, manages kernel memory. To build
//! a user page table, you should always start from calling [`KernelPgTable::clone`].
//! This method replicates the kernel page table as a template for all user page tables.
//! Having kernel pages existing in all user memory spaces, there will be no need to
//! switch page table when doing a system call.

mod entry;

use alloc::string::String;
use core::ptr;
use core::{arch::asm, mem::transmute};

use crate::error::OsError;
use crate::mem::{
    layout::{MMIO_BASE, PLIC_BASE, VM_BASE},
    malloc::{kalloc, kfree},
    palloc::{PhysMemPool, UserPool},
    userbuf::{read_user_item, write_user_item, write_user_str},
    utils::{PageAlign, PhysAddr, PG_SIZE},
};
use crate::mem::{KERN_BASE, PG_SHIFT, SUPPLEMENTAL_PAGETABLE, VM_OFFSET};
use crate::sync::OnceCell;
use crate::thread::current;
use crate::Result;

pub use self::entry::*;

const PPN_MASK: usize = (1 << 44) - 1;

/// Reference to a in-memory page table
pub struct PageTable {
    /// Each page table has 512 entries.
    entries: &'static mut [Entry; Self::NENTRY],
}

impl PageTable {
    const NENTRY: usize = 512;
    const PX_MASK: usize = Self::NENTRY - 1;
    const SV39_MODE: usize = 0x8 << 60;

    /// Activates `self` as the effective page table.
    pub fn activate(&self) {
        // SATP layout: MODE(WARL) 4 bit | ASID(WARL) 16 bits | PPN(WARL) 44 bits
        let satp: usize = PhysAddr::from(self.entries.as_ptr()).ppn() | Self::SV39_MODE;
        unsafe {
            asm!(
                "sfence.vma zero, zero",
                "csrw satp, {satp}",
                "sfence.vma zero, zero",
                satp = in(reg) satp
            );
        }
    }

    /// Maps `pa` to `va` and allocates page table when necessary.
    pub fn map(&mut self, pa: PhysAddr, va: usize, size: usize, flag: PTEFlags) {
        assert!(pa.is_aligned() && va.is_aligned(), "address misaligns");

        let pa_end = pa.value() + size;
        let (mut pa, mut va) = (pa.value(), va);

        while pa < pa_end {
            let mut l1_table = self.walk_or_create(Self::px(2, va), flag.contains(PTEFlags::G));
            let l0_table = l1_table.walk_or_create(Self::px(1, va), flag.contains(PTEFlags::G));
            l0_table.entries[Self::px(0, va)] = Entry::new(PhysAddr::from_pa(pa), flag);
            pa += PG_SIZE;
            va += PG_SIZE;
        }
    }

    /// Finds the corresponding entry by the given virtual address
    pub fn get_pte(&self, va: usize) -> Option<&Entry> {
        self.walk(Self::px(2, va)).and_then(|l1_table| {
            l1_table
                .walk(Self::px(1, va))
                .map(|l0_table| l0_table.entries.get(Self::px(0, va)).unwrap())
        })
    }

    pub fn get_mut_pte(&self, va: usize) -> Option<&mut Entry> {
        self.walk(Self::px(2, va)).and_then(|l1_table| {
            l1_table
                .walk(Self::px(1, va))
                .map(|l0_table| l0_table.entries.get_mut(Self::px(0, va)).unwrap())
        })
    }

    pub fn try_translate_va(&self, va: usize) -> Result<usize> {
        if let Some(pte) = self.get_pte(va.floor()) {
            if !pte.is_valid() {
                return Err(OsError::BadPtr);
            }
            let offset = va - va.floor();
            Ok(pte.pa().into_va() + offset)
        } else {
            Err(OsError::BadPtr)
        }
    }

    pub fn is_writeable(&self, va: usize) -> bool {
        if let Some(pte) = self.get_pte(va.floor()) {
            pte.is_valid() && pte.is_writeable()
        } else {
            false
        }
    }

    pub fn translate_va(&mut self, va: usize) -> Result<usize> {
        let pa = self.try_translate_va(va);
        if pa.is_ok() {
            return pa;
        }

        // decide if it is stack growth
        let current = current();
        let sp = current.get_sp();
        let bp = current.get_bp();
        if va < sp || va >= bp {
            return Err(OsError::BadPtr);
        }

        // lazy alloc first and then real alloc
        let index = SUPPLEMENTAL_PAGETABLE
            .lock()
            .lazy_alloc(crate::mem::PageType::Swap(None));
        self.map(
            PhysAddr::from_pa(0),
            va.floor(),
            PG_SIZE,
            PTEFlags::V | PTEFlags::R | PTEFlags::W | PTEFlags::U,
        );
        let entry = self.get_mut_pte(va).unwrap();
        entry.evict(index);
        let token = unsafe { PageTable::get_token() };
        // kprintln!("pagetable token: {:#x}", token);
        let pa = PhysMemPool::real_alloc(va.floor(), token) - VM_OFFSET;
        self.map(
            PhysAddr::from_pa(pa),
            va.floor(),
            PG_SIZE,
            PTEFlags::V | PTEFlags::R | PTEFlags::W | PTEFlags::U,
        );
        kprintln!(
            "expand page when syscall {:#x}-{:x}, pa: {:#x}",
            va.floor(),
            va.floor() + PG_SIZE,
            pa,
        );
        let offset = va - va.floor();
        return Ok(pa + offset + VM_OFFSET);
    }

    pub fn read_user_str(&mut self, va: usize) -> Result<String> {
        let mut ptr = va;
        let mut s = String::new();
        loop {
            let c: u8 = self.read_user_item(ptr)?;
            if c == 0 {
                return Ok(s);
            } else {
                s.push(c as char);
                ptr += 1;
            }
        }
    }

    pub fn read_user_item<T: Sized>(&mut self, va: usize) -> Result<T> {
        let pa = self.translate_va(va)?;
        read_user_item(pa as *const T)
    }

    pub fn check_buf(&mut self, va: usize, size: usize) -> Result<()> {
        if va == 0 {
            return Err(OsError::BadPtr);
        }
        let mut ptr = va;
        let end = va + size;
        while ptr < end {
            let _ = self.translate_va(ptr)?;
            if !self.is_writeable(va) {
                return Err(OsError::UnwriteablePtr);
            }
            ptr += PG_SIZE.min((ptr + 1).ceil() - ptr);
        }
        Ok(())
    }

    pub fn write_user_str(&mut self, va: usize, string: &String) -> Result<()> {
        self.check_buf(va, string.len())?;
        let pa = self.translate_va(va)?;
        write_user_str(pa as *mut u8, string)
    }

    pub fn write_user_item<T: Sized>(&mut self, va: usize, item: &T) -> Result<()> {
        self.check_buf(va, core::mem::size_of::<T>())?;
        let pa = self.translate_va(va)?;
        write_user_item(pa as *mut T, item)
    }

    /// Free all memory used by this pagetable back to where they were allocated.
    pub unsafe fn destroy(&mut self) {
        unsafe fn destroy_imp(pgt: &mut PageTable, level: usize) {
            assert!((0..=2).contains(&level));

            pgt.entries
                .iter()
                .filter(|entry| entry.is_valid() && !entry.is_global())
                .for_each(|entry| {
                    let va = entry.pa().into_va();
                    if entry.is_leaf() {
                        UserPool::dealloc_pages(va as *mut _, 1 << (9 * level));
                    } else {
                        destroy_imp(&mut PageTable::from_raw(va as *mut _), level - 1);
                    }
                });
            kfree(pgt.entries.as_mut_ptr().cast(), PG_SIZE, PG_SIZE);
        }
        destroy_imp(self, 2);
    }

    /// Allocates a page to build a new page table
    fn new() -> Self {
        let page = kalloc(PG_SIZE, PG_SIZE);

        unsafe {
            // Clear the pagetable. A page table is exactly the size of
            // a page and must always be aligned to a page boundary.
            ptr::write_bytes(page, 0, PG_SIZE);

            Self::from_raw(page.cast())
        }
    }

    /// Interprets a page of raw memory as a page table
    unsafe fn from_raw(entries: *mut Entry) -> Self {
        assert!((entries as usize).is_aligned());
        Self {
            entries: transmute(entries),
        }
    }

    pub unsafe fn effective_pagetable() -> Self {
        let satp: usize;
        asm!("csrr {v}, satp", v = out(reg) satp);
        let ppn = satp & PPN_MASK;
        Self::from_raw(PhysAddr::from_pa(ppn << PG_SHIFT).into_va() as *mut _)
    }

    pub unsafe fn get_token() -> usize {
        let satp: usize;
        asm!("csrr {v}, satp", v = out(reg) satp);
        satp
    }

    pub unsafe fn from_token(satp: usize) -> Self {
        let ppn = satp & PPN_MASK;
        Self::from_raw(PhysAddr::from_pa(ppn << PG_SHIFT).into_va() as *mut _)
    }

    fn walk(&self, index: usize) -> Option<PageTable> {
        self.entries
            .get(index)
            .filter(|e| e.is_valid())
            .map(|e| unsafe { Self::from_raw(e.pa().into_va() as *mut _) })
    }

    fn walk_or_create(&mut self, index: usize, is_global: bool) -> PageTable {
        let mut flag = PTEFlags::V;
        flag.set(PTEFlags::G, is_global);

        self.walk(index).unwrap_or_else(|| {
            let table = PageTable::new();
            let pa = PhysAddr::from(table.entries.as_ptr());
            self.entries[index] = Entry::new(pa, flag);
            table
        })
    }

    fn px(level: u32, va: usize) -> usize {
        fn px_shift(level: u32) -> usize {
            PG_SHIFT + 9 * level as usize
        }

        (va >> px_shift(level)) & Self::PX_MASK
    }
}

pub fn pt_read_user_str(va: usize) -> Result<String> {
    let mut pt = unsafe { PageTable::effective_pagetable() };
    pt.read_user_str(va)
}

pub fn pt_read_user_item<T: Sized>(va: usize) -> Result<T> {
    let mut pt = unsafe { PageTable::effective_pagetable() };
    pt.read_user_item(va)
}

pub fn pt_write_user_str(va: usize, string: &String) -> Result<()> {
    let mut pt = unsafe { PageTable::effective_pagetable() };
    pt.write_user_str(va, string)
}

pub fn pt_write_user_item<T: Sized>(va: usize, item: &T) -> Result<()> {
    let mut pt = unsafe { PageTable::effective_pagetable() };
    pt.write_user_item(va, item)
}

pub fn pt_check_buf(va: usize, size: usize) -> Result<()> {
    let mut pt = unsafe { PageTable::effective_pagetable() };
    pt.check_buf(va, size)
}

pub struct KernelPgTable(OnceCell<PageTable>);

impl KernelPgTable {
    pub fn get() -> &'static PageTable {
        Self::instance().get()
    }

    /// Clones entries in the kernel page table. Use them as a template for user page tables.
    /// This method ensures all kernel memory mappings exist in user memory space.
    pub fn clone() -> PageTable {
        let other = PageTable::new();
        other.entries.copy_from_slice(Self::get().entries);
        other
    }

    /// Initializes the kernel page table which manages `ram_size` bytes of memory
    pub fn init(ram_size: usize) {
        Self::instance().init(|| Self::init_inner(ram_size))
    }

    /// Set up all kernel page table entries.
    ///
    /// At the entrance of kernel, a crude page table was set up to support basic
    /// paging capability. To strengthen memory protection, it's necessary to set up
    /// a fine-grained page table.
    pub fn init_inner(ram_size: usize) -> PageTable {
        let mut root = PageTable::new();

        // Kernel's code and data exist in all memory spaces, therefore the global bit is set.
        let rx = PTEFlags::R | PTEFlags::X | PTEFlags::G | PTEFlags::V;
        let rw = PTEFlags::R | PTEFlags::W | PTEFlags::G | PTEFlags::V;

        extern "C" {
            fn etext();
        }

        let etext = etext as usize;
        let kr_base = KERN_BASE + VM_OFFSET;
        let kr_end = VM_BASE + ram_size;

        // map kernel text executable and read-only.
        root.map(PhysAddr::from_pa(KERN_BASE), kr_base, etext - kr_base, rx);

        // map kernel data and the physical RAM we'll make use of.
        root.map(PhysAddr::from(etext), etext, kr_end - etext, rw);

        // PLIC
        root.map(PhysAddr::from(PLIC_BASE), PLIC_BASE, 0x400000, rw);

        // virtio mmio disk interface
        root.map(PhysAddr::from(MMIO_BASE), MMIO_BASE, PG_SIZE, rw);

        root.activate();
        root
    }

    fn instance() -> &'static OnceCell<PageTable> {
        static PAGETABLE: KernelPgTable = KernelPgTable(OnceCell::new());

        &PAGETABLE.0
    }
}
