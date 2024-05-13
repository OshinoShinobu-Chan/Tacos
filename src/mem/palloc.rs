//! Global Page Allocator

use core::cmp::min;

use crate::fs::disk::Swap;
use crate::fs::File;
use crate::io::Seek;
use crate::io::Write;
use crate::mem::userbuf::read_user_item;
use crate::mem::utils::*;
use crate::mem::PageTable;
use crate::sync::{Intr, Lazy, Mutex};

// BuddyAllocator allocates at most `1<<MAX_ORDER` pages at a time
const MAX_ORDER: usize = 8;
// How many pages are there in the user memory pool
pub(super) const USER_POOL_LIMIT: usize = 256;

/// Buddy Allocator. It allocates and deallocates memory page-wise.
#[derive(Debug)]
struct BuddyAllocator {
    /// The i-th free list is in charge of memory chunks of 2^i pages
    free_lists: [InMemList; MAX_ORDER + 1],
    /// How many memory does the buddy allocator control
    total: usize,
    /// The number of pages allocated
    allocated: usize,
}

impl BuddyAllocator {
    /// This struct can not be moved due to self reference.
    /// So, construct it and then call `init`.
    const fn empty() -> Self {
        Self {
            free_lists: [InMemList::new(); MAX_ORDER + 1],
            total: 0,
            allocated: 0,
        }
    }

    /// Take the memory segmant from `start` to `end` into page allocator's record
    unsafe fn insert_range(&mut self, start: usize, end: usize) {
        let start = round_up(start, PG_SIZE);
        let end = round_down(end, PG_SIZE);
        self.total += end - start;

        let mut current_start: usize = start;
        while current_start < end {
            // find the biggest alignment of `current_start`
            let size = min(
                1 << current_start.trailing_zeros(),
                prev_power_of_two(end - current_start),
            );
            let order = size.trailing_zeros() as usize - PG_SHIFT;
            // The order we found cannot exceed the preset maximun order
            let order = min(order, MAX_ORDER);
            self.free_lists[order].push(current_start as *mut usize);
            current_start += (1 << order) * PG_SIZE;
        }
    }

    /// Allocate n pages and returns the virtual address.
    unsafe fn alloc(&mut self, n: usize) -> *mut u8 {
        assert!(n <= 1 << MAX_ORDER, "request is too large");

        let order = n.next_power_of_two().trailing_zeros() as usize;
        for i in order..self.free_lists.len() {
            // Find the first non-empty list
            if !self.free_lists[i].is_empty() {
                // Split buffers (from large to small groups)
                for j in (order..i).rev() {
                    // Try to find a large block of group j+1 and then
                    // split it into two blocks of group j
                    if let Some(block) = self.free_lists[j + 1].pop() {
                        let half = (block as usize + (1 << j) * PG_SIZE) as *mut usize;
                        self.free_lists[j].push(half);
                        self.free_lists[j].push(block);
                    }
                }
                self.allocated += 1 << order;
                return self.free_lists[order].pop().unwrap().cast();
            }
        }

        unreachable!("memory is exhausted");
    }

    /// Deallocate a chunk of pages
    unsafe fn dealloc(&mut self, ptr: *mut u8, n: usize) {
        let order = n.next_power_of_two().trailing_zeros() as usize;
        self.free_lists[order].push(ptr.cast());

        // Merge free lists
        let mut curr_ptr = ptr as usize;
        let mut curr_order = order;

        while curr_order < MAX_ORDER {
            // Find the buddy block of the current block
            let buddy = curr_ptr ^ (1 << (curr_order + PG_SHIFT));
            // Try to find and merge blocks
            if let Some(blk) = self.free_lists[curr_order]
                .iter_mut()
                .find(|blk| blk.value() as usize == buddy)
            {
                blk.pop();
                // Merge two blocks into a bigger one
                self.free_lists[curr_order].pop();
                curr_ptr = min(curr_ptr, buddy);
                self.free_lists[curr_order + 1].push(curr_ptr as *mut _);
                // Attempt to form a even bigger block in the next iteration
                curr_order += 1;
            } else {
                break;
            }
        }

        self.allocated -= 1 << order;
    }
}

/// Wraps the buddy allocator
pub struct Palloc(Lazy<Mutex<BuddyAllocator, Intr>>);

unsafe impl Sync for Palloc {}

impl Palloc {
    /// Initialize the page-based allocator
    pub unsafe fn init(start: usize, end: usize) {
        Self::instance().lock().insert_range(start, end);
    }

    /// Allocate n pages of a consecutive memory segment
    pub unsafe fn alloc(n: usize) -> *mut u8 {
        Self::instance().lock().alloc(n)
    }

    /// Free n pages of memory starting at `ptr`
    pub unsafe fn dealloc(ptr: *mut u8, n: usize) {
        Self::instance().lock().dealloc(ptr, n)
    }

    fn instance() -> &'static Mutex<BuddyAllocator, Intr> {
        static PALLOC: Palloc = Palloc(Lazy::new(|| Mutex::new(BuddyAllocator::empty())));

        &PALLOC.0
    }
}

pub struct UserPool(Lazy<Mutex<BuddyAllocator, Intr>>);

unsafe impl Sync for UserPool {}

impl UserPool {
    /// Allocate n pages of consecutive space
    pub unsafe fn alloc_pages(n: usize) -> *mut u8 {
        Self::instance().lock().alloc(n)
    }

    /// Free n pages of memory starting at `ptr`
    pub unsafe fn dealloc_pages(ptr: *mut u8, n: usize) {
        Self::instance().lock().dealloc(ptr, n)
    }

    /// Initialize the page-based allocator
    pub unsafe fn init(start: usize, end: usize) {
        Self::instance().lock().insert_range(start, end);
        PhysMemPool::instance().lock().insert_range(start);
    }

    fn instance() -> &'static Mutex<BuddyAllocator, Intr> {
        static USERPOOL: UserPool = UserPool(Lazy::new(|| Mutex::new(BuddyAllocator::empty())));

        &USERPOOL.0
    }
}

#[derive(Clone, Copy)]
pub struct PhysMemEntry {
    va: Option<usize>,
    index: Option<usize>,
    pt_token: Option<usize>,
    pinned: bool,
}

impl PhysMemEntry {
    pub fn new() -> Self {
        Self {
            va: None,
            index: None,
            pt_token: None,
            pinned: false,
        }
    }

    pub fn alloc(&mut self, va: usize, index: usize, pt_token: usize) {
        self.va = Some(va);
        self.index = Some(index);
        self.pt_token = Some(pt_token);
    }

    pub fn dealloc(&mut self) -> PhysMemEntry {
        let old = self.clone();
        self.va = None;
        self.index = None;
        self.pt_token = None;
        self.pinned = false;
        old
    }

    pub fn evict(
        &mut self,
        new_va: usize,
        new_index: Option<usize>,
        new_pt_token: usize,
    ) -> PhysMemEntry {
        let old = self.clone();
        self.va = Some(new_va);
        self.index = new_index;
        self.pt_token = Some(new_pt_token);
        old
    }

    pub fn write(&self, pa: usize) {
        // write the content back
        if !self.is_dirty() {
            return;
        }
        let supplmental = SUPPLEMENTAL_PAGETABLE.lock();
        match supplmental.get(self.index.unwrap()).unwrap() {
            PageType::Swap(Some(_offset)) => {
                // TODO: Write to the Swap file
            }
            PageType::Swap(None) => {
                // TODO: Write to the Swap file and update the entry
            }
            PageType::Mmap((file, offset)) => {
                write_mmap(file, offset, pa);
            }
            PageType::Code => unreachable!("Code segment should not be dirty!"),
        }
    }

    pub fn get_va(&self) -> Option<usize> {
        self.va
    }

    pub fn get_index(&self) -> Option<usize> {
        self.index
    }

    pub fn get_thread(&self) -> Option<usize> {
        self.pt_token
    }

    pub fn is_used(&self) -> bool {
        self.va.is_some()
    }

    pub fn is_dirty(&self) -> bool {
        let pt = unsafe { PageTable::from_token(self.pt_token.unwrap()) };
        let pte = pt.get_pte(self.va.unwrap()).unwrap();
        pte.is_dirty()
    }

    pub fn is_accessed(&self) -> bool {
        let pt = unsafe { PageTable::from_token(self.pt_token.unwrap()) };
        let pte = pt.get_pte(self.va.unwrap()).unwrap();
        pte.is_accessed()
    }

    pub fn is_pinned(&self) -> bool {
        self.pinned
    }

    pub fn set_unaccessed(&self) {
        let pt = unsafe { PageTable::from_token(self.pt_token.unwrap()) };
        let pte = pt.get_mut_pte(self.va.unwrap()).unwrap();
        pte.set_unaccessed()
    }
}

pub struct PhysMemList {
    list: [PhysMemEntry; USER_POOL_LIMIT],
    pointer: LoopPointer,
    start: usize,
}

struct LoopPointer(isize);

impl LoopPointer {
    pub fn new() -> Self {
        Self(-1)
    }
}

impl Iterator for LoopPointer {
    type Item = usize;
    fn next(&mut self) -> Option<Self::Item> {
        self.0 += 1;
        if self.0 as usize == USER_POOL_LIMIT {
            self.0 = 0;
        }
        Some(self.0 as usize)
    }
}

impl PhysMemList {
    pub fn new() -> Self {
        // const VAL = PhysMemEntry::new();
        Self {
            list: [PhysMemEntry::new(); USER_POOL_LIMIT],
            pointer: LoopPointer::new(),
            start: 0,
        }
    }

    pub fn insert_range(&mut self, start: usize) {
        self.start = start.ceil();
    }

    pub fn clock_algorithm(&mut self) -> usize {
        loop {
            let index = self.pointer.next().unwrap();
            if self.list[index].is_pinned() {}
            if self.list[index].is_accessed() {
                self.list[index].set_unaccessed();
            } else {
                return index;
            }
        }
    }

    pub fn evict(&mut self, va: usize, index: Option<usize>, pt_token: usize) -> usize {
        // kprintln!("...");
        let i = if let Some(i) = self
            .list
            .iter()
            .enumerate()
            .find(|e| !e.1.is_used())
            .map(|e| e.0)
        {
            i
        } else {
            self.clock_algorithm()
        };
        // kprintln!("i: {}", i);
        let pa = self.start + i * PG_SIZE;

        let old = self.list[i].evict(va, index, pt_token);
        if !old.is_used() {
            return pa;
        }
        old.write(pa);
        let pt = unsafe { PageTable::from_token(old.pt_token.unwrap()) };
        pt.get_mut_pte(old.va.unwrap())
            .unwrap()
            .evict(old.index.unwrap());

        pa
    }

    pub fn pinned_alloc(&mut self, va: usize) -> usize {
        let i = if let Some(i) = self
            .list
            .iter()
            .enumerate()
            .find(|e| !e.1.is_used())
            .map(|e| e.0)
        {
            i
        } else {
            unreachable!("memory is exhausted");
        };
        self.list[i].va = Some(va);
        self.list[i].pinned = true;
        self.start + i * PG_SIZE
    }

    pub fn dealloc(&mut self, pa: usize) {
        let index = (pa - self.start) / PG_SIZE;
        let old = self.list[index].dealloc();
        let index = old.get_index().unwrap();
        let mut supplmental = SUPPLEMENTAL_PAGETABLE.lock();
        match supplmental.get(index).unwrap() {
            PageType::Mmap((file, offset)) => {
                write_mmap(file, offset, pa);
            }
            _ => {
                // other situation don't need to write back to disk when dealloc
            }
        }
        supplmental.remove(index);
    }
}

pub struct PhysMemPool(Lazy<Mutex<PhysMemList, Intr>>);

unsafe impl Sync for PhysMemPool {}

impl PhysMemPool {
    pub fn init(start: usize) {
        Self::instance().lock().insert_range(start);
    }

    /// really allocate a page in physical memory, return pa
    pub fn real_alloc(va: usize, pt_token: usize) -> usize {
        let pt = unsafe { PageTable::from_token(pt_token) };
        let index = pt.get_pte(va).unwrap().ppn();
        // kprintln!("index: {}", index);
        Self::instance().lock().evict(va, Some(index), pt_token)
    }

    pub fn pinned_alloc(va: usize) -> usize {
        Self::instance().lock().pinned_alloc(va)
    }

    pub fn dealloc(pa: usize) {
        Self::instance().lock().dealloc(pa)
    }

    fn instance() -> &'static Mutex<PhysMemList, Intr> {
        static PHYSMEMPOOL: PhysMemPool = PhysMemPool(Lazy::new(|| Mutex::new(PhysMemList::new())));

        &PHYSMEMPOOL.0
    }
}

fn write_mmap(file: *mut File, offset: usize, pa: usize) {
    let file = unsafe { file.as_mut().unwrap() };
    file.seek(crate::io::SeekFrom::Start(offset)).unwrap();
    let size = (file.len().unwrap() - offset).min(PG_SIZE);
    for ptr in pa..(pa + size) {
        let b = read_user_item(ptr as *const u8).unwrap();
        file.write_from(b).unwrap();
    }
}
