use crate::mem::palloc::PhysMemPool;
use crate::mem::userbuf::{
    __knrl_read_usr_byte_pc, __knrl_read_usr_exit, __knrl_write_usr_byte_pc, __knrl_write_usr_exit,
};
use crate::mem::SUPPLEMENTAL_PAGETABLE;
use crate::mem::{PTEFlags, PageAlign, PhysAddr, PG_SIZE};
use crate::mem::{PageTable, VM_OFFSET};
use crate::thread::{self, current};
use crate::trap::Frame;
use crate::userproc;

use riscv::register::scause::Exception::{self, *};
use riscv::register::sstatus::{self, SPP};

#[derive(Debug)]
enum HandleType {
    StackGrowth,
    Swap,
    Code,
    Mmap,
    Error,
}

pub fn handler(frame: &mut Frame, fault: Exception, addr: usize) {
    let privilege = frame.sstatus.spp();

    let present = {
        let table = unsafe { PageTable::effective_pagetable() };
        match table.get_pte(addr) {
            Some(entry) => entry.is_valid(),
            None => false,
        }
    };

    unsafe { sstatus::set_sie() };
    let current = current();
    let mut table = unsafe { PageTable::effective_pagetable() };
    // closure to decide if an addr is a valid on stack
    let stack = |addr: usize| {
        let sp = current.get_sp();
        let bp = current.get_bp();
        addr >= sp && addr < bp
    };

    // closure to decide which kind of page fault it is
    let f = || {
        if present {
            return HandleType::Error;
        }

        let entry = table.get_pte(addr);
        if entry.is_none() {
            if stack(addr) {
                return HandleType::StackGrowth;
            }
            return HandleType::Error;
        }
        let entry = entry.unwrap();
        if !entry.on_disk() {
            if stack(addr) {
                return HandleType::StackGrowth;
            }
            return HandleType::Error;
        }
        let index = entry.ppn();
        let entry = SUPPLEMENTAL_PAGETABLE.lock().get(index);
        if entry.is_none() {
            return HandleType::Error;
        }
        let entry = entry.unwrap();
        match entry {
            crate::mem::PageType::Swap(_) => HandleType::Swap,
            crate::mem::PageType::Code => HandleType::Code,
            crate::mem::PageType::Mmap(_) => HandleType::Mmap,
        }
    };

    let handletype = f();
    kprintln!(
        "handletype: {:?}, sp: {:#x}, bp: {:#x}, addr: {:#x}",
        handletype,
        current.get_sp(),
        current.get_bp(),
        addr
    );

    // handle the pagefault by handletype
    match handletype {
        HandleType::StackGrowth => {
            // lazy alloc first and then real alloc
            let index = SUPPLEMENTAL_PAGETABLE
                .lock()
                .lazy_alloc(crate::mem::PageType::Swap(None));
            table.map(
                PhysAddr::from_pa(0),
                addr.floor(),
                PG_SIZE,
                PTEFlags::V | PTEFlags::R | PTEFlags::W | PTEFlags::U,
            );
            let entry = table.get_mut_pte(addr).unwrap();
            entry.evict(index);
            let token = unsafe { PageTable::get_token() };
            // kprintln!("pagetable token: {:#x}", token);
            let pa = PhysMemPool::real_alloc(addr.floor(), token) - VM_OFFSET;
            table.map(
                PhysAddr::from_pa(pa),
                addr.floor(),
                PG_SIZE,
                PTEFlags::V | PTEFlags::R | PTEFlags::W | PTEFlags::U,
            );
            kprintln!(
                "expand page {:#x}-{:x}, pa: {:#x}",
                addr.floor(),
                addr.floor() + PG_SIZE,
                pa,
            );
            return;
        }
        HandleType::Mmap => {
            // TODO
        }
        HandleType::Code => {
            // TODO
        }
        HandleType::Swap => {
            // TODO
        }
        HandleType::Error => {}
    }

    kprintln!(
        "Page fault at {:#x}: {} error {} page in {} context.",
        addr,
        if present { "rights" } else { "not present" },
        match fault {
            StorePageFault => "writing",
            LoadPageFault => "reading",
            InstructionPageFault => "fetching instruction",
            _ => panic!("Unknown Page Fault"),
        },
        match privilege {
            SPP::Supervisor => "kernel",
            SPP::User => "user",
        }
    );

    match privilege {
        SPP::Supervisor => {
            if frame.sepc == __knrl_read_usr_byte_pc as _ {
                // Failed to read user byte from kernel space when trap in pagefault
                frame.x[11] = 1; // set a1 to non-zero
                frame.sepc = __knrl_read_usr_exit as _;
            } else if frame.sepc == __knrl_write_usr_byte_pc as _ {
                // Failed to write user byte from kernel space when trap in pagefault
                frame.x[11] = 1; // set a1 to non-zero
                frame.sepc = __knrl_write_usr_exit as _;
            } else {
                panic!("Kernel page fault");
            }
        }
        SPP::User => {
            kprintln!(
                "User thread {} dying due to page fault.",
                thread::current().name()
            );
            userproc::exit(-1);
        }
    }
}
