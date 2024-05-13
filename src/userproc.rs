//! User process.
//!

mod load;

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::arch::asm;
use core::mem::MaybeUninit;
use riscv::register::sstatus;

use crate::fs::File;
use crate::mem::pagetable::KernelPgTable;
use crate::thread::{self, current, schedule, Thread};
use crate::trap::{trap_exit_u, Frame};

pub struct UserProc {
    #[allow(dead_code)]
    bin: File,
    parent: Weak<Thread>,
}

impl UserProc {
    pub fn new(file: File, parent: Arc<Thread>) -> Self {
        Self {
            bin: file,
            parent: Arc::downgrade(&parent),
        }
    }
}

/// Execute an object file with arguments.
///
/// ## Return
/// - `-1`: On error.
/// - `tid`: Tid of the newly spawned thread.
#[allow(unused_variables)]
pub fn execute(mut file: File, argv: Vec<String>) -> isize {
    #[cfg(feature = "debug")]
    kprintln!(
        "[PROCESS] Kernel thread {} prepare to execute a process with args {:?}",
        thread::current().name(),
        argv
    );

    // It only copies L2 pagetable. This approach allows the new thread
    // to access kernel code and data during syscall without the need to
    // swithch pagetables.
    let mut pt = KernelPgTable::clone();

    let exec_info = match load::load_executable(&mut file, &mut pt) {
        Ok(x) => x,
        Err(_) => unsafe {
            pt.destroy();
            return -1;
        },
    };

    // Initialize frame, pass argument to user.
    let mut frame = unsafe { MaybeUninit::<Frame>::zeroed().assume_init() };
    frame.sepc = exec_info.entry_point;
    frame.x[2] = exec_info.init_sp;

    // Here the new process will be created.
    let current = current();
    let userproc = UserProc::new(file, current);

    // TODO: (Lab2) Pass arguments to user program
    let len = argv.len();
    frame.x[2] -= (len + 1) * core::mem::size_of::<usize>();
    let argv_base = frame.x[2];
    let arg_ptr_addr: Vec<_> = (0..=len)
        .map(|x| (frame.x[2] + x * core::mem::size_of::<usize>()))
        .collect();
    if pt
        .write_user_item(arg_ptr_addr[len], &(0 as usize))
        .is_err()
    {
        return -1;
    }
    for i in 0..len {
        let p = frame.x[2] - 1;
        frame.x[2] -= argv[i].len() + 1;
        // kprintln!(
        //     "arg[{}] pos: {:#x}, value: {:#x}",
        //     i,
        //     arg_ptr_addr[i],
        //     frame.x[2]
        // );
        if pt.write_user_item(arg_ptr_addr[i], &frame.x[2]).is_err() {
            return -1;
        }
        if pt.write_user_str(frame.x[2], &argv[i]).is_err() {
            return -1;
        }
        if pt.write_user_item(p, &(0 as u8)).is_err() {
            return -1;
        }
    }
    frame.x[2] -= frame.x[2] % 8;
    frame.x[10] = len;
    frame.x[11] = argv_base;
    let sp = frame.x[2];

    thread::Builder::new(move || start(frame))
        .pagetable(pt)
        .userproc(userproc)
        .stack(exec_info.init_sp, sp)
        .spawn()
        .id()
}

/// Exits a process.
///
/// Panic if the current thread doesn't own a user process.
pub fn exit(value: isize) -> ! {
    // TODO: Lab2.
    let current = current();
    let parent = current.userproc.lock().as_ref().unwrap().parent.clone();
    let parent = parent.upgrade();
    if let Some(parent) = parent {
        parent.dead_child(current.id() as usize, value)
    }
    drop(current.userproc.lock().take().unwrap().bin);
    thread::exit();
}

/// Waits for a child thread, which must own a user process.
///
/// ## Return
/// - `Some(exit_value)`
/// - `None`: if tid was not created by the current thread.
pub fn wait(tid: isize) -> Option<isize> {
    // TODO: Lab2.
    let current = current();
    loop {
        if let Some(is_dead) = current.check_child(tid as usize) {
            if is_dead {
                return Some(current.remove_child(tid as usize));
            } else {
                schedule();
            }
        } else {
            return Some(-1);
        }
    }
}

/// Initializes a user process in current thread.
///
/// This function won't return.
pub fn start(mut frame: Frame) -> ! {
    unsafe { sstatus::set_spp(sstatus::SPP::User) };
    frame.sstatus = sstatus::read();

    // Set kernel stack pointer to intr frame and then jump to `trap_exit_u()`.
    let kernal_sp = (&frame as *const Frame) as usize;

    unsafe {
        asm!(
            "mv sp, t0",
            "jr t1",
            in("t0") kernal_sp,
            in("t1") trap_exit_u as *const u8
        );
    }

    unreachable!();
}
