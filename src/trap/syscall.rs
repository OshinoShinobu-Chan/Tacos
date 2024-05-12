//! Syscall handlers
//!

#![allow(dead_code)]

/* -------------------------------------------------------------------------- */
/*                               SYSCALL NUMBER                               */
/* -------------------------------------------------------------------------- */
use alloc::string::String;
use alloc::vec::Vec;

use crate::fs::disk::Path;
use crate::fs::disk::DISKFS;
use crate::mem::pagetable::{pt_read_user_item, pt_read_user_str};
use crate::thread::current;
use crate::userproc::{self, execute, wait};
use crate::FileSys;

const SYS_HALT: usize = 1;
const SYS_EXIT: usize = 2;
const SYS_EXEC: usize = 3;
const SYS_WAIT: usize = 4;
const SYS_REMOVE: usize = 5;
const SYS_OPEN: usize = 6;
const SYS_READ: usize = 7;
const SYS_WRITE: usize = 8;
const SYS_SEEK: usize = 9;
const SYS_TELL: usize = 10;
const SYS_CLOSE: usize = 11;
const SYS_FSTAT: usize = 12;

const O_RDONLY: usize = 0x0;
const O_WRONLY: usize = 0x1;
const O_RDWR: usize = 0x2;
const O_CREATE: usize = 0x200;
const O_TRUNC: usize = 0x400;

pub fn syscall_handler(id: usize, args: [usize; 3]) -> isize {
    kprintln!("[SYSCALL] id: {}, args: {:?}", id, args);
    match id {
        SYS_HALT => sys_halt(),
        SYS_EXIT => sys_exit(args[0] as isize),
        SYS_WAIT => sys_wait(args[0] as isize),
        _ => panic!("Unsupported syscall!"),
    }
}

/// Halt the system
fn sys_halt() -> ! {
    crate::sbi::shutdown()
}

/// Terminate this process
fn sys_exit(exit_code: isize) -> ! {
    let current = current();
    if current.userproc.is_some() {
        userproc::exit(exit_code)
    } else {
        unreachable!("thread without userproc should not call sys_exit")
    }
}

fn sys_exec(path: *const u8, argv: *const usize) -> isize {
    let path = {
        let p = pt_read_user_str(path as usize);
        if p.is_ok() {
            p.unwrap()
        } else {
            return -1;
        }
    };
    let file = {
        let f = DISKFS.open(path.as_str().into());
        if f.is_ok() {
            f.unwrap()
        } else {
            return -1;
        }
    };
    // read the args
    let mut args: Vec<String> = Vec::new();
    loop {
        // read pointer of arg
        let arg_ptr = {
            let p = pt_read_user_item(argv as usize);
            if p.is_ok() {
                p.unwrap()
            } else {
                return -1;
            }
        };
        if arg_ptr == 0 {
            break;
        }
        let arg = {
            let s = pt_read_user_str(arg_ptr);
            if s.is_ok() {
                s.unwrap()
            } else {
                return -1;
            }
        };
        args.push(arg);
        unsafe { argv.add(1) };
    }
    execute(file, args)
}

fn sys_wait(pid: isize) -> isize {
    wait(pid).unwrap_or(-1)
}

fn sys_open(path: *const u8, flag: usize) -> isize {
    let current = current();
    let path_str = {
        let s = pt_read_user_str(path as usize);
        if s.is_err() {
            return -1;
        } else {
            s.unwrap()
        }
    };
    let mut mark: usize = 0;
    if Path::exists(Path::from(path_str.clone().as_str())) {
        mark += 1;
    }
    if flag & O_CREATE != 0 {
        mark += 1 << 1;
    }
    if flag & O_TRUNC != 0 {
        mark += 1 << 2;
    }
    kprintln!("mark: {}", mark);
    match mark {
        // file doesn't exists and not create mode
        0 | 4 => -1,
        1 | 3 => {
            // file must exists, and not trunc mode, so just open it
            let file = DISKFS.get().open(Path::from(path_str.as_str())).unwrap();
            current.add_file(file, flag) as isize
        }
        2 | 6 => {
            // file doesn't exist, create it
            if let Ok(file) = DISKFS.create(Path::from(path_str.as_str())) {
                current.add_file(file, flag) as isize
            } else {
                -1
            }
        }
        5 | 7 => {
            // file exists, but in trunc mode, so remove the previous one
            // and create a new one
            if DISKFS
                .remove(Path::from(path_str.clone().as_str()))
                .is_err()
            {
                return -1;
            }
            if let Ok(file) = DISKFS.create(Path::from(path_str.as_str())) {
                current.add_file(file, flag) as isize
            } else {
                -1
            }
        }
        _ => panic!("[SYS_OPEN] unexpected mark value"),
    }
}
