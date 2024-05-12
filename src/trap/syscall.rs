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
use crate::io::Read;
use crate::io::Seek;
use crate::mem::pagetable::{
    pt_check_buf, pt_read_user_item, pt_read_user_str, pt_write_user_item,
};
use crate::sbi::{console_getchar, console_putchar};
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
    // kprintln!("[SYSCALL] id: {}, args: {:?}", id, args);
    match id {
        SYS_HALT => sys_halt(),
        SYS_EXIT => sys_exit(args[0] as isize),
        SYS_WAIT => sys_wait(args[0] as isize),
        SYS_OPEN => sys_open(args[0] as *const u8, args[1] as usize),
        SYS_READ => sys_read(args[0], args[1] as *const u8, args[2]),
        SYS_WRITE => sys_write(args[0], args[1] as *const u8, args[2]),
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
            let mut file = DISKFS.get().open(Path::from(path_str.as_str())).unwrap();
            let _ = file.seek(crate::io::SeekFrom::Start(0));
            current.add_file(file, flag) as isize
        }
        _ => panic!("[SYS_OPEN] unexpected mark value"),
    }
}

fn sys_read(fd: usize, buf: *const u8, size: usize) -> isize {
    let mut ptr = buf;
    if fd == 0 {
        // read from console
        for _ in 0..size {
            let c = console_getchar() as u8;
            if pt_write_user_item(ptr as usize, &c).is_err() {
                return -1;
            }
            unsafe { ptr = ptr.add(1) };
        }
        size as isize
    } else if fd == 1 {
        -1
    } else {
        let current = current();
        let mut file = {
            let f = current.get_file(fd);
            if f.is_none() {
                return -1;
            }
            let (f, flag) = f.unwrap();
            if (flag & O_RDWR == 0) && (flag & O_WRONLY != 0) {
                return -1;
            }
            f
        };
        if pt_check_buf(buf as usize, size).is_err() {
            return -1;
        }
        for i in 0..size {
            let b: Result<u8, crate::OsError> = file.read_into();
            if b.is_err() {
                current.replace_file(fd, file);
                return i as isize;
            }
        }
        current.replace_file(fd, file);
        size as isize
    }
}

fn sys_write(fd: usize, buf: *const u8, size: usize) -> isize {
    if fd == 0 {
        -1
    } else if fd == 1 || fd == 2 {
        let mut ptr = buf;
        for _ in 0..size {
            let c: char = {
                let c = pt_read_user_item(ptr as usize);
                if c.is_err() {
                    return -1;
                } else {
                    c.unwrap()
                }
            };
            console_putchar(c as usize);
            unsafe { ptr = ptr.add(1) };
        }
        size as isize
    } else {
        -1
    }
}
