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
use crate::io::Write;
use crate::mem::pagetable::{
    pt_check_buf, pt_read_user_item, pt_read_user_str, pt_unmap_pages, pt_write_user_item,
    PageTable,
};
use crate::mem::PTEFlags;
use crate::mem::PhysAddr;
use crate::mem::SUPPLEMENTAL_PAGETABLE;
use crate::mem::{PageAlign, PG_SIZE};
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

#[repr(C)]
pub struct Fstat {
    pub ino: u64,
    pub size: u64,
}

pub fn syscall_handler(id: usize, args: [usize; 3]) -> isize {
    // kprintln!("[SYSCALL] id: {}, args: {:?}", id, args);
    match id {
        SYS_HALT => sys_halt(),
        SYS_EXIT => sys_exit(args[0] as isize),
        SYS_EXEC => sys_exec(args[0] as *const u8, args[1] as *const usize),
        SYS_WAIT => sys_wait(args[0] as isize),
        SYS_REMOVE => sys_remove(args[0] as *const u8),
        SYS_OPEN => sys_open(args[0] as *const u8, args[1] as usize),
        SYS_READ => sys_read(args[0], args[1] as *const u8, args[2]),
        SYS_WRITE => sys_write(args[0], args[1] as *const u8, args[2]),
        SYS_SEEK => sys_seek(args[0], args[1]),
        SYS_CLOSE => sys_close(args[0]),
        SYS_TELL => sys_tell(args[0]),
        SYS_FSTAT => sys_fstat(args[0], args[1] as *mut Fstat),
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
    if current.userproc.lock().is_some() {
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
    kprintln!("[EXEC] path: {}", path);
    let file = {
        let f = DISKFS.open(path.as_str().into());
        if f.is_ok() {
            f.unwrap()
        } else {
            return -1;
        }
    };
    // file.deny_write();
    // read the args
    let mut args: Vec<String> = Vec::new();
    let mut ptr = argv;
    loop {
        // read pointer of arg
        let arg_ptr = {
            let p = pt_read_user_item(ptr as usize);
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
        if arg.is_empty() {
            break;
        }
        args.push(arg);
        unsafe { ptr = ptr.add(1) };
    }
    kprintln!("[EXEC] Args: {:?}", args);
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
            if path_str.is_empty() {
                // should not create file with empty name
                return -1;
            }
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
            if pt_write_user_item(ptr as usize, b.as_ref().unwrap()).is_err() {
                return -1;
            }
            unsafe { ptr = ptr.add(1) };
        }
        current.replace_file(fd, file);
        size as isize
    }
}

fn sys_seek(fd: usize, pos: usize) -> isize {
    if fd == 0 || fd == 1 || fd == 2 {
        return -1;
    }
    let current = current();
    let mut file = {
        let f = current.get_file(fd);
        if f.is_none() {
            return -1;
        }
        f.unwrap().0
    };
    let _ = file.seek(crate::io::SeekFrom::Start(pos));
    current.replace_file(fd, file);
    0
}

fn sys_write(fd: usize, buf: *const u8, size: usize) -> isize {
    let mut ptr = buf;
    if fd == 0 {
        -1
    } else if fd == 1 || fd == 2 {
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
        let current = current();
        let mut file = {
            let f = current.get_file(fd);
            if f.is_none() {
                return -1;
            }
            let (f, flag) = f.unwrap();
            if (flag & O_RDWR == 0) && (flag & O_WRONLY == 0) {
                return -1;
            }
            f
        };
        if pt_check_buf(buf as usize, size).is_err() {
            return -1;
        }
        for i in 0..size {
            let b: u8 = {
                let b = pt_read_user_item(ptr as usize);
                if b.is_err() {
                    return -1;
                } else {
                    b.unwrap()
                }
            };
            // if file.write_from(b).is_err() {
            //     current.replace_file(fd, file);
            //     return i as isize;
            // }
            match file.write_from(b) {
                Ok(()) => {}
                Err(crate::OsError::UnexpectedEOF) => {
                    current.replace_file(fd, file);
                    return i as isize;
                }
                Err(_) => {
                    current.replace_file(fd, file);
                    return -1;
                }
            }
            unsafe { ptr = ptr.add(1) };
        }
        current.replace_file(fd, file);
        size as isize
    }
}

fn sys_remove(path: *const u8) -> isize {
    let path_str = {
        let s = pt_read_user_str(path as usize);
        if s.is_err() {
            return -1;
        } else {
            s.unwrap()
        }
    };
    if DISKFS.remove(Path::from(path_str.as_str())).is_ok() {
        0
    } else {
        -1
    }
}

fn sys_tell(fd: usize) -> isize {
    if fd == 0 || fd == 1 || fd == 2 {
        return -1;
    }
    let current = current();
    let mut file = {
        let f = current.get_file(fd);
        if f.is_none() {
            return -1;
        }
        f.unwrap().0
    };
    if let Ok(pos) = file.pos() {
        *pos as isize + 1
    } else {
        -1
    }
}

fn sys_close(fd: usize) -> isize {
    if fd == 0 || fd == 1 || fd == 2 {
        return 0;
    }
    let current = current();
    if current.get_file(fd).is_none() {
        -1
    } else {
        current.remove_file(fd);
        0
    }
}

fn sys_fstat(fd: usize, buf: *mut Fstat) -> isize {
    if fd == 0 || fd == 1 || fd == 2 {
        return -1;
    }
    let current = current();
    let file = {
        let f = current.get_file(fd);
        if f.is_none() {
            return -1;
        }
        f.unwrap().0
    };
    let ino = file.inum() as u64;
    let size = {
        let s = file.len();
        if s.is_err() {
            return -1;
        }
        s.unwrap() as u64
    };
    let stat = Fstat { ino, size };
    if pt_write_user_item(buf as usize, &stat).is_err() {
        return -1;
    }
    return 0;
}

fn sys_mmap(fd: usize, addr: usize) -> isize {
    if addr == 0 {
        return -1;
    }
    if fd == 0 || fd == 1 || fd == 2 {
        return -1;
    }
    if !addr.is_aligned() {
        return -1;
    }
    let current = current();
    let index;
    let size;
    let mut file;
    match current.add_mmap(fd, addr) {
        (-1, _, _) => return -1,
        (i, s, f) => {
            index = i;
            size = s;
            file = f.unwrap();
        }
    }
    let mut ptr = addr;
    let end = addr + size;
    while ptr < end {
        let i = SUPPLEMENTAL_PAGETABLE
            .lock()
            .lazy_alloc(crate::mem::PageType::Mmap((
                core::ptr::addr_of_mut!(file),
                ptr - addr,
            )));
        let mut pt = unsafe { PageTable::effective_pagetable() };
        pt.map(
            PhysAddr::from_pa(0),
            ptr,
            PG_SIZE,
            PTEFlags::V | PTEFlags::R | PTEFlags::W | PTEFlags::U,
        );
        let entry = pt.get_mut_pte(ptr).unwrap();
        entry.evict(i);
        ptr += PG_SIZE;
    }
    index
}

fn sys_unmmap(id: usize) -> isize {
    let current = current();
    let (addr, size) = {
        if let Some((f, addr)) = current.get_mmap_by_id(id) {
            (addr, f.len().unwrap())
        } else {
            return -1;
        }
    };
    current.remove_mmap(id);
    pt_unmap_pages(addr, size);
    0
}
