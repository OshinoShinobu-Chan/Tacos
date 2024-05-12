#![allow(dead_code)]

use alloc::string::String;
use alloc::vec::Vec;
use core::arch::global_asm;

use crate::error::OsError;
use crate::mem::in_kernel_space;
use crate::Result;

/// Read a single byte from user space.
///
/// ## Return
/// - `Ok(byte)`
/// - `Err`: A page fault happened.
fn read_user_byte(user_src: *const u8) -> Result<u8> {
    if in_kernel_space(user_src as usize) {
        return Err(OsError::BadPtr);
    }

    let byte: u8 = 0;
    let ret_status: u8 = unsafe { __knrl_read_usr_byte(user_src, &byte as *const u8) };

    if ret_status == 0 {
        Ok(byte)
    } else {
        Err(OsError::BadPtr)
    }
}

pub fn read_user_str(user_src: *const u8) -> Result<String> {
    let mut ptr = user_src;
    let mut string = String::new();
    loop {
        let ch = read_user_byte(ptr)?;
        if ch == 0 {
            return Ok(string);
        } else {
            string.push(ch as char);
            unsafe { ptr = ptr.add(1) };
        }
    }
}

pub fn read_user_item<T: Sized>(user_src: *const T) -> Result<T> {
    let mut ptr = user_src as *const u8;
    let mut v = Vec::new();
    for _ in 0..core::mem::size_of::<T>() {
        let b = read_user_byte(ptr)?;
        v.push(b);
        unsafe { ptr = ptr.add(1) };
    }
    let buf = v.as_slice();
    let item = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *mut T) };
    Ok(item)
}

/// Write a single byte to user space.
///
/// ## Return
/// - `Ok(())`
/// - `Err`: A page fault happened.
fn write_user_byte(user_src: *const u8, value: u8) -> Result<()> {
    if in_kernel_space(user_src as usize) {
        return Err(OsError::BadPtr);
    }

    let ret_status: u8 = unsafe { __knrl_write_usr_byte(user_src, value) };

    if ret_status == 0 {
        Ok(())
    } else {
        Err(OsError::BadPtr)
    }
}

pub fn write_user_str(user_src: *mut u8, string: &String) -> Result<()> {
    let mut ptr = user_src;
    for c in string.as_bytes() {
        write_user_byte(ptr, c.clone())?;
        unsafe { ptr = ptr.add(1) };
    }
    Ok(())
}

pub fn write_user_item<T: Sized>(user_src: *mut T, item: &T) -> Result<()> {
    let mut ptr = user_src as *mut u8;
    let src = unsafe {
        core::slice::from_raw_parts(item as *const T as *const u8, core::mem::size_of::<T>())
    };
    for b in src {
        write_user_byte(ptr, b.clone())?;
        unsafe { ptr = ptr.add(1) };
    }
    Ok(())
}

extern "C" {
    pub fn __knrl_read_usr_byte(user_src: *const u8, byte_ptr: *const u8) -> u8;
    pub fn __knrl_read_usr_byte_pc();
    pub fn __knrl_read_usr_exit();
    pub fn __knrl_write_usr_byte(user_src: *const u8, value: u8) -> u8;
    pub fn __knrl_write_usr_byte_pc();
    pub fn __knrl_write_usr_exit();
}

global_asm! {r#"
        .section .text
        .globl __knrl_read_usr_byte
        .globl __knrl_read_usr_exit
        .globl __knrl_read_usr_byte_pc

    __knrl_read_usr_byte:
        mv t1, a1
        li a1, 0
    __knrl_read_usr_byte_pc:
        lb t0, (a0)
    __knrl_read_usr_exit:
        # pagefault handler will set a1 if any error occurs
        sb t0, (t1)
        mv a0, a1
        ret

        .globl __knrl_write_usr_byte
        .globl __knrl_write_usr_exit
        .globl __knrl_write_usr_byte_pc

    __knrl_write_usr_byte:
        mv t1, a1
        li a1, 0
    __knrl_write_usr_byte_pc:
        sb t1, (a0)
    __knrl_write_usr_exit:
        # pagefault handler will set a1 if any error occurs
        mv a0, a1
        ret
"#}
