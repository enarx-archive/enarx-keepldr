// SPDX-License-Identifier: Apache-2.0

//! The SGX shim
//!
//! This crate contains the system that traps the syscalls (and cpuid
//! instructions) from the enclave code and proxies them to the host.

#![no_std]
#![feature(asm)]
#![feature(naked_functions)]
#![deny(clippy::all)]
#![deny(missing_docs)]
#![no_main]

extern crate compiler_builtins;
extern crate rcrt1;

#[panic_handler]
#[allow(clippy::empty_loop)]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// _Unwind_Resume is only needed in the `debug` profile
///
/// even though this project has `panic=abort`
/// it seems like the debug libc.rlib has some references
/// with unwinding
/// See also: https://github.com/rust-lang/rust/issues/47493
#[cfg(debug_assertions)]
#[no_mangle]
extern "C" fn _Unwind_Resume() {
    unimplemented!();
}

/// rust_eh_personality is only needed in the `debug` profile
///
/// even though this project has `panic=abort`
/// it seems like the debug libc.rlib has some references
/// with unwinding
/// See also: https://github.com/rust-lang/rust/issues/47493
#[cfg(debug_assertions)]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {
    unimplemented!();
}

// ============== REAL CODE HERE ===============

macro_rules! debug {
    ($dst:expr, $($arg:tt)*) => {
        #[allow(unused_must_use)] {
            use core::fmt::Write;
            write!($dst, $($arg)*);
        }
    };
}

macro_rules! debugln {
    ($dst:expr) => { debugln!($dst,) };
    ($dst:expr, $($arg:tt)*) => {
        #[allow(unused_must_use)] {
            use core::fmt::Write;
            writeln!($dst, $($arg)*);
        }
    };
}

mod enclave;
mod entry;
mod event;
mod handler;
mod hostlib;

use hostlib::Layout;

sallyport::declare_abi_version!();
