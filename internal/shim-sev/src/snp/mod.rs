// SPDX-License-Identifier: Apache-2.0

//! SNP specific modules and functions
use crate::snp::Error::{FailInput, FailSizeMismatch, Unknown};
use x86_64::VirtAddr;

pub mod cpuid_page;
pub mod ghcb;
pub mod secrets_page;

/// Error returned by pvalidate
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Reasons:
    /// - Page size is 2MB and page is not 2MB aligned
    FailInput,
    /// Reasons:
    /// - 2MB validation backed by 4KB pages
    FailSizeMismatch,
    /// Unknown error
    Unknown(u32),
}

/// AMD pvalidate
#[inline(always)]
pub fn pvalidate(addr: VirtAddr, size: usize, flag: u32) -> Result<bool, Error> {
    let rmp_done: u32;
    let ret: u64;

    unsafe {
        asm!("
            pvalidate
            setc    dl
        ",
        inout("rax") addr.as_u64() & (!0xFFF) => ret,
        in("rcx") size,
        inout("edx") flag => rmp_done,
        options(nostack, nomem)
        );
    }

    match ret as u32 {
        0 => Ok(rmp_done as u8 == 0),
        1 => Err(FailInput),
        6 => Err(FailSizeMismatch),
        ret => Err(Unknown(ret)),
    }
}
