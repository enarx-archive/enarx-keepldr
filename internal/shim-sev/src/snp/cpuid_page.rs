// SPDX-License-Identifier: Apache-2.0

//! FIXME

use const_default::ConstDefault;
use core::mem::size_of;

use core::fmt::{Debug, Formatter};

const COUNT_MAX: usize = 64;

/// An entry in the SNP CPUID Page
#[repr(C)]
#[derive(Copy, Clone, Default, ConstDefault, Eq, PartialEq)]
pub struct CpuidFunctionEntry {
    /// function
    pub eax_in: u32,
    /// index
    pub ecx_in: u32,
    /// register state when cpuid is called
    pub xcr0_in: u64,
    /// register state when cpuid is called
    pub xss_in: u64,
    /// cpuid out
    pub eax: u32,
    /// cpuid out
    pub ebx: u32,
    /// cpuid out
    pub ecx: u32,
    /// cpuid out
    pub edx: u32,
    reserved: u64,
}

#[allow(clippy::match_single_binding)]
impl Debug for CpuidFunctionEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CpuidFunctionEntry")
            .field("eax_in", &(format_args!("{:#x}", self.eax_in)))
            .field("ecx_in", &(format_args!("{:#x}", self.ecx_in)))
            .field("xcr0_in", &(format_args!("{:#x}", self.xcr0_in)))
            .field("xss_in", &(format_args!("{:#x}", self.xss_in)))
            .field("eax", &(format_args!("{:#x}", self.eax)))
            .field("ebx", &(format_args!("{:#x}", self.ebx)))
            .field("ecx", &(format_args!("{:#x}", self.ecx)))
            .field("edx", &(format_args!("{:#x}", self.edx)))
            .finish()
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct CpuidPageEntry {
    count: u32,
    reserved_1: u32,
    reserved_2: u64,
    functions: [CpuidFunctionEntry; COUNT_MAX],
}

impl ConstDefault for CpuidPageEntry {
    const DEFAULT: Self = CpuidPageEntry {
        count: 0,
        reserved_1: 0,
        reserved_2: 0,
        functions: [CpuidFunctionEntry::DEFAULT; COUNT_MAX],
    };
}

impl Default for CpuidPageEntry {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The CPUID page to be copied in the guest VM
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct CpuidPage {
    entry: CpuidPageEntry,
    space: [u8; CpuidPage::space_size()],
}

impl CpuidPage {
    #[allow(clippy::integer_arithmetic)]
    const fn space_size() -> usize {
        4096 - size_of::<CpuidPageEntry>()
    }
}

impl ConstDefault for CpuidPage {
    const DEFAULT: Self = CpuidPage {
        entry: ConstDefault::DEFAULT,
        space: [0; CpuidPage::space_size()],
    };
}

impl Default for CpuidPage {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Error thrown by CpuidPage methods
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// no memory allocating structs for the ioctl
    NoMemory,
    /// the page already contains the maximum number of entries
    Full,
}

impl CpuidPage {
    /// Get all entries
    pub fn get_functions(&self) -> &[CpuidFunctionEntry] {
        &self.entry.functions[..self.entry.count as usize]
    }

    /// Add an entry
    #[allow(clippy::integer_arithmetic)]
    pub fn add_entry(&mut self, entry: &CpuidFunctionEntry) -> Result<(), Error> {
        if self.entry.count as usize >= COUNT_MAX {
            return Err(Error::Full);
        }
        self.entry.functions[self.entry.count as usize] = *entry;
        self.entry.count += 1;
        Ok(())
    }
}
