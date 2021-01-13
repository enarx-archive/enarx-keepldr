// SPDX-License-Identifier: Apache-2.0

// Shared components for the shim and the loader
// # Loader
//
// The loader calls [`BootInfo::calculate`] to get the offset for the shim and the code.
//
// The loader starts the virtual machine and jumps to the shim entry point.
//
// The shim expects the following registers:
// * `%rdi` = `SYSCALL_PHYS_ADDR`, address of the page, where the loader placed a copy of `BootInfo`
//            and which is used later on for the communication with the shim.
// * `%rsi` = the start address of the shim memory (contents of `BootInfo.shim.start`)
// * `%rip` = the address of the shim entry point taken from the elf header
//
// Although `%rsi` is redundant, it makes the initial startup function of the `shim` much easier.
//
// # Shim
//
// The shim sets the unencrypted flag for the page at `SYSCALL_PHYS_ADDR` and uses that page
// for further communication with the host.
//
// The `setup` area must not be touched, unless the shim sets up the page tables,
// the GDT and the IDT. After that the setup area is used as free memory except for the pages
// to communicate with the host.
//
// To proxy a syscall to the host, the shim triggers a `#VMEXIT` via I/O on the
// [`SYSCALL_TRIGGER_PORT`].
//
// [`BootInfo::calculate`]: struct.BootInfo.html#method.calculate
// [`SYSCALL_TRIGGER_PORT`]: constant.SYSCALL_TRIGGER_PORT.html

/// I/O port used to trigger a `#VMEXIT`
///
/// FIXME: might change to another mechanism in the future
pub const SYSCALL_TRIGGER_PORT: u16 = 0xFF;

use core::mem::{align_of, size_of, MaybeUninit};
use lset::{Line, Span};
use nbytes::bytes;
use primordial::Page;

/// The first 2MB are unencrypted shared memory
#[allow(clippy::integer_arithmetic)]
pub const MAX_SETUP_SIZE: usize = bytes!(2; MiB);

#[inline(always)]
#[allow(clippy::integer_arithmetic)]
const fn lower(value: usize, boundary: usize) -> usize {
    value / boundary * boundary
}

#[inline(always)]
fn raise(value: usize, boundary: usize) -> Option<usize> {
    value
        .checked_add(boundary)
        .map(|v| v.wrapping_sub(1))
        .map(|v| lower(v, boundary))
}

#[inline(always)]
fn above(rel: impl Into<Line<usize>>, size: usize, align: usize) -> Option<Span<usize>> {
    raise(rel.into().end, align).map(|val| Span {
        start: val,
        count: size,
    })
}

/// The maximum size of the injected secret for SEV keeps
#[allow(clippy::integer_arithmetic)]
pub const SEV_SECRET_MAX_SIZE: usize = bytes!(16; KiB);

/// A 16 byte aligned SevSecret with unknown content
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug)]
pub struct SevSecret {
    /// the secret byte blob
    pub data: MaybeUninit<[u8; SEV_SECRET_MAX_SIZE]>,
}

impl SevSecret {
    /// Get the pointer to the SEV secret relative to the BootInfo pointer
    #[allow(dead_code)]
    pub fn get_secret_ptr(boot_info: *const BootInfo) -> *const SevSecret {
        unsafe {
            let secret_ptr = (boot_info as *const u8).add(size_of::<BootInfo>());
            secret_ptr.add(secret_ptr.align_offset(align_of::<SevSecret>())) as *const SevSecret
        }
    }
}

/// Basic information for the shim and the loader
#[repr(C)]
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq)]
pub struct BootInfo {
    /// Memory for the loader to place page tables, GDT and IDT and the
    /// shared pages
    pub setup: Line<usize>,
    /// Memory where the `shim` is / has to be loaded
    pub shim: Line<usize>,
    /// Memory where the `code` is / has to be loaded
    pub code: Line<usize>,
    /// Memory size
    pub mem_size: usize,
    /// Number of `sallyport::Block` provided
    pub nr_syscall_blocks: usize,
}

/// Basic information about the host memory
#[repr(C)]
#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct MemInfo {
    /// Loader virtual memory offset to shim physical memory
    pub virt_start: usize,
    /// Number of memory slot available for ballooning
    pub mem_slots: usize,
}

impl core::fmt::Debug for MemInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("MemInfo")
            .field(
                "virt_start",
                &format_args!("{:#?}", self.virt_start as *const u8),
            )
            .field("mem_slots", &self.mem_slots)
            .finish()
    }
}

/// Error returned, if the virtual machine memory is to small for the shim to operate.
///
/// Because of `no_std` it does not implement `std::error::Error`.
pub struct NoMemory(());

impl BootInfo {
    /// Calculates the memory layout of various components
    ///
    /// Given the size of the available memory `mem_size`, the addresses of `setup`
    /// and the size of `shim` and `code`, this function calculates
    /// the layout for the `shim` and `code`.
    ///
    /// # Errors
    ///
    /// `NoMemory`: if there is not enough memory for the shim to operate
    #[inline]
    pub fn calculate(
        setup: Line<usize>,
        shim: Span<usize>,
        code: Span<usize>,
    ) -> Result<Self, NoMemory> {
        debug_assert!(
            setup.end < MAX_SETUP_SIZE,
            "The setup area has to be smaller than 2MB < {}",
            setup.end
        );

        // The first 2MB are unencrypted shared memory
        let shim: Line<usize> = above(setup, shim.count, MAX_SETUP_SIZE)
            .ok_or(NoMemory(()))?
            .into();

        let code: Line<usize> = above(shim, code.count, Page::size())
            .ok_or(NoMemory(()))?
            .into();

        let mem_size = raise(code.end, Page::size()).ok_or(NoMemory(()))?;

        Ok(Self {
            setup,
            shim,
            code,
            mem_size,
            nr_syscall_blocks: 0,
        })
    }
}
