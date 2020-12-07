// SPDX-License-Identifier: Apache-2.0

//! memory syscalls

use crate::BaseSyscallHandler;
use sallyport::Result;
use untrusted::{UntrustedRef, UntrustedRefMut};

/// memory syscalls
pub trait MemorySyscallHandler: BaseSyscallHandler {
    /// syscall
    fn brk(&mut self, addr: *const u8) -> Result;

    /// syscall
    fn mmap(
        &mut self,
        addr: UntrustedRef<u8>,
        length: libc::size_t,
        prot: libc::c_int,
        flags: libc::c_int,
        fd: libc::c_int,
        offset: libc::off_t,
    ) -> Result;

    /// syscall
    fn munmap(&mut self, addr: UntrustedRef<u8>, length: libc::size_t) -> Result;

    /// syscall
    fn madvise(
        &mut self,
        addr: *const libc::c_void,
        length: libc::size_t,
        advice: libc::c_int,
    ) -> Result;

    /// syscall
    fn mprotect(&mut self, addr: UntrustedRef<u8>, len: libc::size_t, prot: libc::c_int) -> Result;

    /// syscall
    fn mremap(
        &mut self,
        old_addr: UntrustedRefMut<u8>,
        old_size: libc::size_t,
        new_size: libc::size_t,
        flags: libc::c_int,
        new_addr: UntrustedRef<u8>,
    ) -> Result {
        self.unknown_syscall(
            old_addr.as_ptr().into(),
            old_size.into(),
            (flags as usize).into(),
            new_size.into(),
            new_addr.as_ptr().into(),
            0.into(),
            libc::SYS_mremap as _,
        );
        Err(libc::ENOSYS)
    }
}
