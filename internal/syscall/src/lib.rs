// SPDX-License-Identifier: Apache-2.0

//! Common syscall handling across shims

#![deny(missing_docs)]
#![deny(clippy::all)]
#![cfg_attr(not(test), no_std)]

mod base;
mod enarx;
mod file;
mod memory;
mod network;
mod process;
mod system;

use core::convert::TryInto;
use primordial::Register;
use sallyport::Result;
use untrusted::AddressValidator;

pub use crate::base::BaseSyscallHandler;
pub use crate::enarx::EnarxSyscallHandler;
pub use crate::file::FileSyscallHandler;
pub use crate::memory::MemorySyscallHandler;
pub use crate::network::NetworkSyscallHandler;
pub use crate::process::ProcessSyscallHandler;
pub use crate::system::SystemSyscallHandler;

// import Enarx syscall constants
include!("../../../src/syscall/mod.rs");

// arch_prctl syscalls not available in the libc crate as of version 0.2.69
/// missing in libc
pub const ARCH_SET_GS: libc::c_int = 0x1001;
/// missing in libc
pub const ARCH_SET_FS: libc::c_int = 0x1002;
/// missing in libc
pub const ARCH_GET_FS: libc::c_int = 0x1003;
/// missing in libc
pub const ARCH_GET_GS: libc::c_int = 0x1004;

/// Fake pid returned by enarx
pub const FAKE_PID: usize = 1000;
/// Fake uid returned by enarx
pub const FAKE_UID: usize = 1000;
/// Fake gid returned by enarx
pub const FAKE_GID: usize = 1000;

/// not defined in libc
///
/// FIXME
pub struct KernelSigSet;

type KernelSigAction = [u64; 4];

/// A trait defining a shim syscall handler
///
/// Implemented for each shim. Some common methods are already implemented,
/// but can be overwritten with optimized versions.
pub trait SyscallHandler:
    Sized
    + AddressValidator
    + BaseSyscallHandler
    + MemorySyscallHandler
    + ProcessSyscallHandler
    + FileSyscallHandler
    + NetworkSyscallHandler
    + EnarxSyscallHandler
    + SystemSyscallHandler
{
    /// syscall
    #[allow(clippy::too_many_arguments)]
    fn syscall(
        &mut self,
        a: Register<usize>,
        b: Register<usize>,
        c: Register<usize>,
        d: Register<usize>,
        e: Register<usize>,
        f: Register<usize>,
        nr: usize,
    ) -> Result {
        let mut ret = match nr as _ {
            // MemorySyscallHandler
            libc::SYS_brk => self.brk(a.into()),
            libc::SYS_mmap => self.mmap(
                a.into(),
                b.into(),
                c.try_into().or(Err(libc::EINVAL))?,
                d.try_into().or(Err(libc::EINVAL))?,
                e.try_into().or(Err(libc::EINVAL))?,
                f.into(),
            ),
            libc::SYS_munmap => self.munmap(a.into(), b.into()),
            libc::SYS_madvise => {
                self.madvise(a.into(), b.into(), c.try_into().or(Err(libc::EINVAL))?)
            }
            libc::SYS_mprotect => {
                self.mprotect(a.into(), b.into(), c.try_into().or(Err(libc::EINVAL))?)
            }

            // ProcessSyscallHandler
            libc::SYS_arch_prctl => self.arch_prctl(a.try_into().or(Err(libc::EINVAL))?, b.into()),
            libc::SYS_exit => self.exit(a.try_into().or(Err(libc::EINVAL))?),
            libc::SYS_exit_group => self.exit_group(a.try_into().or(Err(libc::EINVAL))?),
            libc::SYS_set_tid_address => self.set_tid_address(a.into()),
            libc::SYS_rt_sigaction => self.rt_sigaction(
                a.try_into().or(Err(libc::EINVAL))?,
                b.into(),
                c.into(),
                d.into(),
            ),
            libc::SYS_rt_sigprocmask => self.rt_sigprocmask(
                a.try_into().or(Err(libc::EINVAL))?,
                b.into(),
                c.into(),
                d.into(),
            ),
            libc::SYS_sigaltstack => self.sigaltstack(a.into(), b.into()),
            libc::SYS_getpid => self.getpid(),
            libc::SYS_getuid => self.getuid(),
            libc::SYS_getgid => self.getgid(),
            libc::SYS_geteuid => self.geteuid(),
            libc::SYS_getegid => self.getegid(),

            // SystemSyscallHandler
            libc::SYS_getrandom => {
                self.getrandom(a.into(), b.into(), c.try_into().or(Err(libc::EINVAL))?)
            }
            libc::SYS_clock_gettime => {
                self.clock_gettime(a.try_into().or(Err(libc::EINVAL))?, b.into())
            }
            libc::SYS_uname => self.uname(a.into()),

            // FileSyscallHandler
            libc::SYS_close => self.close(a.try_into().or(Err(libc::EINVAL))?),
            libc::SYS_read => self.read(a.try_into().or(Err(libc::EINVAL))?, b.into(), c.into()),
            libc::SYS_readv => self.readv(
                a.try_into().or(Err(libc::EINVAL))?,
                b.into(),
                c.try_into().or(Err(libc::EINVAL))?,
            ),
            libc::SYS_write => self.write(a.try_into().or(Err(libc::EINVAL))?, b.into(), c.into()),
            libc::SYS_writev => self.writev(
                a.try_into().or(Err(libc::EINVAL))?,
                b.into(),
                c.try_into().or(Err(libc::EINVAL))?,
            ),
            libc::SYS_ioctl => self.ioctl(a.try_into().or(Err(libc::EINVAL))?, b.into(), c.into()),
            libc::SYS_readlink => self.readlink(a.into(), b.into(), c.into()),
            libc::SYS_fstat => self.fstat(a.try_into().or(Err(libc::EINVAL))?, b.into()),
            libc::SYS_fcntl => self.fcntl(
                a.try_into().or(Err(libc::EINVAL))?,
                b.try_into().or(Err(libc::EINVAL))?,
                c.try_into().or(Err(libc::EINVAL))?,
            ),
            libc::SYS_poll => self.poll(a.into(), b.into(), c.try_into().or(Err(libc::EINVAL))?),
            libc::SYS_pipe => self.pipe(a.into()),
            libc::SYS_epoll_create1 => self.epoll_create1(a.try_into().or(Err(libc::EINVAL))?),
            libc::SYS_epoll_ctl => self.epoll_ctl(
                a.try_into().or(Err(libc::EINVAL))?,
                b.try_into().or(Err(libc::EINVAL))?,
                c.try_into().or(Err(libc::EINVAL))?,
                d.into(),
            ),
            libc::SYS_epoll_wait => self.epoll_wait(
                a.try_into().or(Err(libc::EINVAL))?,
                b.into(),
                c.try_into().or(Err(libc::EINVAL))?,
                d.try_into().or(Err(libc::EINVAL))?,
            ),
            libc::SYS_epoll_pwait => self.epoll_pwait(
                a.try_into().or(Err(libc::EINVAL))?,
                b.into(),
                c.try_into().or(Err(libc::EINVAL))?,
                d.try_into().or(Err(libc::EINVAL))?,
                e.into(),
            ),
            libc::SYS_eventfd2 => self.eventfd2(usize::from(a) as _, usize::from(b) as _),
            libc::SYS_dup => self.dup(usize::from(a) as _),
            libc::SYS_dup2 => self.dup2(usize::from(a) as _, usize::from(b) as _),
            libc::SYS_dup3 => self.dup3(
                usize::from(a) as _,
                usize::from(b) as _,
                usize::from(c) as _,
            ),

            // NetworkSyscallHandler
            libc::SYS_socket => self.socket(
                a.try_into().or(Err(libc::EINVAL))?,
                b.try_into().or(Err(libc::EINVAL))?,
                c.try_into().or(Err(libc::EINVAL))?,
            ),
            libc::SYS_bind => self.bind(a.try_into().or(Err(libc::EINVAL))?, b.into(), c.into()),
            libc::SYS_listen => self.listen(
                a.try_into().or(Err(libc::EINVAL))?,
                b.try_into().or(Err(libc::EINVAL))?,
            ),
            libc::SYS_getsockname => {
                self.getsockname(a.try_into().or(Err(libc::EINVAL))?, b.into(), c.into())
            }
            libc::SYS_accept => {
                self.accept(a.try_into().or(Err(libc::EINVAL))?, b.into(), c.into())
            }
            libc::SYS_accept4 => self.accept4(
                a.try_into().or(Err(libc::EINVAL))?,
                b.into(),
                c.into(),
                d.try_into().or(Err(libc::EINVAL))?,
            ),
            libc::SYS_connect => {
                self.connect(a.try_into().or(Err(libc::EINVAL))?, b.into(), c.into())
            }
            libc::SYS_recvfrom => self.recvfrom(
                a.try_into().or(Err(libc::EINVAL))?,
                b.into(),
                c.into(),
                d.try_into().or(Err(libc::EINVAL))?,
                e.into(),
                f.into(),
            ),
            libc::SYS_sendto => self.sendto(
                a.try_into().or(Err(libc::EINVAL))?,
                b.into(),
                c.into(),
                d.try_into().or(Err(libc::EINVAL))?,
                e.into(),
                f.into(),
            ),
            libc::SYS_setsockopt => self.setsockopt(
                a.try_into().or(Err(libc::EINVAL))?,
                b.try_into().or(Err(libc::EINVAL))?,
                c.try_into().or(Err(libc::EINVAL))?,
                d.into(),
                e.try_into().or(Err(libc::EINVAL))?,
            ),

            SYS_ENARX_GETATT => self.get_attestation(a.into(), b.into(), c.into(), d.into()),

            _ => {
                self.unknown_syscall(a, b, c, d, e, f, nr);

                Err(libc::ENOSYS)
            }
        };

        #[cfg(target_arch = "x86_64")]
        if nr < 0xEA00 {
            // Non Enarx syscalls don't use `ret[1]` and have
            // to return the original value of `rdx`.
            ret = ret.map(|ret| [ret[0], c]);
        }

        ret
    }
}
