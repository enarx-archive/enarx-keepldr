// SPDX-License-Identifier: Apache-2.0

//! internal fd book keeping

use sallyport::Result;

/// internal fd book keeping
pub trait FdHandler {
    /// register a valid fd
    fn fd_register(&mut self, fd: libc::c_int);

    /// unregister a valid fd
    fn fd_unregister(&mut self, fd: libc::c_int);

    /// check, if an fd is valid
    ///
    /// returns `Err(libc::EBADFD)` if not
    fn fd_is_valid(&mut self, fd: libc::c_int) -> Result;

    /// shadow epoll_ctl
    fn fd_epoll_ctl(
        &mut self,
        epfd: libc::c_int,
        op: libc::c_int,
        fd: libc::c_int,
        event: libc::epoll_event,
    );

    /// get the event data for an fd
    fn fd_get_epoll_event_data(&mut self, epfd: libc::c_int, fd: libc::c_int) -> u64;
}
