// SPDX-License-Identifier: Apache-2.0

//! # Backend
//! TODO: this is a placeholder for proper module documentation

#[cfg(feature = "backend-kvm")]
pub mod kvm;

#[cfg(feature = "backend-sgx")]
pub mod sgx;

mod probe;

use crate::binary::Component;

use std::sync::Arc;

use anyhow::Result;
use sallyport::Block;

/// The Backend trait is an abstraction over the various hardware TEE backends
/// (Intel SGX, AMD SEV, and so on).
/// TODO: explain better
pub trait Backend {
    /// The name of the backend
    fn name(&self) -> &'static str;

    /// The builtin shim
    fn shim(&self) -> &'static [u8];

    /// Whether or not the platform has support for this keep type
    fn have(&self) -> bool {
        !self.data().iter().fold(false, |e, d| e | !d.pass)
    }

    /// The tests that show platform support for the backend
    fn data(&self) -> Vec<Datum>;

    /// Create a keep instance on this backend
    fn build(&self, shim: Component, code: Component) -> Result<Arc<dyn Keep>>;
}

/// A single piece of data about the host's support for a given Backend.
pub struct Datum {
    /// The name of this datum.
    pub name: String,

    /// Whether the datum indicates support for the platform or not.
    pub pass: bool,

    /// Short additional information to display to the user.
    pub info: Option<String>,

    /// Longer explanatory message on how to resolve problems.
    pub mesg: Option<String>,
}

/// The `Keep` trait gives an interface for spawning a Thread inside a Keep.
/// (TODO: more docs...)
pub trait Keep {
    /// Creates a new thread in the keep.
    fn spawn(self: Arc<Self>) -> Result<Option<Box<dyn Thread>>>;
}

/// The `Thread` trait enters the Thread in the Keep and then returns a Command,
/// which indicates why the thread has paused/ceased execution and what we
/// need to do about it. See Command for details.
/// TODO: I made this up; someone should edit/approve it
/// TODO: Link "Command" to the `Command` enum
pub trait Thread {
    /// Enters the keep.
    fn enter(&mut self) -> Result<Command>;
}

/// The Command enum gives the reason we stopped execution of the Thread, and
/// tells us what to do next - either we need to handle a Syscall or we can
/// simply Continue on our way.
/// TODO: uhhh I made that explanation up, someone should rewrite/verify this..
pub enum Command<'a> {
    /// This indicates that we need to handle a SysCall.
    /// TODO: ...or does it mean we just handled one?
    /// TODO: also, explain Block?
    #[allow(dead_code)]
    SysCall(&'a mut Block),

    /// No need to handle a SysCall, we can just continue on our way
    #[allow(dead_code)]
    Continue,
}
