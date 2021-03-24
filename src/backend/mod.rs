// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "backend-kvm")]
pub mod kvm;
#[cfg(feature = "backend-sev")]
pub mod sev;
#[cfg(feature = "backend-sgx")]
pub mod sgx;

mod probe;

use crate::binary::Component;

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use sallyport::Block;

pub trait Backend {
    /// The name of the backend
    fn name(&self) -> &'static str;

    /// Whether or not the platform has support for this keep type
    fn have(&self) -> bool {
        !self.data().iter().fold(false, |e, d| e | !d.pass)
    }

    /// The tests that show platform support for the backend
    fn data(&self) -> Vec<Datum>;

    /// Create a keep instance on this backend
    fn build(&self, code: Component, sock: Option<&Path>) -> Result<Arc<dyn Keep>>;

    /// Create a keep instance on this backend, measure the keep
    /// and output a json record for the specific backend
    fn measure(&self, code: Component) -> Result<String>;
}

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

pub trait Keep {
    /// Creates a new thread in the keep.
    fn add_thread(self: Arc<Self>) -> Result<Box<dyn Thread>>;
}

pub trait Thread {
    /// Enters the keep.
    fn enter(&mut self) -> Result<Command>;
}

pub enum Command<'a> {
    #[allow(dead_code)]
    SysCall(&'a mut Block),
    #[allow(dead_code)]
    Continue,
}
