// SPDX-License-Identifier: Apache-2.0

//! This crate provides the `enarx-keepldr` executable which loads `static-pie`
//! binaries into an Enarx Keep - that is a hardware isolated environment using
//! technologies such as Intel SGX or AMD SEV.
//!
//! # Building
//!
//! Please see **BUILD.md** for instructions.
//!
//! # Run Tests
//!
//!     $ cargo test
//!
//! # Build and Run an Application
//!
//!     $ cat > test.c <<EOF
//!     #include <stdio.h>
//!
//!     int main() {
//!         printf("Hello World!\n");
//!         return 0;
//!     }
//!     EOF
//!
//!     $ musl-gcc -static-pie -fPIC -o test test.c
//!     $ target/debug/enarx-keepldr exec ./test
//!     Hello World!
//!
//! # Select a Different Backend
//!
//! `enarx-keepldr exec` will probe the machine it is running on
//! in an attempt to deduce an appropriate deployment backend unless
//! that target is already specified in an environment variable
//! called `ENARX_BACKEND`.
//!
//! To see what backends are supported on your system, run:
//!
//!     $ target/debug/enarx-keepldr info
//!
//! To manually select a backend, set the `ENARX_BACKEND` environment
//! variable:
//!
//!     $ ENARX_BACKEND=sgx target/debug/enarx-keepldr exec ./test
//!
//! Note that some backends are conditionally compiled. They can all
//! be compiled in like so:
//!
//!     $ cargo build --all-features
//!
//! Or specific backends can be compiled in:
//!
//!     $ cargo build --features=backend-sgx,backend-kvm

#![deny(clippy::all)]
#![deny(missing_docs)]
#![feature(asm)]

mod backend;
mod binary;
mod netlink;
mod protobuf;
mod sallyport;
mod syscall;

// workaround for sallyport tests, until we have internal crates
pub use sallyport::Request;

use backend::{Backend, Command};
use binary::Component;

use anyhow::Result;
use structopt::StructOpt;

use std::ffi::CString;
use std::io::{Error, ErrorKind};
use std::net::IpAddr;
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::ptr::null;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

/// Prints information about your current platform
#[derive(StructOpt)]
struct Info {}

/// Executes a keep
#[derive(StructOpt)]
struct Exec {
    /// Create a new IPVLAN for the keep
    #[structopt(short, long)]
    ipvlan: Option<IpAddr>,

    /// The socket to use for preattestation
    #[structopt(short, long)]
    sock: Option<PathBuf>,

    /// The payload to run inside the keep
    code: PathBuf,
}

/// Get a report from a keep
#[derive(StructOpt)]
struct Report {
    /// The payload to run inside the keep
    code: PathBuf,
}

#[derive(StructOpt)]
#[structopt(version=VERSION, author=AUTHORS.split(";").nth(0).unwrap())]
enum Options {
    Info(Info),
    Exec(Exec),
    Report(Report),
}

#[allow(clippy::unnecessary_wraps)]
fn main() -> Result<()> {
    let backends: &[Box<dyn Backend>] = &[
        #[cfg(feature = "backend-sev")]
        Box::new(backend::sev::Backend),
        #[cfg(feature = "backend-sgx")]
        Box::new(backend::sgx::Backend),
        #[cfg(feature = "backend-kvm")]
        Box::new(backend::kvm::Backend),
    ];

    match Options::from_args() {
        Options::Info(_) => info(backends),
        Options::Exec(e) => exec(backends, e),
        Options::Report(e) => measure(backends, e),
    }
}

#[allow(clippy::unnecessary_wraps)]
fn info(backends: &[Box<dyn Backend>]) -> Result<()> {
    use colorful::*;

    for backend in backends {
        println!("Backend: {}", backend.name());

        let data = backend.data();

        for datum in &data {
            let icon = match datum.pass {
                true => "✔".green(),
                false => "✗".red(),
            };

            if let Some(info) = datum.info.as_ref() {
                println!(" {} {}: {}", icon, datum.name, info);
            } else {
                println!(" {} {}", icon, datum.name);
            }
        }

        for datum in &data {
            if let Some(mesg) = datum.mesg.as_ref() {
                println!("\n{}\n", mesg);
            }
        }
    }

    Ok(())
}

#[allow(unreachable_code)]
#[allow(clippy::unnecessary_wraps)]
fn measure(backends: &[Box<dyn Backend>], opts: Report) -> Result<()> {
    let keep = std::env::var_os("ENARX_BACKEND").map(|x| x.into_string().unwrap());

    let backend = backends
        .iter()
        .filter(|b| keep.is_none() || keep == Some(b.name().into()))
        .find(|b| b.have());

    if let Some(backend) = backend {
        let code = Component::from_path(&opts.code)?;
        let json = backend.measure(code)?;
        println!("{}", json);
    } else {
        panic!(
            "Keep backend '{}' is unsupported.",
            keep.unwrap_or_else(|| String::from("nil"))
        );
    }

    Ok(())
}

#[allow(unreachable_code)]
#[allow(clippy::unnecessary_wraps)]
fn exec(backends: &[Box<dyn Backend>], opts: Exec) -> Result<()> {
    if let Some(addr) = opts.ipvlan {
        fn find(addr: IpAddr) -> Result<netlink::Address, ErrorKind> {
            for address in netlink::Address::list().unwrap() {
                if address.subnet().contains(addr) && address.address() != addr {
                    return Ok(address);
                }
            }

            Err(ErrorKind::InvalidData)
        }

        // Save the original namespace
        let curns = std::fs::File::open("/proc/self/ns/net").unwrap();

        // Create the new namespace
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)
            .expect("unable to create new network namespace");
        let newns = std::fs::File::open("/proc/self/ns/net").unwrap();

        // Swap back the original namespace
        nix::sched::setns(curns.as_raw_fd(), nix::sched::CloneFlags::CLONE_NEWNET).unwrap();

        // Create our macvlan interface in the new namespace
        let address = find(addr).expect("unable to find matching subnet");
        let mut iface = address.interface().expect("unable to find matching iface");
        let ipvlan = iface.add_ipvlan("ipvl0").expect("error creating ipvlan");
        ipvlan.move_to_namespace(newns.as_raw_fd()).unwrap();

        // Swap to the new namespace and destroy the old one
        nix::sched::setns(newns.as_raw_fd(), nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
        drop(curns);
        drop(newns);

        let mut ipvlan = netlink::Interface::find("ipvl0").expect("unable to find ipvlan");
        ipvlan
            .add_address(addr, address.subnet().prefix())
            .expect("unable to add address");
        ipvlan.up().expect("unable to bring up ipvlan");
        ipvlan
            .add_gateway(address.address())
            .expect("unable to add gatweay to ipvlan");
    }

    let keep = std::env::var_os("ENARX_BACKEND").map(|x| x.into_string().unwrap());

    let backend = backends
        .iter()
        .filter(|b| keep.is_none() || keep == Some(b.name().into()))
        .find(|b| b.have());

    if let Some(backend) = backend {
        let code = Component::from_path(&opts.code)?;
        let keep = backend.build(code, opts.sock.as_deref())?;

        let mut thread = keep.clone().add_thread()?;
        loop {
            match thread.enter()? {
                Command::SysCall(block) => unsafe {
                    block.msg.rep = block.msg.req.syscall();
                },
                Command::Continue => (),
            }
        }
    } else {
        match keep {
            Some(name) if name != "nil" => panic!("Keep backend '{}' is unsupported.", name),
            _ => {
                use std::env::args_os;
                let cstr = CString::new(opts.code.as_os_str().as_bytes()).unwrap();
                let name = CString::new(args_os().next().unwrap().as_os_str().as_bytes()).unwrap();
                unsafe {
                    libc::execl(
                        cstr.as_ptr(),
                        name.as_ptr(),
                        cstr.as_ptr(),
                        null::<c_char>(),
                    )
                };
                return Err(Error::last_os_error().into());
            }
        }
    }

    unreachable!();
}
