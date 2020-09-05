// SPDX-License-Identifier: Apache-2.0

//! This crate provides the `enarx-keepldr` executable which loads `static-pie`
//! binaries into an Enarx Keep - that is a hardware isolated environment using
//! technologies such as Intel SGX or AMD SEV.
//!
//! # Install Dependencies
//!
//! ## Fedora
//!
//!     $ sudo dnf install git curl gcc pkg-config openssl-devel musl-gcc
//!
//! ## Debian / Ubuntu
//!
//!     $ sudo apt update
//!     $ sudo apt install git curl gcc pkg-config libssl-dev musl-tools python3-minimal
//!
//! # Install Rust, Nightly and the MUSL target
//!
//!     $ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
//!     $ source $HOME/.cargo/env
//!     $ rustup toolchain install nightly --allow-downgrade -t x86_64-unknown-linux-musl
//!
//! # Build
//!
//!     $ git clone https://github.com/enarx/enarx-keepldr
//!     $ cd enarx-keepldr/
//!     $ cargo +nightly build
//!
//! # Run Tests
//!
//!     $ cargo +nightly test
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

#![deny(clippy::all)]
#![deny(missing_docs)]
#![feature(asm)]

extern crate serde_derive;

mod backend;
mod binary;
mod sallyport;

// workaround for sallyport tests, until we have internal crates
pub use sallyport::Request;

use ::enarx_keepldr::*;
use backend::{Backend, Command};
use binary::Component;

use anyhow::Result;
use structopt::StructOpt;

use std::ffi::CString;
use std::io::Error;
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr::null;

use std::io::prelude::*;
use std::os::unix::net::{UnixListener, UnixStream};
//use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

/// Prints information about your current platform
#[derive(StructOpt)]
struct Info {}

/// Executes a keep
#[derive(StructOpt)]
struct Exec {
    /// The socket to use for preattestation
    #[structopt(short, long)]
    sock: Option<PathBuf>,

    /// The payload to run inside the keep
    code: PathBuf,
}

#[derive(StructOpt)]
#[structopt(version=VERSION, author=AUTHORS.split(";").nth(0).unwrap())]
enum Options {
    Info(Info),
    Exec(Exec),
}

//fn main() -> Result<()> {
fn main() {
    let backends: &[Box<dyn Backend>] = &[
        Box::new(backend::sev::Backend),
        Box::new(backend::sgx::Backend),
        Box::new(backend::kvm::Backend),
    ];

    println!("Welcome to a new keep-loader");

    //get and parse args
    let args: Vec<String> = std::env::args().collect();
    //bind to unix socket
    //await commands
    //TODO - remove hard-coding!
    println!("Keep-loader has received {} args", args.len());
    let kuuid = args[1].clone();
    println!("kuuid = {}", kuuid);
    let bind_socket = format!("/tmp/enarx-keep-{}.sock", kuuid);
    println!("binding to {}", bind_socket);
    let keepapploader = Arc::new(Mutex::new(build_keepapploader(
        "".to_string(),
        KEEP_LOADER_STATE_UNDEF,
        kuuid.parse().expect("problems parsing kuuid"),
        0,
        "".to_string(),
    )));

    let listener = UnixListener::bind(bind_socket).unwrap();
    //initialise state as listening
    //TODO - error checking
    let set_state_result = set_state(KEEP_LOADER_STATE_LISTENING, keepapploader.clone());
    match set_state_result {
        Ok(_v) => {}
        Err(e) => println!("Error setting state, {}", e),
    }

    //only one bind at a time expected here (check for auth-token?)
    //but our connectee may drop, so keep listening
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let childstate = keepapploader.clone();
                thread::spawn(move || keep_loader_connection(stream, childstate));
            }
            Err(err) => {
                println!("Keep-loader error in stream: {}", err);
                //TODO - something better here, including clean-up for /tmp file
                panic!("Stream error {}", err);
            }
        }
    }

    /*
    match Options::from_args() {
        Options::Info(_) => info(backends),
        Options::Exec(e) => exec(backends, e),
    }*/
}

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
fn exec(backends: &[Box<dyn Backend>], opts: Exec) -> Result<()> {
    //TODO - remove, and take this from the command passed to us
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
                let cstr = CString::new(opts.code.as_os_str().as_bytes()).unwrap();
                unsafe { libc::execl(cstr.as_ptr(), cstr.as_ptr(), null::<c_char>()) };
                return Err(Error::last_os_error().into());
            }
        }
    }

    unreachable!();
}

fn build_keepapploader(
    backend_type: String,
    state: u8,
    kuuid: usize,
    app_loader_bind_port: u16,
    bindaddress: String,
) -> KeepLoader {
    KeepLoader {
        backend_type: backend_type,
        state: state,
        kuuid: kuuid,
        app_loader_bind_port: app_loader_bind_port,
        bindaddress: bindaddress,
    }
}

fn keep_loader_connection(stream: UnixStream, keepapploader: Arc<Mutex<KeepLoader>>) {
    //the below values are very much fall-backs
    let mut backend_type: String = String::from("nil");
    let mut app_addr: String = String::from("127.0.0.1");
    let mut app_port: u16 = APP_LOADER_BIND_PORT_START;

    //let mut json_pair: serde_json::value::Value;
    let mut stream = &stream;
    let deserializer = serde_json::Deserializer::from_reader(stream);
    let iterator = deserializer.into_iter::<serde_json::Value>();

    let kal = keepapploader.clone();

    for json_pair in iterator {
        match json_pair {
            Ok(value) => {
                let json_command: JsonCommand = serde_json::from_value(value).unwrap();
                match json_command.commandtype.as_str() {
                    KEEP_BACKEND_SET => {
                        backend_type = json_command.commandcontents;
                        kal.lock().unwrap().backend_type = backend_type.clone();
                    }
                    KEEP_APP_LOADER_ADDR => {
                        app_addr = json_command.commandcontents;
                        kal.lock().unwrap().bindaddress = app_addr.clone();
                    }
                    KEEP_APP_LOADER_PORT => {
                        app_port = json_command
                            .commandcontents
                            .parse()
                            .expect("problems parsing port information");
                        kal.lock().unwrap().app_loader_bind_port = app_port.clone();
                    }
                    KEEP_APP_LOADER_START_COMMAND => {
                        println!("About to spawn, listening on port {}", app_port.to_string());
                        let child_spawn_result =
                            std::process::Command::new(WASM_RUNTIME_BINARY_PATH)
                                .arg(&app_addr)
                                .arg(app_port.to_string())
                                .spawn();
                        match &child_spawn_result {
                            Ok(_v) => {
                                let state_result =
                                    set_state(KEEP_LOADER_STATE_STARTED, kal.clone());
                                match state_result {
                                    Ok(_v) => println!("Spawned new runtime, set state"),
                                    Err(e) => {
                                        println!("Spawned new runtime, no state set due to {}!", e)
                                    }
                                }
                                println!("Set state attempted");
                                println!("State = {}", kal.lock().unwrap().state);
                            }
                            Err(e) => {
                                println!("Error spawning runtime {:?}", e);
                            }
                        }
                    }
                    KEEP_INFO_COMMAND => {
                        //provide information back
                        let keepresponse: KeepLoader = kal.lock().unwrap().clone();
                        println!(
                            "Sending data about KeepLoader, status {}",
                            &keepresponse.state
                        );
                        let serializedjson =
                            serde_json::to_string(&keepresponse).expect("problem serializing data");
                        println!("Sending JSON data from keep-loader\n{}", serializedjson);
                        &stream
                            .write_all(&serializedjson.as_bytes())
                            .expect("failed to write");
                    }
                    KEEP_TYPE_INFO_COMMAND => {
                        //TODO provide information from the existing todo
                    }
                    _ => println!("Unknown command received"),
                }
            }
            Err(e) => println!("Problem parsing command to keep-loader: {}", e),
        }
    }
}

fn set_state(desired_state: u8, keeploaderapp: Arc<Mutex<KeepLoader>>) -> Result<String, String> {
    let mut keep_app = keeploaderapp.lock().unwrap();
    let mut transition_ok = false;
    println!(
        "Attempting to move from state {} to state {}",
        &keep_app.state, &desired_state
    );
    //DEBT: this code works, but is ugly.  Re-write needed.
    //logic for state machine here - there are lots of ways to do this, and this version
    // can probably be optimised
    // options:
    // KEEP_LOADER_STATE_UNDEF
    // KEEP_LOADER_STATE_LISTENING
    // KEEP_LOADER_STATE_STARTED
    // KEEP_LOADER_STATE_COMPLETE
    // KEEP_LOADER_STATE_ERROR
    //
    //TODO - consider taking this back to a set of match statements?
    // (previously had some problems with fallthrough?)
    //note - if you mistype these variable names, Rust sometimes fails to match
    // silently - unclear why
    if keep_app.state == KEEP_LOADER_STATE_UNDEF {
        match desired_state {
            KEEP_LOADER_STATE_LISTENING => {
                transition_ok = true;
            }
            KEEP_LOADER_STATE_ERROR => transition_ok = true,
            _ => transition_ok = false,
        }
    } else if keep_app.state == KEEP_LOADER_STATE_LISTENING {
        match desired_state {
            KEEP_LOADER_STATE_STARTED => transition_ok = true,
            KEEP_LOADER_STATE_ERROR => transition_ok = true,
            _ => transition_ok = false,
        }
    } else if keep_app.state == KEEP_LOADER_STATE_STARTED {
        match desired_state {
            KEEP_LOADER_STATE_COMPLETE => transition_ok = true,
            KEEP_LOADER_STATE_ERROR => transition_ok = true,
            _ => transition_ok = false,
        }
    } else if keep_app.state == KEEP_LOADER_STATE_COMPLETE {
        match desired_state {
            KEEP_LOADER_STATE_ERROR => transition_ok = true,
            _ => transition_ok = false,
        }
    } else if keep_app.state == KEEP_LOADER_STATE_ERROR {
        match desired_state {
            KEEP_LOADER_STATE_ERROR => transition_ok = true,
            _ => transition_ok = false,
        }
    } else {
        println!("State not recognised");
    }

    if transition_ok {
        keep_app.state = desired_state;
        println!("Transitioning to {} state", &keep_app.state);
        Ok(format!("State transitioned to {}", &keep_app.state))
    } else {
        println!("Staying in {} state", &keep_app.state);
        Err(format!("No state transition, still in {}", &keep_app.state))
    }
}
