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
//!     $ ./target/debug/enarx-keepldr exec ./test
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

/// Sets up the keeploader as a daemon, to listen on a Unix socket
#[derive(StructOpt)]
struct Daemon {
    /// The kuuid to run on
    kuuid: String,
}

#[derive(StructOpt)]
#[structopt(version=VERSION, author=AUTHORS.split(";").nth(0).unwrap())]
enum Options {
    Info(Info),
    Exec(Exec),
    Daemon(Daemon),
}

fn main() -> Result<()> {
    println!("Welcome to a new keep-loader");

    //NOTE - this block is replicated in the function exec-keep, which is
    // not optimal
    let backends: &[Box<dyn Backend>] = &[
        Box::new(backend::sev::Backend),
        Box::new(backend::sgx::Backend),
        Box::new(backend::kvm::Backend),
    ];

    //take the ENARX_BACKEND environment variable if available
    let backend_type: String;
    match std::env::var_os("ENARX_BACKEND").map(|x| x.into_string().unwrap()) {
        Some(b) => backend_type = b,
        None => backend_type = String::from(KEEP_ARCH_WASI),
    }

    println!("Using backend_type {}", backend_type);
    match Options::from_args() {
        // we don't need the backends at this point for our Daemon,
        //  and generating a threadsafe version is overkill
        Options::Info(_) => info(backends),
        Options::Exec(e) => exec_keep(build_keepapploader(
            //use some sensible defaults
            backend_type,
            KEEP_LOADER_STATE_UNDEF,
            //TODO need to decide do with this (does it matter?), for now go with 1
            1,
            APP_LOADER_BIND_PORT_START,
            "127.0.0.1".to_string(),
            Some(e),
        )),
        Options::Daemon(d) => {
            println!("About to start the daemon");
            daemon(d, backend_type)
        }
    }
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
fn exec_keep(keeploader: KeepLoader) -> Result<()> {
    let backends: &[Box<dyn Backend>] = &[
        Box::new(backend::sev::Backend),
        Box::new(backend::sgx::Backend),
        Box::new(backend::kvm::Backend),
    ];
    let keep = Some(keeploader.backend_type);
    let backend = backends
        .iter()
        .filter(|b| keep.is_none() || keep == Some(b.name().into()))
        .find(|b| b.have());
    if let Some(backend) = backend {
        let exec: Exec = keeploader.exec.unwrap();
        let code = Component::from_path(&exec.code)?;
        let keep = backend.build(code, exec.sock.as_deref())?;

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
            Some(name) if name == KEEP_ARCH_WASI => {
                /*
                let cstr =
                    CString::new(keeploader.exec.unwrap().code.as_os_str().as_bytes()).unwrap();
                unsafe { libc::execl(cstr.as_ptr(), cstr.as_ptr(), null::<c_char>()) };
                return Err(Error::last_os_error().into());
                 */
                /*
                let binary_path_cstring_ =
                    CString::new(WASM_RUNTIME_BINARY_PATH.as_bytes()).unwrap();
                let address_cstring_ = CString::new("127.0.0.1".as_bytes()).unwrap();
                let port_cstring_ =
                    CString::new(APP_LOADER_BIND_PORT_START.to_string().as_bytes()).unwrap();
                 */
                println!(
                    "About to start a WASM binary ({}) on {}:{}",
                    WASM_RUNTIME_BINARY_PATH,
                    &keeploader.bindaddress,
                    keeploader.app_loader_bind_port,
                );
                let binary_path_cstring_ =
                    CString::new(WASM_RUNTIME_BINARY_PATH.as_bytes()).unwrap();
                let address_cstring_ = CString::new(keeploader.bindaddress.as_bytes()).unwrap();
                let port_cstring_ =
                    CString::new(keeploader.app_loader_bind_port.to_string().as_bytes()).unwrap();
                unsafe {
                    libc::execl(
                        binary_path_cstring_.as_ptr(),
                        address_cstring_.as_ptr(),
                        port_cstring_.as_ptr(),
                        null::<c_char>(),
                    )
                };
                return Err(Error::last_os_error().into());
            }
            _ => {
                panic!("Keep backend is unsupported.");
            }
        }
    }

    unreachable!();
}

fn daemon(opts: Daemon, backend_type: String) -> Result<()> {
    //bind to unix socket
    //await commands
    let kuuid = opts.kuuid;
    println!("kuuid = {}", kuuid);
    let bind_socket = format!("/tmp/enarx-keep-{}.sock", kuuid);
    println!("binding to {}", bind_socket);
    //create a keeploader with some sensible defaults
    let keepapploader = Arc::new(Mutex::new(build_keepapploader(
        backend_type,
        KEEP_LOADER_STATE_UNDEF,
        kuuid.parse().expect("problems parsing kuuid"),
        APP_LOADER_BIND_PORT_START,
        "127.0.0.1".to_string(),
        None,
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
    Ok(())
}

fn build_exec(sock: Option<PathBuf>, code: PathBuf) -> Exec {
    Exec { sock, code }
}

fn build_keepapploader(
    backend_type: String,
    state: u8,
    kuuid: usize,
    app_loader_bind_port: u16,
    bindaddress: String,
    exec: Option<Exec>,
) -> KeepLoader {
    KeepLoader {
        backend_type,
        state,
        kuuid,
        app_loader_bind_port,
        bindaddress,
        exec,
    }
}

fn keep_loader_connection(stream: UnixStream, keepapploader: Arc<Mutex<KeepLoader>>) {
    let mut app_addr;
    let mut app_port;
    let mut backend_type: String;
    let mut exec: Exec = build_exec(Some(PathBuf::new()), PathBuf::new());

    //let mut json_pair: serde_json::value::Value;
    let mut stream = &stream;
    let deserializer = serde_json::Deserializer::from_reader(stream);
    let iterator = deserializer.into_iter::<serde_json::Value>();

    let kal = keepapploader;

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
                        kal.lock().unwrap().app_loader_bind_port = app_port;
                    }
                    KEEP_PREATT_SOCK_COMMAND => {
                        exec.sock = Some(PathBuf::from(json_command.commandcontents));
                        kal.lock().unwrap().exec = Some(exec.clone());
                    }
                    KEEP_PAYLOAD_COMMAND => {
                        exec.code = PathBuf::from(json_command.commandcontents);
                        kal.lock().unwrap().exec = Some(exec.clone());
                    }
                    KEEP_APP_LOADER_START_COMMAND => {
                        println!("About to attempt to spawn keep");
                        let child_spawn_result = exec_keep(kal.lock().unwrap().clone());
                        match &child_spawn_result {
                            Ok(_v) => {
                                //TODO - Will we ever reach here?
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

                        /*
                        //TODO - remove this match, make everything use exec_keep
                        match backend_type.as_str() {
                            KEEP_ARCH_WASI => {
                                //use local
                                println!(
                                    "About to spawn, listening on port {}",
                                    app_port.to_string()
                                );
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
                                            Err(e) => println!(
                                                "Spawned new runtime, no state set due to {}!",
                                                e
                                            ),
                                        }
                                        println!("Set state attempted");
                                        println!("State = {}", kal.lock().unwrap().state);
                                    }
                                    Err(e) => {
                                        println!("Error spawning runtime {:?}", e);
                                    }
                                }
                            }
                            _ => {
                                //manage all other types
                                let exec_result = exec_keep(kal.lock().unwrap().clone());
                                match exec_result {
                                    Ok(_) => {}
                                    Err(e) => {
                                        println!("Failed to execute keep, {}", e);
                                    }
                                }
                            }
                        }*/
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
                        stream
                            .write_all(&serializedjson.as_bytes())
                            .expect("failed to write");
                    }
                    KEEP_TYPE_INFO_COMMAND => {
                        //TODO provide information from the supported backends (see existing info function)
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
