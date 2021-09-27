// SPDX-License-Identifier: Apache-2.0

mod builder;
mod config;
mod thread;

use super::Loader;

use std::sync::Arc;

use anyhow::Result;
use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::{Kvm, VcpuFd, VmFd};
use mmarinus::{perms, Map};
use sallyport::Block;

pub const SHIM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/bin/shim-sev"));

fn dev_kvm() -> super::Datum {
    let dev_kvm = std::path::Path::new("/dev/kvm");

    super::Datum {
        name: "Driver".into(),
        pass: dev_kvm.exists(),
        info: Some("/dev/kvm".into()),
        mesg: None,
    }
}

fn kvm_version() -> super::Datum {
    let version = Kvm::new().map(|kvm| kvm.get_api_version());
    let (pass, info) = match version {
        Ok(v) => (v == 12, Some(v.to_string())),
        Err(_) => (false, None),
    };

    super::Datum {
        name: " API Version".into(),
        pass,
        info,
        mesg: None,
    }
}

struct Cpu {
    fd: VcpuFd,
    block: *mut Block,
}

struct Keep {
    kvm: Kvm,
    vm: VmFd,

    cpus: Vec<Cpu>,
    memory: Vec<Map<perms::ReadWrite>>,
    regions: Vec<kvm_userspace_memory_region>,
}

impl Keep {
    pub fn map(
        &mut self,
        pages: Map<perms::ReadWrite>,
        to: usize,
    ) -> std::io::Result<&mut Map<perms::ReadWrite>> {
        assert_eq!(self.memory.len(), self.regions.len());

        let region = kvm_userspace_memory_region {
            slot: self.memory.len() as u32,
            flags: 0,
            guest_phys_addr: to as u64,
            memory_size: pages.len() as u64,
            userspace_addr: pages.addr() as u64,
        };

        unsafe { self.vm.set_user_memory_region(region)? };
        self.regions.push(region);
        self.memory.push(pages);
        Ok(self.memory.last_mut().unwrap())
    }
}

pub struct Backend;

impl super::Backend for Backend {
    #[inline]
    fn name(&self) -> &'static str {
        "kvm"
    }

    #[inline]
    fn shim(&self) -> &'static [u8] {
        SHIM
    }

    #[inline]
    fn data(&self) -> Vec<super::Datum> {
        vec![dev_kvm(), kvm_version()]
    }

    #[inline]
    fn keep(&self, shim: &[u8], exec: &[u8]) -> Result<Arc<dyn super::Keep>> {
        builder::Builder::load(shim, exec)
    }

    #[inline]
    fn hash(&self, _shim: &[u8], _exec: &[u8]) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }
}
