// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use std::sync::{Arc, RwLock};

use anyhow::{Error, Result};
use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
use kvm_ioctls::Kvm;
use mmarinus::{perms, Map};
use sallyport::Block;

pub struct Builder(super::Keep);

impl TryFrom<super::config::Config> for Builder {
    type Error = Error;

    fn try_from(_config: super::config::Config) -> Result<Self> {
        let kvm = Kvm::new()?;
        Ok(Self(super::Keep {
            vm: kvm.create_vm()?,
            cpus: Vec::new(),
            memory: Vec::new(),
            regions: Vec::new(),
            kvm,
        }))
    }
}

impl super::super::Mapper for Builder {
    type Config = super::config::Config;
    type Output = Arc<dyn super::super::Keep>;

    fn map(&mut self, pages: Map<perms::ReadWrite>, to: usize, with: u32) -> anyhow::Result<()> {
        // Map the pages into the VM
        let pages = self.0.map(pages, to)?;

        // If this is a segment of sallyport blocks, collect them all
        let mut blocks = Vec::<*mut Block>::new();
        if with & sallyport::elf::pf::sgx::TCS != 0 {
            blocks.extend(unsafe { pages.align_to_mut().1 }.iter());
        }

        // For each sallyport block, create a CPU
        for block in blocks {
            let fd = self.0.vm.create_vcpu(self.0.cpus.len() as u64)?;

            let cpuid = self.0.kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?;
            fd.set_cpuid2(&cpuid)?;

            self.0.cpus.push(super::Cpu { fd, block });
        }

        Ok(())
    }
}

impl TryFrom<Builder> for Arc<dyn super::super::Keep> {
    type Error = Error;

    #[inline]
    fn try_from(builder: Builder) -> Result<Self> {
        Ok(Arc::new(RwLock::new(builder.0)))
    }
}
