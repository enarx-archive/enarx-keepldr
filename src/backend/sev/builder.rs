// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use std::sync::{Arc, RwLock};

use super::cpuid_page::CpuidPage;
use super::mem::Region;
use crate::backend::sev::SnpKeepPersonality;
use anyhow::Context;
use anyhow::{Error, Result};
use kvm_bindings::bindings::kvm_userspace_memory_region;
use kvm_bindings::fam_wrappers::KVM_MAX_CPUID_ENTRIES;
use kvm_ioctls::{Kvm, VmFd};
use mmarinus::{perms, Map};
use primordial::Page;
use sallyport::elf::pf::kvm::SALLYPORT;
use sallyport::elf::pf::snp::{CPUID, SECRETS};
use sallyport::Block;
use sev::firmware::Firmware;
use sev::launch::snp::*;
use std::mem::size_of;
use x86_64::VirtAddr;

pub struct Builder {
    kvm_fd: Kvm,
    launcher: Launcher<Started, VmFd, Firmware>,
    regions: Vec<Region>,
    sallyports: Vec<Option<VirtAddr>>,
}

impl TryFrom<super::config::Config> for Builder {
    type Error = Error;

    fn try_from(_config: super::config::Config) -> Result<Self> {
        let kvm_fd = Kvm::new()?;
        let vm_fd = kvm_fd.create_vm()?;

        let sev = Firmware::open()?;
        let launcher = Launcher::new(vm_fd, sev)?;

        let start = SnpStart {
            policy: SnpPolicy {
                flags: SnpPolicyFlags::SMT,
                ..Default::default()
            },
            gosvw: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            ..Default::default()
        };

        let launcher = launcher.start(start)?;

        Ok(Builder {
            kvm_fd,
            launcher,
            regions: Vec::new(),
            sallyports: Vec::new(),
        })
    }
}

impl super::super::Mapper for Builder {
    type Config = super::config::Config;
    type Output = Arc<dyn super::super::Keep>;

    fn map(
        &mut self,
        mut pages: Map<perms::ReadWrite>,
        to: usize,
        with: u32,
    ) -> anyhow::Result<()> {
        // Ignore regions with no pages.
        if pages.is_empty() {
            return Ok(());
        }

        if with & SALLYPORT != 0 {
            for start in (0..pages.size()).step_by(size_of::<Block>()) {
                if start + size_of::<Block>() <= pages.size() {
                    let virt = VirtAddr::from_ptr(pages.as_ptr()) + start;
                    self.sallyports.push(Some(virt));
                }
            }
        }

        let mem_region = kvm_userspace_memory_region {
            slot: self.regions.len() as _,
            flags: 0,
            guest_phys_addr: to as _,
            memory_size: pages.size() as _,
            userspace_addr: pages.addr() as _,
        };

        unsafe { self.launcher.as_mut().set_user_memory_region(mem_region)? };

        let dp = VmplPerms::empty();

        if with & CPUID != 0 {
            assert_eq!(pages.len(), Page::SIZE);
            let mut cpuid_page = CpuidPage::default();
            cpuid_page.import_from_kvm(&mut self.kvm_fd)?;

            let guest_cpuid_page = pages.as_mut_ptr() as *mut CpuidPage;
            unsafe {
                guest_cpuid_page.write(cpuid_page);
            }

            let update = SnpUpdate::new(
                to as u64 >> 12,
                &pages,
                false,
                SnpPageType::Cpuid,
                (dp, dp, dp),
            );

            if self.launcher.update_data(update).is_err() {
                // FIXME: just try again with the firmware corrected values
                self.launcher
                    .update_data(update)
                    .context("launcher.update_data for CPUID failed")?;
            }
        } else if with & SECRETS != 0 {
            assert_eq!(pages.len(), Page::SIZE);

            let update = SnpUpdate::new(
                to as u64 >> 12,
                &pages,
                false,
                SnpPageType::Secrets,
                (dp, dp, dp),
            );

            self.launcher
                .update_data(update)
                .context("SNP Launcher update_data")?;
        } else {
            let update = SnpUpdate::new(
                to as u64 >> 12,
                &pages,
                false,
                SnpPageType::Normal,
                (dp, dp, dp),
            );

            self.launcher
                .update_data(update)
                .context("SNP Launcher update_data")?;
        };

        self.regions.push(Region::new(mem_region, pages));

        Ok(())
    }
}

impl TryFrom<Builder> for Arc<dyn super::super::Keep> {
    type Error = Error;

    fn try_from(mut builder: Builder) -> Result<Self> {
        // If no LOAD segment were defined as sallyport blocks
        if builder.sallyports.is_empty() {
            anyhow::bail!("No sallyport blocks defined!");
        }

        let cpuids = builder.kvm_fd.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?;

        let vcpu_fd = builder.launcher.as_mut().create_vcpu(0)?;
        vcpu_fd.set_cpuid2(&cpuids)?;

        // FIXME: this will be removed with relative addresses in sallyport
        // unwrap, because we have at least one block
        let sallyport_block_start = builder.sallyports.first().unwrap().unwrap();

        let finish = SnpFinish::new(None, None, [0u8; 32]);

        let (vm_fd, sev_fd) = builder.launcher.finish(finish)?;

        Ok(Arc::new(RwLock::new(super::Keep::<SnpKeepPersonality> {
            kvm_fd: builder.kvm_fd,
            vm_fd,
            cpu_fds: vec![vcpu_fd],
            regions: builder.regions,
            sallyports: builder.sallyports,
            sallyport_start: sallyport_block_start,
            personality: SnpKeepPersonality { _sev_fd: sev_fd },
        })))
    }
}
