// SPDX-License-Identifier: Apache-2.0

use super::super::Command;

use std::sync::{Arc, RwLock};

use anyhow::{anyhow, Result};
use kvm_ioctls::VcpuExit;
use mmarinus::{perms, Kind, Map};
use primordial::Register;
use sallyport::syscall::{SYS_ENARX_BALLOON_MEMORY, SYS_ENARX_MEM_INFO};
use sallyport::{Block, Request, KVM_SYSCALL_TRIGGER_PORT};

pub struct Thread {
    keep: Arc<RwLock<super::Keep>>,
    cpu: Option<super::Cpu>,
}

impl Drop for Thread {
    fn drop(&mut self) {
        self.keep
            .write()
            .unwrap()
            .cpus
            .push(self.cpu.take().unwrap())
    }
}

impl super::super::Keep for RwLock<super::Keep> {
    fn spawn(self: Arc<Self>) -> Result<Option<Box<dyn super::super::Thread>>> {
        let cpu = self.write().unwrap().cpus.pop();
        match cpu {
            None => Ok(None),
            Some(cpu) => Ok(Some(Box::new(Thread {
                keep: self,
                cpu: Some(cpu),
            }))),
        }
    }
}

impl Thread {
    fn balloon(&mut self, req: &mut Request) -> Result<[Register<usize>; 2], i32> {
        let pow2: usize = req.arg[0].into();
        let npgs: usize = req.arg[1].into(); // Number of Pages
        let addr: usize = req.arg[2].into(); // Guest Physical Address
        let size: usize = 1 << pow2; // Page Size

        // Get the current page size
        let pgsz = unsafe { libc::sysconf(libc::_SC_PAGE_SIZE) } as usize;
        assert!(pgsz.is_power_of_two());

        // Check that the page size is supported and addr is aligned
        if size != pgsz || addr % size != 0 {
            return Err(libc::EINVAL);
        }

        // Allocate the new memory
        let pages = Map::map(size * npgs)
            .anywhere()
            .anonymously()
            .known::<perms::ReadWrite>(Kind::Private)
            .map_err(|e| e.err.raw_os_error().unwrap_or(libc::ENOTSUP))?;

        // Map the memory into the VM
        let vaddr = self
            .keep
            .write()
            .unwrap()
            .map(pages, addr)
            .map_err(|e| e.raw_os_error().unwrap_or(libc::ENOTSUP))?
            .addr();

        Ok([vaddr.into(), 0.into()])
    }

    fn meminfo(&mut self, block: &mut Block) -> Result<[Register<usize>; 2], i32> {
        block
            .cursor()
            .write(&self.keep.read().unwrap().regions.as_slice())
            .map_err(|_| libc::ENOBUFS)?;
        Ok([0.into(), 0.into()])
    }
}

impl super::super::Thread for Thread {
    fn enter(&mut self) -> Result<Command> {
        let cpu = self.cpu.as_mut().unwrap();
        let block = unsafe { &mut *cpu.block };
        let req = &mut unsafe { block.msg.req };

        match cpu.fd.run()? {
            VcpuExit::IoOut(KVM_SYSCALL_TRIGGER_PORT, ..) => match i64::from(req.num) {
                SYS_ENARX_BALLOON_MEMORY => {
                    block.msg.rep = self.balloon(req).into();
                    Ok(Command::Continue)
                }

                SYS_ENARX_MEM_INFO => {
                    block.msg.rep = self.meminfo(block).into();
                    Ok(Command::Continue)
                }

                _ => Ok(Command::SysCall(block)),
            },

            #[cfg(debug_assertions)]
            reason => Err(anyhow!(
                "{:?} {:#x?} {:#x?}",
                reason,
                cpu.fd.get_regs(),
                cpu.fd.get_sregs()
            )),

            #[cfg(not(debug_assertions))]
            reason => Err(anyhow!("{:?}", reason)),
        }
    }
}
