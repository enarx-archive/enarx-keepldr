// SPDX-License-Identifier: Apache-2.0

//! Functions needing `asm!` blocks

use crate::addr::SHIM_VIRT_OFFSET;
use crate::paging::SHIM_PAGETABLE;
use crate::payload::PAYLOAD_VIRT_ADDR;
use crate::PAYLOAD_READY;
use crate::{get_cbit_mask, print};
use core::mem::size_of;
use core::sync::atomic::Ordering;
use x86_64::instructions::tables::lidt;
use x86_64::structures::paging::Translate;
use x86_64::structures::DescriptorTablePointer;
use x86_64::VirtAddr;

/// Debug helper function for the early boot
///
/// # Safety
///
/// This function causes a triple fault!
#[inline(never)]
pub unsafe fn _early_debug_panic(reason: u64, value: u64) -> ! {
    let mut rbp: u64;

    asm!("mov {}, rbp", out(reg) rbp);

    if get_cbit_mask() > 0 {
        asm!(
            "
    # Use VMGEXIT to request termination. At this point the reason code is
    # located in EAX, so shift it left 16 bits to the proper location.
    #
    # EAX[11:0]  => 0x100 - request termination
    # EAX[15:12] => 0x1   - OVMF
    # EAX[23:16] => 0xXX  - REASON CODE
    #
    shl     rax, 16
    shl     r14, 12
    or      rax, r14
    or      eax, 0x100
    xor     edx, edx
    mov     ecx, {SEV_GHCB_MSR}
    wrmsr
    rep     vmmcall
        ",
        SEV_GHCB_MSR = const 0xc001_0130u32,
        in("r14") (reason & 0x7),
        in("rax") value,
        options(noreturn)
        )
    }

    load_invalid_idt();

    let frames = backtrace(rbp);

    // Provoke an #UD, which will lead to a triple fault, because of the invalid IDT
    asm!("ud2",
    in("rax") frames[0],
    in("rcx") frames[1],
    in("rdx") frames[2],
    in("rsi") frames[3],
    in("rdi") frames[4],
    in("r8") frames[5],
    in("r9") frames[6],
    in("r10") frames[7],
    in("r11") frames[8],
    in("r12") frames[9],
    in("r13") frames[10],
    in("r14") reason,
    in("r15") value,
    options(nomem, nostack)
    );

    // Extra hlt loop, in case hell freezes
    loop {
        x86_64::instructions::hlt()
    }
}

/// Provoke a triple fault to shutdown the machine
///
/// An illegal IDT is loaded with limit=0 and an #UD is produced
///
/// Fun read: http://www.rcollins.org/Productivity/TripleFault.html
///
/// # Safety
///
/// This function causes a triple fault!
#[inline(never)]
pub unsafe fn _enarx_asm_triple_fault() -> ! {
    if get_cbit_mask() > 0 {
        asm!(
        "
    # Use VMGEXIT to request termination. At this point the reason code is
    # located in EAX, so shift it left 16 bits to the proper location.
    #
    # EAX[11:0]  => 0x100 - request termination
    # EAX[15:12] => 0x1   - OVMF
    # EAX[23:16] => 0xXX  - REASON CODE
    #
    shl     rax, 16
    shl     r14, 12
    or      rax, r14
    or      eax, 0x100
    xor     edx, edx
    mov     ecx, {SEV_GHCB_MSR}
    wrmsr
    rep     vmmcall
        ",
        SEV_GHCB_MSR = const 0xc001_0130u32,
        in("r14") 0x7,
        in("rax") 0xFF,
        options(noreturn)
        )
    }

    let mut rbp: u64;

    asm!("mov {}, rbp", out(reg) rbp);

    let frames = backtrace(rbp);

    load_invalid_idt();

    // Provoke an #UD, which will lead to a triple fault, because of the invalid IDT
    asm!("ud2",
    in("rax") frames[0],
    in("rcx") frames[1],
    in("rdx") frames[2],
    in("rsi") frames[3],
    in("rdi") frames[4],
    in("r8") frames[5],
    in("r9") frames[6],
    in("r10") frames[7],
    in("r11") frames[8],
    in("r12") frames[9],
    in("r13") frames[10],
    in("r14") frames[11],
    in("r15") frames[12],
        options(nomem, nostack)
    );

    // Extra hlt loop, in case hell freezes
    loop {
        x86_64::instructions::hlt()
    }
}

/// Load an invalid DescriptorTablePointer with no base and limit
#[inline(always)]
unsafe fn load_invalid_idt() {
    let dtp = DescriptorTablePointer {
        limit: 0,
        base: VirtAddr::new(0),
    };
    // Load the invalid IDT
    lidt(&dtp);
}

/// Produce a backtrace from a frame pointer
#[inline(always)]
unsafe fn backtrace(mut rbp: u64) -> [u64; 16] {
    let mut frames = [0u64; 16];

    for ele in frames.iter_mut() {
        if let Some(rip_rbp) = rbp.checked_add(size_of::<usize>() as _) {
            if rip_rbp < SHIM_VIRT_OFFSET {
                break;
            }
            let rip = *(rip_rbp as *const u64);
            if let Some(rip) = rip
                .checked_sub(SHIM_VIRT_OFFSET)
                .and_then(|v| v.checked_sub(1))
            {
                *ele = rip;
                rbp = *(rbp as *const u64);
            } else {
                // Not a shim virtual address
                break;
            }
        } else {
            // RBP OVERFLOW
            break;
        }
    }
    frames
}

#[inline(never)]
/// print a stack trace from a stack frame pointer
pub fn print_stack_trace() {
    let mut rbp: usize;

    unsafe {
        asm!("mov {}, rbp", out(reg) rbp);
        stack_trace_from_rbp(rbp);
    }
}

unsafe fn stack_trace_from_rbp(mut rbp: usize) {
    print::_eprint(format_args!("TRACE:\n"));

    if SHIM_PAGETABLE.try_read().is_none() {
        SHIM_PAGETABLE.force_unlock_write()
    }

    let shim_offset = crate::addr::SHIM_VIRT_OFFSET as usize;

    let active_table = SHIM_PAGETABLE.read();

    //Maximum 64 frames
    for _frame in 0..64 {
        if rbp == 0
            || VirtAddr::try_new(rbp as _).is_err()
            || active_table
                .translate_addr(VirtAddr::new(rbp as _))
                .is_none()
        {
            break;
        }

        if let Some(rip_rbp) = rbp.checked_add(size_of::<usize>() as _) {
            if active_table
                .translate_addr(VirtAddr::new(rip_rbp as _))
                .is_none()
            {
                break;
            }

            let rip = *(rip_rbp as *const usize);
            if let Some(rip) = rip.checked_sub(1) {
                if rip == 0 {
                    break;
                }

                if let Some(rip) = rip.checked_sub(shim_offset) {
                    print::_eprint(format_args!("S 0x{:>016x}\n", rip));
                    rbp = *(rbp as *const usize);
                } else if PAYLOAD_READY.load(Ordering::Relaxed) {
                    if let Some(rip) = rip.checked_sub(PAYLOAD_VIRT_ADDR.read().as_u64() as _) {
                        print::_eprint(format_args!("P 0x{:>016x}\n", rip));
                        rbp = *(rbp as *const usize);
                    } else {
                        break;
                    }
                }
            } else {
                // RIP zero
                break;
            }
        } else {
            // RBP OVERFLOW
            break;
        }
    }
}
