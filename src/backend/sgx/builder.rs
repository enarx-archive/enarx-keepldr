// SPDX-License-Identifier: Apache-2.0

use crate::binary::Component;

use anyhow::Result;
use lset::Span;
use primordial::Page;
use sgx::enclave::{Builder, Segment};
use sgx::types::{
    page::{Flags, SecInfo},
    tcs::Tcs,
};

/// Creates and loads an enclave, then returns the Builder.
pub fn builder(mut shim: Component, mut code: Component) -> Result<Builder> {
    // Calculate the memory layout for the enclave.
    let layout = crate::backend::sgx::shim::Layout::calculate(shim.region(), code.region());

    // Relocate the shim binary.
    shim.entry += layout.shim.start;
    for seg in shim.segments.iter_mut() {
        seg.dst += layout.shim.start;
    }

    // Relocate the code binary.
    code.entry += layout.code.start;
    for seg in code.segments.iter_mut() {
        seg.dst += layout.code.start;
    }

    // Create SSAs and TCS.
    let ssas = vec![Page::default(); 2];
    let tcs = Tcs::new(
        shim.entry - layout.enclave.start,
        Page::size() * 2, // SSAs after Layout (see below)
        ssas.len() as _,
    );

    let internal = vec![
        // TCS
        Segment {
            si: SecInfo::tcs(),
            dst: layout.prefix.start,
            src: vec![Page::copy(tcs)],
        },
        // Layout
        Segment {
            si: SecInfo::reg(Flags::R),
            dst: layout.prefix.start + Page::size(),
            src: vec![Page::copy(layout)],
        },
        // SSAs
        Segment {
            si: SecInfo::reg(Flags::R | Flags::W),
            dst: layout.prefix.start + Page::size() * 2,
            src: ssas,
        },
        // Heap
        Segment {
            si: SecInfo::reg(Flags::R | Flags::W | Flags::X),
            dst: layout.heap.start,
            src: vec![Page::default(); Span::from(layout.heap).count / Page::size()],
        },
        // Stack
        Segment {
            si: SecInfo::reg(Flags::R | Flags::W),
            dst: layout.stack.start,
            src: vec![Page::default(); Span::from(layout.stack).count / Page::size()],
        },
    ];

    let shim_segs: Vec<_> = shim.segments.into_iter().map(Segment::from).collect();
    let code_segs: Vec<_> = code.segments.into_iter().map(Segment::from).collect();

    // Initiate the enclave building process.
    let mut builder = Builder::new(layout.enclave).expect("Unable to create builder");
    builder.load(&internal)?;
    builder.load(&shim_segs)?;
    builder.load(&code_segs)?;

    Ok(builder)
}
