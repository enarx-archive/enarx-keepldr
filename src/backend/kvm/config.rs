// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;

pub struct Config(());

impl super::super::Config for Config {
    type Flags = u32;

    #[inline]
    fn flags(flags: u32) -> Self::Flags {
        flags
    }

    #[inline]
    fn new(_shim: &super::super::Binary, _exec: &super::super::Binary) -> Result<Self> {
        Ok(Self(()))
    }
}
