use std::net::IpAddr;

#[derive(Copy, Clone, Debug)]
pub struct Subnet {
    address: IpAddr,
    prefix: u8,
}

impl Subnet {
    fn mask(addr: IpAddr, prefix: u8) -> IpAddr {
        match addr {
            IpAddr::V4(addr) => {
                let shift = 32 - prefix;
                let mask = !0 >> shift << shift;
                let addr = u32::from(addr) & mask;
                addr.to_be_bytes().into()
            }

            IpAddr::V6(addr) => {
                let shift = 128 - prefix;
                let mask = !0 >> shift << shift;
                let addr = u128::from(addr) & mask;
                addr.to_be_bytes().into()
            }
        }
    }

    #[inline]
    pub fn new(address: IpAddr, prefix: u8) -> Self {
        Self {
            address: Self::mask(address, prefix),
            prefix,
        }
    }

    #[inline]
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    #[inline]
    pub fn contains(&self, addr: IpAddr) -> bool {
        Self::mask(addr, self.prefix) == self.address
    }
}
