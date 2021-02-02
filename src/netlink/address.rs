use super::{Connection, Error, Interface, Subnet};

use netlink_packet_route::*;

use std::convert::TryFrom;
use std::io::ErrorKind;
use std::net::IpAddr;

#[derive(Copy, Clone, Debug)]
pub struct Address {
    index: u32,
    subnet: Subnet,
    address: IpAddr,
}

impl Address {
    #[inline]
    pub fn new(index: u32, address: IpAddr, prefix: u8) -> Self {
        Self {
            index,
            address,
            subnet: Subnet::new(address, prefix),
        }
    }

    #[inline]
    pub fn list() -> Result<Vec<Self>, Error> {
        let mut nl = Connection::new()?;

        nl.push(NetlinkMessage {
            header: NetlinkHeader {
                flags: NLM_F_REQUEST | NLM_F_DUMP,
                ..Default::default()
            },
            payload: RtnlMessage::GetAddress(Default::default()).into(),
        })?;

        let mut addresses = Vec::new();
        loop {
            match nl.pull()?.payload {
                NetlinkPayload::Done => break Ok(addresses),

                NetlinkPayload::InnerMessage(RtnlMessage::NewAddress(msg)) => {
                    for nla in msg.nlas {
                        let (address, subnet) = match nla {
                            address::Nla::Address(addr) => match msg.header.family.into() {
                                AF_INET => {
                                    let mut bytes = [0u8; 4];
                                    bytes.copy_from_slice(&addr);

                                    (
                                        IpAddr::V4(bytes.into()),
                                        Subnet::new(bytes.into(), msg.header.prefix_len),
                                    )
                                }

                                AF_INET6 => {
                                    let mut bytes = [0u8; 16];
                                    bytes.copy_from_slice(&addr);

                                    (
                                        IpAddr::V6(bytes.into()),
                                        Subnet::new(bytes.into(), msg.header.prefix_len),
                                    )
                                }

                                _ => continue,
                            },
                            _ => continue,
                        };

                        addresses.push(Address {
                            index: msg.header.index,
                            subnet,
                            address,
                        })
                    }
                }

                _ => return Err(ErrorKind::InvalidData.into()),
            }
        }
    }

    #[inline]
    pub fn subnet(&self) -> Subnet {
        self.subnet
    }

    #[inline]
    pub fn address(&self) -> IpAddr {
        self.address
    }

    #[inline]
    pub fn interface(&self) -> Result<Interface, Error> {
        let mut nl = Connection::new()?;

        nl.push(NetlinkMessage {
            header: NetlinkHeader {
                flags: NLM_F_REQUEST,
                ..Default::default()
            },
            payload: RtnlMessage::GetLink(LinkMessage {
                header: LinkHeader {
                    index: self.index,
                    ..Default::default()
                },
                ..Default::default()
            })
            .into(),
        })?;

        Ok(Interface::try_from(nl.pull()?.payload)?)
    }
}
