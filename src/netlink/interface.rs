use super::{connection::Connection, Address, Error};

use netlink_packet_route::*;

use std::convert::TryFrom;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::os::unix::io::RawFd;

#[derive(Clone, Debug)]
pub struct Interface {
    index: u32,
    alias: String,
}

impl TryFrom<NetlinkPayload<RtnlMessage>> for Interface {
    type Error = ErrorKind;

    fn try_from(value: NetlinkPayload<RtnlMessage>) -> Result<Self, Self::Error> {
        if let NetlinkPayload::InnerMessage(RtnlMessage::NewLink(msg)) = value {
            for nla in &msg.nlas {
                if let link::nlas::Nla::IfName(alias) = nla {
                    return Ok(Interface {
                        index: msg.header.index,
                        alias: alias.into(),
                    });
                }
            }
        }

        Err(ErrorKind::InvalidData)
    }
}

impl Interface {
    //const IPVLAN_MODE_L2: u16 = 0;
    //const IPVLAN_MODE_L3: u16 = 1;
    const IPVLAN_MODE_L3S: u16 = 2;

    pub fn find(alias: &str) -> Result<Interface, Error> {
        let mut nl = Connection::new()?;
        nl.push(NetlinkMessage {
            header: NetlinkHeader {
                flags: NLM_F_REQUEST,
                ..Default::default()
            },
            payload: RtnlMessage::GetLink(LinkMessage {
                nlas: vec![link::nlas::Nla::IfName(alias.into())],
                ..Default::default()
            })
            .into(),
        })?;

        Ok(Self::try_from(nl.pull()?.payload)?)
    }

    // This function is useful for testing...
    #[allow(dead_code)]
    pub fn list() -> Result<Vec<Interface>, Error> {
        let mut nl = Connection::new()?;

        nl.push(NetlinkMessage {
            header: NetlinkHeader {
                flags: NLM_F_REQUEST,
                ..Default::default()
            },
            payload: RtnlMessage::GetLink(LinkMessage {
                ..Default::default()
            })
            .into(),
        })?;

        let mut interfaces = Vec::new();
        loop {
            match nl.pull()?.payload {
                NetlinkPayload::Done => break Ok(interfaces),

                NetlinkPayload::InnerMessage(RtnlMessage::NewLink(msg)) => {
                    for nla in msg.nlas {
                        if let link::nlas::Nla::IfName(alias) = nla {
                            interfaces.push(Interface {
                                index: msg.header.index,
                                alias,
                            });
                            break;
                        }
                    }
                }

                _ => return Err(ErrorKind::InvalidData.into()),
            }
        }
    }

    pub fn add_ipvlan(&mut self, alias: &str) -> Result<Self, Error> {
        let mut nl = Connection::new()?;
        nl.push(NetlinkMessage {
            header: NetlinkHeader {
                flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE,
                ..Default::default()
            },
            payload: RtnlMessage::NewLink(LinkMessage {
                nlas: vec![
                    link::nlas::Nla::Link(self.index),
                    link::nlas::Nla::IfName(alias.into()),
                    link::nlas::Nla::Info(vec![
                        link::nlas::Info::Kind(link::nlas::InfoKind::IpVlan),
                        link::nlas::Info::Data(link::nlas::InfoData::IpVlan(vec![
                            link::nlas::InfoIpVlan::Mode(Self::IPVLAN_MODE_L3S),
                            link::nlas::InfoIpVlan::Flags(0),
                        ])),
                    ]),
                ],
                ..Default::default()
            })
            .into(),
        })?;

        match nl.pull::<RtnlMessage>()?.payload {
            NetlinkPayload::Ack(..) => Ok(Interface::find(alias)?),
            _ => Err(ErrorKind::InvalidData.into()),
        }
    }

    pub fn add_address(&mut self, address: IpAddr, prefix: u8) -> Result<Address, Error> {
        let bytes: Vec<u8> = match address {
            IpAddr::V4(x) => x.octets().into(),
            IpAddr::V6(x) => x.octets().into(),
        };

        let mut nl = Connection::new()?;
        nl.push(NetlinkMessage {
            header: NetlinkHeader {
                flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE,
                ..Default::default()
            },
            payload: RtnlMessage::NewAddress(AddressMessage {
                header: AddressHeader {
                    index: self.index,
                    prefix_len: prefix,
                    family: match address {
                        IpAddr::V4(..) => AF_INET as _,
                        IpAddr::V6(..) => AF_INET6 as _,
                    },
                    ..Default::default()
                },
                nlas: vec![
                    address::Nla::Address(bytes.clone()),
                    address::Nla::Local(bytes),
                ],
            })
            .into(),
        })?;

        match nl.pull::<RtnlMessage>()?.payload {
            NetlinkPayload::Ack(..) => Ok(Address::new(self.index, address, prefix)),
            _ => Err(ErrorKind::InvalidData.into()),
        }
    }

    pub fn move_to_namespace(self, nsfd: RawFd) -> Result<(), Error> {
        let mut nl = Connection::new()?;
        nl.push(NetlinkMessage {
            header: NetlinkHeader {
                flags: NLM_F_REQUEST | NLM_F_ACK,
                ..Default::default()
            },
            payload: RtnlMessage::SetLink(LinkMessage {
                header: LinkHeader {
                    index: self.index,
                    ..Default::default()
                },
                nlas: vec![link::nlas::Nla::NetNsFd(nsfd)],
            })
            .into(),
        })?;

        match nl.pull::<RtnlMessage>()?.payload {
            NetlinkPayload::Ack(..) => Ok(()),
            _ => Err(ErrorKind::InvalidData.into()),
        }
    }

    pub fn up(&self) -> Result<(), Error> {
        let mut nl = Connection::new()?;
        nl.push(NetlinkMessage {
            header: NetlinkHeader {
                flags: NLM_F_REQUEST | NLM_F_ACK,
                ..Default::default()
            },
            payload: RtnlMessage::NewLink(LinkMessage {
                header: LinkHeader {
                    index: self.index,
                    flags: IFF_UP,
                    ..Default::default()
                },
                ..Default::default()
            })
            .into(),
        })?;

        match nl.pull::<RtnlMessage>()?.payload {
            NetlinkPayload::Ack(..) => Ok(()),
            _ => Err(ErrorKind::InvalidData.into()),
        }
    }

    pub fn add_gateway(&mut self, address: IpAddr) -> Result<(), Error> {
        let mut nl = Connection::new()?;
        nl.push(NetlinkMessage {
            header: NetlinkHeader {
                flags: NLM_F_REQUEST | NLM_F_ACK | NLM_F_EXCL | NLM_F_CREATE,
                ..Default::default()
            },
            payload: RtnlMessage::NewRoute(RouteMessage {
                header: RouteHeader {
                    kind: RTN_UNICAST,
                    address_family: match address {
                        IpAddr::V4(..) => AF_INET as u8,
                        IpAddr::V6(..) => AF_INET6 as u8,
                    },
                    ..Default::default()
                },
                nlas: vec![
                    route::Nla::Gateway(match address {
                        IpAddr::V4(addr) => addr.octets().into(),
                        IpAddr::V6(addr) => addr.octets().into(),
                    }),
                    route::Nla::Oif(self.index),
                ],
            })
            .into(),
        })?;

        match nl.pull::<RtnlMessage>()?.payload {
            NetlinkPayload::Ack(..) => Ok(()),
            _ => Err(ErrorKind::InvalidData.into()),
        }
    }
}
