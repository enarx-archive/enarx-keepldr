use super::Error;

use netlink_packet_core::{NetlinkDeserializable, NetlinkSerializable};
use netlink_packet_route::NetlinkMessage;
use netlink_sys::protocols::NETLINK_ROUTE;
use netlink_sys::{Socket, SocketAddr};

pub struct Connection {
    socket: netlink_sys::Socket,
    buffer: Vec<u8>,
    first: usize,
    last: usize,
    sequence: u32,
}

impl Connection {
    pub fn new() -> std::io::Result<Self> {
        let socket = Socket::new(NETLINK_ROUTE)?;
        socket.connect(&SocketAddr::new(0, 0))?;

        Ok(Self {
            socket,
            buffer: vec![0u8; 4096],
            first: 0,
            last: 0,
            sequence: 0,
        })
    }

    pub fn push<I>(&mut self, mut msg: NetlinkMessage<I>) -> std::io::Result<usize>
    where
        I: std::fmt::Debug + PartialEq<I> + Eq + Clone + NetlinkSerializable<I>,
    {
        self.sequence += 1;
        msg.header.sequence_number = self.sequence;
        msg.finalize();

        let mut buffer = vec![0u8; msg.buffer_len()];
        msg.serialize(&mut buffer);

        self.socket.send(&buffer, 0)
    }

    pub fn pull<I>(&mut self) -> Result<NetlinkMessage<I>, Error>
    where
        I: std::fmt::Debug + PartialEq<I> + Eq + Clone + NetlinkDeserializable<I>,
    {
        if self.first == self.last {
            self.last = self.socket.recv(&mut self.buffer[..], 0)?;
            self.first = 0;
        }

        let msg = NetlinkMessage::<I>::deserialize(&self.buffer[self.first..self.last])?;
        self.first += msg.header.length as usize;
        Ok(msg)
    }
}
