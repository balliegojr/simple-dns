use std::net::{SocketAddr, UdpSocket};

use simple_dns::PacketBuf;

use crate::{join_multicast, SimpleMdnsError, MULTICAST_IPV4_SOCKET};

pub struct DnsPacketReceiver {
    recv_buffer: [u8; 9000],
    recv_socket: UdpSocket,
}

impl DnsPacketReceiver {
    pub fn new() -> Result<Self, SimpleMdnsError> {
        let recv_socket = join_multicast(&MULTICAST_IPV4_SOCKET)?;
        let _ = recv_socket.set_read_timeout(None);
        let recv_buffer = [0u8; 9000];

        Ok(Self {
            recv_buffer,
            recv_socket,
        })
    }

    pub fn recv_packet(&mut self) -> Result<(PacketBuf, SocketAddr), SimpleMdnsError> {
        let (count, addr) = self.recv_socket.recv_from(&mut self.recv_buffer)?;

        let packet = PacketBuf::from(self.recv_buffer[..count].to_vec());

        Ok((packet, addr))
    }
}
