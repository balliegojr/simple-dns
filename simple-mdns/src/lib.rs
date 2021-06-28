/*!
Pure Rust implementation for mDNS and DNS-SD protocols

For IpAddress and/or Port querying just one single time, see [`OneShotMdnsResolver`]

For Dns Responder, see [`SimpleMdnsResponder`]

For Service discovery, see [`ServiceDiscovery`]
*/
#![warn(missing_docs)]
#[macro_use]
extern crate lazy_static;

use std::{
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    time::Duration,
};

use simple_dns::{PacketBuf, SimpleDnsError};
use thiserror::Error;

pub mod conversion_utils;
mod oneshot_resolver;
mod resource_record_manager;
mod service_discovery;
mod simple_responder;

pub use oneshot_resolver::OneShotMdnsResolver;
pub use service_discovery::ServiceDiscovery;
pub use simple_responder::SimpleMdnsResponder;

const ENABLE_LOOPBACK: bool = cfg!(test);
const UNICAST_RESPONSE: bool = cfg!(not(test));

const MULTICAST_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MULTICAST_PORT: u16 = 5353;
lazy_static! {
    pub(crate) static ref MULTICAST_IPV4_SOCKET: SocketAddr =
        SocketAddr::new(MULTICAST_IPV4.into(), MULTICAST_PORT);
}
// const MULTICAST_ADDR_IPV6: Ipv6Addr = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0xFB);

/// Error types for simple-mdns
#[derive(Debug, Error)]
pub enum SimpleMdnsError {
    /// Udp socket related error
    #[error("There was an error related to UDP socket")]
    UdpSocketError(#[from] std::io::Error),
    /// Simple-dns error related, usually packet parsing
    #[error("Failed to parse dns packet")]
    DnsParsing(#[from] SimpleDnsError),
}

fn send_packet_to_multicast_socket(
    socket: &UdpSocket,
    packet: &PacketBuf,
) -> Result<(), SimpleMdnsError> {
    // TODO: also send to ipv6
    socket.send_to(&packet, *MULTICAST_IPV4_SOCKET)?;

    Ok(())
}

fn create_udp_socket(multicast_loop: bool) -> Result<UdpSocket, SimpleMdnsError> {
    // let addrs = [
    //     SocketAddr::from(([0, 0, 0, 0], MULTICAST_PORT)),
    //     // SocketAddr::from(([0, 0, 0, 0], 0)),
    // ];

    let socket = socket2::Socket::new(socket2::Domain::ipv4(), socket2::Type::dgram(), None)?;
    socket.set_multicast_loop_v4(multicast_loop)?;
    socket.join_multicast_v4(&MULTICAST_IPV4, &Ipv4Addr::new(0, 0, 0, 0))?;
    socket.set_reuse_address(true)?;
    // socket.set_nonblocking(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;

    #[cfg(not(windows))]
    socket.set_reuse_port(true)?;

    socket.bind(&SocketAddr::from(([0, 0, 0, 0], MULTICAST_PORT)).into())?;

    Ok(socket.into_udp_socket())
}
