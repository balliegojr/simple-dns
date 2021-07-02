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
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use simple_dns::SimpleDnsError;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use thiserror::Error;

pub mod conversion_utils;
mod oneshot_resolver;
mod resource_record_manager;
mod service_discovery;
mod simple_responder;

pub use oneshot_resolver::OneShotMdnsResolver;
pub use service_discovery::ServiceDiscovery;
pub use simple_responder::SimpleMdnsResponder;

const UNICAST_RESPONSE: bool = cfg!(not(test));

const MULTICAST_PORT: u16 = 5353;
const MULTICAST_ADDR_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MULTICAST_ADDR_IPV6: Ipv6Addr = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0xFB);

lazy_static! {
    pub(crate) static ref MULTICAST_IPV4_SOCKET: SocketAddr =
        SocketAddr::new(IpAddr::V4(MULTICAST_ADDR_IPV4), MULTICAST_PORT);
    pub(crate) static ref MULTICAST_IPV6_SOCKET: SocketAddr =
        SocketAddr::new(IpAddr::V6(MULTICAST_ADDR_IPV6), MULTICAST_PORT);
}

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

fn create_socket(addr: &SocketAddr) -> io::Result<Socket> {
    let domain = if addr.is_ipv4() {
        Domain::ipv4()
    } else {
        Domain::ipv6()
    };

    let socket = Socket::new(domain, Type::dgram(), Some(Protocol::udp()))?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    socket.set_reuse_address(true)?;

    #[cfg(not(windows))]
    socket.set_reuse_port(true)?;

    Ok(socket)
}

fn join_multicast(addr: &SocketAddr) -> io::Result<Socket> {
    let ip_addr = addr.ip();

    let socket = create_socket(addr)?;

    // depending on the IP protocol we have slightly different work
    match ip_addr {
        IpAddr::V4(ref mdns_v4) => {
            socket.join_multicast_v4(mdns_v4, &Ipv4Addr::UNSPECIFIED)?;
        }
        IpAddr::V6(ref mdns_v6) => {
            socket.join_multicast_v6(mdns_v6, 0)?;
            socket.set_only_v6(true)?;
        }
    };

    bind_multicast(socket, addr)
}

#[cfg(unix)]
fn bind_multicast(socket: Socket, addr: &SocketAddr) -> io::Result<Socket> {
    socket.bind(&SockAddr::from(*addr))?;
    Ok(socket)
}

#[cfg(windows)]
fn bind_multicast(socket: Socket, addr: &SocketAddr) -> io::Result<Socket> {
    let addr = match addr {
        SocketAddr::V4(addr) => {
            SockAddr::from(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), addr.port()))
        }
        SocketAddr::V6(addr) => {
            SockAddr::from(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), addr.port()))
        }
    };

    socket.bind(&addr)?;
    Ok(socket)
}

fn sender_socket(addr: &SocketAddr) -> io::Result<Socket> {
    let socket = create_socket(addr)?;
    if addr.is_ipv4() {
        socket.bind(&SockAddr::from(SocketAddr::new(
            Ipv4Addr::UNSPECIFIED.into(),
            0,
        )))?;
    } else {
        socket.bind(&SockAddr::from(SocketAddr::new(
            Ipv6Addr::UNSPECIFIED.into(),
            0,
        )))?;
    }
    Ok(socket)
}
