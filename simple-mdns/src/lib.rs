#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#[macro_use]
extern crate lazy_static;

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    time::Duration,
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

pub mod conversion_utils;
mod dns_packet_receiver;
mod oneshot_resolver;
mod resource_record_manager;
mod service_discovery;
mod simple_mdns_error;
mod simple_responder;

pub use oneshot_resolver::OneShotMdnsResolver;
pub use service_discovery::{InstanceInformation, ServiceDiscovery};
pub use simple_mdns_error::SimpleMdnsError;
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
fn create_socket(addr: &SocketAddr) -> io::Result<Socket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    socket.set_reuse_address(true)?;

    #[cfg(not(windows))]
    socket.set_reuse_port(true)?;

    Ok(socket)
}

fn join_multicast(addr: &SocketAddr, interface: &Ipv4Addr) -> io::Result<UdpSocket> {
    let ip_addr = addr.ip();

    let socket = create_socket(addr)?;

    // depending on the IP protocol we have slightly different work
    match ip_addr {
        IpAddr::V4(ref mdns_v4) => {
            socket.join_multicast_v4(mdns_v4, interface)?;
        }
        IpAddr::V6(ref mdns_v6) => {
            socket.join_multicast_v6(mdns_v6, 0)?;
            socket.set_only_v6(true)?;
        }
    };

    let socket = bind_multicast(socket, addr)?;
    Ok(socket.into())
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

fn sender_socket(addr: &SocketAddr, interface: &Ipv4Addr) -> io::Result<UdpSocket> {
    let socket = create_socket(addr)?;
    if addr.is_ipv4() {
        socket.bind(&SockAddr::from(SocketAddr::new(
            IpAddr::V4(*interface).into(),
            0,
        )))?;
    } else {
        socket.bind(&SockAddr::from(SocketAddr::new(
            Ipv6Addr::UNSPECIFIED.into(),
            0,
        )))?;
    }
    Ok(socket.into())
}
