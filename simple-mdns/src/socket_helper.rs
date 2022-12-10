use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    time::Duration,
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::{
    network_scope::{MULTICAST_ADDR_IPV4, MULTICAST_ADDR_IPV6, MULTICAST_PORT},
    NetworkScope,
};

pub fn sender_socket(ipv4: bool) -> io::Result<UdpSocket> {
    if ipv4 {
        let socket = create_socket(Domain::IPV4)?;
        socket.bind(&SockAddr::from(SocketAddr::new(
            Ipv4Addr::UNSPECIFIED.into(),
            0,
        )))?;

        Ok(socket.into())
    } else {
        let socket = create_socket(Domain::IPV6)?;
        socket.bind(&SockAddr::from(SocketAddr::new(
            Ipv6Addr::UNSPECIFIED.into(),
            0,
        )))?;

        Ok(socket.into())
    }
}

pub fn join_multicast(network_scope: NetworkScope) -> io::Result<UdpSocket> {
    // depending on the IP protocol we have slightly different work
    match network_scope {
        NetworkScope::V4 => {
            let socket = create_socket(Domain::IPV4)?;
            socket.join_multicast_v4(&MULTICAST_ADDR_IPV4, &Ipv4Addr::UNSPECIFIED)?;

            bind_multicast(socket, &MULTICAST_ADDR_IPV4.into(), MULTICAST_PORT)
                .map(|socket| socket.into())
        }
        NetworkScope::V4WithInterface(ref interface) => {
            let socket = create_socket(Domain::IPV4)?;
            socket.join_multicast_v4(&MULTICAST_ADDR_IPV4, interface)?;

            bind_multicast(socket, &MULTICAST_ADDR_IPV4.into(), MULTICAST_PORT)
                .map(|socket| socket.into())
        }
        NetworkScope::V6 => {
            let socket = create_socket(Domain::IPV6)?;
            socket.join_multicast_v6(&MULTICAST_ADDR_IPV6, 0)?;
            socket.set_only_v6(true)?;

            bind_multicast(socket, &IpAddr::V6(MULTICAST_ADDR_IPV6), MULTICAST_PORT)
                .map(|socket| socket.into())
        }
        NetworkScope::V6WithInterface(interface) => {
            let socket = create_socket(Domain::IPV6)?;
            socket.join_multicast_v6(&MULTICAST_ADDR_IPV6, interface)?;
            socket.set_only_v6(true)?;

            bind_multicast(socket, &IpAddr::V6(MULTICAST_ADDR_IPV6), MULTICAST_PORT)
                .map(|socket| socket.into())
        }
    }
}

#[cfg(feature = "async-tokio")]
pub fn nonblocking(socket: UdpSocket) -> io::Result<tokio::net::UdpSocket> {
    socket.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(socket)
}

fn create_socket(domain: Domain) -> io::Result<Socket> {
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    socket.set_reuse_address(true)?;

    #[cfg(not(windows))]
    socket.set_reuse_port(true)?;

    Ok(socket)
}

#[cfg(unix)]
fn bind_multicast(socket: Socket, address: &IpAddr, port: u16) -> io::Result<Socket> {
    // FIXME: this should not be necessary, why is it not possible to bind on the address for ipv6?
    let addr = match address {
        IpAddr::V4(_) => SockAddr::from(SocketAddr::new(*address, port)),
        IpAddr::V6(_) => SockAddr::from(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port)),
    };

    socket.bind(&addr)?;

    Ok(socket)
}

#[cfg(windows)]
fn bind_multicast(socket: Socket, address: &IpAddr, port: u16) -> io::Result<Socket> {
    let addr = match address {
        IpAddr::V4(_) => SockAddr::from(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port)),
        IpAddr::V6(_) => SockAddr::from(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port)),
    };

    socket.bind(&addr)?;
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(target_os = "macos"))]
    pub fn test_can_bind_multicast() {
        join_multicast(NetworkScope::V4).expect("Failed to join IPV4 multicast");
        join_multicast(NetworkScope::V6).expect("Failed to join IPV6 multicast");
    }
}
