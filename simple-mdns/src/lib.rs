/*!
Pure Rust implementation for mDNS and DNS-SD protocols  

For IpAddress and/or Port querying just one single time, see [`OneShotMdnsResolver`]  
For Dns Responder, see [`SimpleMdnsResponder`]
*/
#![warn(missing_docs)]

use std::{net::{Ipv4Addr, SocketAddr}, time::Duration};

use tokio::{net::UdpSocket};
use simple_dns::{PacketBuf, SimpleDnsError};

mod oneshot_resolver;
mod simple_responder;

pub use oneshot_resolver::OneShotMdnsResolver;
pub use simple_responder::SimpleMdnsResponder;

const ENABLE_LOOPBACK: bool = cfg!(test);
const UNICAST_RESPONSE: bool = cfg!(not(test));


const MULTICAST_ADDR_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
// const MULTICAST_ADDR_IPV6: Ipv6Addr = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0xFB);
const MULTICAST_PORT: u16 = 5353;

#[derive(Debug)]
pub enum SimpleMdnsError {
    ErrorCreatingUDPSocket,
    ErrorSendingDNSPacket,
    ErrorReadingFromUDPSocket,
    DnsParsing(SimpleDnsError)
}

impl From<SimpleDnsError> for SimpleMdnsError {
    fn from(inner: SimpleDnsError) -> Self {
        SimpleMdnsError::DnsParsing(inner)
    }
}


async fn send_packet_to_multicast_socket(socket: &UdpSocket, packet: &PacketBuf) -> Result<(), SimpleMdnsError>{

    // TODO: also send to ipv6
    let target_addr = std::net::SocketAddr::new(MULTICAST_ADDR_IPV4.into(), MULTICAST_PORT);
    socket.send_to(&packet, target_addr)
        .await
        .map_err(|_| SimpleMdnsError::ErrorSendingDNSPacket)?;

    Ok(())
}



fn create_udp_socket(multicast_loop: bool) -> Result<tokio::net::UdpSocket, Box<dyn std::error::Error>> {
    // let addrs = [
    //     SocketAddr::from(([0, 0, 0, 0], MULTICAST_PORT)),
    //     // SocketAddr::from(([0, 0, 0, 0], 0)),
    // ];

    let socket = socket2::Socket::new(socket2::Domain::ipv4(), socket2::Type::dgram(), None).unwrap();
    socket.set_multicast_loop_v4(multicast_loop)?;
    socket.join_multicast_v4(&MULTICAST_ADDR_IPV4, &Ipv4Addr::new(0, 0, 0, 0))?;
    socket.set_reuse_address(true)?;

    #[cfg(not(windows))]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    
    socket.bind(&SocketAddr::from(([0, 0, 0, 0], MULTICAST_PORT)).into())?;
    
    let socket = tokio::net::UdpSocket::from_std(socket.into_udp_socket())?;
    Ok(socket)
}

async fn timeout<T:futures::Future>(duration: Duration, future: T) -> Result<T::Output, Box<dyn std::error::Error>> {
    match tokio::time::timeout(duration, future).await {
        Ok(result) => Ok(result),
        Err(err) => Err(Box::new(err))
    }
}