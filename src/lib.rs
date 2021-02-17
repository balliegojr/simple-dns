// use std::{convert::TryInto, error::Error, net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket}};


pub mod dns;


// const MULTICAST_ADDR_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
// const MULTICAST_ADDR_IPV6: Ipv6Addr = "FF02::FB"
// const MULTICAST_PORT: u16 = 5353;


type Result<T> = std::result::Result<T, SimpleMdnsError>;

#[derive(Debug)]
pub enum SimpleMdnsError {
    InvalidQClass(u16),
    InvalidQType(u16),
    InvalidServiceName,
    InvalidServiceLabel,
    InvalidHeaderData,
    InvalidDnsPacket

}
