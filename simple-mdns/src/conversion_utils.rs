//! Provides helper functions to convert net addresses to resource records

use simple_dns::{
    rdata::{RData, A, AAAA, SRV},
    Name, ResourceRecord, CLASS,
};
use std::net::IpAddr;
use std::{convert::From, net::SocketAddr};

/// Convert the addr to an A (IpV4) or AAAA (IpV6) record
pub fn ip_addr_to_resource_record<'a>(
    name: &Name<'a>,
    addr: &IpAddr,
    rr_ttl: u32,
) -> ResourceRecord<'a> {
    match addr {
        IpAddr::V4(ip) => {
            ResourceRecord::new(name.clone(), CLASS::IN, rr_ttl, RData::A(A::from(ip)))
        }
        IpAddr::V6(ip) => {
            ResourceRecord::new(name.clone(), CLASS::IN, rr_ttl, RData::AAAA(AAAA::from(ip)))
        }
    }
}

/// Convert the port to an SRV record. The provided name will be used as resource name and target
pub fn port_to_srv_record<'a>(name: &Name<'a>, port: u16, rr_ttl: u32) -> ResourceRecord<'a> {
    ResourceRecord::new(
        name.clone(),
        CLASS::IN,
        rr_ttl,
        RData::SRV(Box::new(SRV {
            port,
            priority: 0,
            target: name.clone(),
            weight: 0,
        })),
    )
}

/// Convert the socket address to a SRV and an A (IpV4) or AAAA (IpV6) record, the return will be a tuple where the SRV is the first item
pub fn socket_addr_to_srv_and_address<'a>(
    name: &Name<'a>,
    addr: &SocketAddr,
    rr_ttl: u32,
) -> (ResourceRecord<'a>, ResourceRecord<'a>) {
    (
        port_to_srv_record(name, addr.port(), rr_ttl),
        ip_addr_to_resource_record(name, &addr.ip(), rr_ttl),
    )
}
