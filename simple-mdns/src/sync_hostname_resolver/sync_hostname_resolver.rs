
use crate::{
    NetworkScope, SimpleMdnsError, UNICAST_RESPONSE, socket_helper::join_multicast_with_pktinfo
};
use simple_dns::{header_buffer, rdata::RData, Name, Packet, Question, CLASS, TYPE};

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};
use socket_pktinfo::{PktInfo, PktInfoUdpSocket};

/// Provides One Shot hostname A or AAAA resolution queries (legacy mDNS)
///
/// Every query will timeout after `query_timeout` elapses (defaults to 3 seconds)
///
/// One Shot queries returns only the first valid response to arrive
/// ```
///     use simple_mdns::sync_hostname_resolver::OneShotMdnsHostnameResolver;
///
///
///     let mut resolver = OneShotMdnsHostnameResolver::new().expect("Failed to create resolver");
///     let answer = resolver.query_hostname_address("volumio.local");
///         let result = match answer {
///             Ok(result) => match result {
///                 Some(addr) => addr,
///                 None => {
///                     println!("No answer found for the hostname");
///                     std::process::exit(0);
///                 }
///             },
///             Err(err) => {
///                 println!("err {}", err);
///                 std::process::exit(0);
///             }
///         };
///         for ip in result.ip_addresses {
///             println!("IP address: {}", ip);
///             
///         }
///         println!("scope: {}", result.scope);
/// ```
#[derive(Debug)]
pub struct OneShotMdnsHostnameResolver {
    query_timeout: Duration,
    unicast_response: bool,
    receiver_socket: PktInfoUdpSocket,
    network_scope: NetworkScope,
}

pub struct HostnameResolveResult{
    pub ip_addresses: Vec<IpAddr>,
    pub scope: u64
}
impl OneShotMdnsHostnameResolver {
    /// Creates a new OneShotMdnsResolver using IP V4 with unspecified interface
    pub fn new() -> Result<Self, SimpleMdnsError> {
        Self::new_with_scope(NetworkScope::V4)
    }

    /// Creates a new OneShotMdnsResolver with the specified scope
    pub fn new_with_scope(network_scope: NetworkScope) -> Result<Self, SimpleMdnsError> {
        Ok(Self {
            query_timeout: Duration::from_secs(3),
            unicast_response: UNICAST_RESPONSE,
            network_scope,
            receiver_socket: join_multicast_with_pktinfo(network_scope)?,
        })
    }

    /// Send a query packet and returns the first response
    pub fn query_packet(&self, packet: Packet) -> Result<(Option<Vec<u8>>, PktInfo), SimpleMdnsError> {
        self.receiver_socket.send_to(
            &packet.build_bytes_vec_compressed()?,
            &self.network_scope.socket_address().into(),
        )?;
        let deadline = Instant::now() + self.query_timeout;
        self.get_next_response(packet.id(), deadline)
    }

    /// Send a query for A or AAAA (IP v4 and v6 respectively) resources and return the first address with network interface scope id
    pub fn query_hostname_address(
        &self,
        hostname: &str,
    ) -> Result<Option<HostnameResolveResult>, SimpleMdnsError> {
        let mut packet = Packet::new_query(0);
        let hostname = Name::new(hostname)?;
        let mut result = HostnameResolveResult{
            ip_addresses: Vec::new(),
            scope: 0
        };
        packet.questions.push(Question::new(
            hostname.clone(),
            TYPE::A.into(),
            CLASS::IN.into(),
            self.unicast_response,
        ));

        self.receiver_socket.send_to(
            &packet.build_bytes_vec_compressed()?,
            &self.network_scope.socket_address().into(),
        )?;

        let deadline = Instant::now() + self.query_timeout;
        loop {
            let (buffer, pkt_info) = match self.get_next_response(packet.id(), deadline) {
                Ok((Some(buffer), pkt_info)) => {
                    (buffer, pkt_info)
                },
                Ok((None, _)) => {
                    break
                },
                Err(err) => {
                    log::error!("Received invalid packet: {}", err);
                    continue;
                }
            };

            let response = match Packet::parse(&buffer) {
                Ok(packet) => packet,
                Err(err) => {
                    log::error!("Received invalid packet: {}", err);
                    continue;
                }
            };

            for anwser in response.answers {
                if anwser.name != hostname {
                    continue;
                }
                println!("Found matching answer: {:?}", anwser);
                match anwser.rdata {
                    RData::A(a) => {
                        result.ip_addresses.push(IpAddr::V4(Ipv4Addr::from(a.address)));
                    },
                    RData::AAAA(aaaa) => {
                        result.ip_addresses.push(IpAddr::V6(Ipv6Addr::from(aaaa.address)));
                    },
                    _ => continue,
                };

            }
            for anwser in response.additional_records {
                if anwser.name != hostname {
                    continue;
                }
                println!("Found matching additional_records: {:?}", anwser);
                match anwser.rdata {
                    RData::A(a) => {
                        result.ip_addresses.push(IpAddr::V4(Ipv4Addr::from(a.address)));
                    },
                    RData::AAAA(aaaa) => {
                        result.ip_addresses.push(IpAddr::V6(Ipv6Addr::from(aaaa.address)));
                    },
                    _ => continue,
                };
            }
            result.scope = pkt_info.if_index;
            return Ok(Some(result));
        }

        Ok(None)
    }
    /// Set the one shot mdns resolver's query timeout.
    pub fn set_query_timeout(&mut self, query_timeout: Duration) {
        self.query_timeout = query_timeout;
    }

    /// Set the one shot mdns resolver's unicast response.
    pub fn set_unicast_response(&mut self, unicast_response: bool) {
        self.unicast_response = unicast_response;
    }

    fn get_next_response(
        &self,
        packet_id: u16,
        query_deadline: std::time::Instant,
    ) -> Result<(Option<Vec<u8>>, PktInfo), SimpleMdnsError> {
        let mut buf = [0u8; 4096];
        loop {
            match self.receiver_socket.recv(&mut buf[..]) {
                Ok((count,packt_info)) => {
                    if header_buffer::has_flags(&buf, simple_dns::PacketFlag::RESPONSE)?
                        && header_buffer::id(&buf)? == packet_id
                        && header_buffer::answers(&buf)? > 0
                    {
                        return Ok((Some(buf[..count].to_vec()), packt_info));
                    }
                }
                Err(_) => {
                    if std::time::Instant::now() > query_deadline {
                        return Err(SimpleMdnsError::ServiceDiscoveryStopped);
                    }
                }
            }
        }
    }
}