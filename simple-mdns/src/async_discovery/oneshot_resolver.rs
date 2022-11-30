use crate::{
    socket_helper::{join_multicast, nonblocking, sender_socket},
    NetworkScope, SimpleMdnsError, UNICAST_RESPONSE,
};
use simple_dns::{header_buffer, rdata::RData, Name, Packet, Question, CLASS, TYPE};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::{
    net::UdpSocket,
    time::{timeout_at, Duration, Instant},
};

/// Provides One Shot queries (legacy mDNS)
///
/// Every query will timeout after `query_timeout` elapses (defaults to 3 seconds)
///
/// One Shot queries returns only the first valid response to arrive
/// ```no_run
///     use simple_mdns::async_discovery::OneShotMdnsResolver;
///     use std::time::Duration;
///     
///     let mut resolver = OneShotMdnsResolver::new().expect("Can't create one shot resolver");
///     resolver.set_query_timeout(Duration::from_secs(1));
///     
///     # async {
///     // querying for IP Address
///     let answer = resolver.query_service_address("_myservice._tcp.local").await.expect("Failed to query service address");
///     println!("{:?}", answer);
///     // IpV4Addr or IpV6Addr, depending on what was returned
///    
///     let answer = resolver.query_service_address_and_port("_myservice._tcp.local").await.expect("Failed to query service address and port");
///     println!("{:?}", answer);
///     // SocketAddr, "127.0.0.1:8080", with a ipv4 or ipv6
///
///     # };
/// ```

pub struct OneShotMdnsResolver {
    query_timeout: Duration,
    unicast_response: bool,
    receiver_socket: UdpSocket,
    sender_socket: UdpSocket,
    network_scope: NetworkScope,
}

impl OneShotMdnsResolver {
    /// Creates a new OneShotMdnsResolver using IP V4 with unspecified interface
    pub fn new() -> Result<Self, SimpleMdnsError> {
        Self::new_with_scope(NetworkScope::V4)
    }

    /// Creates a new OneShotMdnsResolver with the specified scope
    pub fn new_with_scope(network_scope: NetworkScope) -> Result<Self, SimpleMdnsError> {
        Ok(Self {
            query_timeout: Duration::from_secs(3),
            unicast_response: UNICAST_RESPONSE,
            sender_socket: sender_socket(network_scope.is_v4()).and_then(nonblocking)?,
            network_scope,
            receiver_socket: join_multicast(network_scope).and_then(nonblocking)?,
        })
    }

    /// Send a query packet and returns the first response
    pub async fn query_packet<'a>(
        &self,
        packet: Packet<'a>,
    ) -> Result<Option<Vec<u8>>, SimpleMdnsError> {
        self.sender_socket
            .send_to(
                &packet.build_bytes_vec_compressed()?,
                self.network_scope.socket_address(),
            )
            .await?;
        let deadline = Instant::now() + self.query_timeout;
        self.get_next_response(packet.id(), deadline).await
    }

    /// Send a query for A or AAAA (IP v4 and v6 respectively) resources and return the first address
    pub async fn query_service_address(
        &self,
        service_name: &str,
    ) -> Result<Option<std::net::IpAddr>, SimpleMdnsError> {
        let mut packet = Packet::new_query(0);
        let service_name = Name::new(service_name)?;
        packet.questions.push(Question::new(
            service_name.clone(),
            TYPE::A.into(),
            CLASS::IN.into(),
            self.unicast_response,
        ));

        self.sender_socket
            .send_to(
                &packet.build_bytes_vec_compressed()?,
                self.network_scope.socket_address(),
            )
            .await?;

        let deadline = Instant::now() + self.query_timeout;
        loop {
            let buffer = match self.get_next_response(packet.id(), deadline).await {
                Ok(Some(packet)) => packet,
                Ok(None) => break,
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
                if anwser.name != service_name {
                    continue;
                }

                return match anwser.rdata {
                    RData::A(a) => Ok(Some(IpAddr::V4(Ipv4Addr::from(a.address)))),
                    RData::AAAA(aaaa) => Ok(Some(IpAddr::V6(Ipv6Addr::from(aaaa.address)))),
                    _ => Ok(None),
                };
            }
        }

        Ok(None)
    }

    /// Send a query for SRV resources and return the first address and port
    pub async fn query_service_address_and_port(
        &self,
        service_name: &str,
    ) -> Result<Option<std::net::SocketAddr>, SimpleMdnsError> {
        let mut packet = Packet::new_query(0);
        let parsed_name_service = Name::new(service_name)?;
        packet.questions.push(Question::new(
            parsed_name_service.clone(),
            TYPE::SRV.into(),
            CLASS::IN.into(),
            self.unicast_response,
        ));

        self.sender_socket
            .send_to(
                &packet.build_bytes_vec()?,
                self.network_scope.socket_address(),
            )
            .await?;

        let deadline = Instant::now() + self.query_timeout;
        loop {
            let buffer = match self.get_next_response(packet.id(), deadline).await {
                Ok(Some(packet)) => packet,
                Ok(None) => break,
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

            let port = response
                .answers
                .iter()
                .filter(|a| a.name == parsed_name_service && a.match_qtype(TYPE::SRV.into()))
                .find_map(|a| match &a.rdata {
                    RData::SRV(srv) => Some(srv.port),
                    _ => None,
                });

            let mut address = response
                .additional_records
                .iter()
                .filter(|a| a.name == parsed_name_service && a.match_qtype(TYPE::A.into()))
                .find_map(|a| match &a.rdata {
                    RData::A(a) => Some(IpAddr::V4(Ipv4Addr::from(a.address))),
                    RData::AAAA(aaaa) => Some(IpAddr::V6(Ipv6Addr::from(aaaa.address))),
                    _ => None,
                });

            if port.is_some() && address.is_none() {
                address = self.query_service_address(service_name).await?;
            }

            if let (Some(port), Some(address)) = (port, address) {
                return Ok(Some(SocketAddr::new(address, port)));
            }
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

    async fn get_next_response(
        &self,
        packet_id: u16,
        deadline: Instant,
    ) -> Result<Option<Vec<u8>>, SimpleMdnsError> {
        let mut buf = [0u8; 4096];

        loop {
            match timeout_at(deadline, self.receiver_socket.recv_from(&mut buf[..])).await {
                Ok(read_task) => {
                    let (count, _) = read_task?;
                    if header_buffer::has_flags(&buf, simple_dns::PacketFlag::RESPONSE)?
                        && header_buffer::id(&buf)? == packet_id
                        && header_buffer::answers(&buf)? > 0
                    {
                        return Ok(Some(buf[..count].to_vec()));
                    }
                }
                Err(_) => {
                    return Ok(None);
                }
            }
        }
    }
}
