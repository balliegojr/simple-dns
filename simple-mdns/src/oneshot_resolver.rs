use std::{net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr}, time::Duration};
use simple_dns::{Name, PacketBuf, PacketHeader, QCLASS, QTYPE, Question, TYPE, rdata::RData};
use crate::{ENABLE_LOOPBACK, SimpleMdnsError, UNICAST_RESPONSE, create_udp_socket, send_packet_to_multicast_socket};

/// Provides One Shot queries (legacy mDNS)
/// Every query will timeout after `query_timeout` elapses (defaults to 3 seconds)
/// One Shot queries returns only the first valid response to arrive
pub struct OneShotMdnsResolver {
    query_timeout: Duration,
    enable_loopback: bool,
    unicast_response: bool
}

impl OneShotMdnsResolver {
    /// Creates a new OneShotMdnsResolver
    pub fn new() -> Self {
        Self { 
            enable_loopback: ENABLE_LOOPBACK,
            query_timeout: Duration::from_secs(3),
            unicast_response: UNICAST_RESPONSE
        }
    }

    /// Send a query packet and returns the first response
    pub async fn query_packet<'a>(&self, packet: PacketBuf) -> Result<Option<PacketBuf>, SimpleMdnsError> {
        let socket = create_udp_socket(self.enable_loopback).map_err(|_| SimpleMdnsError::ErrorCreatingUDPSocket)?;
        send_packet_to_multicast_socket(&socket, &packet).await?;

        match super::timeout(self.query_timeout, get_first_response(&socket, packet.packet_id())).await {
            Ok(packet) => Ok(Some(packet?)),
            Err(_) => Ok(None)
        }
    }

    /// Send a query for A or AAAA (IP v4 and v6 respectively) resources and return the first address
    pub async fn query_service_address(&self, service_name: &str) -> Result<Option<std::net::IpAddr>, SimpleMdnsError> {
        let mut packet = PacketBuf::new( PacketHeader::new_query(rand::random(), false));
        let service_name = Name::new(service_name)?;
        packet.add_question(&Question::new( service_name.clone(), QTYPE::A, QCLASS::IN, self.unicast_response))?;

        let response = self.query_packet(packet).await?;
        if let Some(response) = response {
            let response = response.to_packet()?;
            for anwser in response.answers {
                if anwser.name != service_name {
                    continue;
                }

                return match anwser.rdata {
                    RData::A(a) => Ok(Some(IpAddr::V4(Ipv4Addr::from(a.address)))),
                    RData::AAAA(aaaa) => Ok(Some(IpAddr::V6(Ipv6Addr::from(aaaa.address)))),
                    _ => Ok(None)
                }
            }
        }

        Ok(None)
    }

    /// Send a query for SRV resources and return the first address and port
    pub async fn query_service_address_and_port(&self, service_name: &str) -> Result<Option<std::net::SocketAddr>, SimpleMdnsError> {
        let mut packet = PacketBuf::new( PacketHeader::new_query(rand::random(), false));
        let parsed_name_service = Name::new(service_name)?;
        packet.add_question(&Question::new( parsed_name_service.clone(), QTYPE::SRV, QCLASS::IN, self.unicast_response))?;

        let response = self.query_packet(packet).await?;
        if let Some(response) = response {
            let response = response.to_packet()?;
            let port = response.answers.iter()
                .filter(|a| a.name == parsed_name_service && a.rdatatype == TYPE::SRV)
                .find_map(|a| match &a.rdata { 
                    RData::SRV(srv) => Some(srv.port),
                    _ => None
                });

            let mut address = response.additional_records.iter()
                .filter(|a| a.name == parsed_name_service &&  a.match_qtype(QTYPE::A))
                .find_map(|a| match &a.rdata { 
                    RData::A(a) => Some(IpAddr::V4(Ipv4Addr::from( a.address))),
                    RData::AAAA(aaaa) => Some(IpAddr::V6(Ipv6Addr::from(aaaa.address))),
                    _ => None
                });

            if port.is_some() && address.is_none() {
                address = self.query_service_address(service_name).await?;
            }

            if port.is_some() && address.is_some() {
                return Ok(Some(SocketAddr::new(address.unwrap(), port.unwrap())))
            }
            
        }

        Ok(None)
    }

    /// Set the one shot mdns resolver's query timeout.
    pub fn set_query_timeout(&mut self, query_timeout: Duration) {
        self.query_timeout = query_timeout;
    }

    /// Set the one shot mdns resolver's enable loopback.
    pub fn set_enable_loopback(&mut self, enable_loopback: bool) {
        self.enable_loopback = enable_loopback;
    }

    /// Set the one shot mdns resolver's unicast response.
    pub fn set_unicast_response(&mut self, unicast_response: bool) {
        self.unicast_response = unicast_response;
    }
}

impl Default for OneShotMdnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

async fn get_first_response(socket: &tokio::net::UdpSocket, packet_id: u16) -> Result<PacketBuf, SimpleMdnsError> {
    let mut buf = [0u8; 4096];
    
    loop {
        let (count, _) = socket.recv_from(&mut buf[..])
            .await
            .map_err(|_| SimpleMdnsError::ErrorReadingFromUDPSocket)?;

        if let Ok(header) = PacketHeader::parse(&buf[0..12]) {
            if !header.query && header.id == packet_id && header.answers_count > 0 {
                return Ok(buf[..count].into())
            }
        }
    }
}



#[cfg(test)]
mod tests {
    use std::str::FromStr;
    
    use crate::SimpleMdnsResponder;

    use super::*;

    fn get_oneshot_responder(srv_name: Name<'static>) -> SimpleMdnsResponder {
        let mut responder = SimpleMdnsResponder::default();
        responder.add_service_address(srv_name, &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080));

        responder
    }

    #[tokio::test] 
    async fn one_shot_resolver_address_query() {
        let _responder = get_oneshot_responder(Name::new_unchecked("_srv._tcp.local"));

        let resolver = OneShotMdnsResolver::new();
        let answer = resolver.query_service_address("_srv._tcp.local").await;
        assert!(answer.is_ok());
        let answer = answer.unwrap();
        assert!(answer.is_some());
        assert_eq!(Ipv4Addr::LOCALHOST, answer.unwrap());
    }

    #[tokio::test] 
    async fn one_shot_resolver_address_port_query() {
        let _responder =get_oneshot_responder(Name::new_unchecked("_srv._tcp.local"));

        let resolver = OneShotMdnsResolver::new();
        let answer = resolver.query_service_address_and_port("_srv._tcp.local").await;
        assert!(answer.is_ok());
        let answer = answer.unwrap();
        assert!(answer.is_some());
        assert_eq!(SocketAddr::from_str("127.0.0.1:8080").unwrap(), answer.unwrap())
    }
}
