use crate::{join_multicast, sender_socket, SimpleMdnsError, UNICAST_RESPONSE};
use simple_dns::{rdata::RData, Name, PacketBuf, PacketHeader, Question, CLASS, TYPE};

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    time::{Duration, Instant},
};
/// Provides One Shot queries (legacy mDNS)
///
/// Every query will timeout after `query_timeout` elapses (defaults to 3 seconds)
///
/// One Shot queries returns only the first valid response to arrive
/// ```
///     use simple_mdns::OneShotMdnsResolver;
///     use std::time::Duration;
///     
///     let mut resolver = OneShotMdnsResolver::new().expect("Can't create one shot resolver");
///     resolver.set_query_timeout(Duration::from_secs(1));
///     
///     // querying for IP Address
///     let answer = resolver.query_service_address("_myservice._tcp.local").expect("Failed to query service address");
///     println!("{:?}", answer);
///     // IpV4Addr or IpV6Addr, depending on what was returned
///    
///     let answer = resolver.query_service_address_and_port("_myservice._tcp.local").expect("Failed to query service address and port");
///     println!("{:?}", answer);
///     // SocketAddr, "127.0.0.1:8080", with a ipv4 or ipv6
/// ```

pub struct OneShotMdnsResolver {
    query_timeout: Duration,
    unicast_response: bool,
    receiver_socket: UdpSocket,
    sender_socket: UdpSocket,
}

impl OneShotMdnsResolver {
    /// Creates a new OneShotMdnsResolver
    pub fn new() -> Result<Self, SimpleMdnsError> {
        Ok(Self {
            query_timeout: Duration::from_secs(3),
            unicast_response: UNICAST_RESPONSE,
            receiver_socket: join_multicast(&super::MULTICAST_IPV4_SOCKET)?,
            sender_socket: sender_socket(&super::MULTICAST_IPV4_SOCKET)?,
        })
    }

    /// Send a query packet and returns the first response
    pub fn query_packet(&self, packet: PacketBuf) -> Result<Option<PacketBuf>, SimpleMdnsError> {
        // let mut socket = create_udp_socket(self.enable_loopback)?;
        // send_packet_to_multicast_socket(&socket, &packet)?;
        self.sender_socket
            .send_to(&packet, &*super::MULTICAST_IPV4_SOCKET)?;
        let deadline = Instant::now() + self.query_timeout;
        self.get_next_response(packet.packet_id(), deadline)
    }

    /// Send a query for A or AAAA (IP v4 and v6 respectively) resources and return the first address
    pub fn query_service_address(
        &self,
        service_name: &str,
    ) -> Result<Option<std::net::IpAddr>, SimpleMdnsError> {
        let mut packet = PacketBuf::new(PacketHeader::new_query(0, false), true);
        let service_name = Name::new(service_name)?;
        packet.add_question(&Question::new(
            service_name.clone(),
            TYPE::A.into(),
            CLASS::IN.into(),
            self.unicast_response,
        ))?;

        self.sender_socket
            .send_to(&packet, &*super::MULTICAST_IPV4_SOCKET)?;

        let deadline = Instant::now() + self.query_timeout;
        while let Some(response) = self.get_next_response(packet.packet_id(), deadline)? {
            let response = match response.to_packet() {
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
    pub fn query_service_address_and_port(
        &self,
        service_name: &str,
    ) -> Result<Option<std::net::SocketAddr>, SimpleMdnsError> {
        let mut packet = PacketBuf::new(PacketHeader::new_query(0, false), true);
        let parsed_name_service = Name::new(service_name)?;
        packet.add_question(&Question::new(
            parsed_name_service.clone(),
            TYPE::SRV.into(),
            CLASS::IN.into(),
            self.unicast_response,
        ))?;

        self.sender_socket
            .send_to(&packet, &*super::MULTICAST_IPV4_SOCKET)?;

        let deadline = Instant::now() + self.query_timeout;
        while let Some(response) = self.get_next_response(packet.packet_id(), deadline)? {
            let response = match response.to_packet() {
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
                address = self.query_service_address(service_name)?;
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
    fn get_next_response(
        &self,
        packet_id: u16,
        query_deadline: std::time::Instant,
    ) -> Result<Option<PacketBuf>, SimpleMdnsError> {
        let mut buf = [0u8; 4096];
        loop {
            match self.receiver_socket.recv_from(&mut buf[..]) {
                Ok((count, _)) => {
                    if let Ok(header) = PacketHeader::parse(&buf[0..12]) {
                        if !header.query && header.id == packet_id && header.answers_count > 0 {
                            return Ok(Some(buf[..count].into()));
                        }
                    }
                }
                Err(_) => {
                    if std::time::Instant::now() > query_deadline {
                        return Ok(None);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, thread};

    use crate::{conversion_utils::socket_addr_to_srv_and_address, SimpleMdnsResponder};

    use super::*;

    fn get_oneshot_responder(srv_name: Name<'static>) -> SimpleMdnsResponder {
        let mut responder = SimpleMdnsResponder::default();
        let (r1, r2) = socket_addr_to_srv_and_address(
            &srv_name,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            0,
        );
        responder.add_resource(r1);
        responder.add_resource(r2);
        responder
    }

    #[test]
    fn one_shot_resolver_address_query() {
        let _responder = get_oneshot_responder(Name::new_unchecked("_srv._tcp.local"));
        thread::sleep(Duration::from_millis(500));

        let resolver = OneShotMdnsResolver::new().expect("Failed to create resolver");
        let answer = resolver.query_service_address("_srv._tcp.local");

        assert!(answer.is_ok());
        let answer = answer.unwrap();
        assert!(answer.is_some());
        assert_eq!(Ipv4Addr::LOCALHOST, answer.unwrap());

        let answer = resolver.query_service_address_and_port("_srv._tcp.local");
        assert!(answer.is_ok());
        let answer = answer.unwrap();
        assert!(answer.is_some());
        assert_eq!(
            SocketAddr::from_str("127.0.0.1:8080").unwrap(),
            answer.unwrap()
        )
    }

    #[test]
    fn one_shot_resolver_timeout() {
        let resolver = OneShotMdnsResolver::new().expect("Failed to create resolver");
        let answer = resolver.query_service_address("_srv_miss._tcp.local");
        assert!(answer.is_ok());
        let answer = answer.unwrap();
        assert!(answer.is_none());
    }
}
