use std::{
    collections::HashSet,
    net::{SocketAddr, UdpSocket, Ipv4Addr},
    sync::{Arc, RwLock},
};

use simple_dns::{rdata::RData, PacketBuf, PacketHeader, ResourceRecord, TYPE};

use crate::{
    dns_packet_receiver::DnsPacketReceiver, resource_record_manager::ResourceRecordManager,
    sender_socket, SimpleMdnsError, MULTICAST_IPV4_SOCKET,
};

const FIVE_MINUTES: u32 = 60 * 5;

/// A simple mDNS responder aimed for service discovery.
/// In case you don't have a mDNS responder in your network, or for some reason don't want to use the ones available.
///
/// This responder will list for any mDNS query in the network via Multicast and will reply only to the resources that were added.
///
/// ```
///     use simple_mdns::SimpleMdnsResponder;
///     use simple_dns::{Name, CLASS, ResourceRecord, rdata::{RData, A, SRV}};
///     use std::net::Ipv4Addr;
///
///
///     let mut responder = SimpleMdnsResponder::new(10, &Ipv4Addr::UNSPECIFIED);
///     let srv_name = Name::new_unchecked("_srvname._tcp.local");
///
///     responder.add_resource(ResourceRecord::new(
///         srv_name.clone(),
///         CLASS::IN,
///         10,
///         RData::A(A { address: Ipv4Addr::LOCALHOST.into() }),
///     ));
///
///     responder.add_resource(ResourceRecord::new(
///         srv_name.clone(),
///         CLASS::IN,
///         10,
///         RData::SRV(SRV {
///             port: 8080,
///             priority: 0,
///             weight: 0,
///             target: srv_name
///         })
///     ));
/// ```
///
/// This struct heavily relies on [`simple_dns`] crate and the same must be added as a dependency
pub struct SimpleMdnsResponder {
    resources: Arc<RwLock<ResourceRecordManager<'static>>>,
    rr_ttl: u32,
}

impl SimpleMdnsResponder {
    /// Creates a new SimpleMdnsResponder with ttl of 5 minutes and enabled loopback
    /// 
    /// Ipv4 interface to listen on can be specified, or `&Ipv4Addr::UNSPECIFIED` for OS choice
    pub fn new(rr_ttl: u32, interface: &Ipv4Addr) -> Self {
        let responder = Self {
            resources: Arc::new(RwLock::new(ResourceRecordManager::new())),
            rr_ttl,
        };

        let resources = responder.resources.clone();
        let iface = interface.clone();
        std::thread::spawn(move || {
            if let Err(err) = Self::reply_dns_queries(resources, &iface) {
                log::error!("Dns Responder failed: {}", err);
            }
        });
        responder
    }

    /// Register a Resource Record
    pub fn add_resource(&mut self, resource: ResourceRecord<'static>) {
        let mut resources = self.resources.write().unwrap();
        resources.add_owned_resource(resource);
    }

    /// Remove a resource record
    pub fn remove_resource_record(&mut self, resource: ResourceRecord<'static>) {
        let mut resources = self.resources.write().unwrap();
        resources.remove_resource_record(&resource);
    }

    /// Remove all resource records
    pub fn clear(&mut self) {
        let mut resources = self.resources.write().unwrap();
        resources.clear();
    }

    fn reply_dns_queries(
        resources: Arc<RwLock<ResourceRecordManager<'_>>>,
        interface: &Ipv4Addr
    ) -> Result<(), SimpleMdnsError> {
        let mut receiver = DnsPacketReceiver::new(interface)?;
        let sender_socket = sender_socket(&MULTICAST_IPV4_SOCKET, interface)?;

        loop {
            match receiver.recv_packet() {
                Ok((header, packet, addr)) => {
                    if header.query {
                        send_reply(packet, &resources.read().unwrap(), &sender_socket, addr)?;
                    }
                }
                Err(_) => {
                    log::error!("Received Invalid packet")
                }
            };
        }
    }

    /// Set the simple mdns responder's rr default ttl in seconds (defaults to 300).
    pub fn set_rr_ttl(&mut self, rr_default_ttl: u32) {
        self.rr_ttl = rr_default_ttl;
    }
}

impl Default for SimpleMdnsResponder {
    fn default() -> Self {
        Self::new(FIVE_MINUTES, &Ipv4Addr::UNSPECIFIED)
    }
}

pub(crate) fn send_reply<'a>(
    packet: PacketBuf,
    resources: &'a ResourceRecordManager<'a>,
    socket: &UdpSocket,
    addr: SocketAddr,
) -> Result<(), SimpleMdnsError> {
    if let Some((reply_packet, reply_addr)) = build_reply(packet, addr, resources) {
        socket.send_to(&reply_packet, &reply_addr)?;
    }

    Ok(())
}

pub(crate) fn build_reply<'b>(
    packet: PacketBuf,
    from_addr: SocketAddr,
    resources: &'b ResourceRecordManager<'b>,
) -> Option<(PacketBuf, SocketAddr)> {
    let header = PacketHeader::parse(&packet).ok()?;
    let mut reply_packet = PacketBuf::new(PacketHeader::new_reply(header.id, header.opcode), true);

    let mut unicast_response = false;
    let mut additional_records = HashSet::new();

    // TODO: fill the questions for the response
    // TODO: filter out questions with known answers
    for question in packet.questions_iter() {
        if question.unicast_response {
            unicast_response = question.unicast_response
        }

        for d_resources in resources.get_domain_resources(&question.qname, true, true) {
            for answer in d_resources
                .filter(|r| r.match_qclass(question.qclass) && r.match_qtype(question.qtype))
            {
                reply_packet.add_answer(answer).ok()?;

                if let RData::SRV(srv) = &answer.rdata {
                    let target = resources
                        .get_domain_resources(&srv.target, false, true)
                        .flatten()
                        .filter(|r| {
                            r.match_qtype(TYPE::A.into()) && r.match_qclass(question.qclass)
                        });

                    additional_records.extend(target);
                }
            }
        }
    }

    for additional_record in additional_records {
        reply_packet.add_additional_record(additional_record).ok()?;
    }

    let reply_addr = if unicast_response {
        from_addr
    } else {
        *MULTICAST_IPV4_SOCKET
    };

    if reply_packet.has_answers() {
        Some((reply_packet, reply_addr))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use simple_dns::Name;
    use std::{
        convert::TryInto,
        net::{Ipv4Addr, Ipv6Addr},
        str::FromStr,
    };

    use simple_dns::Question;

    use crate::conversion_utils::{ip_addr_to_resource_record, port_to_srv_record};

    use super::*;

    fn get_resources() -> ResourceRecordManager<'static> {
        let mut resources = ResourceRecordManager::new();
        resources.add_owned_resource(port_to_srv_record(
            &Name::new_unchecked("_res1._tcp.com"),
            8080,
            0,
        ));
        resources.add_owned_resource(ip_addr_to_resource_record(
            &Name::new_unchecked("_res1._tcp.com"),
            Ipv4Addr::LOCALHOST.into(),
            0,
        ));
        resources.add_owned_resource(ip_addr_to_resource_record(
            &Name::new_unchecked("_res1._tcp.com"),
            Ipv6Addr::LOCALHOST.into(),
            0,
        ));

        resources.add_owned_resource(port_to_srv_record(
            &Name::new_unchecked("_res2._tcp.com"),
            8080,
            0,
        ));
        resources.add_owned_resource(ip_addr_to_resource_record(
            &Name::new_unchecked("_res2._tcp.com"),
            Ipv4Addr::LOCALHOST.into(),
            0,
        ));
        resources
    }

    #[test]
    fn test_build_reply_with_no_questions() {
        let resources = get_resources();

        let packet = PacketBuf::new(PacketHeader::new_query(1, false), true);
        assert!(build_reply(
            packet,
            SocketAddr::from_str("127.0.0.1:80").unwrap(),
            &resources,
        )
        .is_none());
    }

    #[test]
    fn test_build_reply_without_valid_answers() {
        let resources = get_resources();

        let mut packet = PacketBuf::new(PacketHeader::new_query(1, false), true);
        packet
            .add_question(&Question::new(
                "_res3._tcp.com".try_into().unwrap(),
                simple_dns::QTYPE::ANY,
                simple_dns::QCLASS::ANY,
                false,
            ))
            .unwrap();

        assert!(build_reply(
            packet,
            SocketAddr::from_str("127.0.0.1:80").unwrap(),
            &resources,
        )
        .is_none());
    }

    #[test]
    fn test_build_reply_with_valid_answer() {
        let resources = get_resources();

        let mut packet = PacketBuf::new(PacketHeader::new_query(1, false), true);
        packet
            .add_question(&Question::new(
                "_res1._tcp.com".try_into().unwrap(),
                simple_dns::TYPE::A.into(),
                simple_dns::QCLASS::ANY,
                true,
            ))
            .unwrap();

        let (reply, addr) = build_reply(
            packet,
            SocketAddr::from_str("127.0.0.1:80").unwrap(),
            &resources,
        )
        .unwrap();
        let reply = reply.to_packet().unwrap();

        assert_eq!(addr, SocketAddr::from_str("127.0.0.1:80").unwrap());
        assert_eq!(2, reply.answers.len());
        assert_eq!(0, reply.additional_records.len());
    }

    #[test]
    fn test_build_reply_for_srv() {
        let resources = get_resources();

        let mut packet = PacketBuf::new(PacketHeader::new_query(1, false), true);
        packet
            .add_question(&Question::new(
                "_res1._tcp.com".try_into().unwrap(),
                simple_dns::TYPE::SRV.into(),
                simple_dns::QCLASS::ANY,
                false,
            ))
            .unwrap();

        let (reply, addr) = build_reply(
            packet,
            SocketAddr::from_str("127.0.0.1:80").unwrap(),
            &resources,
        )
        .unwrap();
        let reply = reply.to_packet().unwrap();

        assert_eq!(addr, *crate::MULTICAST_IPV4_SOCKET);
        assert_eq!(1, reply.answers.len());
        assert_eq!(2, reply.additional_records.len());
    }
}
