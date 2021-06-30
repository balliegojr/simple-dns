use std::sync::{Arc, RwLock};

use simple_dns::{rdata::RData, PacketBuf, PacketHeader, ResourceRecord, QTYPE};
use socket2::SockAddr;

use crate::{
    join_multicast, resource_record_manager::ResourceRecordManager, sender_socket, SimpleMdnsError,
    MULTICAST_IPV4_SOCKET,
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
///     let mut responder = SimpleMdnsResponder::new(10);
///     let srv_name = Name::new_unchecked("_srvname._tcp.local");
///
///     responder.add_resource(ResourceRecord {
///         class: CLASS::IN,
///         name: srv_name.clone(),
///         ttl: 10,
///         rdata: RData::A(A { address: Ipv4Addr::LOCALHOST.into() }),
///     });
///
///     responder.add_resource(ResourceRecord {
///         class: CLASS::IN,
///         name: srv_name.clone(),
///         ttl: 10,
///         rdata: RData::SRV(Box::new(SRV {
///             port: 8080,
///             priority: 0,
///             weight: 0,
///             target: srv_name
///         }))
///     });
/// ```
///
/// This struct heavily relies on [`simple_dns`] crate and the same must be added as a dependency
pub struct SimpleMdnsResponder {
    resources: Arc<RwLock<ResourceRecordManager<'static>>>,
    rr_ttl: u32,
}

impl SimpleMdnsResponder {
    /// Creates a new SimpleMdnsResponder with ttl of 5 minutes and enabled loopback
    pub fn new(rr_ttl: u32) -> Self {
        let responder = Self {
            resources: Arc::new(RwLock::new(ResourceRecordManager::new())),
            rr_ttl,
        };

        responder.listen();
        responder
    }

    /// Register a Resource Record
    pub fn add_resource(&mut self, resource: ResourceRecord<'static>) {
        let mut resources = self.resources.write().unwrap();
        resources.add_resource(resource);
    }

    /// Remove a resource record
    pub fn remove_resource_record(&mut self, resource: &ResourceRecord<'static>) {
        let mut resources = self.resources.write().unwrap();
        resources.remove_resource_record(resource);
    }

    /// Remove all resource records
    pub fn clear(&mut self) {
        let mut resources = self.resources.write().unwrap();
        resources.clear();
    }

    /// Start listening to requests
    fn listen(&self) {
        let resources = self.resources.clone();
        std::thread::spawn(move || {
            if let Err(err) = Self::create_socket_and_wait_messages(resources) {
                log::error!("Dns Responder failed: {}", err);
            }
        });
    }

    fn create_socket_and_wait_messages(
        resources: Arc<RwLock<ResourceRecordManager<'_>>>,
    ) -> Result<(), SimpleMdnsError> {
        let mut recv_buffer = vec![0; 4096];

        let socket = join_multicast(*MULTICAST_IPV4_SOCKET)?;
        let _ = socket.set_read_timeout(None);
        let sender_socket = sender_socket(&MULTICAST_IPV4_SOCKET)?;

        loop {
            let (count, addr) = socket.recv_from(&mut recv_buffer)?;

            if let Ok(header) = PacketHeader::parse(&recv_buffer[..12]) {
                if !header.query {
                    continue;
                }
            }

            let packet = PacketBuf::from(&recv_buffer[..count]);
            let response = build_reply(packet, &resources.read().unwrap());

            if let Some((unicast_response, reply_packet)) = response {
                if unicast_response {
                    sender_socket.send_to(&reply_packet, &addr)?;
                } else {
                    sender_socket
                        .send_to(&reply_packet, &SockAddr::from(*MULTICAST_IPV4_SOCKET))?;
                }
            }
        }
    }

    /// Set the simple mdns responder's rr default ttl in seconds (defaults to 300).
    pub fn set_rr_ttl(&mut self, rr_default_ttl: u32) {
        self.rr_ttl = rr_default_ttl;
    }
}

impl Default for SimpleMdnsResponder {
    fn default() -> Self {
        Self::new(FIVE_MINUTES)
    }
}

pub(crate) fn build_reply<'b>(
    packet: PacketBuf,
    resources: &'b ResourceRecordManager<'b>,
) -> Option<(bool, PacketBuf)> {
    let header = PacketHeader::parse(&packet).ok()?;
    let mut reply_packet = PacketBuf::new(PacketHeader::new_reply(header.id, header.opcode));

    let mut unicast_response = false;
    let mut additional_records = Vec::new();

    // TODO: fill the questions for the response
    // TODO: filter out questions with known answers
    for question in packet.questions_iter() {
        if question.unicast_response {
            unicast_response = question.unicast_response
        }

        for answer in resources.find_matching_resources(|r| {
            r.name == question.qname
                && r.match_qtype(question.qtype)
                && r.match_qclass(question.qclass)
        }) {
            reply_packet.add_answer(answer).ok()?;

            if let RData::SRV(srv) = &answer.rdata {
                additional_records.extend(resources.find_matching_resources(|r| {
                    r.name == srv.target
                        && r.match_qtype(QTYPE::A)
                        && r.match_qclass(question.qclass)
                }));
            }
        }
    }

    for additional_record in additional_records {
        reply_packet.add_additional_record(additional_record).ok()?;
    }

    if reply_packet.has_answers() {
        Some((unicast_response, reply_packet))
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
    };

    use simple_dns::Question;

    use crate::conversion_utils::{ip_addr_to_resource_record, port_to_srv_record};

    use super::*;

    fn get_resources() -> ResourceRecordManager<'static> {
        let mut resources = ResourceRecordManager::new();
        resources.add_resource(port_to_srv_record(
            &Name::new_unchecked("_res1._tcp.com"),
            8080,
            0,
        ));
        resources.add_resource(ip_addr_to_resource_record(
            &Name::new_unchecked("_res1._tcp.com"),
            Ipv4Addr::LOCALHOST.into(),
            0,
        ));
        resources.add_resource(ip_addr_to_resource_record(
            &Name::new_unchecked("_res1._tcp.com"),
            Ipv6Addr::LOCALHOST.into(),
            0,
        ));

        resources.add_resource(port_to_srv_record(
            &Name::new_unchecked("_res2._tcp.com"),
            8080,
            0,
        ));
        resources.add_resource(ip_addr_to_resource_record(
            &Name::new_unchecked("_res2._tcp.com"),
            Ipv4Addr::LOCALHOST.into(),
            0,
        ));
        resources
    }

    #[test]
    fn test_build_reply_with_no_questions() {
        let resources = get_resources();

        let packet = PacketBuf::new(PacketHeader::new_query(1, false));
        assert!(build_reply(packet, &resources).is_none());
    }

    #[test]
    fn test_build_reply_without_valid_answers() {
        let resources = get_resources();

        let mut packet = PacketBuf::new(PacketHeader::new_query(1, false));
        packet
            .add_question(&Question::new(
                "_res3._tcp.com".try_into().unwrap(),
                simple_dns::QTYPE::ANY,
                simple_dns::QCLASS::ANY,
                false,
            ))
            .unwrap();

        assert!(build_reply(packet, &resources).is_none());
    }

    #[test]
    fn test_build_reply_with_valid_answer() {
        let resources = get_resources();

        let mut packet = PacketBuf::new(PacketHeader::new_query(1, false));
        packet
            .add_question(&Question::new(
                "_res1._tcp.com".try_into().unwrap(),
                simple_dns::QTYPE::A,
                simple_dns::QCLASS::ANY,
                false,
            ))
            .unwrap();

        let (unicast_response, reply) = build_reply(packet, &resources).unwrap();
        let reply = reply.to_packet().unwrap();

        assert!(!unicast_response);
        assert_eq!(2, reply.answers.len());
        assert_eq!(0, reply.additional_records.len());
    }

    #[test]
    fn test_build_reply_for_srv() {
        let resources = get_resources();

        let mut packet = PacketBuf::new(PacketHeader::new_query(1, false));
        packet
            .add_question(&Question::new(
                "_res1._tcp.com".try_into().unwrap(),
                simple_dns::QTYPE::SRV,
                simple_dns::QCLASS::ANY,
                false,
            ))
            .unwrap();

        let (unicast_response, reply) = build_reply(packet, &resources).unwrap();
        let reply = reply.to_packet().unwrap();

        assert!(!unicast_response);
        assert_eq!(1, reply.answers.len());
        assert_eq!(2, reply.additional_records.len());
    }
}
