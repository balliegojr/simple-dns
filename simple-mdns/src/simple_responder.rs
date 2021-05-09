use std::sync::{Arc, RwLock};

use simple_dns::{rdata::RData, PacketBuf, PacketHeader, ResourceRecord, QTYPE};

use crate::{
    create_udp_socket, resource_record_manager::ResourceRecordManager, SimpleMdnsError,
    ENABLE_LOOPBACK, MULTICAST_IPV4_SOCKET,
};

const FIVE_MINUTES: u32 = 60 * 5;

/// A simple mDNS responder aimed for service discovery.
/// This struct is provided as an alternative for external mDNS resource configuration
pub struct SimpleMdnsResponder {
    enable_loopback: bool,
    resources: Arc<RwLock<ResourceRecordManager<'static>>>,
    rr_ttl: u32,
}

impl SimpleMdnsResponder {
    /// Creates a new SimpleMdnsResponder with ttl of 5 minutes and enabled loopback
    pub fn new(rr_ttl: u32, enable_loopback: bool) -> Self {
        let responder = Self {
            resources: Arc::new(RwLock::new(ResourceRecordManager::new())),
            enable_loopback,
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
        let enable_loopback = self.enable_loopback;
        let resources = self.resources.clone();
        tokio::spawn(async move {
            if let Err(err) =
                Self::create_socket_and_wait_messages(enable_loopback, resources).await
            {
                log::error!("Dns Responder failed: {}", err);
            }
        });
    }

    async fn create_socket_and_wait_messages(
        enable_loopback: bool,
        resources: Arc<RwLock<ResourceRecordManager<'_>>>,
    ) -> Result<(), SimpleMdnsError> {
        let mut recv_buffer = vec![0; 4096];

        let socket = create_udp_socket(enable_loopback)?;

        loop {
            let (count, addr) = socket.recv_from(&mut recv_buffer).await?;

            if let Ok(header) = PacketHeader::parse(&recv_buffer[..12]) {
                if !header.query {
                    continue;
                }
            }

            let packet = PacketBuf::from(&recv_buffer[..count]);
            let response = build_reply(packet, &resources.read().unwrap());
            if let Some((unicast_response, reply_packet)) = response {
                let target_addr = if unicast_response {
                    addr
                } else {
                    *MULTICAST_IPV4_SOCKET
                };

                socket.send_to(&reply_packet, target_addr).await?;
            }
        }
    }

    /// Set the simple mdns responder's enable loopback.
    pub fn set_enable_loopback(&mut self, enable_loopback: bool) {
        self.enable_loopback = enable_loopback;
    }

    /// Set the simple mdns responder's rr default ttl in seconds (defaults to 300).
    pub fn set_rr_ttl(&mut self, rr_default_ttl: u32) {
        self.rr_ttl = rr_default_ttl;
    }
}

impl Default for SimpleMdnsResponder {
    fn default() -> Self {
        Self::new(FIVE_MINUTES, ENABLE_LOOPBACK)
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
            &Ipv4Addr::LOCALHOST.into(),
            0,
        ));
        resources.add_resource(ip_addr_to_resource_record(
            &Name::new_unchecked("_res1._tcp.com"),
            &Ipv6Addr::LOCALHOST.into(),
            0,
        ));

        resources.add_resource(port_to_srv_record(
            &Name::new_unchecked("_res2._tcp.com"),
            8080,
            0,
        ));
        resources.add_resource(ip_addr_to_resource_record(
            &Name::new_unchecked("_res2._tcp.com"),
            &Ipv4Addr::LOCALHOST.into(),
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
