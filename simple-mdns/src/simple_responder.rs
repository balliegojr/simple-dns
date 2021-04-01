use std::{collections::HashMap, sync::{Arc, RwLock}};

use simple_dns::{PacketBuf, PacketHeader, ResourceRecord, rdata::RData};

use crate::{ENABLE_LOOPBACK, MULTICAST_ADDR_IPV4, MULTICAST_PORT, SimpleMdnsError, create_udp_socket};

/// A simple mDNS responder aimed for service discovery.  
/// This struct is provided as an alternative for external mDNS resource configuration
pub struct SimpleMdnsResponder {
    enable_loopback: bool,
    resources: Arc<RwLock<HashMap<String, Vec<ResourceRecord<'static>>>>>
}

impl SimpleMdnsResponder {
    /// Creates a new SimpleMdnsResponder
    pub fn new() -> Self {
        Self {
            resources: Arc::new(RwLock::new(HashMap::new())),
            enable_loopback: ENABLE_LOOPBACK
        }
    }

    /// Register a Resource Record
    pub fn add_resouce(&mut self, resource: ResourceRecord<'static>) {
        let mut resources = self.resources.write().unwrap();
        match resources.get_mut(&resource.name.to_string()) {
            Some(rec) => { rec.push(resource) },
            None => { resources.insert(resource.name.to_string(), vec![resource]); }
        }
    }

    /// Start listening to requests
    pub fn listen(&self) {
        let enable_loopback = self.enable_loopback;
        let resources = self.resources.clone();
        tokio::spawn(async move {
            Self::create_socket_and_wait_messages(enable_loopback, resources).await
        });
    }

    async fn create_socket_and_wait_messages(enable_loopback: bool, resources: Arc<RwLock<HashMap<String, Vec<ResourceRecord<'static>>>>>) -> Result<(), SimpleMdnsError> {
        let mut recv_buffer = vec![0; 4096];
        
        let socket = create_udp_socket(enable_loopback)
            .map_err(|_| SimpleMdnsError::ErrorCreatingUDPSocket)?;
        
        
        loop {
            let (count, addr) = socket.recv_from(&mut recv_buffer)
                .await
                .map_err(|_| SimpleMdnsError::ErrorReadingFromUDPSocket)?;
    

            let packet = PacketBuf::from(&recv_buffer[..count]);
            let response = build_reply(packet, &resources.read().unwrap());
            if let Some((unicast_response, reply_packet)) = response {
                let target_addr = if unicast_response {
                    addr
                } else {
                    std::net::SocketAddr::new(MULTICAST_ADDR_IPV4.into(), MULTICAST_PORT)
                };
    
                // reply_packet.questions.clear();
                socket.send_to(&reply_packet, target_addr)
                    .await
                    .map_err(|_| SimpleMdnsError::ErrorSendingDNSPacket)?;
            }
        }
    }

    /// Set the simple mdns responder's enable loopback.
    pub fn set_enable_loopback(&mut self, enable_loopback: bool) {
        self.enable_loopback = enable_loopback;
    }
}

impl Default for SimpleMdnsResponder {
    fn default() -> Self {
        Self::new()
    }
}

fn build_reply(packet: PacketBuf, resources: &HashMap<String, Vec<ResourceRecord>>) -> Option<(bool, PacketBuf)> {
    let header = PacketHeader::parse(&packet).ok()?;
    let mut reply_packet = PacketBuf::new(PacketHeader::new_reply(header.id, header.opcode));

    let mut unicast_response = false;
    let mut additional_records = Vec::new();
    for question in packet.questions_iter() {
        if question.unicast_response { 
            unicast_response = question.unicast_response
        }

        if let Some(resource) = resources.get(&question.qname.to_string()) {
            for answer in resource.iter().filter(|r| r.match_qclass(question.qclass) && r.match_qtype(question.qtype)) {
                reply_packet.add_answer(answer).ok()?;

                if let RData::SRV(srv) = &answer.rdata {
                    if srv.target == question.qname {
                        additional_records.extend(resource.iter().filter(|r| r.match_qtype(simple_dns::QTYPE::A)));
                    } else {
                        let target = resources.get(&srv.target.to_string())
                            .map(|f| f.iter().filter(|r| r.match_qclass(question.qclass) && r.match_qtype(simple_dns::QTYPE::A)));
                        if let Some(target) = target {
                            additional_records.extend(target);
                        }
                    }
                }
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
    use std::{convert::TryInto, net::{Ipv4Addr, Ipv6Addr}};

    use simple_dns::{CLASS, Question, rdata::{A, AAAA, SRV}};

    use super::*;

    fn get_resources() -> HashMap<String, Vec<ResourceRecord<'static>>> {
        let mut resources = HashMap::new();
        resources.insert(
            "_res1._tcp.com".to_string(), 
            vec![
                ResourceRecord { 
                    class: CLASS::IN, 
                    name: "_res1._tcp.com".try_into().unwrap(),
                    rdatatype: simple_dns::TYPE::A,
                    ttl: 10,
                    rdata: RData::A(A { address: Ipv4Addr::LOCALHOST.into() }), 
                },
                ResourceRecord { 
                    class: CLASS::IN, 
                    name: "_res1._tcp.com".try_into().unwrap(),
                    rdatatype: simple_dns::TYPE::AAAA,
                    ttl: 10,
                    rdata: RData::AAAA(AAAA { address: Ipv6Addr::LOCALHOST.into() }), 
                },
                ResourceRecord { 
                    class: CLASS::IN, 
                    name: "_res1._tcp.com".try_into().unwrap(),
                    rdatatype: simple_dns::TYPE::SRV,
                    ttl: 10,
                    rdata: RData::SRV(Box::new(SRV { port: 8080, priority: 0, weight: 0, target: "_res1._tcp.com".try_into().unwrap() })), 
                }
            ]
        );

        resources.insert(
            "_res2._tcp.com".to_string(),
            vec![
                ResourceRecord { 
                    class: CLASS::IN, 
                    name: "_res2._tcp.com".try_into().unwrap(),
                    rdatatype: simple_dns::TYPE::A,
                    ttl: 10,
                    rdata: RData::A(A { address: Ipv4Addr::LOCALHOST.into() }), 
                }
            ]
        );

        resources
    }

    #[test]
    fn test_add_resource() {
        let mut responder = SimpleMdnsResponder::new();
        responder.add_resouce(ResourceRecord { 
            class: CLASS::IN, 
            name: "_res1._tcp.com".try_into().unwrap(),
            rdatatype: simple_dns::TYPE::A,
            ttl: 10,
            rdata: RData::A(A { address: Ipv4Addr::LOCALHOST.into() }), 
        });

        responder.add_resouce(ResourceRecord { 
            class: CLASS::IN, 
            name: "_res1._tcp.com".try_into().unwrap(),
            rdatatype: simple_dns::TYPE::AAAA,
            ttl: 10,
            rdata: RData::AAAA(AAAA { address: Ipv6Addr::LOCALHOST.into() }), 
        });

        responder.add_resouce(ResourceRecord { 
            class: CLASS::IN, 
            name: "_res2._tcp.com".try_into().unwrap(),
            rdatatype: simple_dns::TYPE::A,
            ttl: 10,
            rdata: RData::A(A { address: Ipv4Addr::LOCALHOST.into() }), 
        });

        let resources = responder.resources.read().unwrap();

        assert_eq!(2, resources.len());
        assert_eq!(2, resources.get("_res1._tcp.com").unwrap().len());
        assert_eq!(1, resources.get("_res2._tcp.com").unwrap().len());
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
        packet.add_question(&Question::new("_res3._tcp.com".try_into().unwrap(), simple_dns::QTYPE::ANY, simple_dns::QCLASS::ANY, false)).unwrap();
        
        assert!(build_reply(packet, &resources).is_none());
    }

    #[test]
    fn test_build_reply_with_valid_answer() {
        let resources = get_resources();

        let mut packet = PacketBuf::new(PacketHeader::new_query(1, false));
        packet.add_question(&Question::new("_res1._tcp.com".try_into().unwrap(), simple_dns::QTYPE::A, simple_dns::QCLASS::ANY, false)).unwrap();
        
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
        packet.add_question(&Question::new("_res1._tcp.com".try_into().unwrap(), simple_dns::QTYPE::SRV, simple_dns::QCLASS::ANY, false)).unwrap();
        
        let (unicast_response, reply) = build_reply(packet, &resources).unwrap();
        let reply = reply.to_packet().unwrap();

        assert!(!unicast_response);
        assert_eq!(1, reply.answers.len());
        assert_eq!(2, reply.additional_records.len());
    }
}