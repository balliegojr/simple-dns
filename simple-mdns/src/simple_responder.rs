use std::{collections::HashMap, sync::{Arc, RwLock}};

use simple_dns::{PacketBuf, PacketHeader, ResourceRecord, TYPE, rdata::RData};

use crate::{ENABLE_LOOPBACK, MULTICAST_ADDR_IPV4, MULTICAST_PORT, SimpleMdnsError, create_udp_socket};


pub struct SimpleMdnsResponder {
    enable_loopback: bool,
    resources: Arc<RwLock<HashMap<String, Vec<ResourceRecord<'static>>>>>
}

impl SimpleMdnsResponder {
    pub fn new() -> Self {
        Self {
            resources: Arc::new(RwLock::new(HashMap::new())),
            enable_loopback: ENABLE_LOOPBACK
        }
    }

    pub fn set_loopback(&mut self, enable_loopback: bool) {
        self.enable_loopback = enable_loopback
    }

    pub fn add_resouce(&mut self, resource: ResourceRecord<'static>) {
        self.resources.write()
            .unwrap()
            .entry(resource.name.to_string())
            .or_default()
            .push(resource);
    }

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
}

impl Default for SimpleMdnsResponder {
    fn default() -> Self {
        Self::new()
    }
}

fn build_reply(packet: PacketBuf, resources: &HashMap<String, Vec<ResourceRecord<'static>>>) -> Option<(bool, PacketBuf)> {
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
                        additional_records.extend(resource.iter().filter(|r| r.rdatatype == TYPE::A));
                    } else {
                        let target = resources.get(&srv.target.to_string())
                            .map(|f| f.iter().filter(|r| r.match_qclass(question.qclass) && r.match_qtype(question.qtype) && r.rdatatype == TYPE::A));
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

