use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use simple_dns::{
    rdata::RData, Name, Packet, PacketBuf, PacketHeader, Question, OPCODE, QCLASS, QTYPE,
};
use tokio::net::UdpSocket;

use crate::{
    create_udp_socket, resource_record_manager::ResourceRecordManager,
    simple_responder::build_reply, MULTICAST_ADDR_IPV4, MULTICAST_PORT,
};

#[derive(Debug, Clone, Copy)]
struct InstanceTimes {
    refresh_at: Instant,
    expire_at: Instant,
}

impl InstanceTimes {
    pub fn new(ttl: u64) -> Self {
        let added = Instant::now();
        let expire_at = added + Duration::from_secs(ttl);
        let refresh_at = match ttl {
            0 => expire_at,
            ttl if ttl < 60 => added + Duration::from_secs(ttl / 2),
            ttl => added + Duration::from_secs(ttl / 10 * 8),
        };

        Self {
            expire_at,
            refresh_at,
        }
    }
}

pub struct ServiceDiscovery {
    service_name: Name<'static>,
    resource_manager: Arc<RwLock<ResourceRecordManager<'static>>>,
    known_instances: Arc<RwLock<HashMap<SocketAddr, InstanceTimes>>>,
    resource_ttl: u32,
    udp_socket: Arc<UdpSocket>,
    multicast_addr: SocketAddr,
    enable_loopback: bool,
}

impl ServiceDiscovery {
    pub fn new(service_name: Name<'static>, resource_ttl: u32, enable_loopback: bool) -> Self {
        let service_discory = Self {
            service_name,
            multicast_addr: std::net::SocketAddr::new(MULTICAST_ADDR_IPV4.into(), MULTICAST_PORT),
            resource_manager: Arc::new(RwLock::new(ResourceRecordManager::new())),
            known_instances: Arc::new(RwLock::new(HashMap::new())),
            resource_ttl,
            udp_socket: Arc::new(create_udp_socket(enable_loopback).unwrap()),
            enable_loopback,
        };

        service_discory.wait_replies();
        service_discory.probe_instances();
        service_discory.verify_instances_ttl();

        service_discory
    }

    pub fn add_address_to_discovery(&mut self, socket_addr: &SocketAddr) {
        self.resource_manager.write().unwrap().add_service_address(
            self.service_name.clone(),
            socket_addr,
            self.resource_ttl,
        );

        self.advertise_service();
    }
    pub fn remove_service_from_discovery(&mut self, service_name: &'static Name) {
        self.resource_manager
            .write()
            .unwrap()
            .remove_all_resource_records(service_name);
    }
    pub fn get_known_services<'b>(&self) -> Vec<SocketAddr> {
        let instances = self.known_instances.read().unwrap();
        instances.keys().cloned().collect()
    }

    fn verify_instances_ttl(&self) {
        let known_instances = self.known_instances.clone();
        let service_name = self.service_name.clone();
        let socket = self.udp_socket.clone();
        let addr = self.multicast_addr;

        tokio::spawn(async move {
            let service_name = service_name;
            loop {
                let now = Instant::now();

                known_instances
                    .write()
                    .unwrap()
                    .retain(|_, times| times.expire_at > now);

                let next_expiration = {
                    let known_instances = known_instances.read().unwrap();
                    known_instances
                        .values()
                        .min_by(|a, b| a.refresh_at.cmp(&b.refresh_at))
                        .cloned()
                };
                match next_expiration {
                    Some(expiration) => {
                        if expiration.refresh_at < now {
                            send_question(service_name.clone(), &socket, addr).await;
                        } else {
                            tokio::time::sleep_until(expiration.refresh_at.into()).await;
                        }
                    }
                    None => {
                        tokio::time::sleep(Duration::from_secs(3)).await;
                    }
                }
            }
        });
    }

    fn advertise_service(&self) {
        let mut packet = PacketBuf::new(PacketHeader::new_reply(0, OPCODE::StandardQuery));
        {
            let resource_manager = self.resource_manager.read().unwrap();
            if let Some(srv) = resource_manager
                .find_matching_resources(&self.service_name, QTYPE::SRV, QCLASS::IN)
                .next()
            {
                packet.add_answer(srv);
            }

            for additional_record in
                resource_manager.find_matching_resources(&self.service_name, QTYPE::A, QCLASS::IN)
            {
                packet.add_additional_record(additional_record);
            }
        }

        if packet.has_answers() && packet.has_additional_records() {
            let socket = self.udp_socket.clone();
            let addr = self.multicast_addr;

            tokio::spawn(async move { socket.send_to(&packet, addr).await });
        }
    }
    fn probe_instances(&self) {
        let service_name = self.service_name.clone();
        let socket = self.udp_socket.clone();
        let dest = self.multicast_addr;

        tokio::spawn(async move {
            send_question(service_name, &socket, dest).await;
        });
    }

    fn wait_replies(&self) {
        let service_name = self.service_name.clone();
        let known_instances = self.known_instances.clone();
        let resources = self.resource_manager.clone();
        let multicast_addr = self.multicast_addr;
        let enable_loopback = self.enable_loopback;

        tokio::spawn(async move {
            let mut recv_buffer = vec![0; 4096];
            let socket = create_udp_socket(enable_loopback).unwrap();
            let service_name = service_name;

            loop {
                let (count, addr) = socket.recv_from(&mut recv_buffer).await.unwrap();

                if let Ok(header) = PacketHeader::parse(&recv_buffer[..12]) {
                    if header.query {
                        let packet = PacketBuf::from(&recv_buffer[..count]);
                        let reply = {
                            let resources = resources.read().unwrap();
                            build_reply(packet, &resources)
                        };

                        if let Some((unicast_reply, packet)) = reply {
                            let addr_reply = if unicast_reply { addr } else { multicast_addr };
                            socket.send_to(&packet, addr_reply).await;
                        }
                    } else {
                        add_response_to_known_instances(
                            &recv_buffer[..count],
                            &service_name,
                            &known_instances,
                            &resources.read().unwrap(),
                        );
                    }
                }
            }
        });
    }
}

fn add_response_to_known_instances<'a>(
    recv_buffer: &[u8],
    service_name: &Name<'a>,
    known_instances: &RwLock<HashMap<SocketAddr, InstanceTimes>>,
    owned_resources: &ResourceRecordManager,
) {
    if let Some(packet) = Packet::parse(&recv_buffer).ok() {
        let port = packet
            .answers
            .iter()
            .filter(|aw| {
                aw.name == *service_name
                    && aw.match_qtype(QTYPE::SRV)
                    && !owned_resources.has_resource(&aw)
            })
            .find_map(|a| match &a.rdata {
                RData::SRV(srv) => Some(srv.port),
                _ => None,
            });

        if port.is_none() {
            return;
        }

        let address = packet
            .additional_records
            .iter()
            .chain(packet.answers.iter())
            .filter(|ar| ar.name == *service_name && ar.match_qtype(QTYPE::A))
            .find_map(|ar| match &ar.rdata {
                RData::A(a) => Some((IpAddr::V4(Ipv4Addr::from(a.address)), ar.ttl)),
                RData::AAAA(aaaa) => Some((IpAddr::V6(Ipv6Addr::from(aaaa.address)), ar.ttl)),
                _ => None,
            });

        if address.is_none() {
            return;
        }

        let (address, ttl) = address.unwrap();
        let address = SocketAddr::new(address, port.unwrap());
        let instance_times = InstanceTimes::new(ttl as u64);

        known_instances
            .write()
            .unwrap()
            .insert(address, instance_times);
    }
}

async fn send_question<'a>(service_name: Name<'a>, socket: &UdpSocket, addr: SocketAddr) {
    let mut packet = PacketBuf::new(PacketHeader::new_query(0, false));
    packet.add_question(&Question::new(service_name, QTYPE::SRV, QCLASS::IN, false));

    if packet.has_questions() {
        socket.send_to(&packet, addr).await;
    }
}
