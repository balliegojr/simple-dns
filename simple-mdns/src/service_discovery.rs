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

use crate::{MULTICAST_IPV4_SOCKET, SimpleMdnsError, create_udp_socket, resource_record_manager::ResourceRecordManager, simple_responder::build_reply};

/// Provides known service expiration and refresh times
#[derive(Debug, Clone, Copy)]
struct ExpirationTimes {
    refresh_at: Instant,
    expire_at: Instant,
}

impl ExpirationTimes {
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

/// Service Discovery implementation using DNS-SD.
/// This implementation advertise all the registered addresses, query for the same service on the same network and
/// keeps a cache of known service instances
///
/// ## Example
/// ```
/// let mut discovery = ServiceDiscovery::new(Name::new_unchecked("_mysrv._tcp.local"), 60, true);
///
/// discovery.add_address_to_discovery(my_socket_addr);
/// ```
pub struct ServiceDiscovery {
    service_name: Name<'static>,
    resource_manager: Arc<RwLock<ResourceRecordManager<'static>>>,
    known_instances: Arc<RwLock<HashMap<SocketAddr, ExpirationTimes>>>,
    resource_ttl: u32,
    udp_socket: Arc<UdpSocket>,
    enable_loopback: bool,
}

impl ServiceDiscovery {
    /// Creates a new ServiceDiscovery by providing [service name](`simple_dns::Name`), resource ttl and loopback activation.
    /// `resource_ttl` refers to the amount of time in seconds your service will be cached in the dns responder.
    /// set `enable_loopback` to true if you may have more than one instance of your service running in the same machine
    pub fn new(service_name: Name<'static>, resource_ttl: u32, enable_loopback: bool) -> Self {
        let service_discovery = Self {
            service_name,
            resource_manager: Arc::new(RwLock::new(ResourceRecordManager::new())),
            known_instances: Arc::new(RwLock::new(HashMap::new())),
            resource_ttl,
            udp_socket: Arc::new(create_udp_socket(enable_loopback).unwrap()),
            enable_loopback,
        };

        service_discovery.wait_replies();
        service_discovery.probe_instances();
        service_discovery.verify_instances_ttl();


        service_discovery
    }

    /// Add the given socket address to discovery. An advertise will be broadcasted just after adding the address.
    pub fn add_address_to_discovery(&mut self, socket_addr: &SocketAddr) {
        self.resource_manager.write().unwrap().add_service_address(
            self.service_name.clone(),
            socket_addr,
            self.resource_ttl,
        );

        self.advertise_service();
    }

    /// Remove all addresses from service discovery
    pub fn remove_service_from_discovery(&'static mut self) {
        self.resource_manager
            .write()
            .unwrap()
            .remove_all_resource_records(&self.service_name);
    }

    /// Return the addresses of all known services
    pub fn get_known_services<'b>(&self) -> Vec<SocketAddr> {
        let instances = self.known_instances.read().unwrap();
        instances.keys().cloned().collect()
    }

    fn verify_instances_ttl(&self) {
        let known_instances = self.known_instances.clone();
        let service_name = self.service_name.clone();
        let socket = self.udp_socket.clone();

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
                            if let Err(err) = send_question(service_name.clone(), &socket, *MULTICAST_IPV4_SOCKET).await {
                                log::error!("There was an error sending the question packet: {}", err);
                            }
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
                if let Err(err) =  packet.add_answer(srv) {
                    log::error!("There was an error adding the answer to the packet: {}", err);
                }
            }

            for additional_record in
                resource_manager.find_matching_resources(&self.service_name, QTYPE::A, QCLASS::IN)
            {
                if let Err(err) = packet.add_additional_record(additional_record) {
                    log::error!("There was an error adding the additional record to the packet: {}", err);
                }
            }
        }

        if packet.has_answers() && packet.has_additional_records() {
            let socket = self.udp_socket.clone();
            tokio::spawn(async move {
                if let Err(err) = socket.send_to(&packet, *MULTICAST_IPV4_SOCKET).await {
                    log::error!("Error advertising the service: {}", err);
                }
            });
        }
    }
    fn probe_instances(&self) {
        let service_name = self.service_name.clone();
        let socket = self.udp_socket.clone();

        tokio::spawn(async move {
            if let Err(err) = send_question(service_name, &socket, *MULTICAST_IPV4_SOCKET).await {
                log::error!("There was an error sending the question packet: {}", err);
            }
        });
    }

    fn wait_replies(&self) {
        let service_name = self.service_name.clone();
        let known_instances = self.known_instances.clone();
        let resources = self.resource_manager.clone();
        let enable_loopback = self.enable_loopback;

        tokio::spawn(async move {
            let mut recv_buffer = vec![0; 4096];
            let socket = create_udp_socket(enable_loopback).unwrap();
            let service_name = service_name;

            loop {
                let (count, addr) = socket.recv_from(&mut recv_buffer).await.unwrap();
                dbg!(count, &addr);
                if let Ok(header) = PacketHeader::parse(&recv_buffer[..12]) {
                    if header.query {
                        let packet = PacketBuf::from(&recv_buffer[..count]);
                        let reply = {
                            let resources = resources.read().unwrap();
                            build_reply(packet, &resources)
                        };

                        if let Some((unicast_reply, packet)) = reply {
                            let addr_reply = if unicast_reply { addr } else { *MULTICAST_IPV4_SOCKET };
                            if let Err(err) = socket.send_to(&packet, addr_reply).await {
                                log::error!("There was an error sending the packet: {}", err);
                            }
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
    known_instances: &RwLock<HashMap<SocketAddr, ExpirationTimes>>,
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
        let instance_times = ExpirationTimes::new(ttl as u64);

        known_instances
            .write()
            .unwrap()
            .insert(address, instance_times);
    }
}

async fn send_question<'a>(service_name: Name<'a>, socket: &UdpSocket, addr: SocketAddr) -> Result<(), SimpleMdnsError> {
    let mut packet = PacketBuf::new(PacketHeader::new_query(0, false));
    packet.add_question(&Question::new(service_name, QTYPE::SRV, QCLASS::IN, false))?;

    if packet.has_questions() {
        socket.send_to(&packet, addr).await?;
    }

    Ok(())
}
