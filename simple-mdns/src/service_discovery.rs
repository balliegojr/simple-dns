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
    conversion_utils::{
        ip_addr_to_resource_record, port_to_srv_record, socket_addr_to_srv_and_address,
    },
    create_udp_socket,
    resource_record_manager::ResourceRecordManager,
    simple_responder::build_reply,
    SimpleMdnsError, MULTICAST_IPV4_SOCKET,
};

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
/// Notice that this crate does not provide any means of finding your own ip address. There are crates that provide this kind of feature.
///
/// ## Example
/// ```
/// use simple_mdns::ServiceDiscovery;
/// use std::net::SocketAddr;
/// # tokio_test::block_on(async {
///
/// let mut discovery = ServiceDiscovery::new("_mysrv._tcp.local", 60, true).expect("Invalid Service Name");
/// let my_socket_addr = "192.168.1.22:8090".parse().unwrap();
/// discovery.add_socket_address(&my_socket_addr);
///
/// # })
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
    /// Creates a new ServiceDiscovery by providing `service_name`, `resource ttl` and loopback activation.
    ///
    /// `service_name` must be in the standard specified by the mdns RFC, example: **_my_service._tcp.local**
    /// `resource_ttl` refers to the amount of time in seconds your service will be cached in the dns responder.
    /// set `enable_loopback` to true if you may have more than one instance of your service running in the same machine
    pub fn new(
        service_name: &'static str,
        resource_ttl: u32,
        enable_loopback: bool,
    ) -> Result<Self, SimpleMdnsError> {
        let service_discovery = Self {
            service_name: Name::new(service_name)?,
            resource_manager: Arc::new(RwLock::new(ResourceRecordManager::new())),
            known_instances: Arc::new(RwLock::new(HashMap::new())),
            resource_ttl,
            udp_socket: Arc::new(create_udp_socket(enable_loopback).unwrap()),
            enable_loopback,
        };

        service_discovery.wait_replies();
        service_discovery.probe_instances();
        service_discovery.refresh_known_instances();

        Ok(service_discovery)
    }

    /// Add the given ip address to discovery as A or AAAA record, advertise will happen as soon as there is at least one ip and port registered
    pub fn add_ip_address(&'static mut self, ip_addr: &IpAddr) {
        let addr = ip_addr_to_resource_record(&self.service_name, ip_addr, self.resource_ttl);
        self.resource_manager.write().unwrap().add_resource(addr);

        self.advertise_service();
    }

    /// Add the given port to discovery as SRV record, advertise will happen as soon as there is at least one ip and port registered
    pub fn add_port(&'static mut self, port: u16) {
        let srv = port_to_srv_record(&self.service_name, port, self.resource_ttl);
        self.resource_manager.write().unwrap().add_resource(srv);

        self.advertise_service();
    }

    /// Add the given socket address to discovery as SRV and A or AAAA records, there will be an advertise just after adding the address
    pub fn add_socket_address(&mut self, socket_addr: &SocketAddr) {
        let (r1, r2) = socket_addr_to_srv_and_address(
            &self.service_name.clone(),
            socket_addr,
            self.resource_ttl,
        );
        {
            let mut resource_manager = self.resource_manager.write().unwrap();
            resource_manager.add_resource(r1);
            resource_manager.add_resource(r2);
        }

        self.advertise_service();
    }

    /// Remove all addresses from service discovery
    pub fn remove_service_from_discovery(&'static mut self) {
        self.resource_manager.write().unwrap().clear();
    }

    /// Return the addresses of all known services
    pub fn get_known_services(&self) -> Vec<SocketAddr> {
        let instances = self.known_instances.read().unwrap();
        instances.keys().cloned().collect()
    }

    fn refresh_known_instances(&self) {
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
                            if let Err(err) =
                                send_question(service_name.clone(), &socket, *MULTICAST_IPV4_SOCKET)
                                    .await
                            {
                                log::error!(
                                    "There was an error sending the question packet: {}",
                                    err
                                );
                            }
                        } else {
                            tokio::time::sleep_until(expiration.refresh_at.into()).await;
                        }
                    }
                    None => {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });
    }

    fn advertise_service(&self) {
        let mut packet = PacketBuf::new(PacketHeader::new_reply(0, OPCODE::StandardQuery));
        {
            let resource_manager = self.resource_manager.read().unwrap();

            for srv in resource_manager.find_matching_resources(|r| {
                r.match_qtype(QTYPE::SRV) && r.match_qclass(QCLASS::IN)
            }) {
                if let Err(err) = packet.add_answer(srv) {
                    log::error!(
                        "There was an error adding the answer to the packet: {}",
                        err
                    );
                }
            }

            for additional_record in resource_manager
                .find_matching_resources(|r| r.match_qtype(QTYPE::A) && r.match_qclass(QCLASS::IN))
            {
                if let Err(err) = packet.add_additional_record(additional_record) {
                    log::error!(
                        "There was an error adding the additional record to the packet: {}",
                        err
                    );
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
                if let Ok(header) = PacketHeader::parse(&recv_buffer[..12]) {
                    if header.query {
                        let packet = PacketBuf::from(&recv_buffer[..count]);
                        let reply = {
                            let resources = resources.read().unwrap();
                            build_reply(packet, &resources)
                        };

                        if let Some((unicast_reply, packet)) = reply {
                            let addr_reply = if unicast_reply {
                                addr
                            } else {
                                *MULTICAST_IPV4_SOCKET
                            };
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

fn add_response_to_known_instances(
    recv_buffer: &[u8],
    service_name: &Name<'_>,
    known_instances: &RwLock<HashMap<SocketAddr, ExpirationTimes>>,
    owned_resources: &ResourceRecordManager,
) {
    if let Ok(packet) = Packet::parse(&recv_buffer) {
        let mut known_instances = known_instances.write().unwrap();
        let srvs = packet
            .answers
            .iter()
            .filter(|aw| aw.name == *service_name && aw.match_qtype(QTYPE::SRV));

        for srv in srvs {
            let (target, port) = match &srv.rdata {
                RData::SRV(rdata) => (&rdata.target, rdata.port),
                _ => continue,
            };

            let addresses = packet
                .additional_records
                .iter()
                .chain(packet.answers.iter())
                .filter(|ar| {
                    ar.name == *target
                        && ar.match_qtype(QTYPE::A)
                        && !owned_resources.has_resource(ar)
                });

            for addr in addresses {
                let ip_addr = match &addr.rdata {
                    RData::A(addr) => IpAddr::V4(Ipv4Addr::from(addr.address)),
                    RData::AAAA(addr) => IpAddr::V6(Ipv6Addr::from(addr.address)),
                    _ => continue,
                };

                known_instances.insert(
                    SocketAddr::new(ip_addr, port),
                    ExpirationTimes::new(addr.ttl as u64),
                );
            }
        }
    }
}

async fn send_question(
    service_name: Name<'_>,
    socket: &UdpSocket,
    addr: SocketAddr,
) -> Result<(), SimpleMdnsError> {
    let mut packet = PacketBuf::new(PacketHeader::new_query(0, false));
    packet.add_question(&Question::new(service_name, QTYPE::SRV, QCLASS::IN, false))?;
    socket.send_to(&packet, addr).await?;

    Ok(())
}
