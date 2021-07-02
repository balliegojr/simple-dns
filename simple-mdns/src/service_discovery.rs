use simple_dns::{
    rdata::RData, Name, Packet, PacketBuf, PacketHeader, Question, OPCODE, QCLASS, QTYPE,
};
use socket2::{SockAddr, Socket};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use crate::{
    conversion_utils::{
        ip_addr_to_resource_record, port_to_srv_record, socket_addr_to_srv_and_address,
    },
    join_multicast,
    resource_record_manager::ResourceRecordManager,
    sender_socket,
    simple_responder::build_reply,
    SimpleMdnsError,
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
///
/// let mut discovery = ServiceDiscovery::new("_mysrv._tcp.local", 60).expect("Invalid Service Name");
/// let my_socket_addr = "192.168.1.22:8090".parse().unwrap();
/// discovery.add_socket_address(my_socket_addr);
///
/// ```
pub struct ServiceDiscovery {
    service_name: Name<'static>,
    resource_manager: Arc<RwLock<ResourceRecordManager<'static>>>,
    known_instances: Arc<RwLock<HashMap<SocketAddr, ExpirationTimes>>>,
    resource_ttl: u32,
    sender_socket: Socket,
}

impl ServiceDiscovery {
    /// Creates a new ServiceDiscovery by providing `service_name`, `resource ttl` and loopback activation.
    ///
    /// `service_name` must be in the standard specified by the mdns RFC, example: **_my_service._tcp.local**
    /// `resource_ttl` refers to the amount of time in seconds your service will be cached in the dns responder.
    /// set `enable_loopback` to true if you may have more than one instance of your service running in the same machine
    pub fn new(service_name: &'static str, resource_ttl: u32) -> Result<Self, SimpleMdnsError> {
        let service_discovery = Self {
            service_name: Name::new(service_name)?,
            resource_manager: Arc::new(RwLock::new(ResourceRecordManager::new())),
            known_instances: Arc::new(RwLock::new(HashMap::new())),
            resource_ttl,
            sender_socket: sender_socket(&super::MULTICAST_IPV4_SOCKET)?,
        };

        service_discovery.wait_replies();
        service_discovery.probe_instances();
        service_discovery.refresh_known_instances();

        Ok(service_discovery)
    }

    /// Add the given ip address to discovery as A or AAAA record, advertise will happen as soon as there is at least one ip and port registered
    pub fn add_ip_address(&mut self, ip_addr: IpAddr) {
        let addr = ip_addr_to_resource_record(&self.service_name, ip_addr, self.resource_ttl);
        log::info!("added {:?} to discovery", addr);
        self.resource_manager.write().unwrap().add_resource(addr);

        self.advertise_service();
    }

    /// Add the given port to discovery as SRV record, advertise will happen as soon as there is at least one ip and port registered
    pub fn add_port(&mut self, port: u16) {
        let srv = port_to_srv_record(&self.service_name, port, self.resource_ttl);
        log::info!("added {:?} to discovery", srv);
        self.resource_manager.write().unwrap().add_resource(srv);

        self.advertise_service();
    }

    /// Add the given socket address to discovery as SRV and A or AAAA records, there will be an advertise just after adding the address
    pub fn add_socket_address(&mut self, socket_addr: SocketAddr) {
        let (r1, r2) = socket_addr_to_srv_and_address(
            &self.service_name.clone(),
            socket_addr,
            self.resource_ttl,
        );
        {
            let mut resource_manager = self.resource_manager.write().unwrap();
            log::info!("added {:?} to discovery", r1);
            log::info!("added {:?} to discovery", r2);

            resource_manager.add_resource(r1);
            resource_manager.add_resource(r2);
        }

        self.advertise_service();
    }

    /// Remove all addresses from service discovery
    pub fn remove_service_from_discovery(&mut self) {
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
        let socket = sender_socket(&super::MULTICAST_IPV4_SOCKET).unwrap();

        std::thread::spawn(move || {
            let service_name = service_name;
            loop {
                let now = Instant::now();
                log::info!("Refreshing known services");
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

                log::debug!("next expiration: {:?}", next_expiration);
                match next_expiration {
                    Some(expiration) => {
                        if expiration.refresh_at < now {
                            let mut packet = PacketBuf::new(PacketHeader::new_query(0, false));
                            packet
                                .add_question(&Question::new(
                                    service_name.clone(),
                                    QTYPE::SRV,
                                    QCLASS::IN,
                                    false,
                                ))
                                .unwrap();

                            if let Err(err) = socket
                                .send_to(&packet, &SockAddr::from(*super::MULTICAST_IPV4_SOCKET))
                            {
                                log::error!(
                                    "There was an error sending the question packet: {}",
                                    err
                                );
                            }
                        } else {
                            std::thread::sleep(Instant::now() - expiration.refresh_at);
                        }
                    }
                    None => {
                        std::thread::sleep(Duration::from_secs(5));
                    }
                }
            }
        });
    }

    fn advertise_service(&self) {
        log::info!("Advertising service");
        let mut packet = PacketBuf::new(PacketHeader::new_reply(0, OPCODE::StandardQuery));
        {
            let resource_manager = self.resource_manager.read().unwrap();

            for srv in resource_manager.find_matching_resources(|r| {
                r.match_qtype(QTYPE::SRV) && r.match_qclass(QCLASS::IN)
            }) {
                log::debug!("adding srv to packet: {:?}", srv);
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
                log::debug!("adding address to packet: {:?}", additional_record);
                if let Err(err) = packet.add_additional_record(additional_record) {
                    log::error!(
                        "There was an error adding the additional record to the packet: {}",
                        err
                    );
                }
            }
        }

        if packet.has_answers() && packet.has_additional_records() {
            log::debug!("sending advertising packet");
            if let Err(err) = self
                .sender_socket
                .send_to(&packet, &SockAddr::from(*super::MULTICAST_IPV4_SOCKET))
            {
                log::error!("Error advertising the service: {}", err);
            }
        } else {
            log::debug!("packet don't have enough answers or additional records for advertising");
        }
    }

    fn probe_instances(&self) {
        let service_name = self.service_name.clone();

        log::info!("probing service instances");
        let mut packet = PacketBuf::new(PacketHeader::new_query(0, false));
        packet
            .add_question(&Question::new(service_name, QTYPE::SRV, QCLASS::IN, false))
            .unwrap();

        if let Err(err) = self
            .sender_socket
            .send_to(&packet, &SockAddr::from(*super::MULTICAST_IPV4_SOCKET))
        {
            log::error!("There was an error sending the question packet: {}", err);
        }
    }

    fn wait_replies(&self) {
        let service_name = self.service_name.clone();
        let known_instances = self.known_instances.clone();
        let resources = self.resource_manager.clone();

        let receiver_socket = match join_multicast(&super::MULTICAST_IPV4_SOCKET) {
            Ok(socket) => {
                if let Err(_) = socket.set_read_timeout(None) {
                    log::error!("Can't set socket timeout, will poll for packets");
                }

                socket
            }
            Err(err) => {
                log::error!("{}", err);
                return;
            }
        };
        std::thread::spawn(move || {
            let mut recv_buffer = vec![0; 4096];

            let service_name = service_name;

            loop {
                match receiver_socket.recv_from(&mut recv_buffer) {
                    Ok((count, addr)) => match PacketHeader::parse(&recv_buffer[..12]) {
                        Ok(header) => {
                            if header.query {
                                let packet = PacketBuf::from(&recv_buffer[..count]);
                                let reply = match resources.read() {
                                    Ok(resources) => build_reply(packet, &resources),
                                    Err(_) => break,
                                };

                                if let Some((unicast_reply, packet)) = reply {
                                    log::debug!("sending reply for received query");
                                    let reply_addr = if unicast_reply {
                                        addr
                                    } else {
                                        SockAddr::from(*super::MULTICAST_IPV4_SOCKET)
                                    };

                                    if let Err(err) = receiver_socket.send_to(&packet, &reply_addr)
                                    {
                                        log::error!(
                                            "There was an error sending the packet {}",
                                            err
                                        );
                                    }
                                }
                            } else {
                                match resources.read() {
                                    Ok(resources) => add_response_to_known_instances(
                                        &recv_buffer[..count],
                                        &service_name,
                                        &known_instances,
                                        &resources,
                                    ),
                                    Err(_) => break,
                                }
                            }
                        }
                        Err(_) => {
                            log::error!("Received invalid package");
                        }
                    },
                    Err(_) => break,
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
        log::debug!("received packet");
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

            log::debug!("received srv: {:?}", srv);
            let addresses = packet
                .additional_records
                .iter()
                .chain(packet.answers.iter())
                .filter(|ar| ar.name == *target && ar.match_qtype(QTYPE::A));

            for addr in addresses {
                let ip_addr = match &addr.rdata {
                    RData::A(addr) => IpAddr::V4(Ipv4Addr::from(addr.address)),
                    RData::AAAA(addr) => IpAddr::V6(Ipv6Addr::from(addr.address)),
                    _ => continue,
                };

                if !owned_resources.has_resource(addr) || !owned_resources.has_resource(srv) {
                    log::info!("adding known address: {:?}:{:?}", ip_addr, port);
                    known_instances.insert(
                        SocketAddr::new(ip_addr, port),
                        ExpirationTimes::new(addr.ttl as u64),
                    );
                }
            }
        }
    }
}
