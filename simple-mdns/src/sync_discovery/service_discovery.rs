use simple_dns::{rdata::RData, Name, Packet, Question, ResourceRecord, CLASS, TYPE};

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use crate::{
    resource_record_manager::ResourceRecordManager, InstanceInformation, NetworkScope,
    SimpleMdnsError,
};

/// Service Discovery implementation using DNS-SD.
/// This implementation advertise all the registered addresses, query for the same service on the same network and
/// keeps a cache of known service instances
///
/// Notice that this crate does not provide any means of finding your own ip address. There are crates that provide this kind of feature.
///
/// ## Example
/// ```
/// use simple_mdns::sync_discovery::ServiceDiscovery;
/// use std::net::SocketAddr;
/// use std::str::FromStr;
///
/// let mut discovery = ServiceDiscovery::new("a", "_mysrv._tcp.local", 60).expect("Invalid Service Name");
/// discovery.add_service_info(SocketAddr::from_str("192.168.1.22:8090").unwrap().into());
///
/// ```
pub struct ServiceDiscovery {
    full_name: Name<'static>,
    service_name: Name<'static>,
    resource_manager: Arc<RwLock<ResourceRecordManager<'static>>>,
    resource_ttl: u32,
    sender_socket: UdpSocket,
    network_scope: NetworkScope,
}

impl ServiceDiscovery {
    /// Creates a new ServiceDiscovery by providing `instance`, `service_name`, `resource ttl`. The service will be created using IPV4 scope with UNSPECIFIED Interface
    ///
    /// `instance_name` and `service_name` will be composed together in order to advertise this instance, like `instance_name`.`service_name`
    ///
    /// `instance_name` must be in the standard specified by the mdns RFC and short, example: **_my_inst**
    /// `service_name` must be in the standard specified by the mdns RFC, example: **_my_service._tcp.local**
    /// `resource_ttl` refers to the amount of time in seconds your service will be cached in the dns responder.
    pub fn new(
        instance_name: &str,
        service_name: &str,
        resource_ttl: u32,
    ) -> Result<Self, SimpleMdnsError> {
        Self::new_with_scope(instance_name, service_name, resource_ttl, NetworkScope::V4)
    }

    /// Creates a new ServiceDiscovery by providing `instance`, `service_name`, `resource ttl` and loopback activation.
    /// `instance_name` and `service_name` will be composed together in order to advertise this instance, like `instance_name`.`service_name`
    ///
    /// `instance_name` must be in the standard specified by the mdns RFC and short, example: **_my_inst**
    /// `service_name` must be in the standard specified by the mdns RFC, example: **_my_service._tcp.local**
    /// `resource_ttl` refers to the amount of time in seconds your service will be cached in the dns responder.
    /// set `enable_loopback` to true if you may have more than one instance of your service running in the same machine
    pub fn new_with_scope(
        instance_name: &str,
        service_name: &str,
        resource_ttl: u32,
        network_scope: NetworkScope,
    ) -> Result<Self, SimpleMdnsError> {
        let full_name = format!("{}.{}", instance_name, service_name);
        let full_name = Name::new(&full_name)?.into_owned();
        let service_name = Name::new(service_name)?.into_owned();

        let mut resource_manager = ResourceRecordManager::new();
        resource_manager.add_owned_resource(ResourceRecord::new(
            service_name.clone(),
            simple_dns::CLASS::IN,
            0,
            RData::PTR(service_name.clone().into()),
        ));

        let service_discovery = Self {
            full_name,
            service_name,
            resource_manager: Arc::new(RwLock::new(resource_manager)),
            resource_ttl,
            sender_socket: crate::socket_helper::sender_socket(network_scope.is_v4())?,
            network_scope,
        };

        service_discovery.receive_packets_loop()?;
        service_discovery.refresh_known_instances()?;

        if let Err(err) = query_service_instances(
            service_discovery.service_name.clone(),
            &service_discovery.sender_socket,
            &service_discovery.network_scope.socket_address(),
        ) {
            log::error!("There was an error queruing service instances: {err}");
        }

        Ok(service_discovery)
    }

    /// Add the  service info to discovery and immediately advertise the service
    pub fn add_service_info(
        &mut self,
        service_info: InstanceInformation,
    ) -> Result<(), Box<dyn Error>> {
        {
            let mut resource_manager = self.resource_manager.write().unwrap();
            for resource in service_info.into_records(&self.full_name.clone(), self.resource_ttl)? {
                resource_manager.add_owned_resource(resource);
            }
        }

        self.advertise_service(false);
        Ok(())
    }

    /// Remove all addresses from service discovery
    pub fn remove_service_from_discovery(&mut self) {
        self.advertise_service(true);
        self.resource_manager.write().unwrap().clear();
    }

    /// Return the addresses of all known services
    pub fn get_known_services(&self) -> Vec<InstanceInformation> {
        self.resource_manager
            .read()
            .unwrap()
            .get_domain_resources(&self.service_name, true, false)
            .map(|domain_resources| {
                let mut ip_addresses: Vec<IpAddr> = Vec::new();
                let mut ports = Vec::new();
                let mut attributes = HashMap::new();

                for resource in domain_resources {
                    match &resource.rdata {
                        simple_dns::rdata::RData::A(a) => {
                            ip_addresses.push(Ipv4Addr::from(a.address).into())
                        }
                        simple_dns::rdata::RData::AAAA(aaaa) => {
                            ip_addresses.push(Ipv6Addr::from(aaaa.address).into())
                        }
                        simple_dns::rdata::RData::TXT(txt) => attributes.extend(txt.attributes()),
                        simple_dns::rdata::RData::SRV(srv) => ports.push(srv.port),
                        _ => {}
                    }
                }

                InstanceInformation {
                    ip_addresses,
                    ports,
                    attributes,
                }
            })
            .collect()
    }

    fn refresh_known_instances(&self) -> std::io::Result<()> {
        let service_name = self.service_name.clone();
        let resource_manager = self.resource_manager.clone();

        let sender = self.sender_socket.try_clone()?;
        let address = self.network_scope.socket_address();

        std::thread::spawn(move || {
            let service_name = service_name;
            loop {
                log::info!("Refreshing known services");
                let now = Instant::now();
                let next_expiration = resource_manager.read().unwrap().get_next_expiration();

                log::trace!("next expiration: {:?}", next_expiration);
                match next_expiration {
                    Some(expiration) => {
                        if expiration <= now {
                            if let Err(err) =
                                query_service_instances(service_name.clone(), &sender, &address)
                            {
                                log::error!("There was an error querying service instances. {err}");
                            }
                            std::thread::sleep(Duration::from_secs(5));
                        } else {
                            std::thread::sleep(expiration - now);
                        }
                    }
                    None => {
                        std::thread::sleep(Duration::from_secs(5));
                    }
                }
            }
        });

        Ok(())
    }

    fn advertise_service(&self, cache_flush: bool) {
        log::info!("Advertising service");
        let mut packet = Packet::new_reply(1);
        let resource_manager = self.resource_manager.read().unwrap();
        let mut additional_records = HashSet::new();

        for d_resources in
            resource_manager.get_domain_resources(&self.full_name.clone(), true, true)
        {
            if cache_flush {
                d_resources
                    .filter(|r| r.match_qclass(CLASS::IN.into()))
                    .for_each(|r| packet.answers.push(r.to_cache_flush_record()));
            } else {
                d_resources
                    .filter(|r| {
                        r.match_qclass(CLASS::IN.into())
                            && (r.match_qtype(TYPE::SRV.into()) || r.match_qtype(TYPE::TXT.into()))
                    })
                    .cloned()
                    .for_each(|resource| {
                        if let RData::SRV(srv) = &resource.rdata {
                            let target = resource_manager
                                .get_domain_resources(&srv.target, false, true)
                                .flatten()
                                .filter(|r| {
                                    r.match_qtype(TYPE::A.into())
                                        && r.match_qclass(CLASS::IN.into())
                                })
                                .cloned();

                            additional_records.extend(target);
                        }

                        packet.answers.push(resource);
                    });
            };
        }

        for additional_record in additional_records {
            packet.additional_records.push(additional_record)
        }

        if !packet.answers.is_empty()
            && packet
                .build_bytes_vec_compressed()
                .map(|bytes| {
                    send_packet(
                        &self.sender_socket,
                        &bytes,
                        &self.network_scope.socket_address(),
                    )
                })
                .is_err()
        {
            log::info!("Failed to advertise service");
        }
    }

    fn receive_packets_loop(&self) -> Result<(), SimpleMdnsError> {
        let service_name = self.service_name.clone();
        let full_name = self.full_name.clone();
        let resources = self.resource_manager.clone();
        let multicast_address = self.network_scope.socket_address();

        let sender_socket = self.sender_socket.try_clone()?;
        let recv_socket = crate::socket_helper::join_multicast(self.network_scope)?;
        recv_socket.set_read_timeout(None)?;

        std::thread::spawn(move || loop {
            let mut recv_buffer = [0u8; 9000];
            let (count, addr) = match recv_socket.recv_from(&mut recv_buffer) {
                Ok(received) => received,
                Err(err) => {
                    log::error!("Failed to read network information {err}");
                    continue;
                }
            };

            match Packet::parse(&recv_buffer[..count]) {
                Ok(packet) => {
                    if packet.has_flags(simple_dns::PacketFlag::RESPONSE) {
                        add_response_to_resources(
                            packet,
                            &service_name,
                            &full_name,
                            &mut resources.write().unwrap(),
                        )
                    } else {
                        match crate::build_reply(packet, &resources.read().unwrap()) {
                            Some((reply_packet, unicast_response)) => {
                                let reply = match reply_packet.build_bytes_vec_compressed() {
                                    Ok(reply) => reply,
                                    Err(err) => {
                                        log::error!("Failed to build reply {err}");
                                        continue;
                                    }
                                };

                                let reply_addr = if unicast_response {
                                    addr
                                } else {
                                    multicast_address
                                };

                                log::debug!("sending reply");
                                send_packet(&sender_socket, &reply, &reply_addr);
                            }
                            None => {
                                log::debug!("No reply to send");
                            }
                        }
                    }
                }
                Err(err) => {
                    log::error!("Received Invalid Packet {err}");
                }
            }
        });

        Ok(())
    }
}

fn query_service_instances(
    service_name: Name,
    socket: &UdpSocket,
    address: &SocketAddr,
) -> Result<(), Box<dyn Error>> {
    log::trace!("probing service instances");
    let mut packet = Packet::new_query(0);
    packet.questions.push(Question::new(
        service_name.clone(),
        TYPE::SRV.into(),
        CLASS::IN.into(),
        false,
    ));
    packet.questions.push(Question::new(
        service_name,
        TYPE::TXT.into(),
        CLASS::IN.into(),
        false,
    ));

    send_packet(socket, &packet.build_bytes_vec_compressed()?, address);

    Ok(())
}

fn send_packet(socket: &UdpSocket, packet_bytes: &[u8], address: &SocketAddr) {
    if let Err(err) = socket.send_to(packet_bytes, address) {
        log::error!("There was an error sending the  packet: {err}");
    }
}

fn add_response_to_resources(
    packet: Packet,
    service_name: &Name<'_>,
    full_name: &Name<'_>,
    owned_resources: &mut ResourceRecordManager,
) {
    let resources = packet
        .answers
        .into_iter()
        .chain(packet.additional_records.into_iter())
        .filter(|aw| {
            aw.name.ne(full_name)
                && aw.name.is_subdomain_of(service_name)
                && (aw.match_qtype(TYPE::SRV.into())
                    || aw.match_qtype(TYPE::TXT.into())
                    || aw.match_qtype(TYPE::A.into())
                    || aw.match_qtype(TYPE::PTR.into()))
        });

    for resource in resources {
        owned_resources.add_expirable_resource(resource.into_owned());
    }
}
