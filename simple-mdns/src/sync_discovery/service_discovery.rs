use simple_dns::{rdata::RData, Name, Packet, Question, ResourceRecord, CLASS, TYPE};

use std::{
    collections::HashSet,
    error::Error,
    net::{SocketAddr, UdpSocket},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use crate::{
    resource_record_manager::{DomainResourceFilter, ResourceRecordManager},
    InstanceInformation, NetworkScope, SimpleMdnsError,
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
/// use simple_mdns::InstanceInformation;
/// use std::str::FromStr;
///
/// let mut discovery = ServiceDiscovery::new(
///     InstanceInformation::new("a".into()).with_socket_address("192.168.1.22:8090".parse().expect("Invalid Socket Address")),
///     "_mysrv._tcp.local",
///     60
/// ).expect("Failed to create service discovery");
///
/// ```
pub struct ServiceDiscovery {
    instance_name: Name<'static>,
    service_name: Name<'static>,
    resource_manager: Arc<RwLock<ResourceRecordManager<'static>>>,
    sender_socket: UdpSocket,
    network_scope: NetworkScope,
}

impl ServiceDiscovery {
    /// Creates a new ServiceDiscovery by providing `instance_information`, `service_name`, `resource ttl`. The service will be created using IPV4 scope with UNSPECIFIED Interface
    ///
    /// `service_name` must be in the standard specified by the mdns RFC, example: **_my_service._tcp.local**
    /// `resource_ttl` refers to the amount of time in seconds your service will be cached in the dns responder.
    pub fn new(
        instance_information: InstanceInformation,
        service_name: &str,
        resource_ttl: u32,
    ) -> Result<Self, SimpleMdnsError> {
        Self::new_with_scope(
            instance_information,
            service_name,
            resource_ttl,
            None,
            NetworkScope::V4,
        )
    }

    /// Creates a new ServiceDiscovery by providing `instance_information`, `service_name`, `resource ttl`, `on_disovery` and `network_scope`
    ///
    /// `service_name` must be in the standard specified by the mdns RFC, example: **_my_service._tcp.local**
    /// `resource_ttl` refers to the amount of time in seconds your service will be cached in the dns responder.
    /// `on_discovery` channel, if provided, will receive every instance information when
    /// discovered
    /// `network_scope` to be used
    pub fn new_with_scope(
        instance_information: InstanceInformation,
        service_name: &str,
        resource_ttl: u32,
        on_discovery: Option<std::sync::mpsc::Sender<InstanceInformation>>,
        network_scope: NetworkScope,
    ) -> Result<Self, SimpleMdnsError> {
        let instance_full_name = format!(
            "{}.{service_name}",
            instance_information.escaped_instance_name()
        );
        let instance_full_name = Name::new(&instance_full_name)?.into_owned();
        let service_name = Name::new(service_name)?.into_owned();

        let mut resource_manager = ResourceRecordManager::new();
        resource_manager.add_authoritative_resource(ResourceRecord::new(
            service_name.clone(),
            simple_dns::CLASS::IN,
            resource_ttl,
            RData::PTR(instance_full_name.clone().into()),
        ));

        for resource in instance_information.into_records(&instance_full_name, resource_ttl)? {
            resource_manager.add_authoritative_resource(resource);
        }

        let service_discovery = Self {
            instance_name: instance_full_name,
            service_name,
            resource_manager: Arc::new(RwLock::new(resource_manager)),
            sender_socket: crate::socket_helper::sender_socket(network_scope.is_v4())?,
            network_scope,
        };

        service_discovery.receive_packets_loop(on_discovery)?;
        service_discovery.refresh_known_instances()?;
        service_discovery.announce(false);

        if let Err(err) = query_service_instances(
            service_discovery.service_name.clone(),
            &service_discovery.sender_socket,
            &service_discovery.network_scope.socket_address(),
        ) {
            log::error!("There was an error queruing service instances: {err}");
        }

        Ok(service_discovery)
    }

    /// Remove service from discovery by announcing with a cache flush and
    /// removing all the internal resource records
    pub fn remove_service_from_discovery(&mut self) {
        self.announce(true);
        self.resource_manager.write().unwrap().clear();
    }

    /// Return the [`InstanceInformation`] of all known services
    pub fn get_known_services(&self) -> HashSet<InstanceInformation> {
        self.resource_manager
            .read()
            .unwrap()
            .get_domain_resources(&self.service_name, DomainResourceFilter::cached())
            .filter_map(|domain_resources| {
                InstanceInformation::from_records(&self.service_name, domain_resources)
            })
            .collect()
    }

    fn refresh_known_instances(&self) -> std::io::Result<()> {
        let service_name = self.service_name.clone();
        let resource_manager = self.resource_manager.clone();

        let sender = self.sender_socket.try_clone()?;
        let address = self.network_scope.socket_address();

        std::thread::spawn(move || loop {
            log::info!("Refreshing known services");
            let now = Instant::now();
            let next_expiration = resource_manager.read().unwrap().get_next_refresh();

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
        });

        Ok(())
    }

    /// Announce the service by sending a packet with all the resource records in the answers
    /// section. It is not necessary to call this method manually, it will be called automatically
    /// when the instance is added to the discovery.
    ///
    /// if `cache_flush` is true, then the resources will have the cache flush flag set, this will
    /// cause them to be removed from any cache that receives the packet.
    pub fn announce(&self, cache_flush: bool) {
        let mut packet = Packet::new_reply(1);
        let resource_manager = self.resource_manager.read().unwrap();
        let mut additional_records = HashSet::new();

        for d_resources in resource_manager.get_domain_resources(
            &self.instance_name.clone(),
            DomainResourceFilter::authoritative(true),
        ) {
            if cache_flush {
                d_resources
                    .filter(|r| r.match_qclass(CLASS::IN.into()))
                    .for_each(|r| packet.answers.push(r.to_cache_flush_record()));
            } else {
                d_resources.cloned().for_each(|resource| {
                    if let RData::SRV(srv) = &resource.rdata {
                        let target = resource_manager
                            .get_domain_resources(
                                &srv.target,
                                DomainResourceFilter::authoritative(false),
                            )
                            .flatten()
                            .filter(|r| {
                                (r.match_qtype(TYPE::A.into()) || r.match_qtype(TYPE::AAAA.into()))
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

    fn receive_packets_loop(
        &self,
        mut on_discovery: Option<std::sync::mpsc::Sender<InstanceInformation>>,
    ) -> Result<(), SimpleMdnsError> {
        let service_name = self.service_name.clone();
        let full_name = self.instance_name.clone();
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
                            &mut on_discovery,
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
    on_discovery: &mut Option<std::sync::mpsc::Sender<InstanceInformation>>,
) {
    let resources = packet
        .answers
        .into_iter()
        .chain(packet.additional_records)
        .filter(|aw| aw.name.ne(full_name) && aw.name.is_subdomain_of(service_name))
        .map(|r| r.into_owned());

    if let Some(channel) = on_discovery {
        let resources: Vec<_> = resources.collect();
        if resources.is_empty() {
            return;
        }

        if let Some(instance_information) =
            InstanceInformation::from_records(service_name, resources.iter())
        {
            if channel.send(instance_information).is_err() {
                *on_discovery = None
            }
        }

        for resource in resources {
            owned_resources.add_cached_resource(resource);
        }
    } else {
        for resource in resources {
            owned_resources.add_cached_resource(resource);
        }
    }
}
