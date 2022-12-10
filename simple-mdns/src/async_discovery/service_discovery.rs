use simple_dns::{rdata::RData, Name, Packet, Question, ResourceRecord, CLASS, TYPE};
use tokio::{
    net::UdpSocket,
    select, spawn,
    sync::{
        mpsc::{channel, Receiver, Sender},
        RwLock,
    },
    time::{sleep_until, Instant},
};

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use crate::{
    resource_record_manager::ResourceRecordManager, socket_helper::nonblocking,
    InstanceInformation, NetworkScope, SimpleMdnsError,
};

/// Service Discovery implementation using DNS-SD.
/// This implementation advertise all the registered addresses, query for the same service on the same network and
/// keeps a cache of known service instances
///
/// Notice that this crate does not provide any means of finding your own ip address. There are crates that provide this kind of feature.
///
/// ## Example
/// ```no_run
/// use simple_mdns::async_discovery::ServiceDiscovery;
/// use std::net::SocketAddr;
/// use std::str::FromStr;
///
/// let mut discovery = ServiceDiscovery::new("a", "_mysrv._tcp.local", 60).expect("Invalid Service Name");
/// discovery.add_service_info(SocketAddr::from_str("192.168.1.22:8090").unwrap().into());
///
/// ```
pub struct ServiceDiscovery {
    resource_manager: Arc<RwLock<ResourceRecordManager<'static>>>,
    full_name: Name<'static>,
    service_name: Name<'static>,
    resource_ttl: u32,

    advertise_tx: Sender<bool>,
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

        let resource_manager = Arc::new(RwLock::new(resource_manager));
        let service_discovery = ServiceDiscoveryExecutor {
            full_name: full_name.clone(),
            service_name: service_name.clone(),
            resource_manager: resource_manager.clone(),
            sender_socket: crate::socket_helper::sender_socket(network_scope.is_v4())
                .and_then(nonblocking)?,
            network_scope,
        };

        let (advertise_tx, advertise_rx) = channel(10);
        spawn(async {
            if let Err(err) = service_discovery.execution_loop(advertise_rx).await {
                log::error!("Service discovery failed {err}");
            }
        });

        Ok(Self {
            resource_manager,
            full_name,
            service_name,
            resource_ttl,
            advertise_tx,
        })
    }

    /// Add the  service info to discovery and immediately advertise the service
    pub async fn add_service_info(
        &mut self,
        service_info: InstanceInformation,
    ) -> Result<(), SimpleMdnsError> {
        {
            let mut resource_manager = self.resource_manager.write().await;
            for resource in service_info.into_records(&self.full_name.clone(), self.resource_ttl)? {
                resource_manager.add_owned_resource(resource);
            }
        }

        self.advertise_service(false).await
    }

    /// Remove all addresses from service discovery
    pub async fn remove_service_from_discovery(&mut self) {
        if (self.advertise_service(true).await).is_err() {
            log::error!("Failed to advertise cache flush");
        };
        self.resource_manager.write().await.clear();
    }

    async fn advertise_service(&mut self, cache_flush: bool) -> Result<(), SimpleMdnsError> {
        self.advertise_tx
            .send(cache_flush)
            .await
            .map_err(|_| SimpleMdnsError::ServiceDiscoveryStopped)
    }

    /// Return the addresses of all known services
    pub async fn get_known_services(&self) -> Vec<InstanceInformation> {
        self.resource_manager
            .read()
            .await
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
}

struct ServiceDiscoveryExecutor {
    full_name: Name<'static>,
    service_name: Name<'static>,
    resource_manager: Arc<RwLock<ResourceRecordManager<'static>>>,
    sender_socket: UdpSocket,
    network_scope: NetworkScope,
}

impl ServiceDiscoveryExecutor {
    async fn execution_loop(self, mut advertise: Receiver<bool>) -> Result<(), SimpleMdnsError> {
        let recv_socket =
            crate::socket_helper::join_multicast(self.network_scope).and_then(nonblocking)?;

        let mut recv_buffer = [0u8; 9000];
        let mut next_expiration = Instant::now() + Duration::from_secs(5);

        self.query_service_instances().await?;

        loop {
            select! {
                packet = recv_socket.recv_from(&mut recv_buffer) => {
                    let (count, addr) = packet?;
                    if let Err(err) = self.process_packet(&recv_buffer[..count], addr).await {
                        log::error!("Failed to process received packet {err}");
                    }
                }
                _ = sleep_until(next_expiration) => {
                    if let Ok(new_expiration) = self.refresh_known_instances().await {
                        next_expiration = new_expiration;
                    }
                }
                cache_flush = advertise.recv() => {
                    match cache_flush {
                        Some(cache_flush) => {
                            if let Err(err) = self.advertise_service(cache_flush).await {
                                log::error!("Failed to advertise service {err}");
                            }
                        }
                        None => {
                            break Ok(())
                        }
                    }
                }
            };
        }
    }

    async fn refresh_known_instances(&self) -> std::io::Result<Instant> {
        log::info!("Refreshing known services");
        let now = Instant::now();
        let next_expiration = self
            .resource_manager
            .read()
            .await
            .get_next_expiration()
            .map(Instant::from_std);

        log::trace!("next expiration: {:?}", next_expiration);
        if let Some(expiration) = next_expiration {
            if expiration <= now {
                if let Err(err) = self.query_service_instances().await {
                    log::error!("There was an error querying service instances. {err}");
                }
            } else {
                return Ok(expiration);
            }
        }

        Ok(now + Duration::from_secs(5))
    }

    async fn process_packet(
        &self,
        buf: &[u8],
        origin_addr: SocketAddr,
    ) -> Result<(), SimpleMdnsError> {
        let packet = Packet::parse(buf)?;
        if packet.has_flags(simple_dns::PacketFlag::RESPONSE) {
            add_response_to_resources(
                packet,
                &self.service_name,
                &self.full_name,
                &mut *self.resource_manager.write().await,
            );
        } else {
            match crate::build_reply(packet, &*self.resource_manager.read().await) {
                Some((reply_packet, unicast_response)) => {
                    let reply = reply_packet.build_bytes_vec_compressed()?;

                    let reply_addr = if unicast_response {
                        origin_addr
                    } else {
                        self.network_scope.socket_address()
                    };

                    self.sender_socket.send_to(&reply, &reply_addr).await?;
                }
                None => {
                    log::debug!("No reply to send");
                }
            }
        }

        Ok(())
    }

    async fn advertise_service(&self, cache_flush: bool) -> Result<(), SimpleMdnsError> {
        log::info!("Advertising service");
        let mut packet = Packet::new_reply(1);
        let resource_manager = self.resource_manager.read().await;
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

        if packet.answers.is_empty() {
            log::info!("Failed to advertise service");
            return Ok(());
        }

        let bytes = packet.build_bytes_vec_compressed()?;
        self.sender_socket
            .send_to(&bytes, &self.network_scope.socket_address())
            .await?;

        Ok(())
    }

    async fn query_service_instances(&self) -> Result<(), SimpleMdnsError> {
        log::trace!("probing service instances");
        let mut packet = Packet::new_query(0);
        packet.questions.push(Question::new(
            self.service_name.clone(),
            TYPE::SRV.into(),
            CLASS::IN.into(),
            false,
        ));
        packet.questions.push(Question::new(
            self.service_name.clone(),
            TYPE::TXT.into(),
            CLASS::IN.into(),
            false,
        ));

        self.sender_socket
            .send_to(
                &packet.build_bytes_vec_compressed()?,
                &self.network_scope.socket_address(),
            )
            .await?;

        Ok(())
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
