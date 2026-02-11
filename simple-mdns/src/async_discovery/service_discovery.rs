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

use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};

use crate::{
    resource_record_manager::{DomainResourceFilter, ResourceRecordManager},
    socket_helper::nonblocking,
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
    resource_manager: Arc<RwLock<ResourceRecordManager<'static>>>,
    service_name: Name<'static>,

    advertise_tx: Sender<(bool, Option<tokio::sync::oneshot::Sender<()>>)>,
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
        on_discovery: Option<tokio::sync::mpsc::Sender<InstanceInformation>>,
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

        let resource_manager = Arc::new(RwLock::new(resource_manager));
        let service_discovery = ServiceDiscoveryExecutor {
            instance_name: instance_full_name,
            service_name: service_name.clone(),
            resource_manager: resource_manager.clone(),
            sender_socket: crate::socket_helper::sender_socket(network_scope.is_v4())
                .and_then(nonblocking)?,
            network_scope,
        };

        let (advertise_tx, advertise_rx) = channel(10);
        spawn(async {
            if let Err(err) = service_discovery
                .execution_loop(advertise_rx, on_discovery)
                .await
            {
                log::error!("Service discovery failed {err}");
            }
        });

        let announce = advertise_tx.clone();
        spawn(async move {
            let _ = announce.send((false, None)).await;
            tokio::time::sleep(Duration::from_secs(1)).await;
            let _ = announce.send((false, None)).await;
        });

        Ok(Self {
            resource_manager,
            service_name,
            advertise_tx,
        })
    }

    /// Remove service from discovery by announcing with a cache flush and
    /// removing all the internal resource records
    pub async fn remove_service_from_discovery(&mut self) {
        if (self.announce(true).await).is_err() {
            log::error!("Failed to advertise cache flush");
        };
    }

    /// Announce the service by sending a packet with all the resource records in the answers
    /// section. It is not necessary to call this method manually, it will be called automatically
    /// when the instance is added to the discovery.
    ///
    /// if `cache_flush` is true, then the resources will have the cache flush flag set, this will
    /// cause them to be removed from any cache that receives the packet.
    pub async fn announce(&mut self, cache_flush: bool) -> Result<(), SimpleMdnsError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.advertise_tx
            .send((cache_flush, Some(tx)))
            .await
            .map_err(|_| SimpleMdnsError::ServiceDiscoveryStopped)?;

        rx.await
            .map_err(|_| SimpleMdnsError::ServiceDiscoveryStopped)
    }

    /// Return the [`InstanceInformation`] of all known services
    pub async fn get_known_services(&self) -> HashSet<InstanceInformation> {
        self.resource_manager
            .read()
            .await
            .get_domain_resources(&self.service_name, DomainResourceFilter::cached())
            .filter_map(|domain_resources| {
                InstanceInformation::from_records(&self.service_name, domain_resources)
            })
            .collect()
    }
}

struct ServiceDiscoveryExecutor {
    instance_name: Name<'static>,
    service_name: Name<'static>,
    resource_manager: Arc<RwLock<ResourceRecordManager<'static>>>,
    sender_socket: UdpSocket,
    network_scope: NetworkScope,
}

impl ServiceDiscoveryExecutor {
    async fn execution_loop(
        self,
        mut advertise: Receiver<(bool, Option<tokio::sync::oneshot::Sender<()>>)>,
        mut on_discovery: Option<tokio::sync::mpsc::Sender<InstanceInformation>>,
    ) -> Result<(), SimpleMdnsError> {
        let recv_socket =
            crate::socket_helper::join_multicast(self.network_scope).and_then(nonblocking)?;

        let mut recv_buffer = [0u8; 9000];
        let mut next_expiration = Instant::now() + Duration::from_secs(5);

        self.query_service_instances().await?;

        loop {
            select! {
                packet = recv_socket.recv_from(&mut recv_buffer) => {
                    let (count, addr) = packet?;
                    if let Err(err) = self.process_packet(&recv_buffer[..count], addr, &mut on_discovery).await {
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
                        Some((cache_flush, notify)) => {
                            match self.advertise_service(cache_flush).await {
                                Err(err) => log::error!("Failed to advertise service {err}"),
                                Ok(()) => {
                                    if cache_flush {
                                        self.resource_manager.write().await.remove_domain_resources(&self.instance_name);
                                    }
                                    if let Some(notify) = notify {
                                        let _ = notify.send(());
                                    }
                                }
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
            .get_next_refresh()
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
        on_discovery: &mut Option<tokio::sync::mpsc::Sender<InstanceInformation>>,
    ) -> Result<(), SimpleMdnsError> {
        let packet = Packet::parse(buf)?;
        if packet.has_flags(simple_dns::PacketFlag::RESPONSE) {
            add_response_to_resources(
                packet,
                &self.service_name,
                &self.instance_name,
                &mut *self.resource_manager.write().await,
                on_discovery,
            )
            .await;
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

        // FIXME: include only the resources with appropriate network scope
        for d_resources in resource_manager.get_domain_resources(
            &self.service_name,
            DomainResourceFilter::authoritative(true),
        ) {
            if cache_flush {
                log::info!("advertising cache flush");
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

        if packet.answers.is_empty() {
            log::info!("Failed to advertise service, no answers to send");
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

async fn add_response_to_resources(
    packet: Packet<'_>,
    service_name: &Name<'_>,
    full_name: &Name<'_>,
    owned_resources: &mut ResourceRecordManager<'static>,
    on_discovery: &mut Option<tokio::sync::mpsc::Sender<InstanceInformation>>,
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

        let mut instance_name: Option<String> = Default::default();
        let instance_information = InstanceInformation::from_records(
            service_name,
            resources.iter().inspect(|record| {
                if instance_name.is_none() {
                    instance_name = record
                        .name
                        .without(service_name)
                        .map(|sub_domain| sub_domain.to_string());
                }
            }),
        );

        if let Some(instance_information) = instance_information {
            if channel.send(instance_information).await.is_err() {
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
