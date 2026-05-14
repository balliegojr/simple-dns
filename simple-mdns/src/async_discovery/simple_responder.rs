use std::{future::Future, sync::Arc};
use tokio::{select, spawn, sync::RwLock};

use simple_dns::{header_buffer, Packet, PacketFlag, ResourceRecord};

use crate::{
    build_reply,
    resource_record_manager::ResourceRecordManager,
    socket_helper::{join_multicast, nonblocking, sender_socket},
    NetworkScope, SimpleMdnsError,
};

const FIVE_MINUTES: u32 = 60 * 5;

/// A simple mDNS responder aimed for service discovery.
/// In case you don't have a mDNS responder in your network, or for some reason don't want to use the ones available.
///
/// This responder will list for any mDNS query in the network via Multicast and will reply only to the resources that were added.
///
/// ```no_run
///     use simple_mdns::async_discovery::SimpleMdnsResponder;
///     use simple_dns::{Name, CLASS, ResourceRecord, rdata::{RData, A, SRV}};
///     use std::net::Ipv4Addr;
///
///     let mut responder = SimpleMdnsResponder::new(10);
///     let srv_name = Name::new_unchecked("_srvname._tcp.local");
///
///     responder.add_resource(ResourceRecord::new(
///         srv_name.clone(),
///         CLASS::IN,
///         10,
///         RData::A(A { address: Ipv4Addr::LOCALHOST.into() }),
///     ));
///
///     responder.add_resource(ResourceRecord::new(
///         srv_name.clone(),
///         CLASS::IN,
///         10,
///         RData::SRV(SRV {
///             port: 8080,
///             priority: 0,
///             weight: 0,
///             target: srv_name
///         })
///     ));
/// ```
///
/// This struct heavily relies on [`simple_dns`] crate and the same must be added as a dependency
pub struct SimpleMdnsResponder {
    resources: Arc<RwLock<ResourceRecordManager<'static>>>,
    rr_ttl: u32,
}

impl SimpleMdnsResponder {
    /// Creates a new SimpleMdnsResponder with specified ttl and IPV4 scope with UNSPECIFIED
    /// Interface
    pub fn new(rr_ttl: u32) -> Self {
        Self::new_with_scope(rr_ttl, NetworkScope::V4, None::<std::future::Pending<()>>)
    }

    /// Creates a new SimpleMdnsResponder with specified ttl, network scope and optional shutdown
    /// signal.
    pub fn new_with_scope<F: Future + Send + 'static>(
        rr_ttl: u32,
        scope: NetworkScope,
        shutdown: Option<F>,
    ) -> Self {
        let responder = Self {
            resources: Arc::new(RwLock::new(ResourceRecordManager::new())),
            rr_ttl,
        };

        let resources = responder.resources.clone();
        spawn(async move {
            if let Err(err) = Self::responder_loop(resources, scope, shutdown).await {
                log::error!("Dns Responder failed: {}", err);
            }
        });
        responder
    }

    /// Register a Resource Record
    pub async fn add_resource(&mut self, resource: ResourceRecord<'static>) {
        let mut resources = self.resources.write().await;
        resources.add_authoritative_resource(resource);
    }

    /// Remove a resource record
    pub async fn remove_resource_record(&mut self, resource: ResourceRecord<'static>) {
        let mut resources = self.resources.write().await;
        resources.remove_resource_record(&resource);
    }

    /// Remove all resource records
    pub async fn clear(&mut self) {
        let mut resources = self.resources.write().await;
        resources.clear();
    }

    async fn responder_loop<F: Future + Send>(
        resources: Arc<RwLock<ResourceRecordManager<'_>>>,
        scope: NetworkScope,
        shutdown: Option<F>,
    ) -> Result<(), SimpleMdnsError> {
        let mut recv_buffer = [0u8; 9000];
        let sender_socket = sender_socket(scope.is_v4()).and_then(nonblocking)?;

        let recv_socket = join_multicast(scope).and_then(nonblocking)?;

        let mut recv_and_process = async || -> Result<(), SimpleMdnsError> {
            let (count, addr) = recv_socket.recv_from(&mut recv_buffer).await?;
            if header_buffer::has_flags(&recv_buffer[..count], PacketFlag::RESPONSE).unwrap_or(true)
            {
                return Ok(());
            }

            match Packet::parse(&recv_buffer[..count]) {
                Ok(packet) => {
                    if let Some((reply_packet, unicast_response)) =
                        build_reply(packet, &*resources.read().await)
                    {
                        let reply = match reply_packet.build_bytes_vec_compressed() {
                            Ok(reply) => reply,
                            Err(err) => {
                                log::error!("Failed to build reply {err}");
                                return Ok(());
                            }
                        };

                        let reply_addr = if unicast_response {
                            addr
                        } else {
                            scope.socket_address()
                        };

                        sender_socket.send_to(&reply, reply_addr).await?;
                    };
                }
                Err(err) => {
                    log::error!("Received Invalid packet {err}");
                }
            }

            Ok(())
        };

        match shutdown {
            Some(shutdown) => {
                tokio::pin!(shutdown);

                loop {
                    select! {
                        _ = &mut shutdown => {}
                        _ = recv_and_process() => {

                        }
                    }
                }
            }
            None => loop {
                recv_and_process().await?
            },
        }
    }

    /// Set the simple mdns responder's rr default ttl in seconds (defaults to 300).
    pub fn set_rr_ttl(&mut self, rr_default_ttl: u32) {
        self.rr_ttl = rr_default_ttl;
    }
}

impl Default for SimpleMdnsResponder {
    fn default() -> Self {
        Self::new(FIVE_MINUTES)
    }
}
