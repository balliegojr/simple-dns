use std::net::SocketAddr;

use crate::{SimpleMdnsError, SimpleMdnsResponder};

pub struct ServiceDiscovery {
    mdns_responder: SimpleMdnsResponder
}

impl ServiceDiscovery {
    pub fn add_service_to_discovery(&mut self, service_name: &'static str, socket_addr: SocketAddr) -> Result<(), SimpleMdnsError>{
        self.mdns_responder.add_service_address(service_name, socket_addr.ip(), socket_addr.port())
    }
    pub fn remove_service_from_discovery(&mut self, service_name: &str) {
        self.mdns_responder.remove_all_resource_records(service_name);

    }
}
