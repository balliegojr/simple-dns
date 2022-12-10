use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use crate::conversion_utils::{hashmap_to_txt, ip_addr_to_resource_record, port_to_srv_record};
use simple_dns::{Name, ResourceRecord};

/// Represents a single instance of the service.
/// Notice that it is not possible to associate a port to a single ip address, due to limitations of the DNS protocol
#[derive(Debug)]
pub struct InstanceInformation {
    /// Ips for this instance
    pub ip_addresses: Vec<IpAddr>,
    /// Ports for this instance
    pub ports: Vec<u16>,
    /// Attributes for this instance
    pub attributes: HashMap<String, Option<String>>,
}

impl Default for InstanceInformation {
    fn default() -> Self {
        Self::new()
    }
}

impl InstanceInformation {
    /// Creates an empty InstanceInformation
    pub fn new() -> Self {
        Self {
            ip_addresses: Vec::new(),
            ports: Vec::new(),
            attributes: HashMap::new(),
        }
    }

    /// Transform into a [Vec<ResourceRecord>](`Vec<ResourceRecord>`)
    pub fn into_records<'a>(
        self,
        service_name: &Name<'a>,
        ttl: u32,
    ) -> Result<Vec<ResourceRecord<'a>>, crate::SimpleMdnsError> {
        let mut records = Vec::new();

        for ip_address in self.ip_addresses {
            records.push(ip_addr_to_resource_record(service_name, ip_address, ttl));
        }

        for port in self.ports {
            records.push(port_to_srv_record(service_name, port, ttl));
        }

        records.push(hashmap_to_txt(service_name, self.attributes, ttl)?);

        Ok(records)
    }

    /// Creates a Iterator of [`SocketAddr`](`std::net::SocketAddr`) for each ip address and port combination
    pub fn get_socket_addresses(&'_ self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.ip_addresses.iter().copied().flat_map(move |addr| {
            self.ports
                .iter()
                .copied()
                .map(move |port| SocketAddr::new(addr, port))
        })
    }
}

impl std::hash::Hash for InstanceInformation {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.ip_addresses.hash(state);
        self.ports.hash(state);
    }
}

impl From<SocketAddr> for InstanceInformation {
    fn from(addr: SocketAddr) -> Self {
        let ip_address = addr.ip();
        let port = addr.port();

        Self {
            ip_addresses: vec![ip_address],
            ports: vec![port],
            attributes: HashMap::new(),
        }
    }
}
