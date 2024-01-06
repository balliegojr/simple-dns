use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
};

use crate::conversion_utils::{hashmap_to_txt, ip_addr_to_resource_record, port_to_srv_record};
use simple_dns::{Name, ResourceRecord};

/// Represents a single instance of the service.
/// Notice that it is not possible to associate a port to a single ip address, due to limitations of the DNS protocol
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct InstanceInformation {
    instance_name: String,
    /// Ips for this instance
    pub ip_addresses: HashSet<IpAddr>,
    /// Ports for this instance
    pub ports: HashSet<u16>,
    /// Attributes for this instance
    pub attributes: HashMap<String, Option<String>>,
}

impl<'a> InstanceInformation {
    /// Creates an empty InstanceInformation
    pub fn new(instance_name: String) -> Self {
        Self {
            instance_name,
            ip_addresses: Default::default(),
            ports: Default::default(),
            attributes: HashMap::new(),
        }
    }

    /// Adds the `ip_address` and `port` to this instance information. This is the equivalent of
    /// `with_ip_address(ip_address).with_port(port)`
    pub fn with_socket_address(mut self, socket_address: SocketAddr) -> Self {
        self.ip_addresses.insert(socket_address.ip());
        self.ports.insert(socket_address.port());

        self
    }

    /// Adds `ip_address` to the list of ip addresses for this instance
    pub fn with_ip_address(mut self, ip_address: IpAddr) -> Self {
        self.ip_addresses.insert(ip_address);
        self
    }

    /// Adds `port` to the list of ports for this instance
    pub fn with_port(mut self, port: u16) -> Self {
        self.ports.insert(port);
        self
    }

    /// Add and attribute to the list of attributes
    pub fn with_attribute(mut self, key: String, value: Option<String>) -> Self {
        self.attributes.insert(key, value);
        self
    }

    /// Escape the instance name
    ///
    /// . will be replaced with \.
    /// \ will be replaced with \\
    pub fn escaped_instance_name(&self) -> String {
        escaped_instance_name(self.instance_name.as_str())
    }

    /// Unescape the instance name
    ///
    /// \. will be replaced with .
    /// \\ will be replaced with \
    pub fn unescaped_instance_name(&self) -> String {
        unescaped_instance_name(self.instance_name.as_str())
    }

    pub(crate) fn from_records<'b>(
        service_name: &Name<'b>,
        records: impl Iterator<Item = &'b ResourceRecord<'b>>,
    ) -> Option<Self> {
        let mut ip_addresses: HashSet<IpAddr> = Default::default();
        let mut ports = HashSet::new();
        let mut attributes = HashMap::new();

        let mut instance_name: Option<String> = Default::default();
        for resource in records {
            if instance_name.is_none() {
                instance_name = resource
                    .name
                    .without(service_name)
                    .map(|sub_domain| sub_domain.to_string());
            }

            match &resource.rdata {
                simple_dns::rdata::RData::A(a) => {
                    ip_addresses.insert(std::net::Ipv4Addr::from(a.address).into());
                }
                simple_dns::rdata::RData::AAAA(aaaa) => {
                    ip_addresses.insert(std::net::Ipv6Addr::from(aaaa.address).into());
                }
                simple_dns::rdata::RData::TXT(txt) => attributes.extend(txt.attributes()),
                simple_dns::rdata::RData::SRV(srv) => {
                    ports.insert(srv.port);
                }
                _ => {}
            }
        }

        instance_name.map(|instance_name| InstanceInformation {
            instance_name,
            ip_addresses,
            ports,
            attributes,
        })
    }

    /// Transform into a [Vec<ResourceRecord>](`Vec<ResourceRecord>`)
    pub fn into_records(
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
        self.instance_name.hash(state);
        self.ip_addresses.iter().for_each(|v| v.hash(state));
        self.ports.iter().for_each(|v| v.hash(state));
    }
}

fn escaped_instance_name(instance_name: &str) -> String {
    let mut escaped_name = String::new();

    for c in instance_name.chars() {
        match c {
            '.' => escaped_name.push_str("\\."),
            '\\' => escaped_name.push_str("\\\\"),
            _ => escaped_name.push(c),
        }
    }

    escaped_name
}

fn unescaped_instance_name(instance_name: &str) -> String {
    let mut unescaped_name = String::new();
    let mut maybe_scaped = instance_name.chars();

    while let Some(c) = maybe_scaped.next() {
        match c {
            '\\' => {
                if let Some(c) = maybe_scaped.next() {
                    unescaped_name.push(c)
                }
            }
            _ => unescaped_name.push(c),
        }
    }

    unescaped_name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escaped_instance_name_simple() {
        let instance_name = "example.com";
        let expected_escaped_name = "example\\.com";

        let escaped_name = escaped_instance_name(instance_name);

        assert_eq!(escaped_name, expected_escaped_name);
    }

    #[test]
    fn test_escaped_instance_name_with_backslash() {
        let instance_name = "\\example.com";
        let expected_escaped_name = "\\\\example\\.com";

        let escaped_name = escaped_instance_name(instance_name);

        assert_eq!(escaped_name, expected_escaped_name);
    }

    #[test]
    fn test_escaped_instance_name_with_multiple_dots() {
        let instance_name = "foo.bar.baz";
        let expected_escaped_name = "foo\\.bar\\.baz";

        let escaped_name = escaped_instance_name(instance_name);

        assert_eq!(escaped_name, expected_escaped_name);
    }

    #[test]
    fn test_unescaped_instance_name_simple() {
        let instance_name = "example\\.com";
        let expected_unescaped_name = "example.com";

        let unescaped_name = unescaped_instance_name(instance_name);

        assert_eq!(unescaped_name, expected_unescaped_name);
    }

    #[test]
    fn test_unescaped_instance_name_with_multiple_slashes() {
        let instance_name = r#"example\\\.com"#;
        let expected_unescaped_name = "example\\.com";

        let unescaped_name = unescaped_instance_name(instance_name);

        assert_eq!(unescaped_name, expected_unescaped_name);
    }
}
