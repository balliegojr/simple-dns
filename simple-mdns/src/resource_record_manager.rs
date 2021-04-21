use std::{collections::HashMap, net::SocketAddr};

use simple_dns::{CLASS, Name, QCLASS, QTYPE, ResourceRecord, TYPE, rdata::{A, AAAA, RData, SRV}};

pub struct ResourceRecordManager<'a> {
    resources: HashMap<String, HashMap<u16, ResourceRecord<'a>>>,
}

impl<'a> ResourceRecordManager<'a> {
    pub fn new() -> Self {
        Self {
            resources: HashMap::new(),
        }
    }

    /// Register a Resource Record
    pub fn add_resource(&mut self, resource: ResourceRecord<'static>) {
        let service_name = resource.name.to_string();
        match self.resources.get_mut(&service_name) {
            Some(rec) => {
                rec.insert(resource.rdatatype.into(), resource);
            }
            None => {
                let mut resource_records = HashMap::new();
                resource_records.insert(resource.rdatatype.into(), resource);
                self.resources.insert(service_name, resource_records);
            }
        }
    }

    /// Helper function to register the service address as a Resource Record and an SRV Resource Record
    pub fn add_service_address(
        &mut self,
        name: Name<'static>,
        addr: &SocketAddr,
        rr_ttl: u32,
    ) {
        let addr_resource = match addr {
           SocketAddr::V4(ip) => ResourceRecord::new(
                name.clone(),
                TYPE::A,
                CLASS::IN,
                rr_ttl,
                RData::A(A::from(ip.ip())),
            ),
            SocketAddr::V6(ip) => ResourceRecord::new(
                name.clone(),
                TYPE::AAAA,
                CLASS::IN,
                rr_ttl,
                RData::AAAA(AAAA::from(ip.ip())),
            ),
        };

        self.add_resource(addr_resource);
        self.add_resource(ResourceRecord::new(
            name.clone(),
            TYPE::SRV,
            CLASS::IN,
            rr_ttl,
            RData::SRV(Box::new(SRV {
                port: addr.port(),
                priority: 0,
                target: name,
                weight: 0,
            })),
        ));
    }

    /// Helper function to remove a service address
    pub fn remove_service_address(&mut self, name: &'static str, addr: &SocketAddr) {
        let resource_type = match addr {
            SocketAddr::V4(_) => TYPE::A,
            SocketAddr::V6(_) => TYPE::AAAA
        };
        self.remove_resource_record(name, &resource_type)
    }
    /// Remove a resource record by service name and resource type
    pub fn remove_resource_record(&mut self, service_name: &str, resource_type: &TYPE) {
        if let Some(service_resource_records) = self.resources.get_mut(service_name) {
            service_resource_records.remove(&u16::from(*resource_type));
            if service_resource_records.len() == 0 {
                self.resources.remove(service_name);
            }
        }
    }

    /// Remove all resource records for a service name
    pub fn remove_all_resource_records(&mut self, service_name: &str) {
        self.resources.remove(service_name);
    }

    /// Returns an [`Iterator`<Item=`&ResourceRecord`>] with all matching resources
    pub fn find_matching_resources(
        &self,
        service_name: &str,
        qtype: QTYPE,
        qclass: QCLASS,
    ) -> impl Iterator<Item = &ResourceRecord> {
        let mut matching = Vec::new();

        match self.resources.get(service_name) {
            Some(resource_records) => match qtype {
                QTYPE::A | QTYPE::AAAA => {
                    matching.extend(
                        resource_records
                            .get(&(QTYPE::A as u16))
                            .filter(|rr| rr.match_qclass(qclass)),
                    );
                    matching.extend(
                        resource_records
                            .get(&(QTYPE::AAAA as u16))
                            .filter(|rr| rr.match_qclass(qclass)),
                    );
                }
                QTYPE::ANY => {
                    matching.extend(
                        resource_records
                            .values()
                            .filter(|rr| rr.match_qclass(qclass)),
                    );
                }
                _ => {
                    matching.extend(
                        resource_records
                            .get(&(qtype as u16))
                            .filter(|rr| rr.match_qclass(qclass)),
                    );
                }
            },
            None => {}
        }

        return matching.into_iter();
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr };

    use simple_dns::{rdata::RData, rdata::A, CharacterString, Name};

    use super::*;

    #[test]
    pub fn test_add_resource() {
        let mut resources = ResourceRecordManager::new();
        resources.add_resource(ResourceRecord::new(
            Name::new_unchecked("_srv1._tcp"),
            TYPE::TXT,
            simple_dns::CLASS::IN,
            0,
            RData::TXT(CharacterString::new(&"version=1".as_bytes()).unwrap()),
        ));

        assert_eq!(1, resources.resources.len());
        assert_eq!(1, resources.resources.get("_srv1._tcp").unwrap().len());
    }

    #[test]
    pub fn test_find_matching_resource() {
        let mut resources = ResourceRecordManager::new();
        resources.add_resource(ResourceRecord::new(
            Name::new_unchecked("_srv1._tcp"),
             TYPE::TXT,
             simple_dns::CLASS::IN,
             0,
             RData::TXT(CharacterString::new(&"version=1".as_bytes()).unwrap()),
        ));
        resources.add_resource(ResourceRecord::new(
            Name::new_unchecked("_srv1._tcp"),
             TYPE::A,
             simple_dns::CLASS::CS,
             0,
             RData::A(A::from(&Ipv4Addr::LOCALHOST)),
        ));

        assert_eq!(
            2,
            resources
                .find_matching_resources("_srv1._tcp", QTYPE::ANY, QCLASS::ANY)
                .count()
        );
        assert_eq!(
            1,
            resources
                .find_matching_resources("_srv1._tcp", QTYPE::TXT, QCLASS::ANY)
                .count()
        );
        assert_eq!(
            1,
            resources
                .find_matching_resources("_srv1._tcp", QTYPE::ANY, QCLASS::CS)
                .count()
        );
        assert_eq!(
            0,
            resources
                .find_matching_resources("_srv2._tcp", QTYPE::ANY, QCLASS::ANY)
                .count()
        );
    }

    #[test]
    fn test_add_service_address() {
        let mut resources = ResourceRecordManager::new();
        resources.add_service_address(Name::new_unchecked("_res1._tcp.com"), &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),0);
        resources.add_service_address(Name::new_unchecked("_res1._tcp.com"), &SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080),0);
        resources.add_service_address(Name::new_unchecked("_res2._tcp.com"), &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),0);

        assert_eq!(3, resources.find_matching_resources("_res1._tcp.com", QTYPE::ANY, QCLASS::IN).count());
        assert_eq!(1, resources.find_matching_resources("_res1._tcp.com", QTYPE::SRV, QCLASS::IN).count());
        assert_eq!(2, resources.find_matching_resources("_res2._tcp.com", QTYPE::ANY, QCLASS::ANY).count());
    }
}
