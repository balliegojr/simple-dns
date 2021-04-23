use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
};

use simple_dns::{
    rdata::{RData, A, AAAA, SRV},
    Name, ResourceRecord, CLASS, QCLASS, QTYPE, TYPE,
};

pub struct ResourceRecordManager<'a> {
    resources: HashMap<String, HashMap<u16, HashSet<ResourceRecord<'a>>>>,
}

impl<'a> ResourceRecordManager<'a> {
    pub fn new() -> Self {
        Self {
            resources: HashMap::new(),
        }
    }

    /// Register a Resource Record
    pub fn add_resource(&mut self, resource: ResourceRecord<'a>) {
        let mut service_records = self
            .resources
            .entry(resource.name.to_string())
            .or_insert(HashMap::new());
        let mut type_records = service_records
            .entry(resource.rdatatype.into())
            .or_insert(HashSet::new());
        type_records.insert(resource);
    }

    /// Helper function to register the service address as a Resource Record and an SRV Resource Record
    pub fn add_service_address(&mut self, name: Name<'a>, addr: &SocketAddr, rr_ttl: u32) {
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
    pub fn remove_service_address(&mut self, name: &'a Name, addr: &SocketAddr) {
        todo!()
        // let resource_type = match addr {
        //     SocketAddr::V4(_) => TYPE::A,
        //     SocketAddr::V6(_) => TYPE::AAAA
        // };
        // self.remove_resource_record(name, &resource_type)
    }
    /// Remove every resource record of the given type
    pub fn remove_resource_records_of_type(
        &mut self,
        service_name: &'a Name,
        resource_type: &TYPE,
    ) {
        if let Some(service_resource_records) = self.resources.get_mut(&service_name.to_string()) {
            service_resource_records.remove(&u16::from(*resource_type));
            if service_resource_records.len() == 0 {
                self.resources.remove(&service_name.to_string());
            }
        }
    }

    pub fn remove_resource_record(&mut self, resource_record: &'a ResourceRecord) {
        if let Some(service_resource_records) =
            self.resources.get_mut(&resource_record.name.to_string())
        {
            let rtype = u16::from(resource_record.rdatatype);
            if let Some(resource_set) = service_resource_records.get_mut(&rtype) {
                resource_set.remove(&resource_record);

                if resource_set.is_empty() {
                    service_resource_records.remove(&rtype);
                }
            }

            if service_resource_records.is_empty() {
                self.resources.remove(&resource_record.name.to_string());
            }
        }
    }

    /// Remove all resource records for a service name
    pub fn remove_all_resource_records(&mut self, service_name: &'a Name) {
        self.resources.remove(&service_name.to_string());
    }

    /// Returns an [`Iterator`<Item=`&ResourceRecord`>] with all matching resources
    pub fn find_matching_resources(
        &self,
        service_name: &Name,
        qtype: QTYPE,
        qclass: QCLASS,
    ) -> impl Iterator<Item = &ResourceRecord> {
        let mut matching = Vec::new();

        match self.resources.get(&service_name.to_string()) {
            Some(resource_records) => match qtype {
                QTYPE::A | QTYPE::AAAA => {
                    match resource_records.get(&(QTYPE::A as u16)) {
                        Some(resource_set) => {
                            matching
                                .extend(resource_set.iter().filter(|rr| rr.match_qclass(qclass)));
                        }
                        None => {}
                    }
                    match resource_records.get(&(QTYPE::AAAA as u16)) {
                        Some(resource_set) => {
                            matching
                                .extend(resource_set.iter().filter(|rr| rr.match_qclass(qclass)));
                        }
                        None => {}
                    }
                }
                QTYPE::ANY => {
                    for resource_set in resource_records.values() {
                        matching.extend(resource_set.iter().filter(|rr| rr.match_qclass(qclass)));
                    }
                }
                _ => match resource_records.get(&(qtype as u16)) {
                    Some(resource_set) => {
                        matching.extend(resource_set.iter().filter(|rr| rr.match_qclass(qclass)));
                    }
                    None => {}
                },
            },
            None => {}
        }

        return matching.into_iter();
    }

    pub fn has_resource(&self, resource: &ResourceRecord) -> bool {
        self.resources
            .get(&resource.name.to_string())
            .and_then(|r| r.get(&u16::from(resource.rdatatype)))
            .map(|r| r.contains(resource))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
        let service_name = Name::new_unchecked("_srv1._tcp");
        resources.add_resource(ResourceRecord::new(
            service_name.clone(),
            TYPE::TXT,
            simple_dns::CLASS::IN,
            0,
            RData::TXT(CharacterString::new(&"version=1".as_bytes()).unwrap()),
        ));
        resources.add_resource(ResourceRecord::new(
            service_name.clone(),
            TYPE::A,
            simple_dns::CLASS::CS,
            0,
            RData::A(A::from(&Ipv4Addr::LOCALHOST)),
        ));

        assert_eq!(
            2,
            resources
                .find_matching_resources(&service_name, QTYPE::ANY, QCLASS::ANY)
                .count()
        );
        assert_eq!(
            1,
            resources
                .find_matching_resources(&service_name, QTYPE::TXT, QCLASS::ANY)
                .count()
        );
        assert_eq!(
            1,
            resources
                .find_matching_resources(&service_name, QTYPE::ANY, QCLASS::CS)
                .count()
        );
        assert_eq!(
            0,
            resources
                .find_matching_resources(
                    &Name::new_unchecked("_srv2._tcp"),
                    QTYPE::ANY,
                    QCLASS::ANY
                )
                .count()
        );
    }

    #[test]
    fn test_add_service_address() {
        let mut resources = ResourceRecordManager::new();
        resources.add_service_address(
            Name::new_unchecked("_res1._tcp.com"),
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            0,
        );
        resources.add_service_address(
            Name::new_unchecked("_res1._tcp.com"),
            &SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080),
            0,
        );
        resources.add_service_address(
            Name::new_unchecked("_res2._tcp.com"),
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            0,
        );

        assert_eq!(
            3,
            resources
                .find_matching_resources(
                    &Name::new_unchecked("_res1._tcp.com"),
                    QTYPE::ANY,
                    QCLASS::IN
                )
                .count()
        );
        assert_eq!(
            1,
            resources
                .find_matching_resources(
                    &Name::new_unchecked("_res1._tcp.com"),
                    QTYPE::SRV,
                    QCLASS::IN
                )
                .count()
        );
        assert_eq!(
            2,
            resources
                .find_matching_resources(
                    &Name::new_unchecked("_res2._tcp.com"),
                    QTYPE::ANY,
                    QCLASS::ANY
                )
                .count()
        );
    }
}
