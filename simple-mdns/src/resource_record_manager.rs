use std::collections::HashSet;

use simple_dns::ResourceRecord;

pub struct ResourceRecordManager<'a> {
    resources: HashSet<ResourceRecord<'a>>,
}

impl<'a> ResourceRecordManager<'a> {
    pub fn new() -> Self {
        Self {
            resources: HashSet::new(),
        }
    }

    /// Register a Resource Record
    pub fn add_resource(&mut self, resource: ResourceRecord<'a>) {
        self.resources.insert(resource);
    }

    pub fn remove_resource_record(&mut self, resource_record: &ResourceRecord<'a>) {
        self.resources.remove(resource_record);
    }

    /// Remove all resource records
    pub fn clear(&mut self) {
        self.resources.clear();
    }

    /// Returns an [`Iterator`<Item=`&ResourceRecord`>] with all matching resources
    pub fn find_matching_resources<P: FnMut(&&ResourceRecord) -> bool>(
        &self,
        filter: P,
    ) -> impl Iterator<Item = &ResourceRecord> {
        self.resources.iter().filter(filter).into_iter()
    }

    pub fn has_resource(&self, resource: &ResourceRecord) -> bool {
        self.resources.contains(resource)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use simple_dns::{rdata::RData, rdata::A, CharacterString, Name, QCLASS, QTYPE};

    use super::*;

    #[test]
    pub fn test_add_resource() {
        let mut resources = ResourceRecordManager::new();
        resources.add_resource(ResourceRecord::new(
            Name::new_unchecked("_srv1._tcp"),
            simple_dns::CLASS::IN,
            0,
            RData::TXT(CharacterString::new(&"version=1".as_bytes()).unwrap()),
        ));

        assert_eq!(1, resources.resources.len());
    }

    #[test]
    pub fn test_find_matching_resource() {
        let mut resources = ResourceRecordManager::new();
        let service_name = Name::new_unchecked("_srv1._tcp");
        resources.add_resource(ResourceRecord::new(
            service_name.clone(),
            simple_dns::CLASS::IN,
            0,
            RData::TXT(CharacterString::new(&"version=1".as_bytes()).unwrap()),
        ));
        resources.add_resource(ResourceRecord::new(
            service_name.clone(),
            simple_dns::CLASS::CS,
            0,
            RData::A(A::from(&Ipv4Addr::LOCALHOST)),
        ));

        assert_eq!(
            2,
            resources
                .find_matching_resources(|r| r.name == service_name
                    && r.match_qtype(QTYPE::ANY)
                    && r.match_qclass(QCLASS::ANY))
                .count()
        );
        assert_eq!(
            1,
            resources
                .find_matching_resources(|r| r.name == service_name
                    && r.match_qtype(QTYPE::TXT)
                    && r.match_qclass(QCLASS::ANY))
                .count()
        );
        assert_eq!(
            1,
            resources
                .find_matching_resources(|r| r.name == service_name
                    && r.match_qtype(QTYPE::ANY)
                    && r.match_qclass(QCLASS::CS))
                .count()
        );
        assert_eq!(
            0,
            resources
                .find_matching_resources(|r| r.name == Name::new_unchecked("_srv2._tcp")
                    && r.match_qtype(QTYPE::ANY)
                    && r.match_qclass(QCLASS::ANY))
                .count()
        );
    }
}
