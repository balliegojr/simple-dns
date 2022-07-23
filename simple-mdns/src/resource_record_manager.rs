use std::collections::HashMap;
use std::time::{Duration, Instant};

use radix_trie::{Trie, TrieCommon};
use simple_dns::{Name, ResourceRecord};

#[derive(Debug)]
pub struct ResourceRecordManager<'a> {
    // resources: HashSet<ResourceRecord<'a>>,
    resources: Trie<Vec<u8>, HashMap<ResourceRecord<'a>, ResourceRecordType>>,
}

impl<'a> ResourceRecordManager<'a> {
    pub fn new() -> Self {
        Self {
            // resources: HashSet::new(),
            resources: Trie::new(),
        }
    }

    /// Register a Resource Record
    pub fn add_owned_resource(&mut self, resource: ResourceRecord<'a>) {
        let key = get_key(&resource.name);
        match self.resources.get_mut(&key) {
            Some(resources) => {
                resources.insert(resource, ResourceRecordType::Owned);
            }
            None => {
                let mut resources = HashMap::new();
                resources.insert(resource, ResourceRecordType::Owned);

                self.resources.insert(key, resources);
            }
        }
    }

    pub fn add_expirable_resource(&mut self, resource: ResourceRecord<'a>) {
        log::debug!("adding expirable resouce");
        let key = get_key(&resource.name);

        let ttl = if resource.cache_flush {
            1
        } else {
            resource.ttl
        };

        let exp_info = ExpirationInfo::new(ttl);
        match self.resources.get_mut(&key) {
            Some(resources) => {
                resources.insert(resource, ResourceRecordType::Expirable(exp_info));
            }
            None => {
                let mut resources = HashMap::new();
                resources.insert(resource, ResourceRecordType::Expirable(exp_info));

                self.resources.insert(key, resources);
            }
        }
    }

    pub fn remove_resource_record(&mut self, resource_record: &ResourceRecord<'a>) {
        let key = get_key(&resource_record.name);
        self.resources
            .get_mut(&key)
            .map(|resources| resources.remove(resource_record));
    }

    /// Remove all resource records
    pub fn clear(&mut self) {
        self.resources = Trie::new();
    }

    pub fn get_next_expiration(&self) -> Option<Instant> {
        self.resources
            .iter()
            .flat_map(|(_, resources)| {
                resources.values().filter_map(|resource_type| {
                    if resource_type.should_refresh() {
                        return None;
                    }
                    match resource_type {
                        ResourceRecordType::Owned => None,
                        ResourceRecordType::Expirable(exp_info) => Some(exp_info.refresh_at),
                    }
                })
            })
            .min_by(|a, b| a.cmp(b))
    }

    pub fn get_domain_resources<'b>(
        &'a self,
        name: &'b Name,
        include_subdomain: bool,
        include_owned: bool,
    ) -> impl Iterator<Item = impl Iterator<Item = &'a ResourceRecord<'a>>> {
        let key = get_key(name);

        let filter_expired_resource = |resource_pair: (
            &'a ResourceRecord,
            &'a ResourceRecordType,
        )|
         -> Option<&ResourceRecord> {
            let (resource, resource_type) = resource_pair;
            if !include_owned && resource_type.is_owned() || resource_type.is_expired() {
                None
            } else {
                Some(resource)
            }
        };
        let mut found: Vec<Vec<&'a ResourceRecord>> = Vec::new();

        if include_subdomain {
            if let Some(trie) = self.resources.subtrie(&key) {
                found = trie
                    .iter()
                    .map(|(_domain, resources)| {
                        resources
                            .iter()
                            .filter_map(filter_expired_resource)
                            .collect()
                    })
                    .collect();
            };
        } else if let Some(resources) = self.resources.get(&key) {
            found = vec![resources
                .iter()
                .filter_map(filter_expired_resource)
                .collect()]
        }

        found
            .into_iter()
            .filter(|resources| !resources.is_empty())
            .map(|inner| inner.into_iter())
    }
}

fn get_key(name: &Name) -> Vec<u8> {
    name.get_labels()
        .iter()
        .rev()
        .flat_map(|label| label.to_string().into_bytes())
        .collect()
}

#[derive(Debug)]
enum ResourceRecordType {
    Owned,
    Expirable(ExpirationInfo),
}

impl ResourceRecordType {
    pub fn is_owned(&self) -> bool {
        matches!(self, &ResourceRecordType::Owned)
    }
    pub fn is_expired(&self) -> bool {
        match self {
            ResourceRecordType::Owned => false,
            ResourceRecordType::Expirable(exp_info) => exp_info.expire_at < Instant::now(),
        }
    }

    pub fn should_refresh(&self) -> bool {
        match self {
            ResourceRecordType::Owned => false,
            ResourceRecordType::Expirable(exp_info) => exp_info.refresh_at < Instant::now(),
        }
    }
}

/// Provides known service expiration and refresh times
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
struct ExpirationInfo {
    refresh_at: Instant,
    expire_at: Instant,
}

impl ExpirationInfo {
    pub fn new(ttl: u32) -> Self {
        let ttl = ttl as u64;
        let added = Instant::now();
        let expire_at = added + Duration::from_secs(ttl);
        let refresh_at = match ttl {
            0 => expire_at,
            ttl if ttl < 60 => added + Duration::from_secs(ttl / 2),
            ttl => added + Duration::from_secs(ttl / 10 * 8),
        };

        Self {
            expire_at,
            refresh_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{convert::TryInto, net::Ipv4Addr, str::FromStr};

    use simple_dns::{rdata::RData, rdata::A, rdata::TXT, Name};

    use super::*;

    #[test]
    pub fn test_add_resource() {
        let mut resources = ResourceRecordManager::new();
        resources.add_owned_resource(ResourceRecord::new(
            Name::new_unchecked("_srv1._tcp"),
            simple_dns::CLASS::IN,
            0,
            RData::TXT(TXT::new().with_string("version=1").unwrap()),
        ));

        assert_eq!(1, resources.resources.len());
    }

    #[test]
    pub fn test_get_domain_resources() {
        let mut resources = ResourceRecordManager::new();
        resources.add_owned_resource(ResourceRecord::new(
            "a._srv._tcp.local".try_into().unwrap(),
            simple_dns::CLASS::IN,
            0,
            RData::A(A::from(Ipv4Addr::from_str("127.0.0.1").unwrap())),
        ));
        resources.add_owned_resource(ResourceRecord::new(
            "b._srv._tcp.local".try_into().unwrap(),
            simple_dns::CLASS::IN,
            0,
            RData::A(A::from(Ipv4Addr::from_str("127.0.0.2").unwrap())),
        ));
        resources.add_owned_resource(ResourceRecord::new(
            "_srv._tcp.local".try_into().unwrap(),
            simple_dns::CLASS::IN,
            0,
            RData::A(A::from(Ipv4Addr::from_str("127.0.0.3").unwrap())),
        ));

        let get_records = |domain: &str, include_subdomains: bool| -> Vec<Vec<&ResourceRecord>> {
            resources
                .get_domain_resources(&domain.try_into().unwrap(), include_subdomains, true)
                .map(|r| r.collect())
                .collect()
        };

        let compare_ips = |record: &ResourceRecord, ip: &str| {
            if let RData::A(address) = &record.rdata {
                assert_eq!(
                    Ipv4Addr::from(address.address),
                    Ipv4Addr::from_str(ip).unwrap()
                )
            } else {
                panic!("something is wrong");
            }
        };

        let records = get_records("a._srv._tcp.local", true);
        assert_eq!(1, records.len());
        compare_ips(records[0][0], "127.0.0.1");

        let records = get_records("b._srv._tcp.local", true);
        assert_eq!(1, records.len());
        compare_ips(records[0][0], "127.0.0.2");

        let records = get_records("_srv._tcp.local", false);
        assert_eq!(1, records.len());
        compare_ips(records[0][0], "127.0.0.3");

        let records = get_records("_srv._tcp.local", true);
        assert_eq!(3, records.len());

        let records = get_records("_xxx._tcp.local", true);
        assert_eq!(0, records.len());

        let records = get_records("v._tcp.local", true);
        assert_eq!(0, records.len());
    }
}
