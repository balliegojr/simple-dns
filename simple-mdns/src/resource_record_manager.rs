use std::collections::HashMap;
use std::time::{Duration, Instant};

use radix_trie::{Trie, TrieCommon};
use simple_dns::{Name, ResourceRecord};

#[derive(Debug)]
pub struct ResourceRecordManager<'a> {
    resources: Trie<Vec<u8>, HashMap<ResourceRecord<'a>, ResourceRecordType>>,
}

impl<'a> ResourceRecordManager<'a> {
    pub fn new() -> Self {
        Self {
            resources: Trie::new(),
        }
    }

    /// Register a Resource Record
    pub fn add_authoritative_resource(&mut self, resource: ResourceRecord<'a>) {
        let key = get_key(&resource.name);
        match self.resources.get_mut(&key) {
            Some(resources) => {
                resources.insert(resource, ResourceRecordType::Authoritative);
            }
            None => {
                let mut resources = HashMap::new();
                resources.insert(resource, ResourceRecordType::Authoritative);

                self.resources.insert(key, resources);
            }
        }
    }

    pub fn add_cached_resource(&mut self, resource: ResourceRecord<'a>) {
        let key = get_key(&resource.name);

        let ttl = if resource.cache_flush {
            1
        } else {
            resource.ttl
        };

        let exp_info = ExpirationInfo::new(ttl);
        match self.resources.get_mut(&key) {
            Some(resources) => {
                resources.insert(resource, ResourceRecordType::Cached(exp_info));
            }
            None => {
                let mut resources = HashMap::new();
                resources.insert(resource, ResourceRecordType::Cached(exp_info));

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

    pub fn get_next_refresh(&self) -> Option<Instant> {
        self.resources
            .iter()
            .flat_map(|(_, resources)| {
                resources.values().filter_map(|resource_type| {
                    if !resource_type.should_refresh() {
                        return None;
                    }
                    match resource_type {
                        ResourceRecordType::Authoritative => None,
                        ResourceRecordType::Cached(exp_info) => Some(exp_info.refresh_at),
                    }
                })
            })
            .min_by(|a, b| a.cmp(b))
    }

    pub fn get_domain_resources<'b>(
        &'a self,
        name: &'b Name,
        filter: DomainResourceFilter,
    ) -> impl Iterator<Item = impl Iterator<Item = &'a ResourceRecord<'a>>> {
        let key = get_key(name);

        let filter_expired_resource = |resource_pair: (
            &'a ResourceRecord,
            &'a ResourceRecordType,
        )|
         -> Option<&ResourceRecord> {
            let (resource, resource_type) = resource_pair;
            if filter.match_filter(resource_type) {
                Some(resource)
            } else {
                None
            }
        };
        let mut found: Vec<Vec<&'a ResourceRecord>> = Vec::new();

        if filter.subdomain {
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

impl Default for ResourceRecordManager<'_> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct DomainResourceFilter {
    subdomain: bool,
    authoritative: bool,
    cached: bool,
}

impl DomainResourceFilter {
    pub fn authoritative(include_subdomains: bool) -> Self {
        Self {
            authoritative: true,
            subdomain: include_subdomains,
            cached: false,
        }
    }
    pub fn cached() -> Self {
        Self {
            authoritative: false,
            subdomain: true,
            cached: true,
        }
    }
    #[allow(dead_code)]
    pub fn all() -> Self {
        Self {
            authoritative: true,
            subdomain: true,
            cached: true,
        }
    }

    fn match_filter(&self, resource_type: &ResourceRecordType) -> bool {
        match resource_type {
            ResourceRecordType::Authoritative => self.authoritative,
            ResourceRecordType::Cached(exp_info) => {
                self.cached && exp_info.expire_at > Instant::now()
            }
        }
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
    Authoritative,
    Cached(ExpirationInfo),
}

impl ResourceRecordType {
    pub fn should_refresh(&self) -> bool {
        match self {
            ResourceRecordType::Authoritative => false,
            ResourceRecordType::Cached(exp_info) => exp_info.refresh_at < Instant::now(),
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
        resources.add_authoritative_resource(ResourceRecord::new(
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
        resources.add_authoritative_resource(ResourceRecord::new(
            "a._srv._tcp.local".try_into().unwrap(),
            simple_dns::CLASS::IN,
            0,
            RData::A(A::from(Ipv4Addr::from_str("127.0.0.1").unwrap())),
        ));
        resources.add_cached_resource(ResourceRecord::new(
            "b._srv._tcp.local".try_into().unwrap(),
            simple_dns::CLASS::IN,
            60,
            RData::A(A::from(Ipv4Addr::from_str("127.0.0.2").unwrap())),
        ));
        resources.add_authoritative_resource(ResourceRecord::new(
            "_srv._tcp.local".try_into().unwrap(),
            simple_dns::CLASS::IN,
            0,
            RData::A(A::from(Ipv4Addr::from_str("127.0.0.3").unwrap())),
        ));

        let get_records =
            |domain: &str, filter: DomainResourceFilter| -> Vec<Vec<&ResourceRecord>> {
                resources
                    .get_domain_resources(&domain.try_into().unwrap(), filter)
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

        let records = get_records(
            "a._srv._tcp.local",
            DomainResourceFilter::authoritative(false),
        );
        assert_eq!(1, records.len());
        compare_ips(records[0][0], "127.0.0.1");

        let records = get_records("b._srv._tcp.local", DomainResourceFilter::cached());
        assert_eq!(1, records.len());
        compare_ips(records[0][0], "127.0.0.2");

        let records = get_records("_srv._tcp.local", DomainResourceFilter::authoritative(true));
        assert_eq!(2, records.len());
        compare_ips(records[0][0], "127.0.0.3");
        compare_ips(records[1][0], "127.0.0.1");

        let records = get_records("_srv._tcp.local", DomainResourceFilter::all());
        assert_eq!(3, records.len());

        assert!(get_records(
            "_xxx._tcp.local",
            DomainResourceFilter::authoritative(false)
        )
        .is_empty());
        assert!(get_records(
            "b._srv._tcp.local",
            DomainResourceFilter::authoritative(false)
        )
        .is_empty());
        assert!(get_records(
            "_xxx._tcp.local",
            DomainResourceFilter::authoritative(false)
        )
        .is_empty());
    }
}
