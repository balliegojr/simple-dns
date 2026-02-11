#![allow(unused)]
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::{Duration, Instant};

use radix_trie::{Trie, TrieCommon};
use simple_dns::{Name, ResourceRecord};

#[derive(Debug)]
pub struct ResourceRecordManager<'a> {
    authoritative: Trie<Vec<u8>, HashSet<ResourceRecord<'a>>>,
    cached: Trie<Vec<u8>, HashMap<ResourceRecord<'a>, ExpirationInfo>>,
}

impl<'a> ResourceRecordManager<'a> {
    pub fn new() -> Self {
        Self {
            authoritative: Default::default(),
            cached: Default::default(),
        }
    }

    /// Register a Resource Record
    pub fn add_authoritative_resource(&mut self, resource: ResourceRecord<'a>) {
        let key = get_key(&resource.name);
        match self.authoritative.get_mut(&key) {
            Some(resources) => {
                resources.insert(resource);
            }
            None => {
                let mut resources = HashSet::new();
                resources.insert(resource);

                self.authoritative.insert(key.clone(), resources);
            }
        }

        // FIXME: the trie implementation is not able to find subtries unless the parent prefix has
        // been manually added, this workaround is required to be able to find cached resources
        // related to subdomains. This assumes the main domain will be added in the authoritative
        // resources at some point
        if self.cached.get(&key).is_none() {
            self.cached.insert(key, Default::default());
        }
    }

    pub fn add_cached_resource(&mut self, resource: ResourceRecord<'a>) {
        let key = get_key(&resource.name);

        let exp_info = ExpirationInfo::new(resource.ttl);
        match self.cached.get_mut(&key) {
            Some(resources) if resource.cache_flush => {
                resources.remove(&resource);
            }
            Some(resources) => {
                resources.insert(resource, exp_info);
            }
            None if !resource.cache_flush => {
                let mut resources = HashMap::new();
                resources.insert(resource, exp_info);

                self.cached.insert(key, resources);
            }
            _ => {}
        }
    }

    pub fn remove_resource_record(&mut self, resource_record: &ResourceRecord<'a>) {
        let key = get_key(&resource_record.name);
        let remove_key = self
            .authoritative
            .get_mut(&key)
            .map(|resources| {
                resources.remove(&resource_record.clone());
                !resources.is_empty()
            })
            .unwrap_or_default();

        if remove_key {
            self.authoritative.remove(&key);
        }
    }

    pub fn remove_domain_resources(&mut self, name: &Name) -> usize {
        let key = get_key(name);
        self.authoritative
            .remove(&key)
            .map(|resources| resources.len())
            .unwrap_or(0)
    }

    /// Remove all resource records
    pub fn clear(&mut self) {
        self.authoritative = Default::default();
        self.cached = Default::default();
    }

    pub fn get_next_refresh(&self) -> Option<Instant> {
        self.cached
            .iter()
            .flat_map(|(_, resources)| {
                resources.values().filter_map(|exp_info| {
                    if !exp_info.should_refresh() {
                        None
                    } else {
                        Some(exp_info.refresh_at)
                    }
                })
            })
            .min_by(|a, b| a.cmp(b))
    }

    /// Get all the resources matching the filter criteria and returns the results grouped by
    /// domain.
    ///
    /// if the filter does not include subdomains, the resulting iterator will contain a single
    /// value (the requested domain) and all the resource records for that domain.
    ///
    /// otherwise, the resulting iterator will contain one item for each subdomain found.
    pub fn get_domain_resources<'b>(
        &'a self,
        name: &'b Name,
        filter: DomainResourceFilter,
    ) -> impl Iterator<Item = impl Iterator<Item = &'a ResourceRecord<'a>>> {
        let key = get_key(name);
        let mut found: Vec<Vec<&'a ResourceRecord>> = Vec::new();

        fn filter_expired<'b>(
            (resource, exp_info): (&'b ResourceRecord<'b>, &'b ExpirationInfo),
        ) -> Option<&'b ResourceRecord<'b>> {
            if exp_info.is_expired() {
                None
            } else {
                Some(resource)
            }
        }

        if filter.subdomain {
            let mut domain_resources: BTreeMap<&Vec<u8>, HashSet<&ResourceRecord>> =
                Default::default();
            if filter.authoritative {
                if let Some(authoritative) = self.authoritative.subtrie(&key) {
                    for (domain, resources) in authoritative.iter() {
                        domain_resources
                            .entry(domain)
                            .or_default()
                            .extend(resources);
                    }
                }
            }

            if filter.cached {
                if let Some(cached) = self.cached.subtrie(&key) {
                    for (domain, resources) in cached.iter() {
                        let non_expired: Vec<&ResourceRecord> =
                            resources.iter().filter_map(filter_expired).collect();

                        if !non_expired.is_empty() {
                            domain_resources
                                .entry(domain)
                                .or_default()
                                .extend(non_expired);
                        }
                    }
                }
            }

            found.extend(
                domain_resources
                    .into_values()
                    .filter(|resources| !resources.is_empty())
                    .map(|inner| inner.into_iter().collect()),
            );
        } else {
            let mut resources = Vec::new();
            if filter.authoritative {
                if let Some(authoritative) = self.authoritative.get(&key) {
                    resources.extend(authoritative);
                }
            }

            if filter.cached {
                if let Some(cached) = self.cached.get(&key) {
                    resources.extend(cached.iter().filter_map(filter_expired));
                }
            }

            if !resources.is_empty() {
                found.push(resources);
            }
        }

        found
            .into_iter()
            .filter(|resources| !resources.is_empty())
            .map(|inner| inner.into_iter())
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
}

fn get_key(name: &Name) -> Vec<u8> {
    name.get_labels()
        .iter()
        .rev()
        .flat_map(|label| label.to_string().into_bytes())
        .collect()
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

    pub fn should_refresh(&self) -> bool {
        self.refresh_at < Instant::now()
    }

    pub fn is_expired(&self) -> bool {
        self.expire_at < Instant::now()
    }
}

#[cfg(test)]
mod tests {
    use std::{convert::TryInto, net::Ipv4Addr, str::FromStr};

    use simple_dns::{rdata::RData, rdata::A, rdata::TXT, Name};

    use super::*;

    #[test]
    pub fn test_add_authoritative_resource() {
        let mut resources = ResourceRecordManager::new();
        resources.add_authoritative_resource(ResourceRecord::new(
            Name::new_unchecked("_srv1._tcp"),
            simple_dns::CLASS::IN,
            0,
            RData::TXT(TXT::new().with_string("version=1").unwrap()),
        ));

        assert_eq!(1, resources.authoritative.len());
    }

    #[test]
    pub fn test_add_cached_resource() {
        let mut resources = ResourceRecordManager::new();
        resources.add_cached_resource(ResourceRecord::new(
            Name::new_unchecked("_srv1._tcp"),
            simple_dns::CLASS::IN,
            0,
            RData::TXT(TXT::new().with_string("version=1").unwrap()),
        ));

        assert_eq!(1, resources.cached.len());
    }

    #[test]
    pub fn test_add_cached_resource_dont_override_authoritative() {
        let name = Name::new_unchecked("_srv1._tcp");
        let mut resources = ResourceRecordManager::new();
        resources.add_authoritative_resource(ResourceRecord::new(
            name.clone(),
            simple_dns::CLASS::IN,
            0,
            RData::TXT(TXT::new().with_string("version=1").unwrap()),
        ));

        resources.add_cached_resource(ResourceRecord::new(
            name.clone(),
            simple_dns::CLASS::IN,
            0,
            RData::TXT(TXT::new().with_string("version=2").unwrap()),
        ));

        assert_eq!(
            ResourceRecord::new(
                name.clone(),
                simple_dns::CLASS::IN,
                0,
                RData::TXT(TXT::new().with_string("version=1").unwrap()),
            ),
            *resources
                .authoritative
                .get(&get_key(&name))
                .unwrap()
                .iter()
                .next()
                .unwrap()
        );
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

    #[test]
    pub fn test_remove_resources() {
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

        assert_eq!(
            1,
            resources.remove_domain_resources(&Name::new_unchecked("a._srv._tcp.local"))
        );

        assert_eq!(
            1,
            resources.remove_domain_resources(&Name::new_unchecked("_srv._tcp.local"))
        );
    }
}
