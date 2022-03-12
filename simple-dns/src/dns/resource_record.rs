use crate::{QCLASS, QTYPE};

use super::{rdata::RData, DnsPacketContent, Name, CLASS, TYPE};
use core::fmt::Debug;
use std::{collections::HashMap, convert::TryInto, hash::Hash};

mod flag {
    pub const CACHE_FLUSH: u16 = 0b1000_0000_0000_0000;
}
/// Resource Records are used to represent the answer, authority, and additional sections in DNS packets.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct ResourceRecord<'a> {
    /// A [`Name`] to which this resource record pertains.
    pub name: Name<'a>,
    /// A [`CLASS`] that defines the class of the rdata field
    pub class: CLASS,
    /// The time interval (in seconds) that the resource record may becached before it should be discarded.  
    /// Zero values are interpreted to mean that the RR can only be used for the transaction in progress, and should not be cached.
    pub ttl: u32,
    /// A [`RData`] with the contents of this resource record
    pub rdata: RData<'a>,

    /// Indicates if this RR is a cache flush
    pub cache_flush: bool,
}

impl<'a> ResourceRecord<'a> {
    /// Creates a new ResourceRecord
    pub fn new(name: Name<'a>, class: CLASS, ttl: u32, rdata: RData<'a>) -> Self {
        Self {
            name,
            class,
            ttl,
            rdata,
            cache_flush: false,
        }
    }

    /// Consume self and change the cache_flush bit
    pub fn with_cache_flush(mut self, cache_flush: bool) -> Self {
        self.cache_flush = cache_flush;
        self
    }

    /// Returns a cloned self with cache_flush = true
    pub fn to_cache_flush_record(&self) -> Self {
        self.clone().with_cache_flush(true)
    }

    /// Return true if current resource match given query class
    pub fn match_qclass(&self, qclass: QCLASS) -> bool {
        qclass == QCLASS::ANY || self.class as u16 == qclass as u16
    }

    /// Return true if current resource match given query type
    /// The types `A` and `AAAA` will match each other
    pub fn match_qtype(&self, qtype: QTYPE) -> bool {
        let type_code = self.rdata.type_code();
        match qtype {
            QTYPE::A | QTYPE::AAAA => type_code == TYPE::A || type_code == TYPE::AAAA,
            QTYPE::ANY => true,
            qtype => Into::<u16>::into(type_code) == qtype as u16,
        }
    }

    fn append_common(&self, out: &mut Vec<u8>) {
        let class = if self.cache_flush {
            ((self.class as u16) | flag::CACHE_FLUSH).to_be_bytes()
        } else {
            (self.class as u16).to_be_bytes()
        };

        out.extend(u16::from(self.rdata.type_code()).to_be_bytes());
        out.extend(class);
        out.extend(self.ttl.to_be_bytes());
        out.extend((self.rdata.len() as u16).to_be_bytes());
    }

    /// Transforms the inner data into it's owned type
    pub fn into_owned<'b>(self) -> ResourceRecord<'b> {
        ResourceRecord {
            name: self.name.into_owned(),
            class: self.class,
            ttl: self.ttl,
            rdata: self.rdata.into_owned(),
            cache_flush: self.cache_flush,
        }
    }
}

impl<'a> DnsPacketContent<'a> for ResourceRecord<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let name = Name::parse(data, position)?;
        let offset = position + name.len();

        let class_value = u16::from_be_bytes(data[offset + 2..offset + 4].try_into()?);
        let cache_flush = class_value & flag::CACHE_FLUSH == flag::CACHE_FLUSH;
        let class = (class_value & !flag::CACHE_FLUSH).try_into()?;

        let ttl = u32::from_be_bytes(data[offset + 4..offset + 8].try_into()?);

        let rdata = RData::parse(data, offset)?;

        Ok(Self {
            name,
            class,
            ttl,
            rdata,
            cache_flush,
        })
    }

    fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        self.name.append_to_vec(out)?;
        self.append_common(out);
        self.rdata.append_to_vec(out)
    }

    fn compress_append_to_vec(
        &self,
        out: &mut Vec<u8>,
        name_refs: &mut HashMap<u64, usize>,
    ) -> crate::Result<()> {
        self.name.compress_append_to_vec(out, name_refs)?;
        self.append_common(out);
        self.rdata.compress_append_to_vec(out, name_refs)
    }

    fn len(&self) -> usize {
        self.name.len() + self.rdata.len() + 10
    }
}

impl<'a> Hash for ResourceRecord<'a> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.class.hash(state);
        self.rdata.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };

    use crate::{dns::rdata::NULL, rdata::TXT};

    use super::*;

    #[test]
    fn test_parse() {
        let bytes = b"\x04_srv\x04_udp\x05local\x00\x00\x01\x00\x01\x00\x00\x00\x0a\x00\x04\xff\xff\xff\xff";
        let rr = ResourceRecord::parse(&bytes[..], 0).unwrap();

        assert_eq!("_srv._udp.local", rr.name.to_string());
        assert_eq!(CLASS::IN, rr.class);
        assert_eq!(10, rr.ttl);
        assert_eq!(4, rr.rdata.len());
        assert!(!rr.cache_flush);

        match rr.rdata {
            RData::A(a) => assert_eq!(4294967295, a.address),
            _ => panic!("invalid rdata"),
        }
    }

    #[test]
    fn test_cache_flush_parse() {
        let bytes = b"\x04_srv\x04_udp\x05local\x00\x00\x01\x80\x01\x00\x00\x00\x0a\x00\x04\xff\xff\xff\xff";
        let rr = ResourceRecord::parse(&bytes[..], 0).unwrap();

        assert_eq!(CLASS::IN, rr.class);
        assert!(rr.cache_flush);
    }

    #[test]
    fn test_append_to_vec() {
        let mut out = Vec::new();
        let rdata = [255u8; 4];

        let rr = ResourceRecord {
            class: CLASS::IN,
            name: "_srv._udp.local".try_into().unwrap(),
            ttl: 10,
            rdata: RData::NULL(0, NULL::new(&rdata).unwrap()),
            cache_flush: false,
        };

        assert!(rr.append_to_vec(&mut out).is_ok());
        assert_eq!(
            b"\x04_srv\x04_udp\x05local\x00\x00\x00\x00\x01\x00\x00\x00\x0a\x00\x04\xff\xff\xff\xff",
            &out[..]
        );
        assert_eq!(out.len(), rr.len());
    }

    #[test]
    fn test_append_to_vec_cache_flush() {
        let mut out = Vec::new();
        let rdata = [255u8; 4];

        let rr = ResourceRecord {
            class: CLASS::IN,
            name: "_srv._udp.local".try_into().unwrap(),
            ttl: 10,
            rdata: RData::NULL(0, NULL::new(&rdata).unwrap()),
            cache_flush: true,
        };

        assert!(rr.append_to_vec(&mut out).is_ok());
        assert_eq!(
            b"\x04_srv\x04_udp\x05local\x00\x00\x00\x80\x01\x00\x00\x00\x0a\x00\x04\xff\xff\xff\xff",
            &out[..]
        );
        assert_eq!(out.len(), rr.len());
    }

    #[test]
    fn test_match_qclass() {
        let rr = ResourceRecord {
            class: CLASS::IN,
            name: "_srv._udp.local".try_into().unwrap(),
            ttl: 10,
            rdata: RData::NULL(0, NULL::new(&[255u8; 4]).unwrap()),
            cache_flush: false,
        };

        assert!(rr.match_qclass(QCLASS::ANY));
        assert!(rr.match_qclass(QCLASS::IN));
        assert!(!rr.match_qclass(QCLASS::CS));
    }

    #[test]
    fn test_match_qtype() {
        let rr = ResourceRecord {
            class: CLASS::IN,
            name: "_srv._udp.local".try_into().unwrap(),
            ttl: 10,
            rdata: RData::A(crate::rdata::A { address: 0 }),
            cache_flush: false,
        };

        assert!(rr.match_qtype(QTYPE::ANY));
        assert!(rr.match_qtype(QTYPE::A));
        assert!(!rr.match_qtype(QTYPE::WKS));
    }

    #[test]
    fn test_match_qtype_for_aaaa() {
        let mut rr = ResourceRecord {
            class: CLASS::IN,
            name: "_srv._udp.local".try_into().unwrap(),
            ttl: 10,
            rdata: RData::A(crate::rdata::A { address: 0 }),
            cache_flush: false,
        };

        assert!(rr.match_qtype(QTYPE::A));
        assert!(rr.match_qtype(QTYPE::AAAA));

        rr.rdata = RData::AAAA(crate::rdata::AAAA { address: 0 });

        assert!(rr.match_qtype(QTYPE::A));
        assert!(rr.match_qtype(QTYPE::AAAA));
    }

    #[test]
    fn test_eq() {
        let a = ResourceRecord::new(
            Name::new_unchecked("_srv.local"),
            CLASS::IN,
            10,
            RData::TXT(TXT::new().with_string("text").unwrap()),
        );
        let b = ResourceRecord::new(
            Name::new_unchecked("_srv.local"),
            CLASS::IN,
            10,
            RData::TXT(TXT::new().with_string("text").unwrap()),
        );

        assert_eq!(a, b);
        assert_eq!(get_hash(&a), get_hash(&b));
    }

    #[test]
    fn test_hash_ignore_ttl() {
        let a = ResourceRecord::new(
            Name::new_unchecked("_srv.local"),
            CLASS::IN,
            10,
            RData::TXT(TXT::new().with_string("text").unwrap()),
        );
        let mut b = ResourceRecord::new(
            Name::new_unchecked("_srv.local"),
            CLASS::IN,
            10,
            RData::TXT(TXT::new().with_string("text").unwrap()),
        );

        assert_eq!(get_hash(&a), get_hash(&b));
        b.ttl = 50;

        assert_eq!(get_hash(&a), get_hash(&b));
    }

    fn get_hash(rr: &ResourceRecord) -> u64 {
        let mut hasher = DefaultHasher::default();
        rr.hash(&mut hasher);
        hasher.finish()
    }
}
