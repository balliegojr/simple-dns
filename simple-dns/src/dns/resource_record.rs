use crate::{QCLASS, QTYPE};

use super::{name::Label, rdata::RData, Name, WireFormat, CLASS, TYPE};
use core::fmt::Debug;
use std::{collections::HashMap, convert::TryInto, hash::Hash};

mod flag {
    pub const CACHE_FLUSH: u16 = 0b1000_0000_0000_0000;
}
/// Resource Records are used to represent the answer, authority, and additional sections in DNS packets.
#[derive(Debug, Eq, Clone)]
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
        match qclass {
            QCLASS::CLASS(class) => class == self.class,
            QCLASS::ANY => true,
        }
    }

    /// Return true if current resource match given query type
    pub fn match_qtype(&self, qtype: QTYPE) -> bool {
        let type_code = self.rdata.type_code();
        match qtype {
            QTYPE::ANY => true,
            QTYPE::IXFR => false,
            QTYPE::AXFR => true, // TODO: figure out what to do here
            QTYPE::MAILB => type_code == TYPE::MR || type_code == TYPE::MB || type_code == TYPE::MG,
            QTYPE::MAILA => type_code == TYPE::MX,
            QTYPE::TYPE(ty) => ty == type_code,
        }
    }

    /// Transforms the inner data into its owned type
    pub fn into_owned<'b>(self) -> ResourceRecord<'b> {
        ResourceRecord {
            name: self.name.into_owned(),
            class: self.class,
            ttl: self.ttl,
            rdata: self.rdata.into_owned(),
            cache_flush: self.cache_flush,
        }
    }

    fn write_common<T: std::io::Write>(&self, out: &mut T) -> crate::Result<()> {
        out.write_all(&u16::from(self.rdata.type_code()).to_be_bytes())?;

        if let RData::OPT(ref opt) = self.rdata {
            out.write_all(&opt.udp_packet_size.to_be_bytes())?;
        } else {
            let class = if self.cache_flush {
                ((self.class as u16) | flag::CACHE_FLUSH).to_be_bytes()
            } else {
                (self.class as u16).to_be_bytes()
            };

            out.write_all(&class)?;
        }

        out.write_all(&self.ttl.to_be_bytes())
            .map_err(crate::SimpleDnsError::from)
    }
}

impl<'a> WireFormat<'a> for ResourceRecord<'a> {
    const MINIMUM_LEN: usize = 10;

    // Disable redundant length check.
    fn parse(data: &'a [u8], position: &mut usize) -> crate::Result<Self> {
        Self::parse_after_check(data, position)
    }

    fn parse_after_check(data: &'a [u8], position: &mut usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let name = Name::parse(data, position)?;
        if *position + 8 > data.len() {
            return Err(crate::SimpleDnsError::InsufficientData);
        }

        let class_value = u16::from_be_bytes(data[*position + 2..*position + 4].try_into()?);
        let ttl = u32::from_be_bytes(data[*position + 4..*position + 8].try_into()?);
        let rdata = RData::parse(data, position)?;

        if rdata.type_code() == TYPE::OPT {
            Ok(Self {
                name,
                class: CLASS::IN,
                ttl,
                rdata,
                cache_flush: false,
            })
        } else {
            let cache_flush = class_value & flag::CACHE_FLUSH == flag::CACHE_FLUSH;
            let class = (class_value & !flag::CACHE_FLUSH).try_into()?;

            Ok(Self {
                name,
                class,
                ttl,
                rdata,
                cache_flush,
            })
        }
    }

    fn len(&self) -> usize {
        self.name.len() + self.rdata.len() + Self::MINIMUM_LEN
    }

    fn write_to<T: std::io::Write>(&self, out: &mut T) -> crate::Result<()> {
        self.name.write_to(out)?;
        self.write_common(out)?;
        out.write_all(&(self.rdata.len() as u16).to_be_bytes())?;
        self.rdata.write_to(out)
    }

    fn write_compressed_to<T: std::io::Write + std::io::Seek>(
        &'a self,
        out: &mut T,
        name_refs: &mut HashMap<&'a [Label<'a>], usize>,
    ) -> crate::Result<()> {
        self.name.write_compressed_to(out, name_refs)?;
        self.write_common(out)?;

        let len_position = out.stream_position()?;
        out.write_all(&[0, 0])?;

        self.rdata.write_compressed_to(out, name_refs)?;
        let end = out.stream_position()?;

        out.seek(std::io::SeekFrom::Start(len_position))?;
        out.write_all(&((end - len_position - 2) as u16).to_be_bytes())?;
        out.seek(std::io::SeekFrom::End(0))?;
        Ok(())
    }
}

impl<'a> Hash for ResourceRecord<'a> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.class.hash(state);
        self.rdata.hash(state);
    }
}

impl<'a> PartialEq for ResourceRecord<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.class == other.class && self.rdata == other.rdata
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
        io::Cursor,
    };

    use crate::{dns::rdata::NULL, rdata::TXT};

    use super::*;

    #[test]
    fn test_parse() {
        let bytes = b"\x04_srv\x04_udp\x05local\x00\x00\x01\x00\x01\x00\x00\x00\x0a\x00\x04\xff\xff\xff\xff";
        let rr = ResourceRecord::parse(&bytes[..], &mut 0).unwrap();

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
    fn test_empty_rdata() {
        let rr = ResourceRecord {
            class: CLASS::NONE,
            name: "_srv._udp.local".try_into().unwrap(),
            ttl: 0,
            rdata: RData::Empty(TYPE::A),
            cache_flush: false,
        };

        assert_eq!(rr.rdata.type_code(), TYPE::A);
        assert_eq!(rr.rdata.len(), 0);

        let mut data = Vec::new();
        rr.write_to(&mut data).expect("failed to write");

        let parsed_rr = ResourceRecord::parse(&data, &mut 0).expect("failed to parse");
        assert_eq!(parsed_rr.rdata.type_code(), TYPE::A);
        assert_eq!(parsed_rr.rdata.len(), 0);
        assert!(matches!(parsed_rr.rdata, RData::Empty(TYPE::A)));
    }

    #[test]
    fn test_cache_flush_parse() {
        let bytes = b"\x04_srv\x04_udp\x05local\x00\x00\x01\x80\x01\x00\x00\x00\x0a\x00\x04\xff\xff\xff\xff";
        let rr = ResourceRecord::parse(&bytes[..], &mut 0).unwrap();

        assert_eq!(CLASS::IN, rr.class);
        assert!(rr.cache_flush);
    }

    #[test]
    fn test_write() {
        let mut out = Cursor::new(Vec::new());
        let rdata = [255u8; 4];

        let rr = ResourceRecord {
            class: CLASS::IN,
            name: "_srv._udp.local".try_into().unwrap(),
            ttl: 10,
            rdata: RData::NULL(0, NULL::new(&rdata).unwrap()),
            cache_flush: false,
        };

        assert!(rr.write_to(&mut out).is_ok());
        assert_eq!(
            b"\x04_srv\x04_udp\x05local\x00\x00\x00\x00\x01\x00\x00\x00\x0a\x00\x04\xff\xff\xff\xff",
            &out.get_ref()[..]
        );
        assert_eq!(out.get_ref().len(), rr.len());
    }

    #[test]
    fn test_append_to_vec_cache_flush() {
        let mut out = Cursor::new(Vec::new());
        let rdata = [255u8; 4];

        let rr = ResourceRecord {
            class: CLASS::IN,
            name: "_srv._udp.local".try_into().unwrap(),
            ttl: 10,
            rdata: RData::NULL(0, NULL::new(&rdata).unwrap()),
            cache_flush: true,
        };

        assert!(rr.write_to(&mut out).is_ok());
        assert_eq!(
            b"\x04_srv\x04_udp\x05local\x00\x00\x00\x80\x01\x00\x00\x00\x0a\x00\x04\xff\xff\xff\xff",
            &out.get_ref()[..]
        );
        assert_eq!(out.get_ref().len(), rr.len());
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
        assert!(rr.match_qclass(CLASS::IN.into()));
        assert!(!rr.match_qclass(CLASS::CS.into()));
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
        assert!(rr.match_qtype(TYPE::A.into()));
        assert!(!rr.match_qtype(TYPE::WKS.into()));
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

    #[test]
    fn parse_sample_files() -> Result<(), Box<dyn std::error::Error>> {
        for file_path in std::fs::read_dir("samples/zonefile")? {
            let data = std::fs::read(file_path?.path())?;
            let mut pos = 0;
            while pos < data.len() {
                crate::ResourceRecord::parse(&data, &mut pos)?;
            }
        }

        Ok(())
    }
}
