use byteorder::{ ByteOrder, BigEndian };

use super::{CLASS, DnsPacketContent, Name, rdata::RData, TYPE, rdata::parse_rdata};
use core::fmt::Debug;
use std::{convert::{ TryInto }};

/// Resource Records are used to represent the answer, authority, and additional sections in DNS packets.
#[derive(Debug)]
pub struct ResourceRecord<'a> {
    /// A [`Name`] to which this resource record pertains.
    pub name: Name<'a>,
    /// A [`TYPE`] that defines the contents of the rdata field
    pub rdatatype: TYPE,
    /// A [`CLASS`] that defines the class of the rdata field
    pub class: CLASS,
    /// The time interval (in seconds) that the resource record may becached before it should be discarded.  
    /// Zero values are interpreted to mean that the RR can only be used for the transaction in progress, and should not be cached.
    pub ttl: u32,
    /// A [`RData`] with the contents of this resource record
    pub rdata: RData<'a>
}

impl <'a> DnsPacketContent<'a> for ResourceRecord<'a> {
    fn len(&self) -> usize {
        self.name.len() + self.rdata.len() + 10
    }
    
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self> where Self: Sized {
        let name = Name::parse(data, position)?;
        let offset = position + name.len();

        let rdatatype = BigEndian::read_u16(&data[offset..offset+2]).into();
        let class = BigEndian::read_u16(&data[offset+2..offset+4]).try_into()?;
        let ttl = BigEndian::read_u32(&data[offset+4..offset+8]);
        let rdatalen = BigEndian::read_u16(&data[offset+8..offset+10]) as usize;

        let position = offset + 10;
        let rdata = parse_rdata(&data[..position+rdatalen], position, rdatatype)?;

        Ok(Self{
            name,
            rdatatype,
            class,
            ttl,
            rdata
        })
    }

    fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        self.name.append_to_vec(out)?;

        let mut buf = [0u8; 10];
        BigEndian::write_u16(&mut buf[..2], self.rdatatype.into());
        BigEndian::write_u16(&mut buf[2..4], self.class as u16);
        BigEndian::write_u32(&mut buf[4..8], self.ttl);
        BigEndian::write_u16(&mut buf[8..10], self.rdata.len() as u16);

        out.extend(&buf);
        self.rdata.append_to_vec(out)
    }
}

#[cfg(test)]
mod tests {
    use crate::dns::rdata::NULL;
    use super::*;
    
    #[test]
    fn test_parse() {
        let bytes = b"\x04_srv\x04_udp\x05local\x00\x00\x01\x00\x01\x00\x00\x00\x0a\x00\x04\xff\xff\xff\xff";
        let rr = ResourceRecord::parse(&bytes[..], 0).unwrap();
        
        assert_eq!("_srv._udp.local", rr.name.to_string());
        assert_eq!(TYPE::A, rr.rdatatype);
        assert_eq!(CLASS::IN, rr.class);
        assert_eq!(10, rr.ttl);
        assert_eq!(4, rr.rdata.len());
        match rr.rdata {
            RData::A(a) => assert_eq!(4294967295, a.address),
            _ => panic!("invalid rdata")
        }
    }

    #[test]
    fn test_append_to_vec() {
        let mut out = Vec::new();
        let rdata = [255u8; 4];

        let rr = ResourceRecord {
            class: CLASS::IN,
            name: "_srv._udp.local".try_into().unwrap(),
            rdatatype: TYPE::Unknown(0),
            ttl: 10,
            rdata: RData::NULL(NULL::new(&rdata).unwrap())
        };

        assert!(rr.append_to_vec(&mut out).is_ok());
        assert_eq!(
            b"\x04_srv\x04_udp\x05local\x00\x00\x00\x00\x01\x00\x00\x00\x0a\x00\x04\xff\xff\xff\xff",
            &out[..]
        );
        assert_eq!(out.len(), rr.len());
    }

}