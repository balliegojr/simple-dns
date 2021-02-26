
use byteorder::{ ByteOrder, BigEndian };

use super::{DnsPacketContent, Name, TYPE};
use core::fmt::Debug;

mod a;

pub use a::A;

#[derive(Debug)]
pub enum RData<'a> {
    A(A),
    NS(Name<'a>),
    MD(Name<'a>),
    CNAME(Name<'a>),
    MB(Name<'a>),
    MG(Name<'a>),
    MR(Name<'a>),
    PTR(Name<'a>),
    MF(Name<'a>),
    Raw(RawRData<'a>)
}

impl <'a> RData<'a> {
    pub fn len(&self) -> usize {
        match &self {
            RData::A(data) => data.len(),
            RData::NS(data) | 
            RData::CNAME(data) |
            RData::MB(data) |
            RData::MG(data) |
            RData::MR(data) |
            RData::PTR(data) |
            RData::MF(data) |
            RData::MD(data) => data.len(),
            RData::Raw(data) => data.len()
        }
    }

    pub fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        match &self {
            RData::A(data) => data.append_to_vec(out),
            RData::NS(data) |
            RData::CNAME(data) |
            RData::MB(data) |
            RData::MG(data) |
            RData::MR(data) |
            RData::PTR(data) |
            RData::MF(data) |
            RData::MD(data) => data.append_to_vec(out),
            RData::Raw(data) => data.append_to_vec(out)
        }
    }
}

// pub trait RData<'a> : DnsPacketContent<'a> + Debug {}

pub fn parse_rdata<'a>(data: &'a [u8], position: usize, rdatatype: TYPE) -> crate::Result<RData<'a>> {
    let rdata = match rdatatype {
        TYPE::A => RData::A(A::parse(data, position)?),
        TYPE::NS => RData::NS(Name::parse(data, position)?),
        TYPE::MD => RData::MD(Name::parse(data, position)?),
        TYPE::CNAME => RData::CNAME(Name::parse(data, position)?),
        TYPE::MB => RData::MB(Name::parse(data, position)?),
        TYPE::MG => RData::MG(Name::parse(data, position)?),
        TYPE::MR => RData::MR(Name::parse(data, position)?),
        TYPE::PTR => RData::PTR(Name::parse(data, position)?),
        TYPE::MF => RData::NS(Name::parse(data, position)?),
        // TYPE::SOA => {}
        // TYPE::NULL => {}
        // TYPE::WKS => {}
        // TYPE::HINFO => {}
        // TYPE::MINFO => {}
        // TYPE::MX => {}
        // TYPE::TXT => {}
        _ => RData::Raw(RawRData::parse(data, position)?)
    };

    Ok(rdata)
}


#[derive(Debug)]
pub struct RawRData<'a> {
    length: u16,
    data: &'a [u8]
}

impl <'a> RawRData<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            length: data.len() as u16,
            data
        }
    }
}


impl <'a> DnsPacketContent<'a> for RawRData<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self> where Self: Sized {
        let length = BigEndian::read_u16(&data[position..position+2]);
        Ok(Self::new(&data[position+2..position+2+length as usize]))
    }

    fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        let mut buf = [0u8; 2];
        BigEndian::write_u16(&mut buf, self.length);

        out.extend(&buf);
        out.extend(self.data);

        Ok(())
    }

    fn len(&self) -> usize {
        self.length as usize
    }
}
