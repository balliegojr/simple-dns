
use byteorder::{ ByteOrder, BigEndian };

use super::{DnsPacketContent, Name, TYPE};
use core::fmt::Debug;

mod a;

pub use a::A;

pub trait RData<'a> : DnsPacketContent<'a> + Debug {}

pub fn parse_rdata<'a>(data: &'a [u8], position: usize, rdatatype: TYPE) -> crate::Result<Box<dyn RData<'a> + 'a>> {
    let rdata = match rdatatype {
        TYPE::A => Box::new(A::parse(data, position)?) as Box<dyn RData<'a>>,
        TYPE::NS => Box::new(NS::parse(data, position)?) as Box<dyn RData<'a>>,
        TYPE::MD => Box::new(MD::parse(data, position)?) as Box<dyn RData<'a>>,
        TYPE::MF => Box::new(MF::parse(data, position)?) as Box<dyn RData<'a>>,
        TYPE::CNAME => Box::new(CNAME::parse(data, position)?) as Box<dyn RData<'a>>,
        // TYPE::SOA => {}
        TYPE::MB => Box::new(MB::parse(data, position)?) as Box<dyn RData<'a>>,
        TYPE::MG => Box::new(MG::parse(data, position)?) as Box<dyn RData<'a>>,
        TYPE::MR => Box::new(MR::parse(data, position)?) as Box<dyn RData<'a>>,
        // TYPE::NULL => {}
        // TYPE::WKS => {}
        TYPE::PTR => Box::new(PTR::parse(data, position)?) as Box<dyn RData<'a>>,
        // TYPE::HINFO => {}
        // TYPE::MINFO => {}
        // TYPE::MX => {}
        // TYPE::TXT => {}
        _ => Box::new(RawRData::parse(data, position)?) as Box<dyn RData<'a>>
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

impl <'a>  RData<'a> for RawRData<'a> {}
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


impl <'a> RData<'a> for Name<'a> {}

pub type CNAME<'a> = Name<'a>;
pub type PTR<'a> = Name<'a>;
pub type MB<'a> = Name<'a>;
pub type MD<'a> = Name<'a>;
pub type MF<'a> = Name<'a>;
pub type MG<'a> = Name<'a>;
pub type MR<'a> = Name<'a>;
pub type NS<'a> = Name<'a>;