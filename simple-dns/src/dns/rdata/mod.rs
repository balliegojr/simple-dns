use super::{CharacterString, DnsPacketContent, Name, TYPE};
use core::fmt::Debug;

mod a;
mod hinfo;
mod minfo;
mod mx;
mod null;
mod soa;
mod wks;
mod srv;

pub use a::A;
pub use hinfo::HINFO;
pub use minfo::MINFO;
pub use mx::MX;
pub use null::NULL;
pub use soa::SOA;
pub use wks::WKS;
pub use srv::SRV;

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
    HINFO(HINFO<'a>),
    MINFO(MINFO<'a>),
    MX(MX<'a>),
    NULL(NULL<'a>),
    TXT(CharacterString<'a>),
    SOA(Box<SOA<'a>>),
    WKS(WKS<'a>),
    SRV(Box<SRV<'a>>)
    
}

impl <'a> RData<'a> {
    pub(crate) fn len(&self) -> usize {
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
            RData::HINFO(data) => data.len(),
            RData::MINFO(data) => data.len(),
            RData::MX(data) => data.len(),
            RData::NULL(data) => data.len(),
            RData::TXT(data) => data.len(),
            RData::SOA(data) => data.len(),
            RData::WKS(data) => data.len(),
            RData::SRV(data) => data.len()
        }
    }

    pub(crate) fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()> {
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
            RData::HINFO(data) => data.append_to_vec(out),
            RData::MINFO(data) => data.append_to_vec(out),
            RData::MX(data) => data.append_to_vec(out),
            RData::NULL(data) => data.append_to_vec(out),
            RData::TXT(data) => data.append_to_vec(out),
            RData::SOA(data) => data.append_to_vec(out),
            RData::WKS(data) => data.append_to_vec(out),
            RData::SRV(data) => data.append_to_vec(out),
        }
    }
}

pub(crate) fn parse_rdata(data: &[u8], position: usize, rdatatype: TYPE) -> crate::Result<RData> {
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
        TYPE::SOA => RData::SOA(Box::new(SOA::parse(data, position)?)),
        TYPE::WKS => RData::WKS(WKS::parse(data, position)?),
        TYPE::HINFO => RData::HINFO(HINFO::parse(data, position)?),
        TYPE::MINFO => RData::MINFO(MINFO::parse(data, position)?),
        TYPE::MX => RData::MX(MX::parse(data, position)?),
        TYPE::TXT => RData::TXT(CharacterString::parse(data, position)?),
        TYPE::SRV => RData::SRV(Box::new(SRV::parse(data, position)?)),
        _ => RData::NULL(NULL::parse(data, position)?)
    };

    Ok(rdata)
}
