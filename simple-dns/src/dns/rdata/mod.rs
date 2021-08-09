use super::{CharacterString, DnsPacketContent, Name, TYPE};
use core::fmt::Debug;
use std::collections::HashMap;

mod a;
mod aaaa;
mod hinfo;
mod minfo;
mod mx;
mod null;
mod soa;
mod srv;
mod wks;

pub use a::A;
pub use aaaa::AAAA;
use byteorder::{BigEndian, ByteOrder};
pub use hinfo::HINFO;
pub use minfo::MINFO;
pub use mx::MX;
pub use null::NULL;
pub use soa::SOA;
pub use srv::SRV;
pub use wks::WKS;

/// Represents the RData of each [`TYPE`]
#[derive(Debug, Eq, PartialEq, Hash)]
pub enum RData<'a> {
    A(A),
    AAAA(AAAA),
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
    TXT(CharacterString<'a>),
    SOA(Box<SOA<'a>>),
    WKS(WKS<'a>),
    SRV(Box<SRV<'a>>),
    NULL(u16, NULL<'a>),
}

impl<'a> DnsPacketContent<'a> for RData<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let rdatatype = BigEndian::read_u16(&data[position..position + 2]).into();
        let rdatalen = BigEndian::read_u16(&data[position + 8..position + 10]) as usize;

        parse_rdata(&data[position + 10..position + 10 + rdatalen], 0, rdatatype)
    }

    fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        match &self {
            RData::A(data) => data.append_to_vec(out),
            RData::AAAA(data) => data.append_to_vec(out),
            RData::NS(data)
            | RData::CNAME(data)
            | RData::MB(data)
            | RData::MG(data)
            | RData::MR(data)
            | RData::PTR(data)
            | RData::MF(data)
            | RData::MD(data) => data.append_to_vec(out),
            RData::HINFO(data) => data.append_to_vec(out),
            RData::MINFO(data) => data.append_to_vec(out),
            RData::MX(data) => data.append_to_vec(out),
            RData::NULL(_, data) => data.append_to_vec(out),
            RData::TXT(data) => data.append_to_vec(out),
            RData::SOA(data) => data.append_to_vec(out),
            RData::WKS(data) => data.append_to_vec(out),
            RData::SRV(data) => data.append_to_vec(out),
        }
    }

    fn compress_append_to_vec(
        &self,
        out: &mut Vec<u8>,
        name_refs: &mut HashMap<u64, usize>,
    ) -> crate::Result<()> {
        match &self {
            RData::A(data) => data.compress_append_to_vec(out, name_refs),
            RData::AAAA(data) => data.compress_append_to_vec(out, name_refs),
            RData::NS(data)
            | RData::CNAME(data)
            | RData::MB(data)
            | RData::MG(data)
            | RData::MR(data)
            | RData::PTR(data)
            | RData::MF(data)
            | RData::MD(data) => data.compress_append_to_vec(out, name_refs),
            RData::HINFO(data) => data.compress_append_to_vec(out, name_refs),
            RData::MINFO(data) => data.compress_append_to_vec(out, name_refs),
            RData::MX(data) => data.compress_append_to_vec(out, name_refs),
            RData::NULL(_, data) => data.compress_append_to_vec(out, name_refs),
            RData::TXT(data) => data.compress_append_to_vec(out, name_refs),
            RData::SOA(data) => data.compress_append_to_vec(out, name_refs),
            RData::WKS(data) => data.compress_append_to_vec(out, name_refs),
            RData::SRV(data) => data.compress_append_to_vec(out, name_refs),
        }
    }

    fn len(&self) -> usize {
        match &self {
            RData::A(data) => data.len(),
            RData::AAAA(data) => data.len(),
            RData::NS(data)
            | RData::CNAME(data)
            | RData::MB(data)
            | RData::MG(data)
            | RData::MR(data)
            | RData::PTR(data)
            | RData::MF(data)
            | RData::MD(data) => data.len(),
            RData::HINFO(data) => data.len(),
            RData::MINFO(data) => data.len(),
            RData::MX(data) => data.len(),
            RData::NULL(_, data) => data.len(),
            RData::TXT(data) => data.len(),
            RData::SOA(data) => data.len(),
            RData::WKS(data) => data.len(),
            RData::SRV(data) => data.len(),
        }
    }
}

impl<'a> RData<'a> {
    /// Returns the [`TYPE`] of this RData
    pub fn type_code(&self) -> TYPE {
        match self {
            RData::A(_) => TYPE::A,
            RData::AAAA(_) => TYPE::AAAA,
            RData::NS(_) => TYPE::NS,
            RData::MD(_) => TYPE::MD,
            RData::CNAME(_) => TYPE::CNAME,
            RData::MB(_) => TYPE::MB,
            RData::MG(_) => TYPE::MG,
            RData::MR(_) => TYPE::MR,
            RData::PTR(_) => TYPE::PTR,
            RData::MF(_) => TYPE::MF,
            RData::HINFO(_) => TYPE::HINFO,
            RData::MINFO(_) => TYPE::MINFO,
            RData::MX(_) => TYPE::MX,
            RData::TXT(_) => TYPE::TXT,
            RData::SOA(_) => TYPE::SOA,
            RData::WKS(_) => TYPE::WKS,
            RData::SRV(_) => TYPE::SRV,
            RData::NULL(type_code, _) => TYPE::Unknown(*type_code),
        }
    }
}

fn parse_rdata(data: &[u8], position: usize, rdatatype: TYPE) -> crate::Result<RData> {
    let rdata = match rdatatype {
        TYPE::A => RData::A(A::parse(data, position)?),
        TYPE::AAAA => RData::AAAA(AAAA::parse(data, position)?),
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
        rdatatype => RData::NULL(rdatatype.into(), NULL::parse(data, position)?),
    };

    Ok(rdata)
}
