//! Contains RData implementations

use crate::CharacterString;

use super::{DnsPacketContent, Name, TYPE};
use core::fmt::Debug;
use std::{collections::HashMap, convert::TryInto};

mod a;
mod aaaa;
mod afsdb;
mod hinfo;
mod isdn;
mod minfo;
mod mx;
mod null;
mod route_through;
mod rp;
mod soa;
mod srv;
mod txt;
mod wks;

pub use a::A;
pub use aaaa::AAAA;
pub use afsdb::AFSDB;
pub use hinfo::HINFO;
pub use isdn::ISDN;
pub use minfo::MINFO;
pub use mx::MX;
pub use null::NULL;
pub use route_through::RouteThrough;
pub use rp::RP;
pub use soa::SOA;
pub use srv::SRV;
pub use txt::TXT;
pub use wks::WKS;

/// Represents the RData of each [`TYPE`]
#[derive(Debug, Eq, PartialEq, Hash, Clone)]
#[allow(missing_docs)]
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
    TXT(TXT<'a>),
    SOA(Box<SOA<'a>>),
    WKS(WKS<'a>),
    SRV(SRV<'a>),
    NULL(u16, NULL<'a>),
    RP(RP<'a>),
    AFSDB(AFSDB<'a>),
    X25(CharacterString<'a>),
    ISDN(ISDN<'a>),
    RouteThrough(RouteThrough<'a>),
}

impl<'a> DnsPacketContent<'a> for RData<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        if position + 10 > data.len() {
            return Err(crate::SimpleDnsError::NoEnoughData);
        }

        let rdatatype = u16::from_be_bytes(data[position..position + 2].try_into()?).into();
        let rdatalen = u16::from_be_bytes(data[position + 8..position + 10].try_into()?) as usize;

        if position + 10 + rdatalen > data.len() {
            return Err(crate::SimpleDnsError::NoEnoughData);
        }

        parse_rdata(&data[..position + 10 + rdatalen], position + 10, rdatatype)
    }

    fn append_to_vec(
        &self,
        out: &mut Vec<u8>,
        name_refs: &mut Option<&mut HashMap<u64, usize>>,
    ) -> crate::Result<()> {
        match &self {
            RData::A(data) => data.append_to_vec(out, name_refs),
            RData::AAAA(data) => data.append_to_vec(out, name_refs),
            RData::NS(data)
            | RData::CNAME(data)
            | RData::MB(data)
            | RData::MG(data)
            | RData::MR(data)
            | RData::PTR(data)
            | RData::MF(data)
            | RData::MD(data) => data.append_to_vec(out, name_refs),
            RData::HINFO(data) => data.append_to_vec(out, name_refs),
            RData::MINFO(data) => data.append_to_vec(out, name_refs),
            RData::MX(data) => data.append_to_vec(out, name_refs),
            RData::NULL(_, data) => data.append_to_vec(out, name_refs),
            RData::TXT(data) => data.append_to_vec(out, name_refs),
            RData::SOA(data) => data.append_to_vec(out, name_refs),
            RData::WKS(data) => data.append_to_vec(out, name_refs),
            RData::SRV(data) => data.append_to_vec(out, name_refs),
            RData::RP(data) => data.append_to_vec(out, name_refs),
            RData::AFSDB(data) => data.append_to_vec(out, name_refs),
            RData::X25(data) => data.append_to_vec(out, name_refs),
            RData::ISDN(data) => data.append_to_vec(out, name_refs),
            RData::RouteThrough(data) => data.append_to_vec(out, name_refs),
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
            RData::RP(data) => data.len(),
            RData::AFSDB(data) => data.len(),
            RData::X25(data) => data.len(),
            RData::ISDN(data) => data.len(),
            RData::RouteThrough(data) => data.len(),
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
            RData::RP(_) => TYPE::RP,
            RData::AFSDB(_) => TYPE::AFSDB,
            RData::X25(_) => TYPE::X25,
            RData::ISDN(_) => TYPE::ISDN,
            RData::RouteThrough(_) => TYPE::RouteThrough,
            RData::NULL(type_code, _) => TYPE::Unknown(*type_code),
        }
    }

    /// Transforms the inner data into it's owned type
    pub fn into_owned<'b>(self) -> RData<'b> {
        match self {
            RData::A(data) => RData::A(data),
            RData::AAAA(data) => RData::AAAA(data),
            RData::NS(data) => RData::NS(data.into_owned()),
            RData::MD(data) => RData::MD(data.into_owned()),
            RData::CNAME(data) => RData::CNAME(data.into_owned()),
            RData::MB(data) => RData::MB(data.into_owned()),
            RData::MG(data) => RData::MG(data.into_owned()),
            RData::MR(data) => RData::MR(data.into_owned()),
            RData::PTR(data) => RData::PTR(data.into_owned()),
            RData::MF(data) => RData::MF(data.into_owned()),
            RData::HINFO(data) => RData::HINFO(data.into_owned()),
            RData::MINFO(data) => RData::MINFO(data.into_owned()),
            RData::MX(data) => RData::MX(data.into_owned()),
            RData::TXT(data) => RData::TXT(data.into_owned()),
            RData::SOA(data) => RData::SOA(Box::new(data.into_owned())),
            RData::WKS(data) => RData::WKS(data.into_owned()),
            RData::SRV(data) => RData::SRV(data.into_owned()),
            RData::NULL(rdatatype, data) => RData::NULL(rdatatype, data.into_owned()),
            RData::RP(data) => RData::RP(data.into_owned()),
            RData::AFSDB(data) => RData::AFSDB(data.into_owned()),
            RData::X25(data) => RData::X25(data.into_owned()),
            RData::ISDN(data) => RData::ISDN(data.into_owned()),
            RData::RouteThrough(data) => RData::RouteThrough(data.into_owned()),
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
        TYPE::TXT => RData::TXT(TXT::parse(data, position)?),
        TYPE::SRV => RData::SRV(SRV::parse(data, position)?),
        TYPE::RP => RData::RP(RP::parse(data, position)?),
        TYPE::AFSDB => RData::AFSDB(AFSDB::parse(data, position)?),
        TYPE::X25 => RData::X25(CharacterString::parse(data, position)?),
        TYPE::ISDN => RData::ISDN(ISDN::parse(data, position)?),
        TYPE::RouteThrough => RData::RouteThrough(RouteThrough::parse(data, position)?),
        TYPE::NULL => RData::NULL(rdatatype.into(), NULL::parse(data, position)?),
        TYPE::Unknown(rdatatype) => RData::NULL(rdatatype, NULL::parse(data, position)?),
    };

    Ok(rdata)
}
