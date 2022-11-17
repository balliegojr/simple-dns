use crate::{
    dns::{header::Header, PacketPart},
    RCODE,
};
use std::{borrow::Cow, collections::HashMap};

use super::RR;

pub mod masks {
    pub const RCODE_MASK: u32 = 0b0000_0000_0000_0000_0000_0000_1111_1111;
    pub const VERSION_MASK: u32 = 0b0000_0000_0000_0000_1111_1111_0000_0000;
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct OPT<'a> {
    pub code: u16, // NOTE: include an OPT_CODE enum???
    pub data: Cow<'a, [u8]>,

    /// UDP packet size supported by the responder
    pub udp_packet_size: u16,

    /// EDNS version supported by the responder
    pub version: u8,
}

impl<'a> RR for OPT<'a> {
    const TYPE_CODE: u16 = 41;
}

impl<'a> PacketPart<'a> for OPT<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        // udp packet size comes from CLASS position
        let udp_packet_size = u16::from_be_bytes(data[position - 8..position - 6].try_into()?);
        let ttl = u32::from_be_bytes(data[position - 6..position - 2].try_into()?);
        let version = ((ttl & masks::VERSION_MASK) >> masks::VERSION_MASK.trailing_zeros()) as u8;

        let code = u16::from_be_bytes(data[position..position + 2].try_into()?);
        let length = u16::from_be_bytes(data[position + 2..position + 4].try_into()?);
        let data = Cow::Borrowed(&data[position + 4..position + 4 + length as usize]);

        Ok(Self {
            code,
            data,
            udp_packet_size,
            version,
        })
    }

    fn append_to_vec(
        &self,
        out: &mut Vec<u8>,
        _name_refs: &mut Option<&mut HashMap<u64, usize>>,
    ) -> crate::Result<()> {
        out.extend(self.code.to_be_bytes());
        out.extend(self.data.len().to_be_bytes());
        out.extend(&self.data[..]);

        Ok(())
    }

    fn len(&self) -> usize {
        self.data.len() + 4
    }
}

impl<'a> OPT<'a> {
    pub(crate) fn extract_rcode_from_ttl(ttl: u32, header: &Header) -> RCODE {
        let mut rcode = (ttl & masks::RCODE_MASK) << 4;
        rcode |= header.response_code as u32;
        RCODE::from(rcode as u16)
    }

    pub(crate) fn encode_ttl(&self, header: &Header) -> u32 {
        let mut ttl: u32 = (header.response_code as u32 & masks::RCODE_MASK) >> 4;
        ttl |= (self.version as u32) << masks::VERSION_MASK.trailing_zeros();
        ttl
    }
    /// Transforms the inner data into it's owned type
    pub fn into_owned<'b>(self) -> OPT<'b> {
        OPT {
            code: self.code,
            // length: self.length,
            udp_packet_size: self.udp_packet_size,
            version: self.version,
            data: self.data.into_owned().into(),
        }
    }
}
