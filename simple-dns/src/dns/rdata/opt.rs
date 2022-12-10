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

/// OPT is a pseudo-rr used to carry control information  
/// If an OPT record is present in a received request, responders MUST include an OPT record in their respective responses.  
/// OPT RRs MUST NOT be cached, forwarded, or stored in or loaded from master files.  
///
/// There must be only one OPT record in the message.
/// If a query message with more than one OPT RR is received, a FORMERR (RCODE=1) MUST be returned.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct OPT<'a> {
    /// The variable part of this OPT RR
    pub opt_codes: Vec<OPTCode<'a>>,
    /// UDP packet size supported by the responder
    pub udp_packet_size: u16,

    /// EDNS version supported by the responder
    pub version: u8,
}

impl<'a> RR for OPT<'a> {
    const TYPE_CODE: u16 = 41;
}

impl<'a> PacketPart<'a> for OPT<'a> {
    fn parse(data: &'a [u8], mut position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        if position < 8 {
            return Err(crate::SimpleDnsError::InsufficientData);
        }

        // udp packet size comes from CLASS
        let udp_packet_size = u16::from_be_bytes(data[position - 8..position - 6].try_into()?);
        // version comes from ttl
        let ttl = u32::from_be_bytes(data[position - 6..position - 2].try_into()?);
        let version = ((ttl & masks::VERSION_MASK) >> masks::VERSION_MASK.trailing_zeros()) as u8;

        let mut opt_codes = Vec::new();
        while position < data.len() {
            if position + 4 > data.len() {
                return Err(crate::SimpleDnsError::InsufficientData);
            }

            let code = u16::from_be_bytes(data[position..position + 2].try_into()?);
            let length = u16::from_be_bytes(data[position + 2..position + 4].try_into()?) as usize;

            if position + 4 + length > data.len() {
                return Err(crate::SimpleDnsError::InsufficientData);
            }

            let inner_data = Cow::Borrowed(&data[position + 4..position + 4 + length]);

            opt_codes.push(OPTCode {
                code,
                data: inner_data,
            });

            position += 4 + length as usize;
        }

        Ok(Self {
            opt_codes,
            udp_packet_size,
            version,
        })
    }

    fn append_to_vec(
        &self,
        out: &mut Vec<u8>,
        _name_refs: &mut Option<&mut HashMap<u64, usize>>,
    ) -> crate::Result<()> {
        for code in self.opt_codes.iter() {
            out.extend(code.code.to_be_bytes());
            out.extend((code.data.len() as u16).to_be_bytes());
            out.extend(&code.data[..]);
        }

        Ok(())
    }

    fn len(&self) -> usize {
        self.opt_codes.iter().map(|o| o.data.len() + 4).sum()
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
            // length: self.length,
            udp_packet_size: self.udp_packet_size,
            version: self.version,
            opt_codes: self.opt_codes.into_iter().map(|o| o.into_owned()).collect(),
        }
    }
}

/// Represents the variable part of an OPT rr
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct OPTCode<'a> {
    // TODO: include an OPT_CODE enum???
    /// Assigned by the Expert Review process as defined by the DNSEXT working group and the IESG.
    pub code: u16,
    /// Varies per OPTION-CODE.  MUST be treated as a bit field.
    pub data: Cow<'a, [u8]>,
}

impl<'a> OPTCode<'a> {
    /// Transforms the inner data into it's owned type
    pub fn into_owned<'b>(self) -> OPTCode<'b> {
        OPTCode {
            code: self.code,
            data: self.data.into_owned().into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{rdata::RData, Name, ResourceRecord};

    use super::*;

    #[test]
    fn parse_and_write_opt_empty() {
        let header = Header::new_reply(1, crate::OPCODE::StandardQuery);

        let opt = OPT {
            udp_packet_size: 500,
            version: 2,
            opt_codes: Vec::new(),
        };
        let opt_rr = ResourceRecord {
            ttl: opt.encode_ttl(&header),
            name: Name::new_unchecked("."),
            class: crate::CLASS::IN,
            cache_flush: false,
            rdata: RData::OPT(opt),
        };

        let mut data = Vec::new();
        assert!(opt_rr.append_to_vec(&mut data, &mut None).is_ok());

        let opt = match ResourceRecord::parse(&data, 0)
            .expect("failed to parse")
            .rdata
        {
            RData::OPT(rdata) => rdata,
            _ => unreachable!(),
        };

        assert_eq!(data.len(), opt_rr.len());
        assert_eq!(500, opt.udp_packet_size);
        assert_eq!(2, opt.version);
        assert!(opt.opt_codes.is_empty());
    }

    #[test]
    fn parse_and_write_opt() {
        let header = Header::new_reply(1, crate::OPCODE::StandardQuery);

        let opt = OPT {
            udp_packet_size: 500,
            version: 2,
            opt_codes: vec![
                OPTCode {
                    code: 1,
                    data: Cow::Owned(vec![255, 255]),
                },
                OPTCode {
                    code: 2,
                    data: Cow::Owned(vec![255, 255, 255]),
                },
            ],
        };

        let opt_rr = ResourceRecord {
            ttl: opt.encode_ttl(&header),
            name: Name::new_unchecked("."),
            class: crate::CLASS::IN,
            cache_flush: false,
            rdata: RData::OPT(opt),
        };

        let mut data = Vec::new();
        assert!(opt_rr.append_to_vec(&mut data, &mut None).is_ok());

        let mut opt = match ResourceRecord::parse(&data, 0)
            .expect("failed to parse")
            .rdata
        {
            RData::OPT(rdata) => rdata,
            _ => unreachable!(),
        };

        assert_eq!(data.len(), opt_rr.len());
        assert_eq!(500, opt.udp_packet_size);
        assert_eq!(2, opt.version);
        assert_eq!(2, opt.opt_codes.len());

        let opt_code = opt.opt_codes.pop().unwrap();
        assert_eq!(2, opt_code.code);
        assert_eq!(vec![255, 255, 255], *opt_code.data);

        let opt_code = opt.opt_codes.pop().unwrap();
        assert_eq!(1, opt_code.code);
        assert_eq!(vec![255, 255], *opt_code.data);
    }

    // #[test]
    // fn parse_sample() -> Result<(), Box<dyn std::error::Error>> {
    //     let sample_file = std::fs::read("samples/zonefile/OPT.sample")?;
    //
    //     let sample_rdata = match ResourceRecord::parse(&sample_file, 0)?.rdata {
    //         RData::OPT(rdata) => rdata,
    //         _ => unreachable!(),
    //     };
    //
    //     Ok(())
    // }
}
