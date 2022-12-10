use std::convert::TryInto;

use crate::{rdata::OPT, ResourceRecord};

use super::{PacketFlag, OPCODE, RCODE};

pub(crate) mod masks {
    pub const OPCODE_MASK: u16 = 0b0111_1000_0000_0000;
    pub const RESERVED_MASK: u16 = 0b0000_0000_0100_0000;
    pub const RESPONSE_CODE_MASK: u16 = 0b0000_0000_0000_1111;
}
/// Contains general information about the packet
#[derive(Debug, Clone)]
pub(crate) struct Header<'a> {
    /// The identification of the packet, must be defined when querying
    pub id: u16,
    /// Indicates the type of query in this packet
    pub opcode: OPCODE,
    /// [RCODE](`RCODE`) indicates the response code for this packet
    pub response_code: RCODE,

    pub z_flags: PacketFlag,

    pub opt: Option<OPT<'a>>,
}

impl<'a> Header<'a> {
    /// Creates a new header for a query packet
    pub fn new_query(id: u16) -> Self {
        Self {
            id,
            opcode: OPCODE::StandardQuery,
            response_code: RCODE::NoError,
            z_flags: PacketFlag::empty(),
            opt: None,
        }
    }

    /// Creates a new header for a reply packet
    pub fn new_reply(id: u16, opcode: OPCODE) -> Self {
        Self {
            id,
            opcode,
            response_code: RCODE::NoError,
            z_flags: PacketFlag::RESPONSE,
            opt: None,
        }
    }

    pub fn set_flags(&mut self, flags: PacketFlag) {
        self.z_flags |= flags;
    }

    pub fn remove_flags(&mut self, flags: PacketFlag) {
        self.z_flags.remove(flags);
    }

    pub fn has_flags(&self, flags: PacketFlag) -> bool {
        self.z_flags.contains(flags)
    }

    /// Parse a slice of 12 bytes into a Packet header
    pub fn parse(data: &[u8]) -> crate::Result<Self> {
        if data.len() < 12 {
            return Err(crate::SimpleDnsError::InsufficientData);
        }

        let flags = u16::from_be_bytes(data[2..4].try_into()?);
        if flags & masks::RESERVED_MASK != 0 {
            return Err(crate::SimpleDnsError::InvalidHeaderData);
        }

        let header = Self {
            id: u16::from_be_bytes(data[..2].try_into()?),
            opcode: ((flags & masks::OPCODE_MASK) >> masks::OPCODE_MASK.trailing_zeros()).into(),
            response_code: (flags & masks::RESPONSE_CODE_MASK).into(),
            z_flags: PacketFlag { bits: flags },
            opt: None,
        };
        Ok(header)
    }

    /// Writes this header to a buffer of 12 bytes
    pub fn write_to(&self, buffer: &mut [u8]) {
        assert_eq!(12, buffer.len(), "Header buffer must have length of 12");

        buffer[0..2].copy_from_slice(&self.id.to_be_bytes());
        buffer[2..4].copy_from_slice(&self.get_flags().to_be_bytes());
    }

    fn get_flags(&self) -> u16 {
        let mut flags = self.z_flags.bits();

        flags |= (self.opcode as u16) << masks::OPCODE_MASK.trailing_zeros();
        flags |= self.response_code as u16 & masks::RESPONSE_CODE_MASK;

        flags
    }

    pub(crate) fn opt_rr(&self) -> Option<ResourceRecord> {
        self.opt.as_ref().map(|opt| {
            ResourceRecord::new(
                crate::Name::new_unchecked("."),
                crate::CLASS::IN,
                opt.encode_ttl(self),
                crate::rdata::RData::OPT(opt.clone()),
            )
        })
    }

    pub(crate) fn extract_info_from_opt_rr(&mut self, opt_rr: Option<ResourceRecord<'a>>) {
        if let Some(opt) = opt_rr {
            self.response_code = OPT::extract_rcode_from_ttl(opt.ttl, self);
            self.opt = match opt.rdata {
                crate::rdata::RData::OPT(opt) => Some(opt),
                _ => unreachable!(),
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::header_buffer;

    use super::*;

    #[test]
    fn write_example_query() {
        let mut header = Header::new_query(core::u16::MAX);

        header.set_flags(PacketFlag::TRUNCATION | PacketFlag::RECURSION_DESIRED);

        let mut buf = [0u8; 12];
        header.write_to(&mut buf);

        assert_eq!(b"\xff\xff\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00", &buf);
    }

    #[test]
    fn parse_example_query() {
        let buffer = b"\xff\xff\x03\x00\x00\x02\x00\x02\x00\x02\x00\x02";
        let header = Header::parse(&buffer[..]).unwrap();

        assert_eq!(core::u16::MAX, header.id);
        assert_eq!(OPCODE::StandardQuery, header.opcode);
        assert!(!header.has_flags(
            PacketFlag::AUTHORITATIVE_ANSWER
                | PacketFlag::RECURSION_AVAILABLE
                | PacketFlag::RESPONSE
        ));
        assert!(header.has_flags(PacketFlag::TRUNCATION | PacketFlag::RECURSION_DESIRED));
        assert_eq!(RCODE::NoError, header.response_code);
        assert_eq!(2, header_buffer::additional_records(&buffer[..]).unwrap());
        assert_eq!(2, header_buffer::answers(&buffer[..]).unwrap());
        assert_eq!(2, header_buffer::name_servers(&buffer[..]).unwrap());
        assert_eq!(2, header_buffer::questions(&buffer[..]).unwrap());
    }

    #[test]
    fn read_write_questions_count() {
        let mut buffer = [0u8; 12];
        header_buffer::set_questions(&mut buffer, 1);
        assert_eq!(1, header_buffer::questions(&buffer).unwrap());
    }

    #[test]
    fn read_write_answers_count() {
        let mut buffer = [0u8; 12];
        header_buffer::set_answers(&mut buffer, 1);
        assert_eq!(1, header_buffer::answers(&buffer).unwrap());
    }

    #[test]
    fn read_write_name_servers_count() {
        let mut buffer = [0u8; 12];
        header_buffer::set_name_servers(&mut buffer, 1);
        assert_eq!(1, header_buffer::name_servers(&buffer).unwrap());
    }

    #[test]
    fn read_write_additional_records_count() {
        let mut buffer = [0u8; 12];
        header_buffer::set_additional_records(&mut buffer, 1);
        assert_eq!(1, header_buffer::additional_records(&buffer).unwrap());
    }

    #[test]
    fn big_rcode_doesnt_break_header() {
        let mut header = Header::new_reply(1, OPCODE::StandardQuery);
        header.response_code = RCODE::BADVERS;

        let mut buffer = [0u8; 12];
        header.write_to(&mut buffer[..]);

        assert_ne!(RCODE::BADVERS, header_buffer::rcode(&buffer[..]).unwrap());

        let header = Header::parse(&buffer[..]).expect("Header parsing failed");
        assert_eq!(RCODE::NoError, header.response_code);
        assert!(header.has_flags(PacketFlag::RESPONSE));
    }
}
