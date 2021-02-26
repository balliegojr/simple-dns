mod packet_header;
mod packet;
mod question;
mod name;
mod resource_record;
mod rdata;

use std::{convert::TryFrom };

pub use packet_header::PacketHeader;
pub use packet::Packet;
pub use question::Question;
pub use name::Name;
pub use resource_record::ResourceRecord;
pub use rdata::{RData, RawRData};

const MAX_LABEL_LENGTH: usize = 63;
const MAX_NAME_LENGTH: usize = 255;

/// DNS TXT records can have up to 255 characters as a single string value.
///
/// Current values are usually around 170-190 bytes long, varying primarily
/// with the length of the contained `Multiaddr`.
const MAX_TXT_VALUE_LENGTH: usize = 255;

/// A conservative maximum size (in bytes) of a complete TXT record,
/// as encoded by [`append_txt_record`].
const MAX_TXT_RECORD_SIZE: usize = MAX_TXT_VALUE_LENGTH + 45;

/// The maximum DNS packet size is 9000 bytes less the maximum
/// sizes of the IP (60) and UDP (8) headers.
const MAX_PACKET_SIZE: usize = 9000 - 68;

/// A conservative maximum number of records that can be packed into
/// a single DNS UDP packet, allowing up to 100 bytes of MDNS packet
/// header data to be added by [`query_response_packet()`].
const MAX_RECORDS_PER_PACKET: usize = (MAX_PACKET_SIZE - 100) / MAX_TXT_RECORD_SIZE;

pub trait DnsPacketContent<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self> where Self: Sized;
    
    fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()>;
    fn len(&self) -> usize;
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TYPE {
    A, // a host address
    NS, // an authoritative name server
    MD, // a mail destination (Obsolete - use MX)
    MF, // a mail forwarder (Obsolete - use MX)
    CNAME, // the canonical name for an alias
    SOA, // marks the start of a zone of authority
    MB, // a mailbox domain name (EXPERIMENTAL)
    MG, // a mail group member (EXPERIMENTAL)
    MR, // a mail rename domain name (EXPERIMENTAL)
    NULL, // a null RR (EXPERIMENTAL)
    WKS, // a well known service description
    PTR, // a domain name pointer
    HINFO, // host information
    MINFO, // mailbox or mail list information
    MX, // mail exchange
    TXT, // text strings
    Unknown(u16)
}

impl From<TYPE> for u16 {
    fn from(value: TYPE) -> Self {
        match value {
            TYPE::A => 1,
            TYPE::NS => 2,
            TYPE::MD => 3,
            TYPE::MF => 4,
            TYPE::CNAME => 5,
            TYPE::SOA => 6,
            TYPE::MB => 7,
            TYPE::MG => 8,
            TYPE::MR => 9,
            TYPE::NULL => 10,
            TYPE::WKS => 11,
            TYPE::PTR => 12,
            TYPE::HINFO => 13,
            TYPE::MINFO => 14,
            TYPE::MX => 15,
            TYPE::TXT => 16,
            TYPE::Unknown(x) => x
        }
    }
}

impl From<u16> for TYPE {
    fn from(value: u16) -> Self {
        use self::TYPE::*;

        match value {
            1 => A,
            2 => NS,
            3 => MD,
            4 => MF,
            5 => CNAME,
            6 => SOA,
            7 => MB,
            8 => MG,
            9 => MR,
            10 => NULL,
            11 => WKS,
            12 => PTR,
            13 => HINFO,
            14 => MINFO,
            15 => MX,
            16 => TXT,
            v => TYPE::Unknown(v)
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum QTYPE {
    A = 1, // a host address
    NS =  2, // an authoritative name server
    MD =  3, // a mail destination (Obsolete - use MX)
    MF =  4, // a mail forwarder (Obsolete - use MX)
    CNAME =  5, // the canonical name for an alias
    SOA =  6, // marks the start of a zone of authority
    MB =  7, // a mailbox domain name (EXPERIMENTAL)
    MG =  8, // a mail group member (EXPERIMENTAL)
    MR =  9, // a mail rename domain name (EXPERIMENTAL)
    NULL = 10, // a null RR (EXPERIMENTAL)
    WKS = 11, // a well known service description
    PTR = 12, // a domain name pointer
    HINFO = 13, // host information
    MINFO = 14, // mailbox or mail list information
    MX = 15, // mail exchange
    TXT = 16, // text strings
    AXFR = 252, // A request for a transfer of an entire zone
    MAILB = 253, // A request for mailbox-related records (MB, MG or MR)
    MAILA = 254, // A request for mail agent RRs (Obsolete - see MX)
    ANY = 255, // A request for all records
}

impl TryFrom<u16> for QTYPE {
    type Error = crate::SimpleDnsError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        use self::QTYPE::*;

        match value {
            1 => Ok(A),
            2 => Ok(NS),
            3 => Ok(MD),
            4 => Ok(MF),
            5 => Ok(CNAME),
            6 => Ok(SOA),
            7 => Ok(MB),
            8 => Ok(MG),
            9 => Ok(MR),
            10 => Ok(NULL),
            11 => Ok(WKS),
            12 => Ok(PTR),
            13 => Ok(HINFO),
            14 => Ok(MINFO),
            15 => Ok(MX),
            16 => Ok(TXT),
            252 => Ok(AXFR),
            253 => Ok(MAILB),
            254 => Ok(MAILA),
            255 => Ok(ANY),
            v => Err(Self::Error::InvalidQType(v))
        }

    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum  CLASS {
    IN = 1, // the Internet
    CS = 2, // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CH = 3, // the CHAOS class
    HS = 4, // Hesiod [Dyer 87]
}

impl TryFrom<u16> for CLASS {
    type Error = crate::SimpleDnsError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        use self::CLASS::*;
        match value {
            1 => Ok(IN),
            2 => Ok(CS),
            3 => Ok(CH),
            4 => Ok(HS),
            v => Err(Self::Error::InvalidClass(v))
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum QCLASS {
    IN = 1, // the Internet
    CS = 2, // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CH = 3, // the CHAOS class
    HS = 4, // Hesiod [Dyer 87],
    ANY = 255
}

impl TryFrom<u16> for QCLASS {
    type Error = crate::SimpleDnsError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        use self::QCLASS::*;
        match value {
            1 => Ok(IN),
            2 => Ok(CS),
            3 => Ok(CH),
            4 => Ok(HS),
            255 => Ok(ANY),
            v => Err(Self::Error::InvalidQClass(v))
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum OPCODE {
    /// Normal query
    StandardQuery = 0,
    /// Inverse query (query a name by IP)
    InverseQuery = 1,
    /// Server status request
    ServerStatusRequest = 2,
    /// Reserved opcode for future use
    Reserved,
}

impl From<u16> for OPCODE {
    fn from(code: u16) -> Self {
        match code {
            0 => OPCODE::StandardQuery,
            1 => OPCODE::InverseQuery,
            2 => OPCODE::ServerStatusRequest,
            _ => OPCODE::Reserved
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum RCODE {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
    Reserved
}

impl From<u16> for RCODE {
    fn from(code: u16) -> Self {
        match code {
            0  => RCODE::NoError,
            1  => RCODE::FormatError,
            2  => RCODE::ServerFailure,
            3  => RCODE::NameError,
            4  => RCODE::NotImplemented,
            5  => RCODE::Refused,
            _  => RCODE::Reserved,
        }
    }
}