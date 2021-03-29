//! Provides parsing and manipulation for DNS packets

mod packet_header;
mod packet;
mod question;
mod name;
mod resource_record;
pub mod rdata;
mod character_string;

use std::{convert::TryFrom };

pub use packet_header::PacketHeader;
pub use packet::{Packet, PacketBuf, PacketSectionIter};
pub use question::Question;
pub use name::Name;
pub use resource_record::ResourceRecord;
// pub use rdata::RData;
pub use character_string::CharacterString;

const MAX_LABEL_LENGTH: usize = 63;
const MAX_NAME_LENGTH: usize = 255;
const MAX_CHARACTER_STRING_LENGTH: usize = 255;
const MAX_NULL_LENGTH: usize = 65535;

/// The maximum DNS packet size is 9000 bytes less the maximum
/// sizes of the IP (60) and UDP (8) headers.
// const MAX_PACKET_SIZE: usize = 9000 - 68; 


pub trait DnsPacketContent<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self> where Self: Sized;
    
    fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()>;
    fn len(&self) -> usize;
}

/// Possible TYPE values in DNS Resource Records  
/// Each value is described according to its own RFC
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum TYPE {
    /// Host address, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    A,
    /// Authoritative name server, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    NS,
    /// Mail destination (Obsolete - use MX), [RFC 1035](https://tools.ietf.org/html/rfc1035)
    MD,
    /// Mail forwarder (Obsolete - use MX), [RFC 1035](https://tools.ietf.org/html/rfc1035)
    MF, 
    /// Canonical name for an alias, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    CNAME, 
    /// Marks the start of a zone of authority, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    SOA, 
    /// Mailbox domain name (EXPERIMENTAL), [RFC 1035](https://tools.ietf.org/html/rfc1035)
    MB, 
    /// Mail group member (EXPERIMENTAL), [RFC 1035](https://tools.ietf.org/html/rfc1035)
    MG, 
    /// Mail rename domain name (EXPERIMENTAL), [RFC 1035](https://tools.ietf.org/html/rfc1035)
    MR, 
    /// Null RR (EXPERIMENTAL), [RFC 1035](https://tools.ietf.org/html/rfc1035)
    NULL, 
    /// Well known service description, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    WKS, 
    /// Domain name pointer, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    PTR, 
    /// Host information, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    HINFO, 
    /// Mailbox or mail list information, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    MINFO, 
    /// Mail exchange, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    MX, 
    /// Text strings, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    TXT, 
    /// SRV specifies the location of the server(s) for a specific protocol and domain. [RFC 2780](https://tools.ietf.org/html/rfc2782)
    SRV,
    /// Unknown value, for future (or unimplemented RFC) compatibility
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
            TYPE::SRV => 33,
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
            33 => SRV,
            v => TYPE::Unknown(v)
        }
    }
}

/// Possible QTYPE values for a Question in a DNS packet  
/// Each value is described according to its own RFC
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum QTYPE {
    /// Host address, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    A = 1,
    /// Authoritative name server, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    NS =  2,
    /// Mail destination (Obsolete - use MX), [RFC 1035](https://tools.ietf.org/html/rfc1035)
    MD =  3,
    /// Mail forwarder (Obsolete - use MX), [RFC 1035](https://tools.ietf.org/html/rfc1035)
    MF =  4,
    /// Canonical name for an alias, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    CNAME =  5,
    /// Marks the start of a zone of authority, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    SOA =  6,
    /// Mailbox domain name (EXPERIMENTAL), [RFC 1035](https://tools.ietf.org/html/rfc1035)
    MB =  7,
    /// Mail group member (EXPERIMENTAL), [RFC 1035](https://tools.ietf.org/html/rfc1035)
    MG =  8,
    /// Mail rename domain name (EXPERIMENTAL), [RFC 1035](https://tools.ietf.org/html/rfc1035)
    MR =  9,
    /// Null RR (EXPERIMENTAL), [RFC 1035](https://tools.ietf.org/html/rfc1035)
    NULL = 10,
    /// Well known service description, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    WKS = 11,
    /// Domain name pointer, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    PTR = 12,
    /// Host Information, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    HINFO = 13,
    /// Mailbox or mail list information, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    MINFO = 14,
    /// Mail exchange, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    MX = 15,
    /// Text strings, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    TXT = 16,
    /// SRV specifies the location of the server(s) for a specific protocol and domain. [RFC 2780](https://tools.ietf.org/html/rfc2782)
    SRV = 33,
    /// A request for a transfer of an entire zone, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    AXFR = 252,
    /// A request for mailbox-related records (MB, MG or MR), [RFC 1035](https://tools.ietf.org/html/rfc1035)
    MAILB = 253,
    /// A request for mail agent RRs (Obsolete - see MX), [RFC 1035](https://tools.ietf.org/html/rfc1035)
    MAILA = 254,
    /// A request for all records, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    ANY = 255,
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
            33 => Ok(SRV),
            252 => Ok(AXFR),
            253 => Ok(MAILB),
            254 => Ok(MAILA),
            255 => Ok(ANY),
            v => Err(Self::Error::InvalidQType(v))
        }

    }
}

/// Possible CLASS values for a Resource in a DNS packet  
/// Each value is described according to its own RFC
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum  CLASS {
    /// The Internet, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    IN = 1, 
    /// The CSNET class (Obsolete - used only for examples in some obsolete RFCs), [RFC 1035](https://tools.ietf.org/html/rfc1035)
    CS = 2, 
    /// The CHAOS class, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    CH = 3, 
    /// Hesiod [Dyer 87], [RFC 1035](https://tools.ietf.org/html/rfc1035)
    HS = 4, 
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

/// Possible QCLASS values for a Question in a DNS packet  
/// Each value is described according to its own RFC
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum QCLASS {
    /// The Internet, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    IN = 1, 
    /// The CSNET class (Obsolete - used only for examples in some obsolete RFCs), [RFC 1035](https://tools.ietf.org/html/rfc1035)
    CS = 2, 
    /// The CHAOS class, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    CH = 3, 
    /// Hesiod [Dyer 87], [RFC 1035](https://tools.ietf.org/html/rfc1035)
    HS = 4, 
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035)
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


/// Possible OPCODE values for a DNS packet, use to specify the type of operation.  
/// [RFC 1035](https://tools.ietf.org/html/rfc1035): A four bit field that specifies kind of query in this message.  
/// This value is set by the originator of a query and copied into the response.
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

/// Possible RCODE values for a DNS packet   
/// [RFC 1035](https://tools.ietf.org/html/rfc1035) Response code - this 4 bit field is set as part of responses.  
/// The values have the following interpretation
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum RCODE {
    /// No error condition
    NoError = 0,
    /// Format error - The name server was unable to interpret the query.
    FormatError = 1,
    /// Server failure - The name server was unable to process this query due to a problem with the name server.
    ServerFailure = 2,
    /// Name Error - Meaningful only for responses from an authoritative name server,  
    /// this code signifies that the domain name referenced in the query does not exist.
    NameError = 3,
    /// Not Implemented - The name server does not support the requested kind of query.
    NotImplemented = 4,
    /// Refused - The name server refuses to perform the specified operation for policy reasons.  
    /// For example, a name server may not wish to provide the information to the particular requester,   
    /// or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data. 
    Refused = 5,
    /// Reserved for future use.
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