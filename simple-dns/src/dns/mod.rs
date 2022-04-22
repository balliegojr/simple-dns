//! Provides parsing and manipulation for DNS packets

mod character_string;
mod name;
mod packet;
mod packet_header;
mod question;
pub mod rdata;
mod resource_record;

use std::{collections::HashMap, convert::TryFrom};

pub use character_string::CharacterString;
pub use name::Name;
pub use packet::{Packet, PacketBuf, QuestionsIter};
pub use packet_header::PacketHeader;
pub use question::Question;
pub use resource_record::ResourceRecord;

const MAX_LABEL_LENGTH: usize = 63;
const MAX_NAME_LENGTH: usize = 255;
const MAX_CHARACTER_STRING_LENGTH: usize = 255;
const MAX_NULL_LENGTH: usize = 65535;

/// The maximum DNS packet size is 9000 bytes less the maximum
/// sizes of the IP (60) and UDP (8) headers.
// const MAX_PACKET_SIZE: usize = 9000 - 68;

/// Represents anything that can be part of a dns packet (Question, Resource Record, RData)
pub(crate) trait DnsPacketContent<'a> {
    /// Parse the contents of the data buffer begining in the given position
    /// It is necessary to pass the full buffer to this function, to be able to correctly implement name compression
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized;

    /// Append the bytes of this content to a given vector
    fn append_to_vec(
        &self,
        out: &mut Vec<u8>,
        name_refs: &mut Option<&mut HashMap<u64, usize>>,
    ) -> crate::Result<()>;

    /// Returns the length in bytes of this content
    fn len(&self) -> usize;
}

/// Possible TYPE values in DNS Resource Records  
/// Each value is described according to its own RFC
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum TYPE {
    /// Host address, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    A,
    /// Host address (IPv6) [rfc3596](https://tools.ietf.org/html/rfc3596)
    AAAA,
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
    /// RP Responsible Person, [RFC 1183](https://datatracker.ietf.org/doc/html/rfc1183#section-2.2)
    RP,
    /// AFS locator, [RFC 1183](https://datatracker.ietf.org/doc/html/rfc1183#section-1)
    AFSDB,
    /// X.25 address, [RFC 1183](https://datatracker.ietf.org/doc/html/rfc1183#section-3.1)
    X25,
    /// ISDN address, [RFC 1183](https://datatracker.ietf.org/doc/html/rfc1183#section-3.2)
    ISDN,
    /// The RT resource record provides a route-through binding for hosts that do not have their own direct wide area network addresses
    /// [RFC 1183](https://datatracker.ietf.org/doc/html/rfc1183#section-3.3)
    RouteThrough,
    /// SRV specifies the location of the server(s) for a specific protocol and domain. [RFC 2780](https://tools.ietf.org/html/rfc2782)
    SRV,
    /// Unknown value, for future (or unimplemented RFC) compatibility
    Unknown(u16),
}

impl From<TYPE> for u16 {
    fn from(value: TYPE) -> Self {
        match value {
            TYPE::A => 1,
            TYPE::AAAA => 28,
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
            TYPE::RP => 17,
            TYPE::AFSDB => 18,
            TYPE::X25 => 19,
            TYPE::ISDN => 20,
            TYPE::RouteThrough => 21,
            TYPE::SRV => 33,
            TYPE::Unknown(x) => x,
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
            17 => RP,
            18 => AFSDB,
            19 => X25,
            20 => ISDN,
            21 => RouteThrough,
            28 => AAAA,
            33 => SRV,
            v => TYPE::Unknown(v),
        }
    }
}

/// Possible QTYPE values for a Question in a DNS packet  
/// Each value is described according to its own RFC
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum QTYPE {
    TYPE(TYPE),
    /// A request for a transfer of an entire zone, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    AXFR,
    /// A request for mailbox-related records (MB, MG or MR), [RFC 1035](https://tools.ietf.org/html/rfc1035)
    MAILB,
    /// A request for mail agent RRs (Obsolete - see MX), [RFC 1035](https://tools.ietf.org/html/rfc1035)
    MAILA,
    /// A request for all records, [RFC 1035](https://tools.ietf.org/html/rfc1035)
    ANY,
}

impl From<TYPE> for QTYPE {
    fn from(v: TYPE) -> Self {
        Self::TYPE(v)
    }
}

impl TryFrom<u16> for QTYPE {
    type Error = crate::SimpleDnsError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            252 => Ok(QTYPE::AXFR),
            253 => Ok(QTYPE::MAILB),
            254 => Ok(QTYPE::MAILA),
            255 => Ok(QTYPE::ANY),
            v => match TYPE::from(v) {
                TYPE::Unknown(_) => Err(Self::Error::InvalidQType(v)),
                ty => Ok(ty.into()),
            },
        }
    }
}

impl From<QTYPE> for u16 {
    fn from(val: QTYPE) -> Self {
        match val {
            QTYPE::TYPE(ty) => ty.into(),
            QTYPE::AXFR => 252,
            QTYPE::MAILB => 253,
            QTYPE::MAILA => 254,
            QTYPE::ANY => 255,
        }
    }
}

/// Possible CLASS values for a Resource in a DNS packet  
/// Each value is described according to its own RFC
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum CLASS {
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
            v => Err(Self::Error::InvalidClass(v)),
        }
    }
}

/// Possible QCLASS values for a Question in a DNS packet  
/// Each value is described according to its own RFC
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum QCLASS {
    CLASS(CLASS),
    /// [RFC 1035](https://tools.ietf.org/html/rfc1035)
    ANY,
}

impl From<CLASS> for QCLASS {
    fn from(v: CLASS) -> Self {
        Self::CLASS(v)
    }
}

impl TryFrom<u16> for QCLASS {
    type Error = crate::SimpleDnsError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            v @ 1..=5 => CLASS::try_from(v).map(|x| x.into()),
            255 => Ok(QCLASS::ANY),
            v => Err(Self::Error::InvalidQClass(v)),
        }
    }
}

impl From<QCLASS> for u16 {
    fn from(val: QCLASS) -> Self {
        match val {
            QCLASS::CLASS(class) => class as u16,
            QCLASS::ANY => 255,
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
            _ => OPCODE::Reserved,
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
    Reserved,
}

impl From<u16> for RCODE {
    fn from(code: u16) -> Self {
        match code {
            0 => RCODE::NoError,
            1 => RCODE::FormatError,
            2 => RCODE::ServerFailure,
            3 => RCODE::NameError,
            4 => RCODE::NotImplemented,
            5 => RCODE::Refused,
            _ => RCODE::Reserved,
        }
    }
}
