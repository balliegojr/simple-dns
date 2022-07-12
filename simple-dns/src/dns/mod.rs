//! Provides parsing and manipulation for DNS packets

mod character_string;
mod name;
mod packet;
mod packet_header;
mod packet_part;
mod question;
pub mod rdata;
mod resource_record;

pub use rdata::TYPE;
use std::convert::TryFrom;

pub use character_string::CharacterString;
pub use name::Name;
pub use packet::{Packet, PacketBuf, QuestionsIter};
pub use packet_header::PacketHeader;
use packet_part::PacketPart;
pub use question::Question;
pub use resource_record::ResourceRecord;

const MAX_LABEL_LENGTH: usize = 63;
const MAX_NAME_LENGTH: usize = 255;
const MAX_CHARACTER_STRING_LENGTH: usize = 255;
const MAX_NULL_LENGTH: usize = 65535;

// /// The maximum DNS packet size is 9000 bytes less the maximum
// /// sizes of the IP (60) and UDP (8) headers.
// // const MAX_PACKET_SIZE: usize = 9000 - 68;

/// Possible QTYPE values for a Question in a DNS packet  
/// Each value is described according to its own RFC
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum QTYPE {
    /// Query for the specific [TYPE]
    TYPE(TYPE),
    /// A request for incremental transfer of a zone. [RFC 1995](https://tools.ietf.org/html/rfc1995)
    IXFR,
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
            251 => Ok(QTYPE::IXFR),
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
            QTYPE::IXFR => 251,
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
    /// Query for the specific [CLASS]
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
    /// Notify query
    Notify = 4,
    /// Reserved opcode for future use
    Reserved,
}

impl From<u16> for OPCODE {
    fn from(code: u16) -> Self {
        match code {
            0 => OPCODE::StandardQuery,
            1 => OPCODE::InverseQuery,
            2 => OPCODE::ServerStatusRequest,
            4 => OPCODE::Notify,
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
