#![warn(missing_docs)]

//! Pure Rust implementation to work with DNS packets
//!
//! You can parse or write a DNS packet by using [`Packet`] or [`PacketBuf`] structs
//!
//! ## Packet
//! Packet holds references for the original data and it is more suitable for situations where
//! you need to manipulate the packet before generating the final bytes buffer
//!
//! ```rust
//! # use simple_dns::*;
//! # use simple_dns::rdata::*;
//! let question = Question::new(Name::new_unchecked("_srv._udp.local"), QTYPE::TXT, QCLASS::IN, false);
//! let resource = ResourceRecord::new(Name::new_unchecked("_srv._udp.local"), CLASS::IN, 10, RData::A(A { address: 10 }));
//!
//! let mut packet = Packet::new_query(1, false);
//! packet.questions.push(question);
//! packet.additional_records.push(resource);
//!
//! let bytes = packet.build_bytes_vec();
//! assert!(bytes.is_ok());
//! ```
//! It doesn't matter what order the resources are added, the packet will be built only when `build_bytes_vec` is called
//!
//! To parse the contents of a buffer into a packet, you need call call [Packet::parse]
//! ```rust
//! # use simple_dns::Packet;
//!
//! let bytes = b"\x00\x03\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";
//! let packet = Packet::parse(&bytes[..]);
//! assert!(packet.is_ok());
//! ```
//!
//! ## PacketBuf
//! PacketBuf holds an internal buffer that is populated right when a resource is added.  
//! It DOES matter the order in which the resources are added
//!
//! ```rust
//! # use simple_dns::*;
//! # use simple_dns::rdata::*;
//! let question = Question::new(Name::new_unchecked("_srv._udp.local"), QTYPE::TXT, QCLASS::IN, false);
//! let resource = ResourceRecord::new(Name::new_unchecked("_srv._udp.local"), CLASS::IN, 10, RData::A(A { address: 10 }));
//!
//! let mut packet = PacketBuf::new(PacketHeader::new_query(1, false));
//! assert!(packet.add_answer(&resource).is_ok());
//! assert!(packet.add_question(&question).is_err()); //This will fail, since an answer is already added
//! ```
//!
//! It is possible to create a `PacketBuf` from a buffer by calling [`PacketBuf::from`], but be aware that this will clone the contents from the buffer

mod dns;

pub use dns::*;
use thiserror::Error;

/// Alias type for Result<T, SimpleDnsError>;
pub type Result<T> = std::result::Result<T, SimpleDnsError>;

/// Error types for SimpleDns
#[derive(Debug, Error)]
pub enum SimpleDnsError {
    /// Invalid value for CLASS type
    #[error("Provided class is invalid: {0}")]
    InvalidClass(u16),
    /// Invalid value for QCLASS type
    #[error("Provided Qclass is invalid: {0}")]
    InvalidQClass(u16),
    /// Invalid value for QTYPE type
    #[error("Provided QType is invalid: {0}")]
    InvalidQType(u16),
    /// Service Name doesn't follow RFC rules
    #[error("Provided service name is not valid")]
    InvalidServiceName,
    /// Service Name Label doesn't follow RFC rules
    #[error("Provied service name contains invalid label")]
    InvalidServiceLabel,
    /// Character String doesn't follow RFC rules
    #[error("Provided character string is not valid")]
    InvalidCharacterString,
    /// Provided data is not valid for a header
    #[error("Provided header information is invalid")]
    InvalidHeaderData,
    /// Provided data is not valid for a DNS Packet
    #[error("Provided information is not a valid DNS packet")]
    InvalidDnsPacket,
}
