#![warn(missing_docs)]
#![allow(upper_case_acronyms)]

//! Pure Rust implementation to work with DNS packets
//!
//! You can parse or write a DNS packet by using the [`Packet`] struct
//!
//! ```rust
//! use simple_dns::Packet;
//!
//! let bytes = b"\x00\x03\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";
//! let packet = Packet::parse(&bytes[..]);
//! assert!(packet.is_ok());
//! ```

mod dns;

use std::{error::Error, fmt::Display};
pub use dns::*;

/// Alias type for Result<T, SimpleDnsError>;
pub type Result<T> = std::result::Result<T, SimpleDnsError>;

/// Error types for SimpleDns
#[derive(Debug)]
pub enum SimpleDnsError {
    /// Invalid value for CLASS type
    InvalidClass(u16),
    /// Invalid value for QCLASS type
    InvalidQClass(u16),
    /// Invalid value for QTYPE type
    InvalidQType(u16),
    /// Service Name doesn't follow RFC rules
    InvalidServiceName,
    /// Service Name Label doesn't follow RFC rules
    InvalidServiceLabel,
    /// Character String doesn't follow RFC rules
    InvalidCharacterString,
    /// Provided data is not valid for a header
    InvalidHeaderData,
    /// Provided data is not valid for a DNS Packet
    InvalidDnsPacket,
}

impl Error for SimpleDnsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl Display for SimpleDnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SimpleDnsError::InvalidClass(class) => write!(f, "Provided class is invalid: {}", class),
            SimpleDnsError::InvalidQClass(qclass) => write!(f, "Provided Qclass is invalid: {}", qclass),
            SimpleDnsError::InvalidQType(qtype) => write!(f, "Provided QType is invalid: {}", qtype),
            SimpleDnsError::InvalidServiceName => write!(f, "Provided service name is not valid"),
            SimpleDnsError::InvalidServiceLabel => write!(f, "Provied service name contains invalid label"),
            SimpleDnsError::InvalidCharacterString => write!(f, "Provided character string is not valid"),
            SimpleDnsError::InvalidHeaderData => write!(f, "Provided header information is invalid"),
            SimpleDnsError::InvalidDnsPacket => write!(f, "Provided information is not a valid DNS packet")
        }
    }
}
