#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

mod dns;

use std::array::TryFromSliceError;

pub use dns::*;
use thiserror::Error;

/// Alias type for Result<T, SimpleDnsError>;
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
    /// Attempted to perform an invalid operation
    #[error("Attempted to perform an invalid operation")]
    AttemptedInvalidOperation,
    /// Incomplete dns packet, should try again after more data available
    #[error("Incomplete dns packet")]
    NoEnoughData,
}

impl From<TryFromSliceError> for SimpleDnsError {
    fn from(_: TryFromSliceError) -> Self {
        Self::InvalidDnsPacket
    }
}
