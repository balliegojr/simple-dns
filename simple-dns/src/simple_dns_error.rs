use std::{array::TryFromSliceError, error::Error, fmt::Display};

/// Error types for SimpleDns
#[derive(Debug, PartialEq, Eq)]
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
    /// Attempted to perform an invalid operation
    AttemptedInvalidOperation,
    /// Incomplete dns packet, should try again after more data available
    InsufficientData,
}

impl From<TryFromSliceError> for SimpleDnsError {
    fn from(_: TryFromSliceError) -> Self {
        Self::InvalidDnsPacket
    }
}

impl Error for SimpleDnsError {}

impl Display for SimpleDnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SimpleDnsError::InvalidClass(class) => {
                write!(f, "Provided class is invalid: {0}", class)
            }
            SimpleDnsError::InvalidQClass(qclass) => {
                write!(f, "Provided Qclass is invalid: {0}", qclass)
            }
            SimpleDnsError::InvalidQType(qtype) => {
                write!(f, "Provided QType is invalid: {0}", qtype)
            }
            SimpleDnsError::InvalidServiceName => write!(f, "Provided service name is not valid"),
            SimpleDnsError::InvalidServiceLabel => {
                write!(f, "Provied service name contains invalid label")
            }
            SimpleDnsError::InvalidCharacterString => {
                write!(f, "Provided character string is not valid")
            }
            SimpleDnsError::InvalidHeaderData => {
                write!(f, "Provided header information is invalid")
            }
            SimpleDnsError::InvalidDnsPacket => {
                write!(f, "Provided information is not a valid DNS packet")
            }
            SimpleDnsError::AttemptedInvalidOperation => {
                write!(f, "Attempted to perform an invalid operation")
            }
            SimpleDnsError::InsufficientData => write!(f, "Incomplete dns packet"),
        }
    }
}
