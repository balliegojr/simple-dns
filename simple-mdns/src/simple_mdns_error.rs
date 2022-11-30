use std::{error::Error, fmt::Display};

use simple_dns::SimpleDnsError;

/// Error types for simple-mdns
#[derive(Debug)]
pub enum SimpleMdnsError {
    /// Udp socket related error
    UdpSocketError(std::io::Error),
    /// Simple-dns error related, usually packet parsing
    DnsParsing(SimpleDnsError),
    /// Service discovery is no longer running
    ServiceDiscoveryStopped,
}

impl Error for SimpleMdnsError {}

impl Display for SimpleMdnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SimpleMdnsError::UdpSocketError(err) => {
                write!(f, "There was an error related to UDP socket: {}", err)
            }
            SimpleMdnsError::DnsParsing(err) => {
                write!(f, "Failed to parse dns packet: {}", err)
            }
            SimpleMdnsError::ServiceDiscoveryStopped => {
                write!(f, "Service discovery is no longer running")
            }
        }
    }
}

impl From<std::io::Error> for SimpleMdnsError {
    fn from(err: std::io::Error) -> Self {
        Self::UdpSocketError(err)
    }
}

impl From<SimpleDnsError> for SimpleMdnsError {
    fn from(v: SimpleDnsError) -> Self {
        Self::DnsParsing(v)
    }
}
