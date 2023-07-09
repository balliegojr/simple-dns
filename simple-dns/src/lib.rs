#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

mod dns;
pub mod master;
mod simple_dns_error;

pub use dns::*;
pub use simple_dns_error::SimpleDnsError;

/// Alias type for Result<T, SimpleDnsError>;
pub type Result<T> = std::result::Result<T, SimpleDnsError>;
