#![warn(missing_docs)]
#![doc = include_str!("../README.md")]
// #![no_std]
// #[cfg(feature = "std")]
// extern crate std;
#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(feature = "alloc")]
extern crate alloc;

mod bytes_buffer;
mod dns;
mod simple_dns_error;
mod write;

pub use simple_dns_error::SimpleDnsError;

pub use dns::*;

mod lib {
    mod core {
        #[cfg(not(feature = "std"))]
        pub use core::*;
        #[cfg(feature = "std")]
        pub use std::*;
    }

    pub use self::core::net::Ipv4Addr;
    pub use self::core::net::Ipv6Addr;

    #[cfg(all(feature = "alloc", not(feature = "std")))]
    pub use alloc::borrow::{Cow, ToOwned};
    #[cfg(feature = "std")]
    pub use std::borrow::{Cow, ToOwned};

    #[cfg(all(feature = "alloc", not(feature = "std")))]
    pub use alloc::string::{FromUtf8Error, String, ToString};
    #[cfg(feature = "std")]
    pub use std::string::{FromUtf8Error, String, ToString};

    #[cfg(all(feature = "alloc", not(feature = "std")))]
    pub use alloc::vec::Vec;
    #[cfg(feature = "std")]
    pub use std::vec::Vec;

    #[cfg(all(feature = "alloc", not(feature = "std")))]
    pub use alloc::vec;
    #[cfg(feature = "std")]
    pub use std::vec;

    #[cfg(all(feature = "alloc", not(feature = "std")))]
    pub use alloc::boxed::Box;
    #[cfg(feature = "std")]
    pub use std::boxed::Box;

    #[cfg(all(feature = "alloc", not(feature = "std")))]
    pub use std::collections::BTreeMap;
    #[cfg(feature = "std")]
    pub use std::collections::BTreeMap;

    #[cfg(all(feature = "alloc", not(feature = "std")))]
    pub use std::collections::BTreeSet;
    #[cfg(feature = "std")]
    pub use std::collections::BTreeSet;

    pub use self::core::array::TryFromSliceError;
    pub use self::core::error::Error;
    pub use self::core::result::Result;

    pub use self::core::convert::TryFrom;

    pub mod fmt {
        pub use super::core::fmt::*;
    }

    pub mod str {
        pub use super::core::str::*;
    }
}

/// Alias type for Result<T, SimpleDnsError>;
pub type Result<T> = lib::Result<T, SimpleDnsError>;

#[allow(missing_docs)]
#[doc(hidden)]
#[cfg(debug_assertions)]
pub mod testing {
    use super::rdata::RR;
    use super::WireFormat;
    use crate::lib::Vec;

    #[allow(private_bounds)]
    pub fn type_code<T: RR>() -> u16 {
        T::TYPE_CODE
    }

    #[allow(private_bounds)]
    pub fn parse<'a, T: WireFormat<'a>>(bytes: &'a [u8]) -> T {
        let mut data = crate::bytes_buffer::BytesBuffer::new(bytes);
        T::parse(&mut data).expect("Failed to parse")
    }

    #[allow(private_bounds)]
    pub fn get_bytes<'a, T: WireFormat<'a>>(data: T) -> Vec<u8> {
        let mut bytes = Vec::new();
        data.write_to(&mut bytes).expect("Failed to write to vec");
        bytes
    }
}
