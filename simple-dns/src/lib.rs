#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

mod bytes_buffer;
mod dns;
mod simple_dns_error;

pub use simple_dns_error::SimpleDnsError;

pub use dns::*;

/// Alias type for Result<T, SimpleDnsError>;
pub type Result<T> = std::result::Result<T, SimpleDnsError>;

#[allow(missing_docs)]
#[doc(hidden)]
#[cfg(debug_assertions)]
pub mod testing {
    use super::rdata::RR;
    use super::WireFormat;

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
