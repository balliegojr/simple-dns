use crate::{dns::PacketPart, master::ParseError};
use std::{convert::TryInto, net::Ipv4Addr};

use super::RR;

/// Represents a Resource Address (IPv4)
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct A {
    /// a 32 bit ip address
    pub address: u32,
}

impl<'a> RR<'a> for A {
    const TYPE_CODE: u16 = 1;

    fn try_build(tokens: &[&str], _origin: &crate::Name) -> Result<Self, ParseError> {
        let address = tokens.first().ok_or(ParseError::UnexpectedEndOfInput)?;

        address
            .parse()
            .map(|address: Ipv4Addr| A {
                address: address.into(),
            })
            .map_err(|_| ParseError::InvalidToken(address.to_string()))
    }
}

impl<'a> PacketPart<'a> for A {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let address = u32::from_be_bytes(data[position..position + 4].try_into()?);
        Ok(Self { address })
    }

    fn write_to<T: std::io::Write>(&self, out: &mut T) -> crate::Result<()> {
        out.write_all(&self.address.to_be_bytes())
            .map_err(crate::SimpleDnsError::from)
    }

    fn len(&self) -> usize {
        4
    }
}

impl A {
    /// Transforms the inner data into it's owned type
    pub fn into_owned(self) -> Self {
        self
    }
}

impl From<Ipv4Addr> for A {
    fn from(addr: Ipv4Addr) -> Self {
        Self {
            address: addr.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{rdata::RData, Name, ResourceRecord};

    use super::*;

    #[test]
    fn parse_and_write_a() {
        let a = A {
            address: 2130706433,
        };

        let mut bytes = Vec::new();
        assert!(a.write_to(&mut bytes).is_ok());

        let a = A::parse(&bytes, 0);
        assert!(a.is_ok());
        let a = a.unwrap();

        assert_eq!(2130706433, a.address);
        assert_eq!(bytes.len(), a.len());
    }

    #[test]
    fn parse_sample() -> Result<(), Box<dyn std::error::Error>> {
        let sample_a = std::fs::read("samples/zonefile/A.sample.A")?;
        let sample_ip: u32 = "26.3.0.103".parse::<Ipv4Addr>()?.into();

        let sample_a_rdata = match ResourceRecord::parse(&sample_a, 0)?.rdata {
            RData::A(a) => a,
            _ => unreachable!(),
        };

        assert_eq!(sample_a_rdata.address, sample_ip);
        Ok(())
    }

    #[test]
    fn test_try_build() {
        assert_eq!(
            Ok(A { address: 0 }),
            A::try_build(&["0.0.0.0"], &Name::new_unchecked("domain.com"))
        )
    }
}
