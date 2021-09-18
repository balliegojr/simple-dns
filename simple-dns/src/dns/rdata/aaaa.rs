use crate::dns::DnsPacketContent;
use std::{convert::TryInto, net::Ipv6Addr};

/// Represents a Resource Address (IPv6) [rfc3596](https://tools.ietf.org/html/rfc3596)
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct AAAA {
    /// a 128 bit ip address
    pub address: u128,
}

impl<'a> DnsPacketContent<'a> for AAAA {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let address = u128::from_be_bytes(data[position..position + 16].try_into()?);
        Ok(Self { address })
    }

    fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        out.extend(self.address.to_be_bytes());
        Ok(())
    }

    fn len(&self) -> usize {
        16
    }
}

impl From<Ipv6Addr> for AAAA {
    fn from(ip: Ipv6Addr) -> Self {
        Self { address: ip.into() }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv6Addr, str::FromStr};

    use super::*;

    #[test]
    fn parse_and_write_a() {
        let address = std::net::Ipv6Addr::from_str("FF02::FB").unwrap();
        let a = AAAA {
            address: address.into(),
        };

        let mut bytes = Vec::new();
        assert!(a.append_to_vec(&mut bytes).is_ok());

        let a = AAAA::parse(&bytes, 0);
        assert!(a.is_ok());
        let a = a.unwrap();

        assert_eq!(address, Ipv6Addr::from(a.address));
        assert_eq!(bytes.len(), a.len());
    }
}
