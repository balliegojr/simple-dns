use std::{collections::HashMap, net::Ipv6Addr};

use byteorder::{BigEndian, ByteOrder};

use crate::dns::DnsPacketContent;

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
        let address = BigEndian::read_u128(&data[position..position + 16]);
        Ok(Self { address })
    }

    fn append_to_vec(
        &self,
        out: &mut Vec<u8>,
        _name_refs: &mut HashMap<u64, usize>,
    ) -> crate::Result<()> {
        let mut buf = [0u8; 16];
        BigEndian::write_u128(&mut buf[..], self.address);

        out.extend(&buf);

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
        let mut name_refs = HashMap::new();
        assert!(a.append_to_vec(&mut bytes, &mut name_refs).is_ok());

        let a = AAAA::parse(&bytes, 0);
        assert!(a.is_ok());
        let a = a.unwrap();

        assert_eq!(address, Ipv6Addr::from(a.address));
        assert_eq!(bytes.len(), a.len());
    }
}
