use crate::dns::PacketPart;
use std::{collections::HashMap, convert::TryInto, net::Ipv6Addr};

use super::RR;

/// Represents a Resource Address (IPv6) [rfc3596](https://tools.ietf.org/html/rfc3596)
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct AAAA {
    /// a 128 bit ip address
    pub address: u128,
}

impl RR for AAAA {
    const TYPE_CODE: u16 = 28;
}

impl<'a> PacketPart<'a> for AAAA {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let address = u128::from_be_bytes(data[position..position + 16].try_into()?);
        Ok(Self { address })
    }

    fn append_to_vec(
        &self,
        out: &mut Vec<u8>,
        _name_refs: &mut Option<&mut HashMap<u64, usize>>,
    ) -> crate::Result<()> {
        out.extend(self.address.to_be_bytes());
        Ok(())
    }

    fn len(&self) -> usize {
        16
    }
}

impl AAAA {
    /// Transforms the inner data into it's owned type
    pub fn into_owned(self) -> Self {
        self
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

    use crate::{rdata::RData, ResourceRecord};

    use super::*;

    #[test]
    fn parse_and_write_a() {
        let address = std::net::Ipv6Addr::from_str("FF02::FB").unwrap();
        let aaaa = AAAA {
            address: address.into(),
        };

        let mut bytes = Vec::new();
        assert!(aaaa.append_to_vec(&mut bytes, &mut None).is_ok());

        let aaaa = AAAA::parse(&bytes, 0);
        assert!(aaaa.is_ok());
        let aaaa = aaaa.unwrap();

        assert_eq!(address, Ipv6Addr::from(aaaa.address));
        assert_eq!(bytes.len(), aaaa.len());
    }

    #[test]
    fn parse_sample() -> Result<(), Box<dyn std::error::Error>> {
        let sample_file = std::fs::read("samples/zonefile/AAAA.sample.")?;
        let sample_ip: u128 = "fd92:7065:b8e:ffff::5".parse::<Ipv6Addr>()?.into();

        let sample_rdata = match ResourceRecord::parse(&sample_file, 0)?.rdata {
            RData::AAAA(rdata) => rdata,
            _ => unreachable!(),
        };

        assert_eq!(sample_rdata.address, sample_ip);
        Ok(())
    }
}
