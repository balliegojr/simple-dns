use crate::dns::PacketPart;
use std::{collections::HashMap, convert::TryInto, net::Ipv4Addr};

use super::RR;

/// Represents a Resource Address (IPv4)
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct A {
    /// a 32 bit ip address
    pub address: u32,
}

impl RR for A {
    const TYPE_CODE: u16 = 1;
}

impl<'a> PacketPart<'a> for A {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let address = u32::from_be_bytes(data[position..position + 4].try_into()?);
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
    use super::*;

    #[test]
    fn parse_and_write_a() {
        let a = A {
            address: 2130706433,
        };

        let mut bytes = Vec::new();
        assert!(a.append_to_vec(&mut bytes, &mut None).is_ok());

        let a = A::parse(&bytes, 0);
        assert!(a.is_ok());
        let a = a.unwrap();

        assert_eq!(2130706433, a.address);
        assert_eq!(bytes.len(), a.len());
    }
}
