use std::{collections::HashMap, convert::TryInto};

use crate::dns::{DnsPacketContent, Name};

/// MX is used to acquire mail exchange information
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct MX<'a> {
    /// A 16 bit integer which specifies the preference given to this RR among others at the same owner.  
    /// Lower values are preferred.
    pub preference: u16,

    /// A [Name](`Name`) which specifies a host willing to act as a mail exchange for the owner name.
    pub exchange: Name<'a>,
}

impl<'a> DnsPacketContent<'a> for MX<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let preference = u16::from_be_bytes(data[position..position + 2].try_into()?);
        let exchange = Name::parse(data, position + 2)?;

        Ok(Self {
            preference,
            exchange,
        })
    }

    fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        out.extend(self.preference.to_be_bytes());
        self.exchange.append_to_vec(out)
    }

    fn len(&self) -> usize {
        self.exchange.len() + 2
    }

    fn compress_append_to_vec(
        &self,
        out: &mut Vec<u8>,
        name_refs: &mut HashMap<u64, usize>,
    ) -> crate::Result<()> {
        out.extend(self.preference.to_be_bytes());
        self.exchange.compress_append_to_vec(out, name_refs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_write_mx() {
        let mx = MX {
            preference: 10,
            exchange: Name::new("e.exchange.com").unwrap(),
        };

        let mut data = Vec::new();
        assert!(mx.append_to_vec(&mut data).is_ok());

        let mx = MX::parse(&data, 0);
        assert!(mx.is_ok());
        let mx = mx.unwrap();

        assert_eq!(data.len(), mx.len());
        assert_eq!(10, mx.preference);
        assert_eq!("e.exchange.com", mx.exchange.to_string());
    }
}
