use std::{borrow::Cow, collections::HashMap, convert::TryInto};

use crate::dns::DnsPacketContent;

/// The WKS record is used to describe the well known services supported by a particular protocol on a particular internet address.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct WKS<'a> {
    /// An 32 bit Internet address
    pub address: u32,
    /// An 8 bit IP protocol number
    pub protocol: u8,
    /// A variable length bit map.  The bit map must be a multiple of 8 bits long.
    pub bit_map: Cow<'a, [u8]>,
}

impl<'a> WKS<'a> {
    /// Transforms the inner data into it's owned type
    pub fn into_owned<'b>(self) -> WKS<'b> {
        WKS {
            address: self.address,
            protocol: self.protocol,
            bit_map: self.bit_map.into_owned().into(),
        }
    }
}

impl<'a> DnsPacketContent<'a> for WKS<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let address = u32::from_be_bytes(data[position..position + 4].try_into()?);
        Ok(Self {
            address,
            protocol: data[position + 4],
            bit_map: Cow::Borrowed(&data[position + 5..]),
        })
    }

    fn append_to_vec(
        &self,
        out: &mut Vec<u8>,
        _name_refs: &mut Option<&mut HashMap<u64, usize>>,
    ) -> crate::Result<()> {
        out.extend(self.address.to_be_bytes());
        out.push(self.protocol);
        out.extend(self.bit_map.iter());

        Ok(())
    }

    fn len(&self) -> usize {
        self.bit_map.len() + 5
    }
}
