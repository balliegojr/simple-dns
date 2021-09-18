use std::convert::TryInto;

use crate::dns::DnsPacketContent;

/// The WKS record is used to describe the well known services supported by a particular protocol on a particular internet address.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct WKS<'a> {
    /// An 32 bit Internet address
    pub address: u32,
    /// An 8 bit IP protocol number
    pub protocol: u8,
    /// A variable length bit map.  The bit map must be a multiple of 8 bits long.
    pub bit_map: &'a [u8],
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
            bit_map: &data[position + 5..],
        })
    }

    fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        out.extend(self.address.to_be_bytes());
        out.push(self.protocol);
        out.extend(self.bit_map);

        Ok(())
    }

    fn len(&self) -> usize {
        self.bit_map.len() + 5
    }
}
