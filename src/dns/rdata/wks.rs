use crate::dns::DnsPacketContent;
use byteorder::{BigEndian, ByteOrder};

#[derive(Debug)]
pub struct WKS<'a> {
    pub address: u32,
    pub protocol: u8,
    pub bit_map: &'a [u8]
}

impl <'a> DnsPacketContent<'a> for WKS<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self> where Self: Sized {
        let address = BigEndian::read_u32(&data[position..position+4]);
        Ok(Self {
            address,
            protocol: data[position+4],
            bit_map: &data[position+5..]
        })
    }

    fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        let mut buf = [0u8; 4];
        BigEndian::write_u32(&mut buf, self.address);

        out.extend(&buf);
        out.push(self.protocol);
        out.extend(self.bit_map);

        Ok(())
    }

    fn len(&self) -> usize {
        self.bit_map.len() + 5
    }
}