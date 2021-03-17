use byteorder::{ByteOrder, BigEndian};

use crate::dns::DnsPacketContent;

/// Represents a Resource Address (IPv4)
#[derive(Debug)]
pub struct A {
    /// a 32 bit ip address
    pub address: u32,
}

impl <'a> DnsPacketContent<'a> for A {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self> where Self: Sized {
        let address = BigEndian::read_u32(&data[position..position+4]);
        Ok(Self{
            address
        })
    }

    fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        let mut buf = [0u8; 4];
        BigEndian::write_u32(&mut buf[..], self.address);

        out.extend(&buf);

        Ok(())
    }

    fn len(&self) -> usize {
        4
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn parse_and_write_a() {
        let a = A {
            address: 2130706433
        };

        let mut bytes = Vec::new();
        assert!(a.append_to_vec(&mut bytes).is_ok());

        let a = A::parse(&bytes, 0);
        assert!(a.is_ok());
        let a = a.unwrap();

        assert_eq!(2130706433, a.address);
        assert_eq!(bytes.len(), a.len());
    }
}