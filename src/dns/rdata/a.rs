use byteorder::{ByteOrder, BigEndian};

use crate::dns::DnsPacketContent;

use super::RData;


#[derive(Debug)]
pub struct A {
    address: u32,
}


impl <'a> RData<'a> for A {}
impl <'a> DnsPacketContent<'a> for A {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self> where Self: Sized {
        let address = BigEndian::read_u32(&data[position+2..position+6]);
        Ok(Self{
            address
        })
    }

    fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        let mut buf = [0u8; 6];
        BigEndian::write_u16(&mut buf[..2], 4);
        BigEndian::write_u32(&mut buf[2..], self.address);

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

        assert_eq!(2130706433, a.address)
        

        
    }

}