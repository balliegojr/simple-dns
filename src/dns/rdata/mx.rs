use byteorder::{ByteOrder, BigEndian};
use crate::dns::{DnsPacketContent, Name};

#[derive(Debug)]
pub struct MX<'a> {
    pub preference: u16,
    pub exchange: Name<'a>
}

impl <'a> DnsPacketContent<'a> for MX<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self> where Self: Sized {
        let preference = BigEndian::read_u16(&data[position..position+2]);
        let exchange = Name::parse(data, position+2)?;

        Ok(
            Self {
                preference,
                exchange
            }
        )
    }

    fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        let mut buf = [0u8; 2];
        BigEndian::write_u16(&mut buf, self.preference);
        out.extend(&buf);

        self.exchange.append_to_vec(out)
    }

    fn len(&self) -> usize {
        self.exchange.len() + 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_write_mx() {
        let mx = MX {
            preference: 10,
            exchange: Name::new("e.exchange.com").unwrap()
        };

        let mut data = Vec::new();
        assert!(mx.append_to_vec(&mut data).is_ok());

        let mx = MX::parse(&data, 0);
        assert!(mx.is_ok());
        let mx = mx.unwrap();

        assert_eq!(17, mx.len());
        assert_eq!(10, mx.preference);
        assert_eq!("e.exchange.com", mx.exchange.to_string());

    }
}