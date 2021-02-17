use std::convert::TryFrom;
use byteorder::{ ByteOrder, BigEndian };

use super::{Name, QCLASS, QTYPE};

#[derive(Debug)]
pub struct Question<'a> {
    pub qname: Name<'a>,
    pub qtype: QTYPE,
    pub qclass: QCLASS
}

impl <'a> Question<'a> {
    pub fn new(qname: Name<'a>, qtype: QTYPE, qclass: QCLASS) -> crate::Result<Self> {
        Ok(Self {
            qname,
            qtype,
            qclass
        })
    }

    pub fn parse(data: &'a [u8], position: usize) -> crate::Result<Self> {
        let qname = Name::parse(data, position)?;
        let offset = position + qname.len() + 1;

        Ok(Self {
            qname,
            qtype: QTYPE::try_from(BigEndian::read_u16(&data[offset..offset+2]))?,
            qclass: QCLASS::try_from(BigEndian::read_u16(&data[offset+2..offset+4]))?
        })
    }

    pub fn to_bytes_vec(&self) -> crate::Result<Vec<u8>> {
        let mut out = self.qname.to_bytes_vec();
        let mut buf = [0u8; 4];

        BigEndian::write_u16(&mut buf[..2], self.qtype as u16);
        BigEndian::write_u16(&mut buf[2..], self.qclass as u16);

        out.extend(&buf);

        Ok(out)
    }

    pub fn len(&self) -> usize {
        self.qname.len() + 4
    }
}

#[cfg(test)] 
mod tests {
    use super::*;
    use std::convert::TryInto;

    #[test]
    fn parse_question() {
        let bytes = b"\x00\x00\x04_srv\x04_udp\x05local\x00\x00\x10\x00\x01";
        let question = Question::parse(bytes, 2);

        assert!(question.is_ok());
        let question = question.unwrap();

        assert_eq!(QCLASS::IN, question.qclass);
        assert_eq!(QTYPE::TXT, question.qtype);
    }

    #[test]
    fn convert_to_bytes_vec() {
        let question = Question::new("_srv._udp.local".try_into().unwrap(), QTYPE::TXT, QCLASS::IN).unwrap();
        let bytes = question.to_bytes_vec().unwrap();

        assert_eq!(b"\x04_srv\x04_udp\x05local\x00\x00\x10\x00\x01", &bytes[..]);
    }
}