use std::convert::TryFrom;
use byteorder::{ ByteOrder, BigEndian };

use super::{DnsPacketContent, Name, QCLASS, QTYPE};

#[derive(Debug)]
pub struct Question<'a> {
    pub qname: Name<'a>,
    pub qtype: QTYPE,
    pub qclass: QCLASS,
    pub unicast_response: bool
}

impl <'a> Question<'a> {
    pub fn new(qname: Name<'a>, qtype: QTYPE, qclass: QCLASS, unicast_response: bool) -> Self {
        Self {
            qname,
            qtype,
            qclass,
            unicast_response
        }
    }
}

impl <'a> DnsPacketContent<'a> for Question<'a> {
    fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        self.qname.append_to_vec(out)?;
        let mut buf = [0u8; 4];

        let qclass = match self.unicast_response { 
            true => self.qclass as u16 | 0x8000,
            false => self.qclass as u16
        };

        BigEndian::write_u16(&mut buf[..2], self.qtype as u16);
        BigEndian::write_u16(&mut buf[2..], qclass);

        out.extend(&buf);

        Ok(())
    }

    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self> {
        let qname = Name::parse(data, position)?;
        let offset = position + qname.len() + 1;

        let qclass = BigEndian::read_u16(&data[offset+2..offset+4]);
        
        Ok(Self {
            qname,
            qtype: QTYPE::try_from(BigEndian::read_u16(&data[offset..offset+2]))?,
            qclass: QCLASS::try_from(qclass & 0x7FFF)?,
            unicast_response: qclass & 0x8000 == 0x8000
        })
    }

    fn len(&self) -> usize {
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
        assert_eq!(false, question.unicast_response);
    }

    #[test]
    fn convert_to_bytes_vec() {
        let question = Question::new("_srv._udp.local".try_into().unwrap(), QTYPE::TXT, QCLASS::IN, false);
        let mut bytes = Vec::new();
        question.append_to_vec(&mut bytes).unwrap();

        assert_eq!(b"\x04_srv\x04_udp\x05local\x00\x00\x10\x00\x01", &bytes[..]);
    }

    #[test]
    fn unicast_response() {
        let mut bytes = Vec::new();
        Question::new("x.local".try_into().unwrap(), QTYPE::TXT, QCLASS::IN, true).append_to_vec(&mut bytes).unwrap();
        let parsed = Question::parse(&bytes, 0).unwrap();

        assert!(parsed.unicast_response);
    }
}