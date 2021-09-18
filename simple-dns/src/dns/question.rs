use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
};

use super::{DnsPacketContent, Name, QCLASS, QTYPE};

/// Question represents a query in the DNS Packet
#[derive(Debug)]
pub struct Question<'a> {
    /// a [Name](`Name`)  to query for
    pub qname: Name<'a>,
    /// a [QTYPE](`QTYPE`) which specifies the type of the query.
    pub qtype: QTYPE,
    /// a [QCLASS](`QCLASS`) whire specifics the class of the query, For Example: IN
    pub qclass: QCLASS,
    /// indicates if the queries prefers a unicast response.  
    /// MDNS related, See [RFC 6762](https://tools.ietf.org/html/rfc6762#section-5.4)
    pub unicast_response: bool,
}

impl<'a> Question<'a> {
    /// Creates a new question
    pub fn new(qname: Name<'a>, qtype: QTYPE, qclass: QCLASS, unicast_response: bool) -> Self {
        Self {
            qname,
            qtype,
            qclass,
            unicast_response,
        }
    }

    fn append_common(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        let qclass = match self.unicast_response {
            true => self.qclass as u16 | 0x8000,
            false => self.qclass as u16,
        };

        out.extend((self.qtype as u16).to_be_bytes());
        out.extend(qclass.to_be_bytes());

        Ok(())
    }
}

impl<'a> DnsPacketContent<'a> for Question<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self> {
        let qname = Name::parse(data, position)?;
        let offset = position + qname.len();

        let qclass = u16::from_be_bytes(data[offset + 2..offset + 4].try_into()?);

        Ok(Self {
            qname,
            qtype: QTYPE::try_from(u16::from_be_bytes(data[offset..offset + 2].try_into()?))?,
            qclass: QCLASS::try_from(qclass & 0x7FFF)?,
            unicast_response: qclass & 0x8000 == 0x8000,
        })
    }

    fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        self.qname.append_to_vec(out)?;
        self.append_common(out)
    }

    fn compress_append_to_vec(
        &self,
        out: &mut Vec<u8>,
        name_refs: &mut HashMap<u64, usize>,
    ) -> crate::Result<()> {
        self.qname.compress_append_to_vec(out, name_refs)?;
        self.append_common(out)
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
        assert!(!question.unicast_response);
    }

    #[test]
    fn append_to_vec() {
        let question = Question::new(
            "_srv._udp.local".try_into().unwrap(),
            QTYPE::TXT,
            QCLASS::IN,
            false,
        );
        let mut bytes = Vec::new();
        question.append_to_vec(&mut bytes).unwrap();

        assert_eq!(b"\x04_srv\x04_udp\x05local\x00\x00\x10\x00\x01", &bytes[..]);
        assert_eq!(bytes.len(), question.len());
    }

    #[test]
    fn unicast_response() {
        let mut bytes = Vec::new();
        Question::new("x.local".try_into().unwrap(), QTYPE::TXT, QCLASS::IN, true)
            .append_to_vec(&mut bytes)
            .unwrap();
        let parsed = Question::parse(&bytes, 0).unwrap();

        assert!(parsed.unicast_response);
    }
}
