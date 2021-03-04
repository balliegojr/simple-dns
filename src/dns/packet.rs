use super::{DnsPacketContent, PacketHeader, Question, ResourceRecord};
#[derive(Debug)]
pub struct Packet<'a> {
    header: PacketHeader,
    pub questions: Vec<Question<'a>>,
    pub answers: Vec<ResourceRecord<'a>>,
    pub name_servers: Vec<ResourceRecord<'a>>,
    pub additional_records: Vec<ResourceRecord<'a>>
}

impl <'a> Packet<'a> {
    pub fn new_query(id: u16, recursion_desired: bool) -> Self {
        Self {
            header: PacketHeader::new_query(id, recursion_desired),
            questions: Vec::new(),
            answers: Vec::new(),
            name_servers: Vec::new(),
            additional_records: Vec::new(),
        }
    }

    pub fn parse(data: &'a [u8]) -> crate::Result<Self> {
        let header = PacketHeader::parse(&data[..12])?;
        
        let mut offset = 12;
        let questions = Self::parse_section(data, &mut offset, header.questions_count)?;
        let answers = Self::parse_section(data, &mut offset, header.answers_count)?;
        let name_servers = Self::parse_section(data, &mut offset, header.name_servers_count)?;
        let additional_records = Self::parse_section(data, &mut offset, header.additional_records_count)?;

        Ok(Self {
            header,
            questions,
            answers,
            name_servers,
            additional_records
        })
    }

    fn parse_section<T: DnsPacketContent<'a>>(data: &'a [u8], offset: &mut usize, items_count: u16) -> crate::Result<Vec<T>> {
        let mut section_items = Vec::with_capacity(items_count as usize);
        
        for _ in 0..items_count {
            let item = T::parse(data, *offset)?;
            *offset += item.len() + 1;
            section_items.push(item);
        }

        Ok(section_items)
    }

    pub fn with_question(mut self, question: Question<'a>) -> Self {
        self.questions.push(question);
        self
    }
    
    pub fn with_answer(mut self, answer: ResourceRecord<'a>) -> Self {
        self.answers.push(answer);
        self
    }
    
    pub fn with_name_server(mut self, name_server: ResourceRecord<'a>) -> Self {
        self.name_servers.push(name_server);
        self
    }

    pub fn with_additional_record(mut self, additional_record: ResourceRecord<'a>) -> Self {
        self.additional_records.push(additional_record);
        self
    }
    
    pub fn to_bytes_vec(&mut self, truncate: bool) -> crate::Result<Vec<u8>> {
        let mut out = vec![0u8; 12];
        
        self.header.questions_count = self.questions.len() as u16;
        self.header.answers_count = self.answers.len() as u16;
        self.header.name_servers_count = self.name_servers.len() as u16;
        self.header.additional_records_count = self.additional_records.len() as u16;
        
        self.header.truncated = Self::add_section(&mut out, truncate, &self.questions)?;
        if !self.header.truncated {
            self.header.truncated = Self::add_section(&mut out, truncate, &self.answers)?;
        }
        if !self.header.truncated {
            self.header.truncated = Self::add_section(&mut out, truncate, &self.name_servers)?;
        }
        if !self.header.truncated {
            self.header.truncated = Self::add_section(&mut out, truncate, &self.additional_records)?;
        }
        
        self.header.write_to(&mut out[0..12]);
        Ok(out)
    }

    fn add_section<'b, T : DnsPacketContent<'b>>(out: &mut Vec<u8>, truncate: bool, section: &[T]) -> crate::Result<bool> {
        for item in section {
            item.append_to_vec(out)?;

            if truncate && out.len() > 243 {
                return Ok(true);
            }
        }

        Ok(false)
    }

}

#[cfg(test)]
mod tests {
    use crate::{SimpleDnsError, dns::CLASS, dns::TYPE};

    use super::*;
    use super::super::{QTYPE, QCLASS};
    use std::convert::TryInto;

    #[test]
    fn build_query_correct() {
        let query = Packet::new_query(1, false)
            .with_question(Question::new("_srv._udp.local".try_into().unwrap(), QTYPE::TXT, QCLASS::IN, false))
            .with_question(Question::new("_srv2._udp.local".try_into().unwrap(), QTYPE::TXT, QCLASS::IN, false))
            .to_bytes_vec(true).unwrap();

        let parsed = Packet::parse(&query);
        assert!(parsed.is_ok());

        let parsed = parsed.unwrap();
        assert_eq!(2, parsed.questions.len());
    }

    #[test]
    fn query_google_com() -> Result<(), SimpleDnsError>{
        let bytes = b"\x00\x03\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";
        let packet = Packet::parse(bytes)?;

        assert_eq!(1, packet.questions.len());
        assert_eq!("google.com", packet.questions[0].qname.to_string());
        assert_eq!(QTYPE::A, packet.questions[0].qtype);
        assert_eq!(QCLASS::IN, packet.questions[0].qclass);

        Ok(())
    }

    #[test]
    fn reply_google_com() -> Result<(), SimpleDnsError> {
        let bytes = b"\x00\x03\x81\x80\x00\x01\x00\x0b\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x23\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x25\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x27\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x20\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x28\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x21\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x29\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x22\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x24\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x2e\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x26";

        let packet = Packet::parse(bytes)?;

        assert_eq!(1, packet.questions.len());
        assert_eq!(11, packet.answers.len());

        assert_eq!("google.com", packet.answers[0].name.to_string());
        assert_eq!(TYPE::A, packet.answers[0].rdatatype);
        assert_eq!(CLASS::IN, packet.answers[0].class);
        assert_eq!(4, packet.answers[0].ttl);
        assert_eq!(4, packet.answers[0].rdata.len());
        
        match &packet.answers[0].rdata {
            crate::dns::RData::A(a) => {
                assert_eq!(1249766435, a.address)
            }
            _ => panic!("invalid RDATA")
        }


        Ok(())
    }
}