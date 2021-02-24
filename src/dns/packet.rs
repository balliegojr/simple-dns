use super::{DnsPacketContent, PacketHeader, Question, ResourceRecord};

#[derive(Debug)]
pub struct Packet<'a> {
    header: PacketHeader,
    questions: Vec<Question<'a>>,
    answers: Vec<ResourceRecord<'a>>,
    name_servers: Vec<ResourceRecord<'a>>,
    additional_records: Vec<ResourceRecord<'a>>
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
        self.header.questions_count = self.questions.len() as u16;
        self
    }

    pub fn to_bytes_vec(&mut self, truncate: bool) -> crate::Result<Vec<u8>> {
        let mut out = vec![0u8; 12];
        
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
    use super::*;
    use super::super::{QTYPE, QCLASS};
    use std::convert::TryInto;

    #[test]
    fn build_query_correct() {
        let query = Packet::new_query(1, false)
            .with_question(Question::new("_srv._udp.local".try_into().unwrap(), QTYPE::TXT, QCLASS::IN, false).unwrap())
            .with_question(Question::new("_srv2._udp.local".try_into().unwrap(), QTYPE::TXT, QCLASS::IN, false).unwrap())
            .to_bytes_vec(true).unwrap();

        let parsed = Packet::parse(&query);
        assert!(parsed.is_ok());

        let parsed = parsed.unwrap();
        assert_eq!(2, parsed.questions.len());
    }
}