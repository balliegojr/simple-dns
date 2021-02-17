use super::{PacketHeader, Question};

#[derive(Debug)]
pub struct Packet<'a> {
    header: PacketHeader,
    questions: Vec<Question<'a>>,
    // ANCOUNT: u16,
    // NSCOUNT: u16,
    // ARCOUNT: u16 
}



impl <'a> Packet<'a> {
    pub fn new_query(id: u16, recursion_desired: bool) -> Self {
        Self {
            header: PacketHeader::new_query(id, recursion_desired),
            questions: Vec::new()
        }
    }

    pub fn parse(data: &'a [u8]) -> crate::Result<Self> {
        let header = PacketHeader::parse(&data[..12])?;
        let mut questions = Vec::with_capacity(header.questions_count as usize);

        let mut offset = 12;
        for _ in 0..header.questions_count {
            let question = Question::parse(data, offset)?;
            offset += question.len() + 1;
            questions.push(question);
        }

        // TODO: implement other message types

        Ok(Self {
            header,
            questions
        })
    }

    pub fn with_question(mut self, question: Question<'a>) -> Self {
        self.questions.push(question);
        self.header.questions_count = self.questions.len() as u16;
        self
    }

    pub fn to_bytes_vec(&mut self, truncate: bool) -> crate::Result<Vec<u8>> {
        let mut out = vec![0u8; 12];
        
        for question in &self.questions {
            out.extend(question.to_bytes_vec()?);

            if truncate && out.len() > 243 {
                self.header.truncated = true;
                break;
            }
        }
        
        self.header.write_to(&mut out[0..12]);
        Ok(out)
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
            .with_question(Question::new("_srv._udp.local".try_into().unwrap(), QTYPE::TXT, QCLASS::IN).unwrap())
            .to_bytes_vec(true).unwrap();

        let parsed = Packet::parse(&query);
        assert!(parsed.is_ok());

        let parsed = parsed.unwrap();
        assert_eq!(1, parsed.questions.len());

    }
}