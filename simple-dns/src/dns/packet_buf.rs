use std::{collections::HashMap, ops::Deref, usize};

use super::{Header, Packet, PacketPart, Question, ResourceRecord};
use crate::{header_buffer, PacketFlag, SimpleDnsError, OPCODE};

/// Owned version of [`Packet`] that contains a internal buffer.  
/// This struct fills the internal buffer on the fly, because of this, it imposes some constraints.  
/// You have to build the packet in order.  
/// ex: It is not possible to add a question after an answer
#[derive(Debug, Clone)]
pub struct PacketBuf {
    name_refs: HashMap<u64, usize>,
    inner: Vec<u8>,
    compression: bool,
}

impl PacketBuf {
    /// Creates a new empty PacketBuf with a query header
    pub fn new_query(compression: bool, id: u16) -> Self {
        let header = Header::new_query(id);
        Self::new(header, compression)
    }

    /// Creates a new empty PacketBuf with a reply header
    pub fn new_reply(compression: bool, id: u16, opcode: OPCODE) -> Self {
        let header = Header::new_reply(id, opcode);
        Self::new(header, compression)
    }

    /// Creates a new empty PacketBuf
    fn new(header: Header, compression: bool) -> Self {
        let mut inner = vec![0; 12];
        header.write_to(&mut inner);
        let name_refs = HashMap::new();
        Self {
            inner,
            name_refs,
            compression,
        }
    }

    /// Create a reply based on this packet
    pub fn reply(&self, compression: bool) -> crate::Result<PacketBuf> {
        Ok(Self::new_reply(
            compression,
            header_buffer::id(self)?,
            header_buffer::opcode(self)?,
        ))
    }

    pub fn set_flags(&mut self, flag: PacketFlag) -> crate::Result<()> {
        header_buffer::set_flags(&mut self.inner[..12], flag)
    }

    pub fn remove_flags(&mut self, flag: PacketFlag) -> crate::Result<()> {
        header_buffer::remove_flags(&mut self.inner[..12], flag)
    }

    pub fn has_flags(&self, flag: PacketFlag) -> crate::Result<bool> {
        header_buffer::has_flags(&self[..12], flag)
    }

    /// Add a [`Question`] to this packet.  
    /// This function will fail if the packet already has any answer, name server or additional records
    pub fn add_question(&mut self, question: &Question) -> crate::Result<()> {
        if self.has_answers() || self.has_name_servers() || self.has_additional_records() {
            return Err(SimpleDnsError::AttemptedInvalidOperation);
        }
        if self.compression {
            question.append_to_vec(&mut self.inner, &mut Some(&mut self.name_refs))?;
        } else {
            question.append_to_vec(&mut self.inner, &mut None)?;
        }
        let questions_count = header_buffer::questions(&self.inner)?;
        header_buffer::set_questions(&mut self.inner, questions_count + 1);
        Ok(())
    }

    /// Add a [Answer](`ResourceRecord`) to this packet.  
    /// This function will fail if the packet already has any name server or additional records
    pub fn add_answer(&mut self, answer: &ResourceRecord) -> crate::Result<()> {
        if self.has_name_servers() || self.has_additional_records() {
            return Err(SimpleDnsError::AttemptedInvalidOperation);
        }

        if self.compression {
            answer.append_to_vec(&mut self.inner, &mut Some(&mut self.name_refs))?;
        } else {
            answer.append_to_vec(&mut self.inner, &mut None)?;
        }

        let answers_count = header_buffer::answers(&self.inner)?;
        header_buffer::set_answers(&mut self.inner, answers_count + 1);
        Ok(())
    }

    /// Add a [Name Server](`ResourceRecord`) to this packet.  
    /// This function will fail if the packet already has any additional records
    pub fn add_name_server(&mut self, name_server: &ResourceRecord) -> crate::Result<()> {
        if self.has_additional_records() {
            return Err(SimpleDnsError::AttemptedInvalidOperation);
        }

        if self.compression {
            name_server.append_to_vec(&mut self.inner, &mut Some(&mut self.name_refs))?;
        } else {
            name_server.append_to_vec(&mut self.inner, &mut None)?;
        }

        let ns_count = header_buffer::name_servers(&self.inner)?;
        header_buffer::set_name_servers(&mut self.inner, ns_count + 1);
        Ok(())
    }

    /// Add an [Additional Record](`ResourceRecord`) to this packet
    pub fn add_additional_record(
        &mut self,
        additional_record: &ResourceRecord,
    ) -> crate::Result<()> {
        if self.compression {
            additional_record.append_to_vec(&mut self.inner, &mut Some(&mut self.name_refs))?;
        } else {
            additional_record.append_to_vec(&mut self.inner, &mut None)?;
        }
        let additional_records_count = header_buffer::additional_records(&self.inner)?;
        header_buffer::set_additional_records(&mut self.inner, additional_records_count + 1);
        Ok(())
    }

    /// Return the packet id from this packet header
    pub fn packet_id(&self) -> crate::Result<u16> {
        header_buffer::id(&self.inner)
    }

    /// Creates a [`Packet`] by calling the [`Packet::parse`] function
    pub fn to_packet(&self) -> crate::Result<Packet> {
        super::Packet::parse(&self.inner)
    }

    /// Return true if this packet has any answers
    pub fn has_answers(&self) -> bool {
        header_buffer::answers(&self.inner)
            .map(|count| count > 0)
            .unwrap_or_default()
    }

    /// Return true if this packet has questions
    pub fn has_questions(&self) -> bool {
        header_buffer::questions(&self.inner)
            .map(|count| count > 0)
            .unwrap_or_default()
    }

    /// Return true if this packet has any name servers
    pub fn has_name_servers(&self) -> bool {
        header_buffer::name_servers(&self.inner)
            .map(|count| count > 0)
            .unwrap_or_default()
    }

    /// Return true if this packet has any additional records
    pub fn has_additional_records(&self) -> bool {
        header_buffer::additional_records(&self.inner)
            .map(|count| count > 0)
            .unwrap_or_default()
    }

    /// Returns an Iterator over questions of this packet
    pub fn questions_iter(&self) -> crate::Result<QuestionsIter> {
        let total = header_buffer::questions(&self.inner)?;
        let pos = 12;

        Ok(QuestionsIter {
            buf: self,
            total,
            pos,
            curr: 0,
        })
    }

    // TODO: implement iterator for answers, name_servers and additional_records
}

impl From<Vec<u8>> for PacketBuf {
    fn from(inner: Vec<u8>) -> Self {
        Self {
            name_refs: HashMap::new(),
            inner,
            compression: true,
        }
    }
}

impl Deref for PacketBuf {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Iterate over the questions of a [`PacketBuf`]
/// If a question is not valid, the iterator will stop
pub struct QuestionsIter<'a> {
    buf: &'a PacketBuf,
    curr: u16,
    total: u16,
    pos: usize,
}
impl<'a> Iterator for QuestionsIter<'a> {
    type Item = Question<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.curr >= self.total {
            return None;
        }

        let question = Self::Item::parse(self.buf, self.pos).ok()?;
        self.curr += 1;
        self.pos += question.len();

        Some(question)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dns::CLASS, dns::TYPE, rdata::RData, rdata::A, Name};

    #[test]
    fn bufpacket_add_question() {
        let mut buf_packet = PacketBuf::new(Header::new_query(0), false);
        let question = Question::new(
            Name::new_unchecked("_srv._udp.local"),
            TYPE::TXT.into(),
            CLASS::IN.into(),
            false,
        );
        let resource = ResourceRecord::new(
            Name::new_unchecked("_srv._udp.local"),
            CLASS::IN,
            10,
            RData::A(A { address: 10 }),
        );

        assert!(buf_packet.add_question(&question).is_ok());
        assert!(buf_packet.has_questions());

        let mut buf_packet = PacketBuf::new(Header::new_query(0), false);
        buf_packet.add_answer(&resource).unwrap();
        assert!(buf_packet.add_question(&question).is_err());
        assert!(!buf_packet.has_questions());

        let mut buf_packet = PacketBuf::new(Header::new_query(0), false);
        buf_packet.add_name_server(&resource).unwrap();
        assert!(buf_packet.add_question(&question).is_err());
        assert!(!buf_packet.has_questions());

        let mut buf_packet = PacketBuf::new(Header::new_query(0), false);
        buf_packet.add_additional_record(&resource).unwrap();
        assert!(buf_packet.add_question(&question).is_err());
        assert!(!buf_packet.has_questions());
    }

    #[test]
    fn bufpacket_add_answers() {
        let mut buf_packet = PacketBuf::new(Header::new_query(0), false);
        let resource = ResourceRecord::new(
            Name::new_unchecked("srv._udp.local"),
            CLASS::IN,
            10,
            RData::A(A { address: 10 }),
        );

        assert!(buf_packet.add_answer(&resource).is_ok());
        assert!(buf_packet.has_answers());

        let mut buf_packet = PacketBuf::new(Header::new_query(0), false);
        buf_packet.add_name_server(&resource).unwrap();
        assert!(buf_packet.add_answer(&resource).is_err());
        assert!(!buf_packet.has_answers());

        let mut buf_packet = PacketBuf::new(Header::new_query(0), false);
        buf_packet.add_additional_record(&resource).unwrap();
        assert!(buf_packet.add_answer(&resource).is_err());
        assert!(!buf_packet.has_answers());
    }

    #[test]
    fn bufpacket_add_name_servers() {
        let mut buf_packet = PacketBuf::new(Header::new_query(0), false);
        let resource = ResourceRecord::new(
            Name::new_unchecked("_srv._udp.local"),
            CLASS::IN,
            10,
            RData::A(A { address: 10 }),
        );

        assert!(buf_packet.add_name_server(&resource).is_ok());
        assert!(buf_packet.has_name_servers());

        let mut buf_packet = PacketBuf::new(Header::new_query(0), false);
        buf_packet.add_additional_record(&resource).unwrap();
        assert!(buf_packet.add_name_server(&resource).is_err());
        assert!(!buf_packet.has_name_servers());
    }

    #[test]
    fn bufpacket_add_additional_records() {
        let mut buf_packet = PacketBuf::new(Header::new_query(0), false);
        let resource = ResourceRecord::new(
            Name::new_unchecked("_srv._udp.local"),
            CLASS::IN,
            10,
            RData::A(A { address: 10 }),
        );

        assert!(buf_packet.add_additional_record(&resource).is_ok());
        assert!(buf_packet.has_additional_records());
    }

    #[test]
    fn bufpacket_questions_iter() {
        let mut buf_packet = PacketBuf::new(Header::new_query(0), false);
        let question = Question::new(
            Name::new_unchecked("_srv._udp.local"),
            TYPE::TXT.into(),
            CLASS::IN.into(),
            false,
        );

        buf_packet.add_question(&question).unwrap();
        buf_packet.add_question(&question).unwrap();

        assert_eq!(2, buf_packet.questions_iter().unwrap().count());
    }
}
