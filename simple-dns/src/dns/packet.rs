use std::{collections::HashMap, ops::Deref, usize};

use crate::{SimpleDnsError, OPCODE};

use super::{PacketHeader, PacketPart, Question, ResourceRecord};

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
    /// Creates a new empty PacketBuf
    pub fn new(header: PacketHeader, compression: bool) -> Self {
        let mut inner = vec![0; 12];
        header.write_to(&mut inner);
        let name_refs = HashMap::new();
        Self {
            inner,
            name_refs,
            compression,
        }
    }

    /// Creates a new empty PacketBuf with a query header
    pub fn new_query(compression: bool) -> Self {
        let header = PacketHeader::new_query(0, false);
        Self::new(header, compression)
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
        let questions_count = PacketHeader::read_questions(&self.inner);
        PacketHeader::write_questions(&mut self.inner, questions_count + 1);
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

        let answers_count = PacketHeader::read_answers(&self.inner);
        PacketHeader::write_answers(&mut self.inner, answers_count + 1);
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

        let ns_count = PacketHeader::read_name_servers(&self.inner);
        PacketHeader::write_name_servers(&mut self.inner, ns_count + 1);
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
        let additional_records_count = PacketHeader::read_additional_records(&self.inner);
        PacketHeader::write_additional_records(&mut self.inner, additional_records_count + 1);
        Ok(())
    }

    /// Return the packet id from this packet header
    pub fn packet_id(&self) -> u16 {
        PacketHeader::id(&self.inner)
    }

    /// Creates a [`Packet`] by calling the [`Packet::parse`] function
    pub fn to_packet(&self) -> crate::Result<Packet> {
        Packet::parse(&self.inner)
    }

    /// Return true if this packet has any answers
    pub fn has_answers(&self) -> bool {
        PacketHeader::read_answers(&self.inner) > 0
    }

    /// Return true if this packet has questions
    pub fn has_questions(&self) -> bool {
        PacketHeader::read_questions(&self.inner) > 0
    }

    /// Return true if this packet has any name servers
    pub fn has_name_servers(&self) -> bool {
        PacketHeader::read_name_servers(&self.inner) > 0
    }

    /// Return true if this packet has any additional records
    pub fn has_additional_records(&self) -> bool {
        PacketHeader::read_additional_records(&self.inner) > 0
    }

    /// Returns an Iterator over questions of this packet
    pub fn questions_iter(&self) -> QuestionsIter {
        let total = PacketHeader::read_questions(&self.inner);
        let pos = 12;

        QuestionsIter {
            buf: self,
            total,
            pos,
            curr: 0,
        }
    }

    // TODO: implement iterator for answers, name_servers and additional_records
}

impl From<&[u8]> for PacketBuf {
    fn from(buffer: &[u8]) -> Self {
        Self {
            name_refs: HashMap::new(),
            inner: buffer.to_vec(),
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

/// Represents a DNS message packet
#[derive(Debug, Clone)]
pub struct Packet<'a> {
    /// Packet header
    pub header: PacketHeader,
    /// Questions section
    pub questions: Vec<Question<'a>>,
    /// Answers section
    pub answers: Vec<ResourceRecord<'a>>,
    /// Name servers section
    pub name_servers: Vec<ResourceRecord<'a>>,
    /// Aditional records section
    pub additional_records: Vec<ResourceRecord<'a>>,
}

impl<'a> Packet<'a> {
    /// Creates a new empty packet with a query header
    pub fn new_query(id: u16, recursion_desired: bool) -> Self {
        Self {
            header: PacketHeader::new_query(id, recursion_desired),
            questions: Vec::new(),
            answers: Vec::new(),
            name_servers: Vec::new(),
            additional_records: Vec::new(),
        }
    }

    /// Creates a new empty packet with a reply header
    pub fn new_reply(id: u16) -> Self {
        Self {
            header: PacketHeader::new_reply(id, OPCODE::StandardQuery),
            questions: Vec::new(),
            answers: Vec::new(),
            name_servers: Vec::new(),
            additional_records: Vec::new(),
        }
    }

    /// Changes this packet into a reply packet by replacing its header
    pub fn into_reply(mut self) -> Self {
        self.header = PacketHeader::new_reply(self.header.id, self.header.opcode);
        self
    }

    /// Parses a packet from a slice of bytes
    pub fn parse(data: &'a [u8]) -> crate::Result<Self> {
        let header = PacketHeader::parse(&data[..12])?;

        let mut offset = 12;
        let questions = Self::parse_section(data, &mut offset, header.questions_count)?;
        let answers = Self::parse_section(data, &mut offset, header.answers_count)?;
        let name_servers = Self::parse_section(data, &mut offset, header.name_servers_count)?;
        let additional_records =
            Self::parse_section(data, &mut offset, header.additional_records_count)?;

        Ok(Self {
            header,
            questions,
            answers,
            name_servers,
            additional_records,
        })
    }

    fn parse_section<T: PacketPart<'a>>(
        data: &'a [u8],
        offset: &mut usize,
        items_count: u16,
    ) -> crate::Result<Vec<T>> {
        let mut section_items = Vec::with_capacity(items_count as usize);

        for _ in 0..items_count {
            let item = T::parse(data, *offset)?;
            *offset += item.len();
            section_items.push(item);
        }

        Ok(section_items)
    }

    /// Creates a new [Vec`<u8>`](`Vec<T>`) from the contents of this package, ready to be sent
    pub fn build_bytes_vec(&self) -> crate::Result<Vec<u8>> {
        let mut out = vec![0u8; 12];

        Self::add_section(&mut out, &self.questions, &mut None)?;
        Self::add_section(&mut out, &self.answers, &mut None)?;
        Self::add_section(&mut out, &self.name_servers, &mut None)?;
        Self::add_section(&mut out, &self.additional_records, &mut None)?;
        self.write_header(&mut out);

        Ok(out)
    }

    /// Creates a new [Vec`<u8>`](`Vec<T>`) from the contents of this package with [Name](`crate::Name`) compression
    pub fn build_bytes_vec_compressed(&self) -> crate::Result<Vec<u8>> {
        let mut out = vec![0u8; 12];
        let mut name_refs = HashMap::new();

        Self::add_section(&mut out, &self.questions, &mut Some(&mut name_refs))?;
        Self::add_section(&mut out, &self.answers, &mut Some(&mut name_refs))?;
        Self::add_section(&mut out, &self.name_servers, &mut Some(&mut name_refs))?;
        Self::add_section(
            &mut out,
            &self.additional_records,
            &mut Some(&mut name_refs),
        )?;
        self.write_header(&mut out);

        Ok(out)
    }
    fn write_header(&self, out: &mut [u8]) {
        self.header.write_to(&mut out[0..12]);
        if !self.questions.is_empty() {
            PacketHeader::write_questions(out, self.questions.len() as u16)
        }

        if !self.answers.is_empty() {
            PacketHeader::write_answers(out, self.answers.len() as u16)
        }

        if !self.name_servers.is_empty() {
            PacketHeader::write_name_servers(out, self.name_servers.len() as u16)
        }

        if !self.additional_records.is_empty() {
            PacketHeader::write_additional_records(out, self.additional_records.len() as u16)
        }
    }

    fn add_section<'b, T: PacketPart<'b>>(
        out: &mut Vec<u8>,
        section: &[T],
        name_refs: &mut Option<&mut HashMap<u64, usize>>,
    ) -> crate::Result<()> {
        for item in section {
            item.append_to_vec(out, name_refs)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{dns::CLASS, dns::TYPE, rdata::RData, rdata::A, Name, SimpleDnsError};

    use super::super::{QCLASS, QTYPE};
    use super::*;
    use std::convert::TryInto;

    #[test]
    fn build_query_correct() {
        let mut query = Packet::new_query(1, false);
        query.questions.push(Question::new(
            "_srv._udp.local".try_into().unwrap(),
            TYPE::TXT.into(),
            CLASS::IN.into(),
            false,
        ));
        query.questions.push(Question::new(
            "_srv2._udp.local".try_into().unwrap(),
            TYPE::TXT.into(),
            CLASS::IN.into(),
            false,
        ));

        let query = query.build_bytes_vec().unwrap();

        let parsed = Packet::parse(&query);
        assert!(parsed.is_ok());

        let parsed = parsed.unwrap();
        assert_eq!(2, parsed.questions.len());
        assert_eq!("_srv._udp.local", parsed.questions[0].qname.to_string());
        assert_eq!("_srv2._udp.local", parsed.questions[1].qname.to_string());
    }

    #[test]
    fn query_google_com() -> Result<(), SimpleDnsError> {
        let bytes = b"\x00\x03\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";
        let packet = Packet::parse(bytes)?;

        assert_eq!(1, packet.questions.len());
        assert_eq!("google.com", packet.questions[0].qname.to_string());
        assert_eq!(QTYPE::TYPE(TYPE::A), packet.questions[0].qtype);
        assert_eq!(QCLASS::CLASS(CLASS::IN), packet.questions[0].qclass);

        Ok(())
    }

    #[test]
    fn reply_google_com() -> Result<(), SimpleDnsError> {
        let bytes = b"\x00\x03\x81\x80\x00\x01\x00\x0b\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\
        \x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x23\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\
        \x00\x04\x4a\x7d\xec\x25\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x27\xc0\x0c\x00\x01\x00\x01\x00\x00\
        \x00\x04\x00\x04\x4a\x7d\xec\x20\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x28\xc0\x0c\x00\x01\x00\x01\
        \x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x21\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x29\xc0\x0c\x00\x01\
        \x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x22\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x24\xc0\x0c\
        \x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x2e\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x04\x00\x04\x4a\x7d\xec\x26";

        let packet = Packet::parse(bytes)?;

        assert_eq!(1, packet.questions.len());
        assert_eq!(11, packet.answers.len());

        assert_eq!("google.com", packet.answers[0].name.to_string());
        assert_eq!(CLASS::IN, packet.answers[0].class);
        assert_eq!(4, packet.answers[0].ttl);
        assert_eq!(4, packet.answers[0].rdata.len());

        match &packet.answers[0].rdata {
            crate::dns::rdata::RData::A(a) => {
                assert_eq!(1249766435, a.address)
            }
            _ => panic!("invalid RDATA"),
        }

        Ok(())
    }

    #[test]
    fn bufpacket_add_question() {
        let mut buf_packet = PacketBuf::new(PacketHeader::new_query(0, false), false);
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

        let mut buf_packet = PacketBuf::new(PacketHeader::new_query(0, false), false);
        buf_packet.add_answer(&resource).unwrap();
        assert!(buf_packet.add_question(&question).is_err());
        assert!(!buf_packet.has_questions());

        let mut buf_packet = PacketBuf::new(PacketHeader::new_query(0, false), false);
        buf_packet.add_name_server(&resource).unwrap();
        assert!(buf_packet.add_question(&question).is_err());
        assert!(!buf_packet.has_questions());

        let mut buf_packet = PacketBuf::new(PacketHeader::new_query(0, false), false);
        buf_packet.add_additional_record(&resource).unwrap();
        assert!(buf_packet.add_question(&question).is_err());
        assert!(!buf_packet.has_questions());
    }

    #[test]
    fn bufpacket_add_answers() {
        let mut buf_packet = PacketBuf::new(PacketHeader::new_query(0, false), false);
        let resource = ResourceRecord::new(
            Name::new_unchecked("srv._udp.local"),
            CLASS::IN,
            10,
            RData::A(A { address: 10 }),
        );

        assert!(buf_packet.add_answer(&resource).is_ok());
        assert!(buf_packet.has_answers());

        let mut buf_packet = PacketBuf::new(PacketHeader::new_query(0, false), false);
        buf_packet.add_name_server(&resource).unwrap();
        assert!(buf_packet.add_answer(&resource).is_err());
        assert!(!buf_packet.has_answers());

        let mut buf_packet = PacketBuf::new(PacketHeader::new_query(0, false), false);
        buf_packet.add_additional_record(&resource).unwrap();
        assert!(buf_packet.add_answer(&resource).is_err());
        assert!(!buf_packet.has_answers());
    }

    #[test]
    fn bufpacket_add_name_servers() {
        let mut buf_packet = PacketBuf::new(PacketHeader::new_query(0, false), false);
        let resource = ResourceRecord::new(
            Name::new_unchecked("_srv._udp.local"),
            CLASS::IN,
            10,
            RData::A(A { address: 10 }),
        );

        assert!(buf_packet.add_name_server(&resource).is_ok());
        assert!(buf_packet.has_name_servers());

        let mut buf_packet = PacketBuf::new(PacketHeader::new_query(0, false), false);
        buf_packet.add_additional_record(&resource).unwrap();
        assert!(buf_packet.add_name_server(&resource).is_err());
        assert!(!buf_packet.has_name_servers());
    }

    #[test]
    fn bufpacket_add_additional_records() {
        let mut buf_packet = PacketBuf::new(PacketHeader::new_query(0, false), false);
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
        let mut buf_packet = PacketBuf::new(PacketHeader::new_query(0, false), false);
        let question = Question::new(
            Name::new_unchecked("_srv._udp.local"),
            TYPE::TXT.into(),
            CLASS::IN.into(),
            false,
        );

        buf_packet.add_question(&question).unwrap();
        buf_packet.add_question(&question).unwrap();

        assert_eq!(2, buf_packet.questions_iter().count());
    }

    #[test]
    fn compression_multiple_names() {
        let mut buf_packet = PacketBuf::new(PacketHeader::new_query(0, false), true);

        buf_packet
            .add_answer(&ResourceRecord::new(
                Name::new_unchecked("a._tcp.local"),
                CLASS::IN,
                10,
                RData::A(A { address: 10 }),
            ))
            .unwrap();
        buf_packet
            .add_answer(&ResourceRecord::new(
                Name::new_unchecked("b._tcp.local"),
                CLASS::IN,
                10,
                RData::A(A { address: 10 }),
            ))
            .unwrap();

        buf_packet
            .add_answer(&ResourceRecord::new(
                Name::new_unchecked("b._tcp.local"),
                CLASS::IN,
                10,
                RData::A(A { address: 10 }),
            ))
            .unwrap();

        assert!(Packet::parse(&buf_packet).is_ok());
    }

    #[test]
    fn parse_ptr_with_compression() {
        let data: &[u8] = &[
            0x00, 0x00, 0x84, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x09, 0x5f,
            0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x07, 0x5f, 0x64, 0x6e, 0x73, 0x2d,
            0x73, 0x64, 0x04, 0x5f, 0x75, 0x64, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00,
            0x00, 0x0c, 0x80, 0x01, 0xc0, 0x0c, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0a,
            0x00, 0x11, 0x09, 0x5f, 0x73, 0x66, 0x74, 0x70, 0x2d, 0x73, 0x73, 0x68, 0x04, 0x5f,
            0x74, 0x63, 0x70, 0xc0, 0x23,
        ];

        assert!(Packet::parse(data).is_ok());
    }

    #[test]
    fn parse_cache_flush_package() {
        let data: &[u8] = &[
            0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0x33,
            0x01, 0x63, 0x01, 0x63, 0x01, 0x64, 0x01, 0x33, 0x01, 0x36, 0x01, 0x31, 0x01, 0x37,
            0x01, 0x65, 0x01, 0x62, 0x01, 0x38, 0x01, 0x37, 0x01, 0x39, 0x01, 0x38, 0x01, 0x32,
            0x01, 0x31, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30,
            0x01, 0x30, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30,
            0x01, 0x38, 0x01, 0x65, 0x01, 0x66, 0x03, 0x69, 0x70, 0x36, 0x04, 0x61, 0x72, 0x70,
            0x61, 0x00, 0x00, 0x0C, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x13, 0x0B, 0x69,
            0x6C, 0x73, 0x6F, 0x6E, 0x2D, 0x75, 0x78, 0x33, 0x31, 0x65, 0x05, 0x6C, 0x6F, 0x63,
            0x61, 0x6C, 0x00, 0xC0, 0x60, 0x00, 0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00,
            0x04, 0xC0, 0xA8, 0x01, 0x48, 0x02, 0x37, 0x32, 0x01, 0x31, 0x03, 0x31, 0x36, 0x38,
            0x03, 0x31, 0x39, 0x32, 0x07, 0x69, 0x6E, 0x2D, 0x61, 0x64, 0x64, 0x72, 0xC0, 0x50,
            0x00, 0x0C, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x02, 0xC0, 0x60, 0xC0, 0x60,
            0x00, 0x1C, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x10, 0xFE, 0x80, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x12, 0x89, 0x78, 0xBE, 0x71, 0x63, 0xDC, 0xC3,
        ];

        assert!(Packet::parse(data).is_ok());
    }
}
