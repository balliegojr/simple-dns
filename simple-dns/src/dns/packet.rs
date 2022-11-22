use std::{collections::HashMap, usize};

use crate::{header_buffer, rdata::OPT, RCODE};

use super::{Header, PacketFlag, PacketPart, Question, ResourceRecord, OPCODE};

/// Represents a DNS message packet
///
/// When working with EDNS packets, use [Packet::opt] and [Packet::opt_mut] to add or access [OPT] packet information
#[derive(Debug, Clone)]
pub struct Packet<'a> {
    /// Packet header
    header: Header<'a>,
    /// Questions section
    pub questions: Vec<Question<'a>>,
    /// Answers section
    pub answers: Vec<ResourceRecord<'a>>,
    /// Name servers section
    pub name_servers: Vec<ResourceRecord<'a>>,
    /// Aditional records section.  
    /// DO NOT use this field to add OPT record, use [`opt_mut`] instead
    pub additional_records: Vec<ResourceRecord<'a>>,
}

impl<'a> Packet<'a> {
    /// Creates a new empty packet with a query header
    pub fn new_query(id: u16) -> Self {
        Self {
            header: Header::new_query(id),
            questions: Vec::new(),
            answers: Vec::new(),
            name_servers: Vec::new(),
            additional_records: Vec::new(),
        }
    }

    /// Creates a new empty packet with a reply header
    pub fn new_reply(id: u16) -> Self {
        Self {
            header: Header::new_reply(id, OPCODE::StandardQuery),
            questions: Vec::new(),
            answers: Vec::new(),
            name_servers: Vec::new(),
            additional_records: Vec::new(),
        }
    }

    /// Get packet id
    pub fn id(&self) -> u16 {
        self.header.id
    }

    /// Set flags in the packet
    pub fn set_flags(&mut self, flags: PacketFlag) {
        self.header.set_flags(flags);
    }

    /// Remove flags present in the packet
    pub fn remove_flags(&mut self, flags: PacketFlag) {
        self.header.remove_flags(flags)
    }

    /// Check if the packet has flags set
    pub fn has_flags(&self, flags: PacketFlag) -> bool {
        self.header.has_flags(flags)
    }

    /// Get this packet [RCODE] information
    pub fn rcode(&self) -> RCODE {
        self.header.response_code
    }

    /// Get a mutable reference for  this packet [RCODE] information
    /// Warning, if the [RCODE] value is greater than 15 (4 bits), you MUST provide an [OPT]
    /// resource record through the [opt_mut] function
    pub fn rcode_mut(&mut self) -> &mut RCODE {
        &mut self.header.response_code
    }

    /// Get this packet [OPCODE] information
    pub fn opcode(&self) -> OPCODE {
        self.header.opcode
    }

    /// Get a mutable reference for this packet [OPCODE] information
    pub fn opcode_mut(&mut self) -> &mut OPCODE {
        &mut self.header.opcode
    }

    /// Get the [OPT] resource record for this packet, if present
    pub fn opt(&self) -> Option<&OPT<'a>> {
        self.header.opt.as_ref()
    }

    /// Get a mutable reference for this packet [OPT] resource record.  
    pub fn opt_mut(&mut self) -> &mut Option<OPT<'a>> {
        &mut self.header.opt
    }

    /// Changes this packet into a reply packet by replacing its header
    pub fn into_reply(mut self) -> Self {
        self.header = Header::new_reply(self.header.id, self.header.opcode);
        self
    }

    /// Parses a packet from a slice of bytes
    pub fn parse(data: &'a [u8]) -> crate::Result<Self> {
        let mut header = Header::parse(&data[..12])?;

        let mut offset = 12;
        let questions = Self::parse_section(data, &mut offset, header_buffer::questions(data)?)?;
        let answers = Self::parse_section(data, &mut offset, header_buffer::answers(data)?)?;
        let name_servers =
            Self::parse_section(data, &mut offset, header_buffer::name_servers(data)?)?;
        let mut additional_records: Vec<ResourceRecord> =
            Self::parse_section(data, &mut offset, header_buffer::additional_records(data)?)?;

        header.incorporate_opt_rr(
            additional_records
                .iter()
                .position(|rr| rr.rdata.type_code() == crate::TYPE::OPT)
                .map(|i| additional_records.remove(i)),
        );

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

        if let Some(rr) = self.header.get_opt_rr() {
            rr.append_to_vec(&mut out, &mut None)?;
        }

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

        if let Some(rr) = self.header.get_opt_rr() {
            rr.append_to_vec(&mut out, &mut None)?;
        }

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
            header_buffer::set_questions(out, self.questions.len() as u16)
        }

        if !self.answers.is_empty() {
            header_buffer::set_answers(out, self.answers.len() as u16)
        }

        if !self.name_servers.is_empty() {
            header_buffer::set_name_servers(out, self.name_servers.len() as u16)
        }

        let additional_records_len =
            self.additional_records.len() + usize::from(self.header.opt.is_some());
        if additional_records_len > 0 {
            header_buffer::set_additional_records(out, additional_records_len as u16)
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
    use crate::{dns::CLASS, dns::TYPE};

    use super::*;
    use std::convert::TryInto;

    #[test]
    fn build_query_correct() {
        let mut query = Packet::new_query(1);
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
}
