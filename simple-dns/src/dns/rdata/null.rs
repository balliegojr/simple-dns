use crate::dns::{DnsPacketContent, MAX_NULL_LENGTH};

/// NULL resources are used to represent any kind of information.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct NULL<'a> {
    length: u16,
    data: &'a [u8]
}

impl <'a> NULL<'a> {
    /// Creates a new NULL rdata
    pub fn new(data: &'a [u8]) -> crate::Result<Self> {
        if data.len() > MAX_NULL_LENGTH {
            return Err(crate::SimpleDnsError::InvalidDnsPacket);
        }

        Ok(
            Self {
                length: data.len() as u16,
                data
           }
        )
    }

    /// get a read only reference to internal data
    pub fn get_data(&self) -> &'a [u8] {
        self.data
    }
}


impl <'a> DnsPacketContent<'a> for NULL<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self> where Self: Sized {
        Self::new(&data[position..])
    }

    fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        out.extend(self.data);
        Ok(())
    }

    fn len(&self) -> usize {
        self.length as usize
    }
}
