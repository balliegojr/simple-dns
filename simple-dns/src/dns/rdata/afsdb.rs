use std::collections::HashMap;

use crate::dns::{Name, PacketPart};

use super::RR;

/// AFSDB records represents servers with ASD cells
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct AFSDB<'a> {
    /// An integer that represents the subtype
    pub subtype: u16,
    /// The <hostname> field is a [name](`Name`) name of a host that has a server for the cell named by the owner name of the RR
    pub hostname: Name<'a>,
}

impl<'a> RR for AFSDB<'a> {
    const TYPE_CODE: u16 = 18;
}

impl<'a> AFSDB<'a> {
    /// Transforms the inner data into it's owned type
    pub fn into_owned<'b>(self) -> AFSDB<'b> {
        AFSDB {
            subtype: self.subtype,
            hostname: self.hostname.into_owned(),
        }
    }
}

impl<'a> PacketPart<'a> for AFSDB<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let subtype = u16::from_be_bytes(data[position..position + 2].try_into()?);
        let hostname = Name::parse(data, position + 2)?;

        Ok(Self { subtype, hostname })
    }

    fn append_to_vec(
        &self,
        out: &mut Vec<u8>,
        name_refs: &mut Option<&mut HashMap<u64, usize>>,
    ) -> crate::Result<()> {
        out.extend(self.subtype.to_be_bytes());
        self.hostname.append_to_vec(out, name_refs)
    }

    fn len(&self) -> usize {
        self.hostname.len() + 2
    }
}

#[cfg(test)]
mod tests {
    use crate::{rdata::RData, ResourceRecord};

    use super::*;

    #[test]
    fn parse_and_write_afsdb() {
        let afsdb = AFSDB {
            subtype: 1,
            hostname: Name::new("e.hostname.com").unwrap(),
        };

        let mut data = Vec::new();
        assert!(afsdb.append_to_vec(&mut data, &mut None).is_ok());

        let afsdb = AFSDB::parse(&data, 0);
        assert!(afsdb.is_ok());
        let afsdb = afsdb.unwrap();

        assert_eq!(data.len(), afsdb.len());
        assert_eq!(1, afsdb.subtype);
        assert_eq!("e.hostname.com", afsdb.hostname.to_string());
    }

    #[test]
    fn parse_sample() -> Result<(), Box<dyn std::error::Error>> {
        let sample_file = std::fs::read("samples/zonefile/AFSDB.sample")?;

        let sample_rdata = match ResourceRecord::parse(&sample_file, 0)?.rdata {
            RData::AFSDB(rdata) => rdata,
            _ => unreachable!(),
        };

        assert_eq!(sample_rdata.subtype, 0);
        assert_eq!(sample_rdata.hostname, "hostname.sample".try_into()?);
        Ok(())
    }
}
