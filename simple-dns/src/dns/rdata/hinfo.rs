use std::collections::HashMap;

use crate::dns::{CharacterString, PacketPart};

use super::RR;

/// HINFO records are used to acquire general information about a host.  
/// The main use is for protocols such as FTP that can use special procedures
/// when talking between machines or operating systems of the same type.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct HINFO<'a> {
    /// A [CharacterString](`CharacterString`) which specifies the CPU type.
    pub cpu: CharacterString<'a>,
    /// A [CharacterString](`CharacterString`) which specifies the operating system type.
    pub os: CharacterString<'a>,
}

impl<'a> RR for HINFO<'a> {
    const TYPE_CODE: u16 = 13;
}

impl<'a> HINFO<'a> {
    /// Transforms the inner data into it's owned type
    pub fn into_owned<'b>(self) -> HINFO<'b> {
        HINFO {
            cpu: self.cpu.into_owned(),
            os: self.os.into_owned(),
        }
    }
}

impl<'a> PacketPart<'a> for HINFO<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let cpu = CharacterString::parse(data, position)?;
        let os = CharacterString::parse(data, position + cpu.len())?;

        Ok(Self { cpu, os })
    }

    fn append_to_vec(
        &self,
        out: &mut Vec<u8>,
        name_refs: &mut Option<&mut HashMap<u64, usize>>,
    ) -> crate::Result<()> {
        self.cpu.append_to_vec(out, name_refs)?;
        self.os.append_to_vec(out, name_refs)
    }

    fn len(&self) -> usize {
        self.cpu.len() + self.os.len()
    }
}

#[cfg(test)]
mod tests {
    use crate::{rdata::RData, ResourceRecord};

    use super::*;

    #[test]
    fn parse_and_write_hinfo() {
        let hinfo = HINFO {
            cpu: CharacterString::new(b"\"some cpu").unwrap(),
            os: CharacterString::new(b"\"some os").unwrap(),
        };

        let mut data = Vec::new();
        assert!(hinfo.append_to_vec(&mut data, &mut None).is_ok());

        let hinfo = HINFO::parse(&data, 0);
        assert!(hinfo.is_ok());
        let hinfo = hinfo.unwrap();

        assert_eq!(data.len(), hinfo.len());
        assert_eq!("\"some cpu", hinfo.cpu.to_string());
        assert_eq!("\"some os", hinfo.os.to_string());
    }

    #[test]
    fn parse_sample() -> Result<(), Box<dyn std::error::Error>> {
        let sample_file = std::fs::read("samples/zonefile/HINFO.sample.")?;

        let sample_rdata = match ResourceRecord::parse(&sample_file, 0)?.rdata {
            RData::HINFO(rdata) => rdata,
            _ => unreachable!(),
        };

        assert_eq!(sample_rdata.cpu, "Generic PC clone".try_into()?);
        assert_eq!(sample_rdata.os, "NetBSD-1.4".try_into()?);
        Ok(())
    }
}
