use std::collections::HashMap;

use crate::dns::{Name, PacketPart};

use super::RR;

/// RP Responsible Person, [RFC 1183](https://datatracker.ietf.org/doc/html/rfc1183#section-2.2)
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct RP<'a> {
    /// A [Name](`Name`) which specifies a mailbox for the responsble person.
    pub mbox: Name<'a>,
    /// A [Name](`Name`) which specifies a domain name the TXT records.
    pub txt: Name<'a>,
}

impl<'a> RR for RP<'a> {
    const TYPE_CODE: u16 = 17;
}

impl<'a> RP<'a> {
    /// Transforms the inner data into it's owned type
    pub fn into_owned<'b>(self) -> RP<'b> {
        RP {
            mbox: self.mbox.into_owned(),
            txt: self.txt.into_owned(),
        }
    }
}

impl<'a> PacketPart<'a> for RP<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let mbox = Name::parse(data, position)?;
        let txt = Name::parse(data, position + mbox.len())?;
        Ok(RP { mbox, txt })
    }

    fn write_to<T: std::io::Write>(&self, out: &mut T) -> crate::Result<()> {
        self.mbox.write_to(out)?;
        self.txt.write_to(out)
    }

    fn write_compressed_to<T: std::io::Write + std::io::Seek>(
        &self,
        out: &mut T,
        name_refs: &mut HashMap<u64, usize>,
    ) -> crate::Result<()> {
        self.mbox.write_compressed_to(out, name_refs)?;
        self.txt.write_compressed_to(out, name_refs)
    }

    fn len(&self) -> usize {
        self.txt.len() + self.mbox.len()
    }
}

#[cfg(test)]
mod tests {
    use crate::{rdata::RData, ResourceRecord};

    use super::*;

    #[test]
    fn parse_and_write_rp() {
        let rp = RP {
            mbox: Name::new("mbox.rp.com").unwrap(),
            txt: Name::new("txt.rp.com").unwrap(),
        };

        let mut data = Vec::new();
        assert!(rp.write_to(&mut data).is_ok());

        let rp = RP::parse(&data, 0);
        assert!(rp.is_ok());
        let rp = rp.unwrap();

        assert_eq!(data.len(), rp.len());
        assert_eq!("mbox.rp.com", rp.mbox.to_string());
        assert_eq!("txt.rp.com", rp.txt.to_string());
    }

    #[test]
    fn parse_sample() -> Result<(), Box<dyn std::error::Error>> {
        let sample_file = std::fs::read("samples/zonefile/RP.sample")?;

        let sample_rdata = match ResourceRecord::parse(&sample_file, 0)?.rdata {
            RData::RP(rdata) => rdata,
            _ => unreachable!(),
        };

        assert_eq!(sample_rdata.mbox, "mbox-dname.sample".try_into()?);
        assert_eq!(sample_rdata.txt, "txt-dname.sample".try_into()?);
        Ok(())
    }
}
