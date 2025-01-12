use std::collections::HashMap;

use crate::{
    bytes_buffer::BytesBuffer,
    dns::{name::Label, CharacterString, WireFormat},
};

use super::RR;

/// An ISDN (Integrated Service Digital Network) number is simply a telephone number.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct ISDN<'a> {
    /// A [CharacterString](`CharacterString`) which specifies the address.
    pub address: CharacterString<'a>,
    /// A [CharacterString](`CharacterString`) which specifies the subaddress.
    pub sa: CharacterString<'a>,
}

impl RR for ISDN<'_> {
    const TYPE_CODE: u16 = 20;
}

impl ISDN<'_> {
    /// Transforms the inner data into its owned type
    pub fn into_owned<'b>(self) -> ISDN<'b> {
        ISDN {
            address: self.address.into_owned(),
            sa: self.sa.into_owned(),
        }
    }
}

impl<'a> WireFormat<'a> for ISDN<'a> {
    const MINIMUM_LEN: usize = 0;
    fn parse(data: &mut BytesBuffer<'a>) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let address = CharacterString::parse(data)?;
        let sa = CharacterString::parse(data)?;

        Ok(Self { address, sa })
    }

    fn write_to<T: std::io::Write>(&self, out: &mut T) -> crate::Result<()> {
        self.address.write_to(out)?;
        self.sa.write_to(out)
    }

    fn write_compressed_to<T: std::io::Write + std::io::Seek>(
        &'a self,
        out: &mut T,
        name_refs: &mut HashMap<&'a [Label<'a>], usize>,
    ) -> crate::Result<()> {
        self.address.write_compressed_to(out, name_refs)?;
        self.sa.write_compressed_to(out, name_refs)
    }

    fn len(&self) -> usize {
        self.address.len() + self.sa.len()
    }
}

#[cfg(test)]
mod tests {
    use crate::{rdata::RData, ResourceRecord};

    use super::*;

    #[test]
    fn parse_and_write_isdn() {
        let isdn = ISDN {
            address: CharacterString::new(b"150862028003217").unwrap(),
            sa: CharacterString::new(b"004").unwrap(),
        };

        let mut data = Vec::new();
        assert!(isdn.write_to(&mut data).is_ok());

        let isdn = ISDN::parse(&mut (&data[..]).into());
        assert!(isdn.is_ok());
        let isdn = isdn.unwrap();

        assert_eq!(data.len(), isdn.len());
        assert_eq!("150862028003217", isdn.address.to_string());
        assert_eq!("004", isdn.sa.to_string());
    }

    #[test]
    fn parse_sample() -> Result<(), Box<dyn std::error::Error>> {
        let sample_file = std::fs::read("samples/zonefile/ISDN.sample")?;

        let sample_rdata = match ResourceRecord::parse(&mut (&sample_file[..]).into())?.rdata {
            RData::ISDN(rdata) => rdata,
            _ => unreachable!(),
        };

        assert_eq!(sample_rdata.address, "isdn-address".try_into()?);
        assert_eq!(sample_rdata.sa, "subaddress".try_into()?);
        Ok(())
    }
}
