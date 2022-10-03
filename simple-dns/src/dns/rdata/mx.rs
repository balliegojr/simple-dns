use std::{collections::HashMap, convert::TryInto};

use crate::dns::{Name, PacketPart};

use super::RR;

/// MX is used to acquire mail exchange information
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct MX<'a> {
    /// A 16 bit integer which specifies the preference given to this RR among others at the same owner.  
    /// Lower values are preferred.
    pub preference: u16,

    /// A [Name](`Name`) which specifies a host willing to act as a mail exchange for the owner name.
    pub exchange: Name<'a>,
}

impl<'a> RR for MX<'a> {
    const TYPE_CODE: u16 = 15;
}

impl<'a> MX<'a> {
    /// Transforms the inner data into it's owned type
    pub fn into_owned<'b>(self) -> MX<'b> {
        MX {
            preference: self.preference,
            exchange: self.exchange.into_owned(),
        }
    }
}

impl<'a> PacketPart<'a> for MX<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let preference = u16::from_be_bytes(data[position..position + 2].try_into()?);
        let exchange = Name::parse(data, position + 2)?;

        Ok(Self {
            preference,
            exchange,
        })
    }

    fn append_to_vec(
        &self,
        out: &mut Vec<u8>,
        name_refs: &mut Option<&mut HashMap<u64, usize>>,
    ) -> crate::Result<()> {
        out.extend(self.preference.to_be_bytes());
        self.exchange.append_to_vec(out, name_refs)
    }

    fn len(&self) -> usize {
        self.exchange.len() + 2
    }
}

#[cfg(test)]
mod tests {
    use crate::{rdata::RData, ResourceRecord};

    use super::*;

    #[test]
    fn parse_and_write_mx() {
        let mx = MX {
            preference: 10,
            exchange: Name::new("e.exchange.com").unwrap(),
        };

        let mut data = Vec::new();
        assert!(mx.append_to_vec(&mut data, &mut None).is_ok());

        let mx = MX::parse(&data, 0);
        assert!(mx.is_ok());
        let mx = mx.unwrap();

        assert_eq!(data.len(), mx.len());
        assert_eq!(10, mx.preference);
        assert_eq!("e.exchange.com", mx.exchange.to_string());
    }

    #[test]
    fn parse_sample() -> Result<(), Box<dyn std::error::Error>> {
        let sample_file = std::fs::read("samples/zonefile/MX.sample")?;

        let sample_rdata = match ResourceRecord::parse(&sample_file, 0)?.rdata {
            RData::MX(rdata) => rdata,
            _ => unreachable!(),
        };

        assert_eq!(sample_rdata.preference, 10);
        assert_eq!(sample_rdata.exchange, "VENERA.sample".try_into()?);
        Ok(())
    }
}
