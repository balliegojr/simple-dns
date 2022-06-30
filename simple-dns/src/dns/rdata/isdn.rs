use std::collections::HashMap;

use crate::dns::{CharacterString, PacketPart};

use super::RR;

/// An ISDN (Integrated Service Digital Network) number is simply a telephone number.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct ISDN<'a> {
    /// A [CharacterString](`CharacterString`) which specifies the address.
    pub address: CharacterString<'a>,
    /// A [CharacterString](`CharacterString`) which specifies the subaddress.
    pub sa: CharacterString<'a>,
}

impl<'a> RR for ISDN<'a> {
    const TYPE_CODE: u16 = 20;
}

impl<'a> ISDN<'a> {
    /// Transforms the inner data into it's owned type
    pub fn into_owned<'b>(self) -> ISDN<'b> {
        ISDN {
            address: self.address.into_owned(),
            sa: self.sa.into_owned(),
        }
    }
}

impl<'a> PacketPart<'a> for ISDN<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let address = CharacterString::parse(data, position)?;
        let sa = CharacterString::parse(data, position + address.len())?;

        Ok(Self { address, sa })
    }

    fn append_to_vec(
        &self,
        out: &mut Vec<u8>,
        name_refs: &mut Option<&mut HashMap<u64, usize>>,
    ) -> crate::Result<()> {
        self.address.append_to_vec(out, name_refs)?;
        self.sa.append_to_vec(out, name_refs)
    }

    fn len(&self) -> usize {
        self.address.len() + self.sa.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_write_isdn() {
        let isdn = ISDN {
            address: CharacterString::new(b"150862028003217").unwrap(),
            sa: CharacterString::new(b"004").unwrap(),
        };

        let mut data = Vec::new();
        assert!(isdn.append_to_vec(&mut data, &mut None).is_ok());

        let isdn = ISDN::parse(&data, 0);
        assert!(isdn.is_ok());
        let isdn = isdn.unwrap();

        assert_eq!(data.len(), isdn.len());
        assert_eq!("150862028003217", isdn.address.to_string());
        assert_eq!("004", isdn.sa.to_string());
    }
}
