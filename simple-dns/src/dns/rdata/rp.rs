use std::collections::HashMap;

use crate::dns::{DnsPacketContent, Name};

/// RP Responsible Person, [RFC 1183](https://datatracker.ietf.org/doc/html/rfc1183#section-2.2)
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct RP<'a> {
    /// A [Name](`Name`) which specifies a mailbox for the responsble person.
    pub mbox: Name<'a>,
    /// A [Name](`Name`) which specifies a domain name the TXT records.
    pub txt: Name<'a>,
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

impl<'a> DnsPacketContent<'a> for RP<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let mbox = Name::parse(data, position)?;
        let txt = Name::parse(data, position + mbox.len())?;
        Ok(RP { mbox, txt })
    }

    fn append_to_vec(
        &self,
        out: &mut Vec<u8>,
        name_refs: &mut Option<&mut HashMap<u64, usize>>,
    ) -> crate::Result<()> {
        self.mbox.append_to_vec(out, name_refs)?;
        self.txt.append_to_vec(out, name_refs)
    }

    fn len(&self) -> usize {
        self.txt.len() + self.mbox.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_write_rp() {
        let rp = RP {
            mbox: Name::new("mbox.rp.com").unwrap(),
            txt: Name::new("txt.rp.com").unwrap(),
        };

        let mut data = Vec::new();
        assert!(rp.append_to_vec(&mut data, &mut None).is_ok());

        let rp = RP::parse(&data, 0);
        assert!(rp.is_ok());
        let rp = rp.unwrap();

        assert_eq!(data.len(), rp.len());
        assert_eq!("mbox.rp.com", rp.mbox.to_string());
        assert_eq!("txt.rp.com", rp.txt.to_string());
    }
}
