use std::collections::HashMap;

use crate::dns::{DnsPacketContent, Name};

/// MINFO recors are used to acquire mailbox or mail list information
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct MINFO<'a> {
    /// A [Name](`Name`) which specifies a mailbox which is responsible for the mailing list or mailbox.  
    pub rmailbox: Name<'a>,
    /// A [Name](`Name`) which specifies a mailbox which is to receive error messages related to  
    /// the mailing list or mailbox specified by the owner of the MINFO RR
    pub emailbox: Name<'a>,
}

impl<'a> DnsPacketContent<'a> for MINFO<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let rmailbox = Name::parse(data, position)?;
        let emailbox = Name::parse(data, position + rmailbox.len())?;

        Ok(Self { rmailbox, emailbox })
    }

    fn append_to_vec(
        &self,
        out: &mut Vec<u8>,
        name_refs: &mut HashMap<u64, usize>,
    ) -> crate::Result<()> {
        self.rmailbox.append_to_vec(out, name_refs)?;
        self.emailbox.append_to_vec(out, name_refs)
    }

    fn len(&self) -> usize {
        self.rmailbox.len() + self.emailbox.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_write_hinfo() {
        let minfo = MINFO {
            rmailbox: Name::new("r.mailbox.com").unwrap(),
            emailbox: Name::new("e.mailbox.com").unwrap(),
        };

        let mut data = Vec::new();
        let mut name_refs = HashMap::new();
        assert!(minfo.append_to_vec(&mut data, &mut name_refs).is_ok());

        let minfo = MINFO::parse(&data, 0);
        assert!(minfo.is_ok());
        let minfo = minfo.unwrap();

        assert_eq!(data.len(), minfo.len());
        assert_eq!("r.mailbox.com", minfo.rmailbox.to_string());
        assert_eq!("e.mailbox.com", minfo.emailbox.to_string());
    }
}
