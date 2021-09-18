use std::{collections::HashMap, convert::TryInto};

use crate::dns::{DnsPacketContent, Name};

/// SOA records are used to mark the start of a zone of authority
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct SOA<'a> {
    /// The [Name](`Name`) of the name server that was the original or primary source of data for this zone.
    pub mname: Name<'a>,
    /// A [Name](`Name`) which specifies the mailbox of the person responsible for this zone.
    pub rname: Name<'a>,
    /// The unsigned 32 bit version number of the original copy of the zone.  Zone transfers preserve this value.  
    /// This value wraps and should be compared using sequence space arithmetic.
    pub serial: u32,
    /// A 32 bit time interval before the zone should be refreshed.
    pub refresh: i32,
    /// A 32 bit time interval that should elapse before a failed refresh should be retried.
    pub retry: i32,
    /// A 32 bit time value that specifies the upper limit on the time interval that can elapse before the zone is no longer authoritative.
    pub expire: i32,
    /// The unsigned 32 bit minimum TTL field that should be exported with any RR from this zone.
    pub minimum: u32,
}

impl<'a> SOA<'a> {
    fn append_commom(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        out.extend(self.serial.to_be_bytes());
        out.extend(self.refresh.to_be_bytes());
        out.extend(self.retry.to_be_bytes());
        out.extend(self.expire.to_be_bytes());
        out.extend(self.minimum.to_be_bytes());
        Ok(())
    }
}

impl<'a> DnsPacketContent<'a> for SOA<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let mname = Name::parse(data, position)?;
        let rname = Name::parse(data, position + mname.len())?;
        let offset = mname.len() + rname.len();

        let serial = u32::from_be_bytes(data[offset..offset + 4].try_into()?);
        let refresh = i32::from_be_bytes(data[offset + 4..offset + 8].try_into()?);
        let retry = i32::from_be_bytes(data[offset + 8..offset + 12].try_into()?);
        let expire = i32::from_be_bytes(data[offset + 12..offset + 16].try_into()?);
        let minimum = u32::from_be_bytes(data[offset + 16..offset + 20].try_into()?);

        Ok(Self {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        })
    }

    fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        self.mname.append_to_vec(out)?;
        self.rname.append_to_vec(out)?;
        self.append_commom(out)
    }

    fn len(&self) -> usize {
        self.mname.len() + self.rname.len() + 20
    }

    fn compress_append_to_vec(
        &self,
        out: &mut Vec<u8>,
        name_refs: &mut HashMap<u64, usize>,
    ) -> crate::Result<()> {
        self.mname.compress_append_to_vec(out, name_refs)?;
        self.rname.compress_append_to_vec(out, name_refs)?;
        self.append_commom(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_and_write_soa() {
        let soa = SOA {
            mname: Name::new("mname.soa.com").unwrap(),
            rname: Name::new("rname.soa.com").unwrap(),
            serial: 1,
            refresh: 2,
            retry: 3,
            expire: 4,
            minimum: 5,
        };

        let mut data = Vec::new();
        assert!(soa.append_to_vec(&mut data).is_ok());

        let soa = SOA::parse(&data, 0);
        assert!(soa.is_ok());
        let soa = soa.unwrap();

        assert_eq!(data.len(), soa.len());
    }
}
