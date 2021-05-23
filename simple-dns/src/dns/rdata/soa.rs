use crate::dns::{DnsPacketContent, Name};
use byteorder::{BigEndian, ByteOrder};

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

impl<'a> DnsPacketContent<'a> for SOA<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let mname = Name::parse(data, position)?;
        let rname = Name::parse(data, position + mname.len())?;
        let offset = mname.len() + rname.len();

        let serial = BigEndian::read_u32(&data[offset..offset + 4]);
        let refresh = BigEndian::read_i32(&data[offset + 4..offset + 8]);
        let retry = BigEndian::read_i32(&data[offset + 8..offset + 12]);
        let expire = BigEndian::read_i32(&data[offset + 12..offset + 16]);
        let minimum = BigEndian::read_u32(&data[offset + 16..offset + 20]);

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

        let mut buffer = [0u8; 20];
        BigEndian::write_u32(&mut buffer[..4], self.serial);
        BigEndian::write_i32(&mut buffer[4..8], self.refresh);
        BigEndian::write_i32(&mut buffer[8..12], self.retry);
        BigEndian::write_i32(&mut buffer[12..16], self.expire);
        BigEndian::write_u32(&mut buffer[16..20], self.minimum);

        out.extend(&buffer[..]);
        Ok(())
    }

    fn len(&self) -> usize {
        self.mname.len() + self.rname.len() + 20
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
