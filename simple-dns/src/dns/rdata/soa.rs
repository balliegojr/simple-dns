use std::{collections::HashMap, convert::TryInto};

use crate::{
    dns::{Name, PacketPart},
    master::ParseError,
};

use super::RR;

/// SOA records are used to mark the start of a zone of authority
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
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

impl<'a> RR<'a> for SOA<'a> {
    const TYPE_CODE: u16 = 6;

    fn try_build(tokens: &[&'a str], origin: &Name) -> Result<Self, ParseError> {
        use ParseError::InvalidToken;
        use ParseError::UnexpectedEndOfInput;

        let mname = tokens.first().ok_or(UnexpectedEndOfInput)?;
        let rname = tokens.get(1).ok_or(UnexpectedEndOfInput)?;
        let serial = tokens.get(2).ok_or(UnexpectedEndOfInput)?;
        let refresh = tokens.get(3).ok_or(UnexpectedEndOfInput)?;
        let retry = tokens.get(4).ok_or(UnexpectedEndOfInput)?;
        let expire = tokens.get(5).ok_or(UnexpectedEndOfInput)?;
        let minimum = tokens.get(6).ok_or(UnexpectedEndOfInput)?;

        Ok(SOA {
            mname: Name::new_from_token(mname, origin)?,
            rname: Name::new_from_token(rname, origin)?,
            serial: serial
                .parse()
                .map_err(|_| InvalidToken(serial.to_string()))?,
            refresh: refresh
                .parse()
                .map_err(|_| InvalidToken(refresh.to_string()))?,
            retry: retry.parse().map_err(|_| InvalidToken(retry.to_string()))?,
            expire: expire
                .parse()
                .map_err(|_| InvalidToken(expire.to_string()))?,
            minimum: minimum
                .parse()
                .map_err(|_| InvalidToken(minimum.to_string()))?,
        })
    }
}

impl<'a> SOA<'a> {
    /// Transforms the inner data into it's owned type
    pub fn into_owned<'b>(self) -> SOA<'b> {
        SOA {
            mname: self.mname.into_owned(),
            rname: self.rname.into_owned(),
            serial: self.serial,
            refresh: self.refresh,
            retry: self.retry,
            expire: self.expire,
            minimum: self.minimum,
        }
    }

    fn write_common<T: std::io::Write>(&self, out: &mut T) -> crate::Result<()> {
        out.write_all(&self.serial.to_be_bytes())?;
        out.write_all(&self.refresh.to_be_bytes())?;
        out.write_all(&self.retry.to_be_bytes())?;
        out.write_all(&self.expire.to_be_bytes())?;
        out.write_all(&self.minimum.to_be_bytes())?;

        Ok(())
    }
}

impl<'a> PacketPart<'a> for SOA<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let mname = Name::parse(data, position)?;
        let rname = Name::parse(data, position + mname.len())?;
        let offset = position + mname.len() + rname.len();

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

    fn write_to<T: std::io::Write>(&self, out: &mut T) -> crate::Result<()> {
        self.mname.write_to(out)?;
        self.rname.write_to(out)?;
        self.write_common(out)
    }

    fn write_compressed_to<T: std::io::Write + std::io::Seek>(
        &self,
        out: &mut T,
        name_refs: &mut HashMap<u64, usize>,
    ) -> crate::Result<()> {
        self.mname.write_compressed_to(out, name_refs)?;
        self.rname.write_compressed_to(out, name_refs)?;
        self.write_common(out)
    }

    fn len(&self) -> usize {
        self.mname.len() + self.rname.len() + 20
    }
}

#[cfg(test)]
mod tests {
    use crate::{rdata::RData, ResourceRecord};

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
        assert!(soa.write_to(&mut data).is_ok());

        let soa = SOA::parse(&data, 0);
        assert!(soa.is_ok());
        let soa = soa.unwrap();

        assert_eq!(data.len(), soa.len());
    }

    #[test]
    fn parse_sample() -> Result<(), Box<dyn std::error::Error>> {
        let sample_file = std::fs::read("samples/zonefile/SOA.sample")?;

        let sample_rdata = match ResourceRecord::parse(&sample_file, 0)?.rdata {
            RData::SOA(rdata) => rdata,
            _ => unreachable!(),
        };

        assert_eq!(sample_rdata.mname, "VENERA.sample".try_into()?);
        assert_eq!(sample_rdata.rname, "Action\\.domains.sample".try_into()?);
        assert_eq!(sample_rdata.serial, 20);
        assert_eq!(sample_rdata.refresh, 7200);
        assert_eq!(sample_rdata.retry, 600);
        assert_eq!(sample_rdata.expire, 3600000);
        assert_eq!(sample_rdata.minimum, 60);

        Ok(())
    }

    #[test]
    fn test_try_build() {
        let soa = SOA::try_build(
            &[
                "VENERA",
                "Action\\.domains",
                "20",
                "7200",
                "600",
                "3600000",
                "60",
            ],
            &Name::new_unchecked("domain.com"),
        )
        .expect("failed to build soa");

        assert_eq!(
            SOA {
                mname: Name::new("VENERA").unwrap(),
                rname: Name::new("Action\\.domains").unwrap(),
                serial: 20,
                refresh: 7200,
                retry: 600,
                expire: 3600000,
                minimum: 60
            },
            soa
        );
    }
}
