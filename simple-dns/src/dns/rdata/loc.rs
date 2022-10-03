use crate::{dns::packet_part::PacketPart, SimpleDnsError};

use super::RR;

///  A Means for Expressing Location Information in the Domain Name System [RFC 1876](https://datatracker.ietf.org/doc/html/rfc1876)
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct LOC {
    /// Version number of the representation.  This must be zero.
    pub version: u8,
    /// The diameter of a sphere enclosing the described entity, in centimeters, expressed as a pair of four-bit unsigned integers
    pub size: u8,
    /// The horizontal precision of the data, in centimeters, expressed using the same representation as SIZE
    pub horizontal_precision: u8,
    /// The vertical precision of the data, in centimeters, expressed using the sane representation as for SIZE
    pub vertical_precision: u8,
    /// The latitude of the center of the sphere described by the SIZE field
    pub latitude: i32,
    /// The longitude of the center of the sphere described by the SIZE field
    pub longitude: i32,
    /// The altitude of the center of the sphere described by the SIZE field
    pub altitude: i32,
}

impl RR for LOC {
    const TYPE_CODE: u16 = 29;
}

impl LOC {
    /// Transforms the inner data into it's owned type
    pub fn into_owned(self) -> Self {
        self
    }
}

impl<'a> PacketPart<'a> for LOC {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        if data.len() < position + 16 {
            return Err(SimpleDnsError::InsufficientData);
        }

        let data = &data[position..position + 16];

        let version = u8::from_be(data[0]);
        if version != 0 {
            return Err(SimpleDnsError::InvalidDnsPacket);
        }

        let size = u8::from_be(data[1]);
        let horizontal_precision = u8::from_be(data[2]);
        let vertical_precision = u8::from_be(data[3]);
        let latitude = i32::from_be_bytes(data[4..8].try_into()?);
        let longitude = i32::from_be_bytes(data[8..12].try_into()?);
        let altitude = i32::from_be_bytes(data[12..16].try_into()?);

        Ok(LOC {
            version,
            size,
            horizontal_precision,
            vertical_precision,
            latitude,
            longitude,
            altitude,
        })
    }

    fn append_to_vec(
        &self,
        out: &mut Vec<u8>,
        _name_refs: &mut Option<&mut std::collections::HashMap<u64, usize>>,
    ) -> crate::Result<()> {
        if self.version != 0 {
            return Err(SimpleDnsError::InvalidDnsPacket);
        }

        out.push(self.version.to_be());
        out.push(self.size.to_be());
        out.push(self.horizontal_precision.to_be());
        out.push(self.vertical_precision.to_be());
        out.extend(self.latitude.to_be_bytes());
        out.extend(self.longitude.to_be_bytes());
        out.extend(self.altitude.to_be_bytes());

        Ok(())
    }

    fn len(&self) -> usize {
        16
    }
}

#[cfg(test)]
mod tests {
    use crate::{rdata::RData, ResourceRecord};

    use super::*;

    #[test]
    fn parse_and_write_loc() {
        let loc = LOC {
            version: 0,
            size: 0x10,
            vertical_precision: 0x11,
            horizontal_precision: 0x12,
            altitude: 1000,
            longitude: 2000,
            latitude: 3000,
        };

        let mut data = Vec::new();
        assert!(loc.append_to_vec(&mut data, &mut None).is_ok());

        let loc = LOC::parse(&data, 0);
        assert!(loc.is_ok());
        let loc = loc.unwrap();

        assert_eq!(0x10, loc.size);
        assert_eq!(0x11, loc.vertical_precision);
        assert_eq!(0x12, loc.horizontal_precision);
        assert_eq!(1000, loc.altitude);
        assert_eq!(2000, loc.longitude);
        assert_eq!(3000, loc.latitude);

        assert_eq!(data.len(), loc.len());
    }

    #[test]
    fn parse_sample() -> Result<(), Box<dyn std::error::Error>> {
        let sample_file = std::fs::read("samples/zonefile/LOC.sample")?;

        let sample_rdata = match ResourceRecord::parse(&sample_file, 0)?.rdata {
            RData::LOC(rdata) => rdata,
            _ => unreachable!(),
        };

        // 60 09 00.000 N 24 39 00.000 E 10.00m 20.00m ( 2000.00m 20.00m )
        assert_eq!(35, sample_rdata.size);
        assert_eq!(35, sample_rdata.vertical_precision);
        assert_eq!(37, sample_rdata.horizontal_precision);
        assert_eq!(10001000, sample_rdata.altitude);
        assert_eq!(-2058743648, sample_rdata.longitude);
        assert_eq!(-1930943648, sample_rdata.latitude);
        Ok(())
    }
}
