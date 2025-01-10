use std::{borrow::Cow, convert::TryInto};

use crate::dns::WireFormat;

use super::RR;

/// The WKS record is used to describe the well known services supported by a particular protocol on a particular internet address.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct WKS<'a> {
    /// An 32 bit Internet address
    pub address: u32,
    /// An 8 bit IP protocol number
    pub protocol: u8,
    /// A variable length bit map.  The bit map must be a multiple of 8 bits long.
    pub bit_map: Cow<'a, [u8]>,
}

impl<'a> RR for WKS<'a> {
    const TYPE_CODE: u16 = 11;
}

impl<'a> WKS<'a> {
    /// Transforms the inner data into its owned type
    pub fn into_owned<'b>(self) -> WKS<'b> {
        WKS {
            address: self.address,
            protocol: self.protocol,
            bit_map: self.bit_map.into_owned().into(),
        }
    }
}

impl<'a> WireFormat<'a> for WKS<'a> {
    const MINIMUM_LEN: usize = 5;

    fn parse_after_check(data: &'a [u8], position: &mut usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let address = u32::from_be_bytes(data[*position..*position + 4].try_into()?);
        let protocol = data[*position + 4];
        let bit_map = Cow::Borrowed(&data[*position + 5..]);

        *position += 5 + bit_map.len();

        Ok(Self {
            address,
            protocol,
            bit_map,
        })
    }

    fn write_to<T: std::io::Write>(&self, out: &mut T) -> crate::Result<()> {
        out.write_all(&self.address.to_be_bytes())?;
        out.write_all(&[self.protocol])?;
        out.write_all(&self.bit_map)?;

        Ok(())
    }

    fn len(&self) -> usize {
        self.bit_map.len() + Self::MINIMUM_LEN
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::{dns::WireFormat, rdata::RData, ResourceRecord};

    #[test]
    fn parse_sample() -> Result<(), Box<dyn std::error::Error>> {
        let sample_file = std::fs::read("samples/zonefile/WKS.sample")?;

        let sample_rdata = match ResourceRecord::parse(&sample_file, &mut 0)?.rdata {
            RData::WKS(rdata) => rdata,
            _ => unreachable!(),
        };

        let sample_ip: u32 = "10.0.0.1".parse::<Ipv4Addr>()?.into();

        assert_eq!(sample_rdata.address, sample_ip);
        assert_eq!(sample_rdata.protocol, 6);
        assert_eq!(sample_rdata.bit_map, vec![224, 0, 5]);

        Ok(())
    }
}
