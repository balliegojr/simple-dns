use crate::{dns::packet_part::PacketPart, SimpleDnsError};

use super::RR;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
/// NSAP structure [RFC 1706](https://datatracker.ietf.org/doc/html/rfc1706)  
///  ATTENTION: this code doesn't validade the content of the NSAP RR, it just split the bytes in the correct order
pub struct NSAP {
    inner: [u8; 20],
}

impl RR for NSAP {
    const TYPE_CODE: u16 = 22;
}

impl NSAP {
    /// Create new NSAP from components
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        afi: u8,
        idi: u16,
        dfi: u8,
        aa: u32,
        rsvd: u16,
        rd: u16,
        area: u16,
        id: u64,
        sel: u8,
    ) -> Self {
        let mut inner = [0_u8; 20];
        inner[0] = afi;
        [inner[1], inner[2]] = idi.to_le_bytes();
        inner[3] = dfi;
        [inner[4], inner[5], inner[6], _] = aa.to_le_bytes();

        [inner[7], inner[8]] = rsvd.to_le_bytes();
        [inner[9], inner[10]] = rd.to_le_bytes();
        [inner[11], inner[12]] = area.to_le_bytes();
        [
            inner[13],
            inner[14],
            inner[15],
            inner[16],
            inner[17],
            inner[18],
            _,
            _,
        ] = id.to_le_bytes();
        inner[19] = sel;

        Self { inner }
    }

    /// Transforms the inner data into it's owned type
    pub fn into_owned(self) -> Self {
        self
    }

    /// Authority and Format Identifier
    pub fn afi(&self) -> u8 {
        self.inner[0]
    }

    /// Initial Domain Identifier
    pub fn idi(&self) -> u16 {
        let bytes = [self.inner[1], self.inner[2]];
        u16::from_le_bytes(bytes)
    }

    /// DSP Format Identifier
    pub fn dfi(&self) -> u8 {
        self.inner[3]
    }

    /// Administrative Authority
    pub fn aa(&self) -> u32 {
        let bytes = [self.inner[4], self.inner[5], self.inner[6], 0];
        u32::from_le_bytes(bytes)
    }

    /// Reserved
    pub fn rsvd(&self) -> u16 {
        let bytes = [self.inner[7], self.inner[8]];
        u16::from_le_bytes(bytes)
    }

    /// Routing Domain Identifier
    pub fn rd(&self) -> u16 {
        let bytes = [self.inner[9], self.inner[10]];
        u16::from_le_bytes(bytes)
    }

    /// Area Identifier
    pub fn area(&self) -> u16 {
        let bytes = [self.inner[11], self.inner[12]];
        u16::from_le_bytes(bytes)
    }

    /// System Identifier
    pub fn id(&self) -> u64 {
        let bytes = [
            self.inner[13],
            self.inner[14],
            self.inner[15],
            self.inner[16],
            self.inner[17],
            self.inner[18],
            0,
            0,
        ];
        u64::from_le_bytes(bytes)
    }

    /// NSAP Selector
    pub fn sel(&self) -> u8 {
        self.inner[19]
    }
}

impl TryFrom<&[u8]> for NSAP {
    type Error = SimpleDnsError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 20 {
            return Err(SimpleDnsError::NoEnoughData);
        }

        value[0..20]
            .try_into()
            .map(|inner| Self { inner })
            .map_err(|_| SimpleDnsError::NoEnoughData)
    }
}

impl<'a> PacketPart<'a> for NSAP {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        (&data[position..position + 20])
            .try_into()
            .map(|inner: [u8; 20]| Self {
                inner: inner.map(u8::from_be),
            })
            .map_err(|_| SimpleDnsError::NoEnoughData)
    }

    fn append_to_vec(
        &self,
        out: &mut Vec<u8>,
        _name_refs: &mut Option<&mut std::collections::HashMap<u64, usize>>,
    ) -> crate::Result<()> {
        let bytes = self.inner.into_iter().map(|b| b.to_be());
        out.extend(bytes);
        Ok(())
    }

    fn len(&self) -> usize {
        20
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn parse_and_write_nsap() {
        let nsap = NSAP::new(
            47,
            5,
            0x80,
            0x005a00,
            0x10,
            0x1000,
            0x0020,
            0x00800a123456,
            0x10,
        );

        let mut data = Vec::new();
        assert!(nsap.append_to_vec(&mut data, &mut None).is_ok());

        let nsap = NSAP::parse(&data, 0);
        assert!(nsap.is_ok());
        let nsap = nsap.unwrap();

        assert_eq!(data.len(), nsap.len());
        assert_eq!(47, nsap.afi());
        assert_eq!(5, nsap.idi());
        assert_eq!(0x80, nsap.dfi());
        assert_eq!(0x005a00, nsap.aa());
        assert_eq!(0x10, nsap.rsvd());
        assert_eq!(0x1000, nsap.rd());
        assert_eq!(0x0020, nsap.area());
        assert_eq!(0x00800a123456, nsap.id());
        assert_eq!(0x10, nsap.sel());
    }
}
