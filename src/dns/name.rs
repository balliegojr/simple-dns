use std::{convert::TryFrom, fmt::Display };

use byteorder::{ByteOrder, BigEndian};

use super::{MAX_LABEL_LENGTH, MAX_NAME_LENGTH};

pub struct Name<'a> {
    labels: Vec<(usize, usize)>,
    data: &'a [u8],
    length_in_bytes: usize
}

impl <'a> Name<'a> {
    pub fn new(name: &'a str) -> crate::Result<Self> {
        if !name.is_ascii() || name.len() > MAX_NAME_LENGTH {
            return Err(crate::SimpleMdnsError::InvalidServiceName);
        }

        let mut out = Vec::new();
        let mut pos = 0usize;

        for element in name.split('.') {
            if element.len() > MAX_LABEL_LENGTH {
                return Err(crate::SimpleMdnsError::InvalidServiceLabel);
            }
            
            out.push((pos, element.len()));
            pos += element.len() + 1;
        }
        

        Ok(
            Self {
                labels: out,
                data: name.as_bytes(),
                length_in_bytes: name.len()
            }
        )
    }

    pub fn parse(data: &'a[u8], initial_position: usize) -> crate::Result<Self> {
        let mut labels = Vec::new();

        let mut position = initial_position;
        let mut end = initial_position;

        while data[position] != 0 {
            match data[position] {
                len if len & 0b1100_0000 == 0b1100_0000 => { //compression
                    if end == initial_position {
                        end = position + 1;
                    }

                    position = (BigEndian::read_u16(
                        &data[position..position + 2]) & !0b1100_0000_0000_0000) as usize;
                }
                len => {
                    labels.push((position + 1, len as usize));
                    position += len as usize + 1;

                }
            }

            if position > data.len() {
                return Err(crate::SimpleMdnsError::InvalidDnsPacket)
            }
        }

        if end == initial_position {
            end = position;
        }
        
        Ok(Self {
            data,
            labels,
            length_in_bytes: end - initial_position
        })
    }

    pub fn len(&self) -> usize {
        self.length_in_bytes
    }

    pub fn to_bytes_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(255);
        for (pos, length) in &self.labels {
            out.push(*length as u8);
            
            out.extend(&self.data[*pos..(pos+length)])
        }
        out.push(0);
        out
    }
}

impl <'a> TryFrom<&'a str> for Name<'a> {
    type Error = crate::SimpleMdnsError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Name::new(value)
    }
}

impl <'a> Display for Name<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, (pos, len)) in self.labels.iter().enumerate() {
            if i != 0 {
                f.write_str(".")?;
            }

            let s = std::str::from_utf8(&self.data[*pos..*pos+*len]).unwrap();
            f.write_str(s)?
        }

        Ok(())
    }
}

impl<'a> std::fmt::Debug for Name<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Name")
            .field(&format!("{}", self))
            .finish()
    }
}

#[cfg(test)] 
mod tests {
    use super::*;

    #[test]
    fn parse_without_compression() {
        let data = b"\x00\x00\x00\x01F\x03ISI\x04ARPA\x00\x03FOO\x01F\x03ISI\x04ARPA\x00\x04ARPA\x00";
        let mut offset = 3usize;
        
        let name = Name::parse(data, offset).unwrap();
        assert_eq!("F.ISI.ARPA", name.to_string());

        offset += name.len() + 1;
        let name = Name::parse(data, offset ).unwrap();
        assert_eq!("FOO.F.ISI.ARPA", name.to_string());
    }

    #[test]
    fn parse_with_compression() {
        let data = b"\x00\x00\x00\x01F\x03ISI\x04ARPA\x00\x03FOO\xc0\x03\x03BAR\xc0\x03";
        let mut offset = 3usize;

        let name = Name::parse(data, offset).unwrap();
        assert_eq!("F.ISI.ARPA", name.to_string());

        offset += name.len() + 1;
        let name = Name::parse(data, offset).unwrap();
        assert_eq!("FOO.F.ISI.ARPA", name.to_string());

        offset += name.len() + 1;
        let name = Name::parse(data, offset).unwrap();
        assert_eq!("BAR.F.ISI.ARPA", name.to_string());
    }


    #[test]
    fn convert_to_bytes_vec() {
        let name = Name::new("_srv._udp.local").unwrap();
        let bytes = name.to_bytes_vec();

        assert_eq!(b"\x04_srv\x04_udp\x05local\x00", &bytes[..]);
    }
}