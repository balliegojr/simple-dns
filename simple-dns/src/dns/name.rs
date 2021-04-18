use std::{convert::TryFrom, fmt::Display};

use byteorder::{ByteOrder, BigEndian};

use super::{DnsPacketContent, MAX_LABEL_LENGTH, MAX_NAME_LENGTH};

const POINTER_MASK: u8 = 0b1100_0000;
const POINTER_MASK_U16: u16 = 0b1100_0000_0000_0000;

/// A Name represents a domain-name, which consists of character strings separated by dots.  
/// Each section of a name is called label  
/// ex: `google.com` consists of two labels `google` and `com`
pub struct Name<'a> {
    labels: Vec<(usize, usize)>,
    data: &'a [u8],
    length_in_bytes: usize
}

impl <'a> Name<'a> {
    /// Creates a new validated Name
    pub fn new(name: &'a str) -> crate::Result<Self> {
        if name.len() > MAX_NAME_LENGTH {
            return Err(crate::SimpleDnsError::InvalidServiceName);
        }

        let name = Self::new_unchecked(name);
        if name.labels.iter().any(|(_, len)| *len > MAX_LABEL_LENGTH) {
            return Err(crate::SimpleDnsError::InvalidServiceLabel)
        }
        
        Ok(name)
    }

    /// Create a new Name without checking for size limits
    pub fn new_unchecked(name: &'a str) -> Self {
        let mut labels = Vec::new();
        let last_pos = name.match_indices('.').fold(0, |acc, (pos, _)| {
            labels.push((acc, pos - acc));
            pos + 1
        });

        labels.push((last_pos, name.len() - last_pos));

        Self {
            labels,
            data: name.as_bytes(),
            length_in_bytes: name.len() + if last_pos == name.len() { 1 } else { 2 }
        }
    }

    /// Verify if name ends with .local.
    pub fn is_link_local(&self) -> bool {
        if self.labels.len() < 2 {
            return false
        }

        let (start, end) = &self.labels[self.labels.len() - 2];
        b"local.".eq_ignore_ascii_case(&self.data[*start..*start + *end + 1])
    }
}

impl <'a> DnsPacketContent<'a> for Name<'a> {
    fn parse(data: &'a [u8], initial_position: usize) -> crate::Result<Self> where Self: Sized {
        let mut labels = Vec::new();

        let mut position = initial_position;
        let mut end = initial_position;

        while data[position] != 0 {
            match data[position] {
                len if len & POINTER_MASK == POINTER_MASK => { //compression
                    if end == initial_position {
                        end = position + 1;
                    }

                    position = (BigEndian::read_u16(
                        &data[position..position + 2]) & !POINTER_MASK_U16) as usize;
                }
                len => {
                    labels.push((position + 1, len as usize));
                    position += len as usize + 1;

                }
            }

            if position > data.len() {
                return Err(crate::SimpleDnsError::InvalidDnsPacket)
            }
        }

        if end == initial_position {
            end = position;
        }
        
        Ok(Self {
            data,
            labels,
            length_in_bytes: end - initial_position + 1
        })
    }
    
    fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        for (pos, length) in self.labels.iter().filter(|(_, l)| *l > 0) {
            out.push(*length as u8);
            out.extend(&self.data[*pos..(pos+length)])
        }
        out.push(0);
        Ok(())
    }
    
    fn len(&self) -> usize {
        self.length_in_bytes
    }
}

impl <'a> TryFrom<&'a str> for Name<'a> {
    type Error = crate::SimpleDnsError;

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

impl<'a> PartialEq for Name<'a> {
    fn eq(&self, other: &Self) -> bool {
        if self.labels.len() != other.labels.len() {
            return false;
        }

        for (&(l_pos, l_len), &(r_pos, r_len) ) in self.labels.iter().zip(other.labels.iter()) {
            if l_len != r_len {
                return false;
            }

            if self.data[l_pos..l_pos + l_len] != other.data[r_pos..r_pos+r_len] {
                return false;
            }
        }

        true
    }
}

impl<'a> Clone for Name<'a> {
    fn clone(&self) -> Self {
        
        Self {
            data: self.data,
            length_in_bytes: self.length_in_bytes,
            labels: self.labels.clone()
        }
    }
}

#[cfg(test)] 
mod tests {
    use crate::SimpleDnsError;
    use super::*;

    #[test]
    fn construct_valid_names() {
        assert!(Name::new("some").is_ok());
        assert!(Name::new("some.local").is_ok());
        assert!(Name::new("some.local.").is_ok());
        assert!(Name::new("\u{1F600}.local.").is_ok());
    }

    #[test]
    fn is_link_local() {
        assert!(!Name::new("some.example.com").unwrap().is_link_local());
        assert!(!Name::new("some.example.local").unwrap().is_link_local());
        assert!(Name::new("some.example.local.").unwrap().is_link_local());
    }

    #[test]
    fn parse_without_compression() {
        let data = b"\x00\x00\x00\x01F\x03ISI\x04ARPA\x00\x03FOO\x01F\x03ISI\x04ARPA\x00\x04ARPA\x00";
        let name = Name::parse(data, 3).unwrap();
        assert_eq!("F.ISI.ARPA", name.to_string());
        
        let name = Name::parse(data, 3 + name.len() ).unwrap();
        assert_eq!("FOO.F.ISI.ARPA", name.to_string());
    }

    #[test]
    fn parse_with_compression() {
        let data = b"\x00\x00\x00\x01F\x03ISI\x04ARPA\x00\x03FOO\xc0\x03\x03BAR\xc0\x03";
        let mut offset = 3usize;

        let name = Name::parse(data, offset).unwrap();
        assert_eq!("F.ISI.ARPA", name.to_string());

        offset += name.len();
        let name = Name::parse(data, offset).unwrap();
        assert_eq!("FOO.F.ISI.ARPA", name.to_string());

        offset += name.len();
        let name = Name::parse(data, offset).unwrap();
        assert_eq!("BAR.F.ISI.ARPA", name.to_string());
    }


    #[test]
    fn convert_to_bytes_vec() {
        
        let mut bytes = Vec::with_capacity(30);
        Name::new("_srv._udp.local").unwrap().append_to_vec(&mut bytes).unwrap();

        assert_eq!(b"\x04_srv\x04_udp\x05local\x00", &bytes[..]);

        let mut bytes = Vec::with_capacity(30);
        Name::new("_srv._udp.local.").unwrap().append_to_vec(&mut bytes).unwrap();

        assert_eq!(b"\x04_srv\x04_udp\x05local\x00", &bytes[..]);
    }

    #[test]
    fn eq_other_name() -> Result<(), SimpleDnsError> {
        assert_eq!(Name::new("example.com")?, Name::new("example.com")?);
        assert_ne!(Name::new("some.example.com")?, Name::new("example.com")?);
        assert_ne!(Name::new("example.co")?, Name::new("example.com")?);
        assert_ne!(Name::new("example.com.org")?, Name::new("example.com")?);

        Ok(())
    }

    #[test]
    fn len() {
        let mut bytes = Vec::new();

        let name_one = Name::new("ex.com.").unwrap();
        name_one.append_to_vec(&mut bytes).unwrap();

        let name_two = Name::parse(&bytes, 0).unwrap();

        assert_eq!(8, bytes.len());
        assert_eq!(8, name_one.len());
        assert_eq!(8, name_two.len());
        assert_eq!(8, Name::new("ex.com").unwrap().len());
    }
}
