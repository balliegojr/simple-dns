use std::{
    collections::HashMap,
    convert::TryFrom,
    fmt::Display,
    hash::{BuildHasher, Hash, Hasher},
};

use byteorder::{BigEndian, ByteOrder};

use super::{DnsPacketContent, MAX_LABEL_LENGTH, MAX_NAME_LENGTH};

const POINTER_MASK: u8 = 0b1100_0000;
const POINTER_MASK_U16: u16 = 0b1100_0000_0000_0000;

/// A Name represents a domain-name, which consists of character strings separated by dots.  
/// Each section of a name is called label  
/// ex: `google.com` consists of two labels `google` and `com`
#[derive(Eq)]
pub struct Name<'a> {
    labels: Vec<Label<'a>>,
    total_size: usize,
}

impl<'a> Name<'a> {
    /// Creates a new validated Name
    pub fn new(name: &'a str) -> crate::Result<Self> {
        let mut labels = Vec::new();
        let mut total_size = 1;
        for data in name.split('.').filter(|d| !d.is_empty()) {
            total_size += data.len() + 1;
            labels.push(Label::new(data.as_bytes())?);
        }

        let name = Self { labels, total_size };

        if name.total_size > MAX_NAME_LENGTH {
            Err(crate::SimpleDnsError::InvalidServiceName)
        } else {
            Ok(name)
        }
    }

    /// Create a new Name without checking for size limits
    pub fn new_unchecked(name: &'a str) -> Self {
        let mut total_size = 1;
        let labels = name
            .split('.')
            .filter(|d| !d.is_empty())
            .map(|data| {
                total_size += data.len() + 1;
                Label::new_unchecked(data.as_bytes())
            })
            .collect();

        Self { labels, total_size }
    }

    /// Verify if name ends with .local.
    pub fn is_link_local(&self) -> bool {
        match self.iter().last() {
            Some(label) => b"local".eq_ignore_ascii_case(label.data),
            None => false,
        }
    }

    /// Returns an Iter of this Name Labels
    pub fn iter(&'a self) -> std::slice::Iter<Label<'a>> {
        self.labels.iter()
    }
}

impl<'a> DnsPacketContent<'a> for Name<'a> {
    fn parse(data: &'a [u8], initial_position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let mut total_size = 0;
        let mut is_compressed = false;
        let mut labels = Vec::new();

        let mut position = initial_position;

        while data[position] != 0 {
            match data[position] {
                len if len & POINTER_MASK == POINTER_MASK => {
                    is_compressed = true;
                    //compression
                    total_size += 1;

                    position = (BigEndian::read_u16(&data[position..position + 2])
                        & !POINTER_MASK_U16) as usize;
                }
                len => {
                    let p = position + 1;
                    let e = p + len as usize;

                    labels.push(Label::new(&data[p..e])?);
                    if !is_compressed {
                        total_size += 1 + len as usize;
                    }
                    position = e;
                }
            }

            if position > data.len() {
                return Err(crate::SimpleDnsError::InvalidDnsPacket);
            }
        }

        total_size += 1;

        Ok(Self { labels, total_size })
    }

    fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        for label in self.iter() {
            out.push(label.len() as u8);
            out.extend(label.data);
        }

        if out[out.len() - 1] != 0 {
            out.push(0);
        }

        Ok(())
    }

    fn len(&self) -> usize {
        self.total_size
    }

    fn compress_append_to_vec(
        &self,
        out: &mut Vec<u8>,
        name_refs: &mut HashMap<u64, usize>,
    ) -> crate::Result<()> {
        for label in self.iter() {
            let mut h = name_refs.hasher().build_hasher();
            label.hash(&mut h);
            let key = h.finish();

            if let std::collections::hash_map::Entry::Vacant(e) = name_refs.entry(key) {
                e.insert(out.len());
                out.push(label.len() as u8);
                out.extend(label.data);
            } else {
                let p = name_refs[&key] as u16;
                let mut buf = [0u8; 2];
                BigEndian::write_u16(&mut buf, p | POINTER_MASK_U16);
                out.extend(buf);
                return Ok(());
            }
        }

        if out[out.len() - 1] != 0 {
            out.push(0);
        }

        Ok(())
    }
}

impl<'a> TryFrom<&'a str> for Name<'a> {
    type Error = crate::SimpleDnsError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Name::new(value)
    }
}

impl<'a> Display for Name<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, label) in self.iter().enumerate() {
            if i != 0 {
                f.write_str(".")?;
            }

            f.write_fmt(format_args!("{}", label))?;
        }

        Ok(())
    }
}

impl<'a> std::fmt::Debug for Name<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Name").field(&format!("{}", self)).finish()
    }
}

impl<'a> PartialEq for Name<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.labels == other.labels
    }
}

impl<'a> Hash for Name<'a> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.labels.hash(state);
    }
}

impl<'a> Clone for Name<'a> {
    fn clone(&self) -> Self {
        Self {
            labels: self.labels.clone(),
            total_size: self.total_size,
        }
    }
}

#[derive(Eq, PartialEq, Hash, Clone)]
pub struct Label<'a> {
    data: &'a [u8],
}

impl<'a> Label<'a> {
    pub fn new(data: &'a [u8]) -> crate::Result<Self> {
        let label = Self::new_unchecked(data);
        if label.len() > MAX_LABEL_LENGTH {
            Err(crate::SimpleDnsError::InvalidServiceLabel)
        } else {
            Ok(label)
        }
    }

    pub fn new_unchecked(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }
}

impl<'a> Display for Label<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match std::str::from_utf8(self.data) {
            Ok(s) => f.write_str(s),
            Err(_) => Err(std::fmt::Error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::hash_map::DefaultHasher, hash::Hasher};

    use super::*;
    use crate::SimpleDnsError;

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
        // assert!(!Name::new("some.example.local").unwrap().is_link_local());
        assert!(Name::new("some.example.local.").unwrap().is_link_local());
    }

    #[test]
    fn parse_without_compression() {
        let data =
            b"\x00\x00\x00\x01F\x03ISI\x04ARPA\x00\x03FOO\x01F\x03ISI\x04ARPA\x00\x04ARPA\x00";
        let name = Name::parse(data, 3).unwrap();
        assert_eq!("F.ISI.ARPA", name.to_string());

        let name = Name::parse(data, 3 + name.len()).unwrap();
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
    fn append_to_vec() {
        let mut bytes = Vec::with_capacity(30);

        Name::new_unchecked("_srv._udp.local")
            .append_to_vec(&mut bytes)
            .unwrap();

        assert_eq!(b"\x04_srv\x04_udp\x05local\x00", &bytes[..]);

        let mut bytes = Vec::with_capacity(30);
        Name::new_unchecked("_srv._udp.local2.")
            .append_to_vec(&mut bytes)
            .unwrap();

        assert_eq!(b"\x04_srv\x04_udp\x06local2\x00", &bytes[..]);
    }

    #[test]
    fn append_to_vec_with_compression() {
        let mut buf = vec![0, 0, 0];

        let mut name_refs = HashMap::new();

        Name::new_unchecked("F.ISI.ARPA")
            .compress_append_to_vec(&mut buf, &mut name_refs)
            .expect("failed to add F.ISI.ARPA");
        Name::new_unchecked("FOO.F.ISI.ARPA")
            .compress_append_to_vec(&mut buf, &mut name_refs)
            .expect("failed to add FOO.F.ISI.ARPA");
        Name::new_unchecked("BAR.F.ISI.ARPA")
            .compress_append_to_vec(&mut buf, &mut name_refs)
            .expect("failed to add FOO.F.ISI.ARPA");

        let data = b"\x00\x00\x00\x01F\x03ISI\x04ARPA\x00\x03FOO\xc0\x03\x03BAR\xc0\x03";
        assert_eq!(data[..], buf[..]);
    }

    #[test]
    fn eq_other_name() -> Result<(), SimpleDnsError> {
        assert_eq!(Name::new("example.com")?, Name::new("example.com")?);
        assert_ne!(Name::new("some.example.com")?, Name::new("example.com")?);
        assert_ne!(Name::new("example.co")?, Name::new("example.com")?);
        assert_ne!(Name::new("example.com.org")?, Name::new("example.com")?);

        let data = b"\x00\x00\x00\x01F\x03ISI\x04ARPA\x00\x03FOO\xc0\x03\x03BAR\xc0\x03";
        assert_eq!(Name::new("F.ISI.ARPA")?, Name::parse(data, 3)?);
        assert_eq!(Name::new("FOO.F.ISI.ARPA")?, Name::parse(data, 15)?);
        Ok(())
    }

    #[test]
    fn len() -> crate::Result<()> {
        let mut bytes = Vec::new();
        let name_one = Name::new_unchecked("ex.com.");
        name_one.append_to_vec(&mut bytes)?;

        assert_eq!(8, bytes.len());
        assert_eq!(bytes.len(), name_one.len());
        assert_eq!(8, Name::parse(&bytes, 0)?.len());

        let mut name_refs = HashMap::new();
        let mut bytes = Vec::new();
        name_one.compress_append_to_vec(&mut bytes, &mut name_refs)?;
        name_one.compress_append_to_vec(&mut bytes, &mut name_refs)?;

        assert_eq!(10, bytes.len());
        Ok(())
    }

    #[test]
    fn hash() -> crate::Result<()> {
        let data = b"\x00\x00\x00\x01F\x03ISI\x04ARPA\x00\x03FOO\xc0\x03\x03BAR\xc0\x03";

        assert_eq!(
            get_hash(&Name::new("F.ISI.ARPA")?),
            get_hash(&Name::parse(data, 3)?)
        );

        assert_eq!(
            get_hash(&Name::new("FOO.F.ISI.ARPA")?),
            get_hash(&Name::parse(data, 15)?)
        );

        Ok(())
    }

    fn get_hash(name: &Name) -> u64 {
        let mut hasher = DefaultHasher::default();
        name.hash(&mut hasher);
        hasher.finish()
    }
}
