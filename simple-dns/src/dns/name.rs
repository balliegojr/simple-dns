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
    first_label: Label<'a>,
    total_size: usize,
}

impl<'a> Name<'a> {
    /// Creates a new validated Name
    pub fn new(name: &'a str) -> crate::Result<Self> {
        let mut prev_label = None;
        let mut total_size = 1;
        for data in name.rsplit('.').filter(|d| !d.is_empty()) {
            let mut label = Label::new(data.as_bytes())?;
            label.next = prev_label.map(Box::new);
            total_size += label.len() + 1;

            prev_label = Some(label);
        }

        let first_label = prev_label.unwrap();

        let name = Self {
            first_label,
            total_size,
        };

        if name.total_size > MAX_NAME_LENGTH {
            Err(crate::SimpleDnsError::InvalidServiceName)
        } else {
            Ok(name)
        }
    }

    /// Create a new Name without checking for size limits
    pub fn new_unchecked(name: &'a str) -> Self {
        let mut total_size = 1;
        let first_label = name
            .rsplit('.')
            .filter(|d| !d.is_empty())
            .fold(None, |prev_label, data| {
                let mut label = Label::new_unchecked(data.as_bytes());
                label.next = prev_label.map(Box::new);
                total_size += label.len() + 1;

                Some(label)
            })
            .unwrap();

        Self {
            first_label,
            total_size,
        }
    }

    /// Verify if name ends with .local.
    pub fn is_link_local(&self) -> bool {
        match self.iter().last() {
            Some(label) => b"local".eq_ignore_ascii_case(label.data),
            None => false,
        }
    }

    pub fn iter(&self) -> NameIter {
        NameIter {
            next_label: Some(&self.first_label),
        }
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

        let first_label = labels
            .into_iter()
            .rfold(None, |prev_label, mut label| {
                label.next = prev_label;
                Some(Box::new(label))
            })
            .unwrap();

        Ok(Self {
            first_label: *first_label,
            total_size,
        })
    }

    fn append_to_vec(
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

    fn len(&self) -> usize {
        self.total_size
    }

    // fn append_to_vec_compressed(
    //     &'a self,
    //     out: &'a mut Vec<u8>,
    //     name_refs: HashMap<&'a Label<'a>, usize>,
    // ) -> crate::Result<()> {
    //     for label in self.iter() {
    //         if name_refs.contains_key(label) {
    //             let p = name_refs[label] as u16;
    //             let mut buf = [0u8; 2];
    //             BigEndian::write_u16(&mut buf, p | POINTER_MASK_U16);
    //             out.extend(buf);
    //             return Ok(());
    //         } else {
    //             name_refs.insert(label, out.len());
    //             out.push(label.len() as u8);
    //             out.extend(label.data);
    //         }
    //     }

    //     if out[out.len() - 1] != 0 {
    //         out.push(0);
    //     }

    //     Ok(())
    // }
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
        self.iter().zip(other.iter()).all(|(a, b)| a == b)
    }
}

impl<'a> Hash for Name<'a> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.total_size.hash(state);
        self.first_label.hash(state);
    }
}

impl<'a> Clone for Name<'a> {
    fn clone(&self) -> Self {
        Self {
            first_label: self.first_label.clone(),
            total_size: self.total_size,
        }
    }
}

pub struct NameIter<'a> {
    next_label: Option<&'a Label<'a>>,
}

impl<'a> Iterator for NameIter<'a> {
    type Item = &'a Label<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_label {
            Some(label) => {
                self.next_label = label.next.as_deref();
                Some(label)
            }
            None => None,
        }
    }
}

#[derive(Eq, PartialEq, Hash, Clone)]
pub struct Label<'a> {
    data: &'a [u8],
    next: Option<Box<Label<'a>>>,
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
        Self { data, next: None }
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
        let mut name_refs = HashMap::new();

        Name::new_unchecked("_srv._udp.local")
            .append_to_vec(&mut bytes, &mut name_refs)
            .unwrap();

        assert_eq!(b"\x04_srv\x04_udp\x05local\x00", &bytes[..]);

        let mut bytes = Vec::with_capacity(30);
        Name::new_unchecked("_srv._udp.local2.")
            .append_to_vec(&mut bytes, &mut name_refs)
            .unwrap();

        assert_eq!(b"\x04_srv\x04_udp\x06local2\x00", &bytes[..]);
    }

    #[test]
    fn append_to_vec_with_compression() {
        let mut buf = vec![0, 0, 0];

        let mut name_refs = HashMap::new();

        Name::new_unchecked("F.ISI.ARPA")
            .append_to_vec(&mut buf, &mut name_refs)
            .expect("failed to add F.ISI.ARPA");
        Name::new_unchecked("FOO.F.ISI.ARPA")
            .append_to_vec(&mut buf, &mut name_refs)
            .expect("failed to add FOO.F.ISI.ARPA");
        Name::new_unchecked("BAR.F.ISI.ARPA")
            .append_to_vec(&mut buf, &mut name_refs)
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

        Ok(())
    }

    #[test]
    fn len() {
        let mut bytes = Vec::new();
        let mut name_refs = HashMap::new();
        let name_one = Name::new_unchecked("ex.com.");
        name_one.append_to_vec(&mut bytes, &mut name_refs).unwrap();

        let name_two = Name::parse(&bytes, 0).unwrap();

        assert_eq!(8, bytes.len());
        assert_eq!(8, name_one.len());
        assert_eq!(8, name_two.len());
        assert_eq!(8, Name::new("ex.com").unwrap().len());
    }

    #[test]
    fn eq() {
        let a = Name::new_unchecked("domain.com");
        let b = Name::new_unchecked("domain.com");
        let c = Name::new_unchecked("domain.xom");

        assert_eq!(a, b);
        assert_ne!(a, c);

        assert_eq!(get_hash(&a), get_hash(&b));
        assert_ne!(get_hash(&a), get_hash(&c));
    }

    fn get_hash(name: &Name) -> u64 {
        let mut hasher = DefaultHasher::default();
        name.hash(&mut hasher);
        hasher.finish()
    }
}
