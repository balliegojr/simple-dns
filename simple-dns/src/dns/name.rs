use std::{
    borrow::Cow,
    collections::HashMap,
    convert::{TryFrom, TryInto},
    fmt::Display,
    hash::{BuildHasher, Hash, Hasher},
};

use super::{PacketPart, MAX_LABEL_LENGTH, MAX_NAME_LENGTH};

const POINTER_MASK: u8 = 0b1100_0000;
const POINTER_MASK_U16: u16 = 0b1100_0000_0000_0000;

// NOTE: there are no extend labels implemented today
// const EXTENDED_LABEL: u8 = 0b0100_0000;
// const EXTENDED_LABEL_U16: u16 = 0b0100_0000_0000_0000;

/// A Name represents a domain-name, which consists of character strings separated by dots.  
/// Each section of a name is called label  
/// ex: `google.com` consists of two labels `google` and `com`
#[derive(Eq, Clone)]
pub struct Name<'a> {
    labels: Vec<Label<'a>>,
    total_size: usize,
}

impl<'a> Name<'a> {
    /// Creates a new validated Name
    pub fn new(name: &'a str) -> crate::Result<Self> {
        let mut total_size = 1;

        let labels = NameSpliter::new(name.as_bytes())
            .map(|label| {
                total_size += label.len() + 1;
                Label::new(label)
            })
            .collect::<Result<Vec<Label>, _>>()?;

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

        let labels = NameSpliter::new(name.as_bytes())
            .map(|label| {
                total_size += label.len() + 1;
                Label::new_unchecked(label)
            })
            .collect();

        Self { labels, total_size }
    }

    /// Verify if name ends with .local.
    pub fn is_link_local(&self) -> bool {
        match self.iter().last() {
            Some(label) => b"local".eq_ignore_ascii_case(&label.data),
            None => false,
        }
    }

    /// Returns an Iter of this Name Labels
    pub fn iter(&'a self) -> std::slice::Iter<Label<'a>> {
        self.labels.iter()
    }

    /// Returns true if self is a subdomain of other
    pub fn is_subdomain_of(&self, other: &Name) -> bool {
        other
            .iter()
            .rev()
            .zip(self.iter().rev())
            .all(|(o, s)| *o == *s)
    }

    /// Transforms the inner data into it's owned type
    pub fn into_owned<'b>(self) -> Name<'b> {
        Name {
            labels: self.labels.into_iter().map(|l| l.into_owned()).collect(),
            total_size: self.total_size,
        }
    }

    /// Get the labels that compose this name
    pub fn get_labels(&'_ self) -> &'_ [Label<'_>] {
        &self.labels[..]
    }

    fn plain_append<T: std::io::Write>(&self, out: &mut T) -> crate::Result<()> {
        for label in self.iter() {
            out.write_all(&[label.len() as u8])?;
            out.write_all(&label.data)?;
        }

        out.write_all(&[0])?;
        Ok(())
    }

    fn compress_append<T: std::io::Write + std::io::Seek>(
        &self,
        out: &mut T,
        name_refs: &mut HashMap<u64, usize>,
    ) -> crate::Result<()> {
        for label in self.iter() {
            let mut h = name_refs.hasher().build_hasher();
            label.hash(&mut h);
            let key = h.finish();

            if let std::collections::hash_map::Entry::Vacant(e) = name_refs.entry(key) {
                e.insert(out.stream_position()? as usize);
                out.write_all(&[label.len() as u8])?;
                out.write_all(&label.data)?;
            } else {
                let p = name_refs[&key] as u16;
                out.write_all(&(p | POINTER_MASK_U16).to_be_bytes())?;

                return Ok(());
            }
        }

        out.write_all(&[0])?;
        Ok(())
    }
}

impl<'a> PacketPart<'a> for Name<'a> {
    fn parse(data: &'a [u8], initial_position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let mut total_size = 1;
        let mut is_compressed = false;
        let mut labels = Vec::new();

        let mut position = initial_position;

        // avoid invalid data caused oom
        let mut name_size = 0usize;

        loop {
            if position >= data.len() {
                return Err(crate::SimpleDnsError::InsufficientData);
            }

            // domain name max size is 255
            if name_size > MAX_NAME_LENGTH {
                return Err(crate::SimpleDnsError::InvalidDnsPacket);
            }

            match data[position] {
                0 => {
                    break;
                }
                len if len & POINTER_MASK == POINTER_MASK => {
                    //compression
                    if !is_compressed {
                        total_size += 1;
                    }
                    is_compressed = true;

                    if position + 2 > data.len() {
                        return Err(crate::SimpleDnsError::InsufficientData);
                    }

                    // avoid pointer forward (RFC 1035)
                    let pointer = (u16::from_be_bytes(data[position..position + 2].try_into()?)
                        & !POINTER_MASK_U16) as usize;
                    if pointer >= position {
                        return Err(crate::SimpleDnsError::InvalidDnsPacket);
                    }
                    position = pointer;
                }
                len => {
                    name_size += 1 + len as usize;

                    let p = position + 1;
                    let e = p + len as usize;

                    if e > data.len() {
                        return Err(crate::SimpleDnsError::InsufficientData);
                    }

                    labels.push(Label::new(&data[p..e])?);
                    if !is_compressed {
                        total_size += 1 + len as usize;
                    }
                    position = e;
                }
            }
        }

        Ok(Self { labels, total_size })
    }

    fn write_to<T: std::io::Write>(&self, out: &mut T) -> crate::Result<()> {
        self.plain_append(out)
    }

    fn write_compressed_to<T: std::io::Write + std::io::Seek>(
        &self,
        out: &mut T,
        name_refs: &mut HashMap<u64, usize>,
    ) -> crate::Result<()> {
        self.compress_append(out, name_refs)
    }

    fn len(&self) -> usize {
        self.total_size
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
        f.debug_tuple("Name")
            .field(&format!("{}", self))
            .field(&format!("{}", self.total_size))
            .finish()
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

struct NameSpliter<'a> {
    bytes: &'a [u8],
    current: usize,
}

impl<'a> NameSpliter<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, current: 0 }
    }
}

impl<'a> Iterator for NameSpliter<'a> {
    type Item = Cow<'a, [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut slices: Vec<&[u8]> = Vec::new();

        for i in self.current..self.bytes.len() {
            if self.bytes[i] == b'.' && i - self.current > 0 {
                let current = std::mem::replace(&mut self.current, i + 1);
                if self.bytes[i - 1] == b'\\' {
                    slices.push(&self.bytes[current..i - 1]);
                    continue;
                }

                return Some(join_slices(slices, &self.bytes[current..i]));
            }
        }

        if self.current < self.bytes.len() {
            let current = std::mem::replace(&mut self.current, self.bytes.len());
            Some(join_slices(slices, &self.bytes[current..]))
        } else {
            None
        }
    }
}

fn join_slices<'a>(mut slices: Vec<&'a [u8]>, slice: &'a [u8]) -> Cow<'a, [u8]> {
    if slices.is_empty() {
        slice.into()
    } else {
        slices.push(slice);

        slices
            .iter_mut()
            .fold(Vec::new(), |mut c, v| {
                if !c.is_empty() {
                    c.push(b'.');
                }

                c.extend(&v[..]);
                c
            })
            .into()
    }
}

#[derive(Eq, PartialEq, Hash, Clone)]
pub struct Label<'a> {
    data: Cow<'a, [u8]>,
}

impl<'a> Label<'a> {
    pub fn new<T: Into<Cow<'a, [u8]>>>(data: T) -> crate::Result<Self> {
        let label = Self::new_unchecked(data);
        if label.len() > MAX_LABEL_LENGTH {
            Err(crate::SimpleDnsError::InvalidServiceLabel)
        } else {
            Ok(label)
        }
    }

    pub fn new_unchecked<T: Into<Cow<'a, [u8]>>>(data: T) -> Self {
        Self { data: data.into() }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn into_owned<'b>(self) -> Label<'b> {
        Label {
            data: self.data.into_owned().into(),
        }
    }
}

impl<'a> Display for Label<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match std::str::from_utf8(&self.data) {
            Ok(s) => f.write_str(s),
            Err(_) => Err(std::fmt::Error),
        }
    }
}

impl<'a> std::fmt::Debug for Label<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Label")
            .field("data", &self.to_string())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::{collections::hash_map::DefaultHasher, hash::Hasher};

    use super::*;
    use crate::SimpleDnsError;

    #[test]
    fn construct_valid_names() -> Result<(), SimpleDnsError> {
        assert!(Name::new("some").is_ok());
        assert!(Name::new("some.local").is_ok());
        assert!(Name::new("some.local.").is_ok());
        assert!(Name::new("\u{1F600}.local.").is_ok());

        let scaped = Name::new("some\\.local")?;
        assert_eq!(scaped.labels.len(), 1);

        Ok(())
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
        let data = b"\x00\x00\x00\x01F\x03ISI\x04ARPA\x00\x03FOO\xc0\x03\x03BAR\xc0\x03\x07INVALID\xc0\x1b";
        let mut offset = 3usize;

        let name = Name::parse(data, offset).unwrap();
        assert_eq!("F.ISI.ARPA", name.to_string());

        offset += name.len();
        let name = Name::parse(data, offset).unwrap();
        assert_eq!("FOO.F.ISI.ARPA", name.to_string());

        offset += name.len();
        let name = Name::parse(data, offset).unwrap();
        assert_eq!("BAR.F.ISI.ARPA", name.to_string());

        offset += name.len();
        assert!(Name::parse(data, offset).is_err());
    }

    #[test]
    fn test_write() {
        let mut bytes = Cursor::new(Vec::with_capacity(30));

        Name::new_unchecked("_srv._udp.local")
            .write_to(&mut bytes)
            .unwrap();

        assert_eq!(b"\x04_srv\x04_udp\x05local\x00", &bytes.get_ref()[..]);

        let mut bytes = Cursor::new(Vec::with_capacity(30));
        Name::new_unchecked("_srv._udp.local2.")
            .write_to(&mut bytes)
            .unwrap();

        assert_eq!(b"\x04_srv\x04_udp\x06local2\x00", &bytes.get_ref()[..]);
    }

    #[test]
    fn append_to_vec_with_compression() {
        let mut buf = Cursor::new(vec![0, 0, 0]);
        buf.set_position(3);

        let mut name_refs = HashMap::new();

        Name::new_unchecked("F.ISI.ARPA")
            .write_compressed_to(&mut buf, &mut name_refs)
            .expect("failed to add F.ISI.ARPA");
        Name::new_unchecked("FOO.F.ISI.ARPA")
            .write_compressed_to(&mut buf, &mut name_refs)
            .expect("failed to add FOO.F.ISI.ARPA");
        Name::new_unchecked("BAR.F.ISI.ARPA")
            .write_compressed_to(&mut buf, &mut name_refs)
            .expect("failed to add FOO.F.ISI.ARPA");

        let data = b"\x00\x00\x00\x01F\x03ISI\x04ARPA\x00\x03FOO\xc0\x03\x03BAR\xc0\x03";
        assert_eq!(data[..], buf.get_ref()[..]);
    }

    #[test]
    fn append_to_vec_with_compression_mult_names() {
        let mut buf = Cursor::new(vec![]);
        let mut name_refs = HashMap::new();

        Name::new_unchecked("ISI.ARPA")
            .write_compressed_to(&mut buf, &mut name_refs)
            .expect("failed to add ISI.ARPA");
        Name::new_unchecked("F.ISI.ARPA")
            .write_compressed_to(&mut buf, &mut name_refs)
            .expect("failed to add F.ISI.ARPA");
        Name::new_unchecked("FOO.F.ISI.ARPA")
            .write_compressed_to(&mut buf, &mut name_refs)
            .expect("failed to add F.ISI.ARPA");
        Name::new_unchecked("BAR.F.ISI.ARPA")
            .write_compressed_to(&mut buf, &mut name_refs)
            .expect("failed to add F.ISI.ARPA");

        let expected = b"\x03ISI\x04ARPA\x00\x01F\xc0\x00\x03FOO\xc0\x0a\x03BAR\xc0\x0a";
        assert_eq!(expected[..], buf.get_ref()[..]);

        let first = Name::parse(buf.get_ref(), 0).unwrap();
        assert_eq!("ISI.ARPA", first.to_string());
        let second = Name::parse(buf.get_ref(), first.len()).unwrap();
        assert_eq!("F.ISI.ARPA", second.to_string());
        let third = Name::parse(buf.get_ref(), first.len() + second.len()).unwrap();
        assert_eq!("FOO.F.ISI.ARPA", third.to_string());
        let fourth = Name::parse(buf.get_ref(), first.len() + second.len() + third.len()).unwrap();
        assert_eq!("BAR.F.ISI.ARPA", fourth.to_string());
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
        let mut bytes = Cursor::new(Vec::new());
        let name_one = Name::new_unchecked("ex.com.");
        name_one.write_to(&mut bytes)?;

        assert_eq!(8, bytes.get_ref().len());
        assert_eq!(bytes.get_ref().len(), name_one.len());
        assert_eq!(8, Name::parse(bytes.get_ref(), 0)?.len());

        let mut name_refs = HashMap::new();
        let mut bytes = Cursor::new(Vec::new());
        name_one.write_compressed_to(&mut bytes, &mut name_refs)?;
        name_one.write_compressed_to(&mut bytes, &mut name_refs)?;

        assert_eq!(10, bytes.get_ref().len());
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

    #[test]
    fn is_subdomain_of() {
        assert!(
            Name::new_unchecked("example.com").is_subdomain_of(&Name::new_unchecked("example.com"))
        );
        assert!(Name::new_unchecked("sub.example.com")
            .is_subdomain_of(&Name::new_unchecked("example.com")));
        assert!(Name::new_unchecked("foo.sub.example.com")
            .is_subdomain_of(&Name::new_unchecked("example.com")));
        assert!(!Name::new_unchecked("example.com")
            .is_subdomain_of(&Name::new_unchecked("example.xom")));
        assert!(!Name::new_unchecked("domain.com")
            .is_subdomain_of(&Name::new_unchecked("other.domain")));
        assert!(!Name::new_unchecked("domain.com")
            .is_subdomain_of(&Name::new_unchecked("domain.com.br")));
    }
}
