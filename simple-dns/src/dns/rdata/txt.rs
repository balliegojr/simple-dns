use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
};

use crate::{dns::DnsPacketContent, CharacterString};

/// Represents a TXT Resource Record
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct TXT<'a> {
    strings: Vec<CharacterString<'a>>,
    size: usize,
}

impl<'a> Default for TXT<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> TXT<'a> {
    /// Creates a new empty TXT Record
    pub fn new() -> Self {
        Self {
            strings: vec![],
            size: 0,
        }
    }

    /// Add `char_string` to this TXT record as a validated [`CharacterString`](`CharacterString`)
    pub fn add_string(&mut self, char_string: &'a str) -> crate::Result<()> {
        self.add_char_string(char_string.try_into()?);
        Ok(())
    }

    /// Add `char_string` to this TXT record
    pub fn add_char_string(&mut self, char_string: CharacterString<'a>) {
        self.size += char_string.len();
        self.strings.push(char_string);
    }

    /// Add `char_string` to this TXT record as a validated [`CharacterString`](`CharacterString`), consuming and returning Self
    pub fn with_string(mut self, char_string: &'a str) -> crate::Result<Self> {
        self.add_char_string(char_string.try_into()?);
        Ok(self)
    }

    /// Add `char_string` to this TXT record, consuming and returning Self
    pub fn with_char_string(mut self, char_string: CharacterString<'a>) -> Self {
        self.add_char_string(char_string);
        self
    }

    /// Returns parsed attributes from this TXT Record, valid formats are:
    /// - key=value
    /// - key=
    /// - key
    ///
    /// If a key is duplicated, only the first one will be considered
    pub fn attributes(&self) -> HashMap<String, Option<String>> {
        let mut attributes = HashMap::new();

        for char_str in &self.strings {
            let mut splited = char_str.data.splitn(2, |c| *c == b'=');
            let key = match splited.next() {
                Some(key) => match std::str::from_utf8(key) {
                    Ok(key) => key.to_owned(),
                    Err(_) => continue,
                },
                None => continue,
            };

            let value = match splited.next() {
                Some(value) if !value.is_empty() => match std::str::from_utf8(value) {
                    Ok(v) => Some(v.to_owned()),
                    Err(_) => Some(String::new()),
                },
                Some(_) => Some(String::new()),
                _ => None,
            };

            attributes.entry(key).or_insert(value);
        }

        attributes
    }

    /// Transforms the inner data into it's owned type
    pub fn into_owned<'b>(self) -> TXT<'b> {
        TXT {
            strings: self.strings.into_iter().map(|s| s.into_owned()).collect(),
            size: self.size,
        }
    }
}

impl<'a> TryFrom<HashMap<String, Option<String>>> for TXT<'a> {
    type Error = crate::SimpleDnsError;

    fn try_from(value: HashMap<String, Option<String>>) -> Result<Self, Self::Error> {
        let mut txt = TXT::new();
        for (key, value) in value {
            match value {
                Some(value) => {
                    txt.add_char_string(format!("{}={}", &key, &value).try_into()?);
                }
                None => txt.add_char_string(key.try_into()?),
            }
        }
        Ok(txt)
    }
}

impl<'a> DnsPacketContent<'a> for TXT<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let mut strings = Vec::new();
        let mut curr_position = position;

        while curr_position < data.len() {
            let char_str = CharacterString::parse(&data[curr_position..], 0)?;
            curr_position += char_str.len();
            strings.push(char_str);
        }

        Ok(Self {
            strings,
            size: data.len() - position,
        })
    }

    fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        if self.strings.is_empty() {
            out.push(0);
        } else {
            for string in &self.strings {
                string.append_to_vec(out)?;
            }
        }

        Ok(())
    }

    fn len(&self) -> usize {
        if self.strings.is_empty() {
            1
        } else {
            self.size
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Result;
    use std::convert::TryInto;

    use super::*;

    #[test]
    pub fn parse_and_write_txt() -> Result<()> {
        let mut out = vec![];
        let txt = TXT::new()
            .with_char_string("version=0.1".try_into()?)
            .with_char_string("proto=123".try_into()?);

        txt.append_to_vec(&mut out)?;
        assert_eq!(out.len(), txt.len());

        let txt2 = TXT::parse(&out, 0)?;
        assert_eq!(2, txt2.strings.len());
        assert_eq!(txt.strings[0], txt2.strings[0]);
        assert_eq!(txt.strings[1], txt2.strings[1]);

        Ok(())
    }

    #[test]
    pub fn get_attributes() -> Result<()> {
        let attributes = TXT::new()
            .with_string("version=0.1")?
            .with_string("flag")?
            .with_string("with_eq=eq=")?
            .with_string("version=dup")?
            .with_string("empty=")?
            .attributes();

        assert_eq!(4, attributes.len());
        assert_eq!(Some("0.1".to_owned()), attributes["version"]);
        assert_eq!(Some("eq=".to_owned()), attributes["with_eq"]);
        assert_eq!(Some(String::new()), attributes["empty"]);
        assert_eq!(None, attributes["flag"]);

        Ok(())
    }
}
