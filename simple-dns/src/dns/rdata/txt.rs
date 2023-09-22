use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
};

use crate::dns::{PacketPart, MAX_CHARACTER_STRING_LENGTH};
use crate::CharacterString;

use super::RR;

/// Represents a TXT Resource Record
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct TXT<'a> {
    strings: Vec<CharacterString<'a>>,
    size: usize,
}

impl<'a> RR for TXT<'a> {
    const TYPE_CODE: u16 = 16;
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

        let full_string: String = (*self).clone().into();

        let parts = full_string.split(|c| (c as u8) == b';');

        for part in parts {
            let key_value = part.splitn(2, |c| (c as u8) == b'=').collect::<Vec<&str>>();

            let key = key_value[0];

            let value = match key_value.len() > 1 {
                true => Some(key_value[1].to_owned()),
                _ => None,
            };

            if !key.is_empty() {
                attributes.entry(key.to_owned()).or_insert(value);
            }
        }

        attributes
    }

    /// Transforms the inner data into its owned type
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

impl<'a> TryFrom<String> for TXT<'a> {
    type Error = crate::SimpleDnsError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut txt = TXT::new();

        let mut start_index = 0;
        let full_length = value.len();

        while start_index < full_length {
            let end_index = (start_index + MAX_CHARACTER_STRING_LENGTH).min(full_length);

            let slice = &value[start_index..end_index];
            txt.add_char_string(slice.to_string().try_into()?);

            start_index = end_index;
        }

        Ok(txt)
    }
}

impl<'a> From<TXT<'a>> for String {
    fn from(val: TXT<'a>) -> Self {
        val.strings
            .into_iter()
            .map(|s| s.into())
            .collect::<Vec<String>>()
            .join("")
    }
}

impl<'a> PacketPart<'a> for TXT<'a> {
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

    fn len(&self) -> usize {
        if self.strings.is_empty() {
            1
        } else {
            self.size
        }
    }

    fn write_to<T: std::io::Write>(&self, out: &mut T) -> crate::Result<()> {
        if self.strings.is_empty() {
            out.write_all(&[0])?;
        } else {
            for string in &self.strings {
                string.write_to(out)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{rdata::RData, ResourceRecord};
    use std::convert::TryInto;

    use super::*;

    #[test]
    pub fn parse_and_write_txt() -> Result<(), Box<dyn std::error::Error>> {
        let mut out = vec![];
        let txt = TXT::new()
            .with_char_string("version=0.1".try_into()?)
            .with_char_string("proto=123".try_into()?);

        txt.write_to(&mut out)?;
        assert_eq!(out.len(), txt.len());

        let txt2 = TXT::parse(&out, 0)?;
        assert_eq!(2, txt2.strings.len());
        assert_eq!(txt.strings[0], txt2.strings[0]);
        assert_eq!(txt.strings[1], txt2.strings[1]);

        Ok(())
    }

    #[test]
    pub fn get_attributes() -> Result<(), Box<dyn std::error::Error>> {
        let attributes = TXT::new()
            .with_string("version=0.1;")?
            .with_string("flag;")?
            .with_string("with_eq=eq=;")?
            .with_string("version=dup;")?
            .with_string("empty=")?
            .attributes();

        assert_eq!(4, attributes.len());
        assert_eq!(Some("0.1".to_owned()), attributes["version"]);
        assert_eq!(Some("eq=".to_owned()), attributes["with_eq"]);
        assert_eq!(Some(String::new()), attributes["empty"]);
        assert_eq!(None, attributes["flag"]);

        Ok(())
    }

    #[test]
    fn parse_sample() -> Result<(), Box<dyn std::error::Error>> {
        let sample_file = std::fs::read("samples/zonefile/TXT.sample")?;

        let sample_rdata = match ResourceRecord::parse(&sample_file, 0)?.rdata {
            RData::TXT(rdata) => rdata,
            _ => unreachable!(),
        };

        let strings = vec!["\"foo\nbar\"".try_into()?];
        assert_eq!(sample_rdata.strings, strings);

        Ok(())
    }

    #[test]
    fn write_and_parse_large_txt() -> Result<(), Box<dyn std::error::Error>> {
        let string = "foo ".repeat(1000);
        let txt: TXT = string.clone().try_into()?;

        let concatenated: String = txt.into();
        assert_eq!(concatenated, string);

        Ok(())
    }

    #[test]
    fn write_and_parse_large_attributes() -> Result<(), Box<dyn std::error::Error>> {
        let big_value = "f".repeat(1000);

        let txt: TXT = (format!("foo={};;flag;bar={}", big_value, big_value)).try_into()?;
        let attributes = txt.attributes();

        assert_eq!(Some(big_value.to_owned()), attributes["bar"]);

        Ok(())
    }
}
