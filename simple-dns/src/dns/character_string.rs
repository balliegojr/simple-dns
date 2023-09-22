use std::{borrow::Cow, convert::TryFrom, fmt::Display};

use crate::SimpleDnsError;

use super::{PacketPart, MAX_CHARACTER_STRING_LENGTH};

/// CharacterString is expressed in one or two ways:
/// - as a contiguous set of characters without interior spaces,
/// - or as a string beginning with a " and ending with a ".  
///
/// Inside a " delimited string any character can occur, except for a " itself,  
/// which must be quoted using \ (back slash).
#[derive(PartialEq, Eq, Hash, Clone)]
pub struct CharacterString<'a> {
    pub(crate) data: Cow<'a, [u8]>,
}

impl<'a> CharacterString<'a> {
    /// Creates a new validated CharacterString
    pub fn new(data: &'a [u8]) -> crate::Result<Self> {
        Self::internal_new(Cow::Borrowed(data))
    }

    fn internal_new(data: Cow<'a, [u8]>) -> crate::Result<Self> {
        if data.len() > MAX_CHARACTER_STRING_LENGTH {
            return Err(SimpleDnsError::InvalidCharacterString);
        }
        match String::from_utf8(data.clone().into_owned()) {
            Ok(_) => Ok(Self { data }),
            Err(_) => Err(SimpleDnsError::InvalidCharacterString),
        }
    }

    /// Transforms the inner data into its owned type
    pub fn into_owned<'b>(self) -> CharacterString<'b> {
        CharacterString {
            data: self.data.into_owned().into(),
        }
    }
}

impl<'a> Into<String> for CharacterString<'a> {
    fn into(self) -> String {
        String::from_utf8(self.data.into_owned()).unwrap()
    }
}

impl<'a> PacketPart<'a> for CharacterString<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let length = data[position] as usize;

        if length < MAX_CHARACTER_STRING_LENGTH && length + position < data.len() {
            Ok(Self {
                data: Cow::Borrowed(&data[position + 1..position + 1 + length]),
            })
        } else {
            Err(SimpleDnsError::InvalidCharacterString)
        }
    }

    fn write_to<T: std::io::Write>(&self, out: &mut T) -> crate::Result<()> {
        out.write_all(&[self.data.len() as u8])?;
        out.write_all(&self.data)
            .map_err(crate::SimpleDnsError::from)
    }

    fn len(&self) -> usize {
        self.data.len() + 1
    }
}

impl<'a> TryFrom<&'a str> for CharacterString<'a> {
    type Error = crate::SimpleDnsError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        CharacterString::internal_new(Cow::Borrowed(value.as_bytes()))
    }
}

impl<'a> TryFrom<String> for CharacterString<'a> {
    type Error = crate::SimpleDnsError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        CharacterString::internal_new(Cow::Owned(value.as_bytes().into()))
    }
}

impl<'a> Display for CharacterString<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = std::str::from_utf8(&self.data).unwrap();
        f.write_str(s)
    }
}

impl<'a> std::fmt::Debug for CharacterString<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CharacterString")
            .field("data", &self.to_string())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };

    use super::*;

    #[test]
    fn construct_valid_character_string() {
        assert!(CharacterString::new(b"Iamvalid").is_ok());
        assert!(CharacterString::new(br#""I am valid""#).is_ok());
        assert!(CharacterString::new(br#""I am \" also valid""#).is_ok());
        assert!(CharacterString::new(b"I am valid").is_ok());

        let long_string = [0u8; 300];
        assert!(CharacterString::new(&long_string).is_err());

        let invalid_utf8 = [0xe2, 0x28, 0xa1];
        assert!(CharacterString::new(&invalid_utf8).is_err());
    }

    #[test]
    fn parse() {
        let c_string = CharacterString::parse(b"\x0esome_long_text", 0);
        assert!(c_string.is_ok());
        let c_string = c_string.unwrap();
        assert_eq!(15, c_string.len());
        assert_eq!("some_long_text", c_string.to_string());
    }

    #[test]
    fn append_to_vec() {
        let mut out = Vec::new();
        let c_string = CharacterString::new("some_long_text".as_bytes()).unwrap();
        c_string.write_to(&mut out).unwrap();

        assert_eq!(b"\x0esome_long_text", &out[..]);
    }

    #[test]
    fn eq() {
        let a = CharacterString::new(b"text").unwrap();
        let b = CharacterString::new(b"text").unwrap();

        assert_eq!(a, b);
        assert_eq!(get_hash(a), get_hash(b));
    }

    fn get_hash(string: CharacterString) -> u64 {
        let mut hasher = DefaultHasher::default();
        string.hash(&mut hasher);
        hasher.finish()
    }
}
