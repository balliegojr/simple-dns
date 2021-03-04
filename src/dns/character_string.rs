use std::{convert::TryFrom, fmt::Display};

use crate::SimpleDnsError;

use super::{DnsPacketContent, MAX_CHARACTER_STRING_LENGTH};

#[derive(Debug)]
pub struct CharacterString<'a> {
    data: &'a [u8]
}

impl <'a> CharacterString<'a> {
    pub fn new(data: &'a [u8]) -> crate::Result<Self> {
        if data.len() > MAX_CHARACTER_STRING_LENGTH {
            return Err(SimpleDnsError::InvalidCharacterString)
        }

        Ok(Self {
            data
        })
    }
}

impl <'a> DnsPacketContent<'a> for CharacterString<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self> where Self: Sized {
        let length = data[position] as usize;

        return Ok(Self{
            data: &data[position + 1..position + 1 + length]
        })
    }

    fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        out.push(self.data.len() as u8);
        out.extend(self.data);
        
        Ok(())
    }

    fn len(&self) -> usize {
        self.data.len() + 1
    }
}

impl <'a> TryFrom<&'a str> for CharacterString<'a> {
    type Error = crate::SimpleDnsError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        CharacterString::new(value.as_bytes())
    }
}

impl <'a> Display for CharacterString<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = std::str::from_utf8(&self.data[..]).unwrap();
        f.write_str(s)

    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construct_valid_character_string() {
        assert!(CharacterString::new(b"I am valid").is_ok());

        let long_string= [0u8; 300];
        assert!(CharacterString::new(&long_string).is_err());
    }

    #[test]
    fn parse() {
        let c_string= CharacterString::parse(b"\x0esome long text", 0);
        assert!(c_string.is_ok());
        let c_string = c_string.unwrap();
        assert_eq!(15, c_string.len());
        assert_eq!("some long text", c_string.to_string());
    }

    #[test]
    fn append_to_vec() {
        let mut out = Vec::new();
        let c_string= CharacterString::new("some long text".as_bytes()).unwrap();
        c_string.append_to_vec(&mut out).unwrap();

        assert_eq!(b"\x0esome long text", &out[..]);
    }
}