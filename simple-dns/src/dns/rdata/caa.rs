use crate::dns::{CharacterString, PacketPart};

use super::RR;

// RFC 8659: Allow domain name holders to indicate whether they are authorized to issue digital certificates for particular domain name
// Used as a security policy for certificate authorities
// This implementation does not validate the tag or value; it splits based on packet byte sturcture
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct CAA<'a> {
    // Critical or noncritical indicator
    pub flag: u8,
    // Property described in the VALUE field. One of `issue`, `issuewild`, or `iodef`
    pub tag: CharacterString<'a>,
    // Value associated with property tag
    pub value: CharacterString<'a>,
}

impl<'a> RR for CAA<'a> {
    const TYPE_CODE: u16 = 257;
}

impl<'a> CAA<'a> {
    /// Transforms the inner data into it owned type
    pub fn into_owned<'b>(self) -> CAA<'b> {
        CAA {
            flag: self.flag,
            tag: self.tag.into_owned(),
            value: self.value.into_owned(),
        }
    }
}

impl<'a> PacketPart<'a> for CAA<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let flag = u8::from_be_bytes(data[position..position + 1].try_into()?);
        let tag = CharacterString::parse(data, position + 1)?;
        let value = CharacterString::parse(data, position + 1 + tag.len())?;

        Ok(Self { flag, tag, value })
    }

    fn write_to<T: std::io::Write>(&self, out: &mut T) -> crate::Result<()> {
        out.write_all(&self.flag.to_be_bytes())?;
        self.tag.write_to(out)?;
        self.value.write_to(out)
    }

    fn len(&self) -> usize {
        self.tag.len() + self.value.len() + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_write_caa() {
        let caa = CAA {
            flag: 0,
            tag: CharacterString::new(b"issue").unwrap(),
            value: CharacterString::new(b"\"example.org").unwrap(),
        };

        let mut data = Vec::new();
        assert!(caa.write_to(&mut data).is_ok());

        let caa = CAA::parse(&data, 0);
        assert!(caa.is_ok());
        let caa = caa.unwrap();

        assert_eq!(data.len(), caa.len());
        assert_eq!(0, caa.flag);
        assert_eq!("issue", caa.tag.to_string());
        assert_eq!("\"example.org", caa.value.to_string());
    }
}
