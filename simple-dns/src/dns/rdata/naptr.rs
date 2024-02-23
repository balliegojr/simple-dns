use crate::dns::{CharacterString, Name, PacketPart};

use super::RR;

/// RFC 3403: Used to map a domain name to a set of services. The fields determine 
///           the order of processing, specify the protocol and service to be used,
///           and transform the original domain name into a new domain name or URI.



#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct NAPTR<'a> {
    /// Order in which NAPTR records must be processed
    pub order: u16,
    /// Order in which NAPTR records with equal Order values should be processed
    pub preference: u16,
    /// Control rewriting and interpretation of the fields in the record
    pub flags: CharacterString<'a>,
    /// Service Parameters applicable to this this delegation path
    pub services: CharacterString<'a>,
    /// Regular expression applied to original string from client
    pub regexp: CharacterString<'a>,
    /// Next domain-name to query for
    pub replacement: Name<'a>,
}

impl<'a> RR for NAPTR<'a> {
    const TYPE_CODE: u16 = 35;
}

impl<'a> NAPTR<'a> {
    /// Transforms the inner data into it owned type
    pub fn into_owned<'b>(self) -> NAPTR<'b> {
        NAPTR {
            order: self.order,
            preference: self.preference,
            flags: self.flags.into_owned(),
            services: self.services.into_owned(),
            regexp: self.regexp.into_owned(),
            replacement: self.replacement.into_owned(),
        }
    }
}

impl<'a> PacketPart<'a> for NAPTR<'a> {
    fn parse(data: &'a [u8], position: &mut usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let order = u16::from_be_bytes(data[*position..*position + 1].try_into()?);
        *position += 1;
        let preference = u16::from_be_bytes(data[*position..*position + 1].try_into()?);
        *position += 1;
        let flags = CharacterString::parse(data, position)?;
        let services = CharacterString::parse(data, position)?;
        let regexp = CharacterString::parse(data, position)?;
        let replacement = Name::parse(data, position)?;

        Ok(Self { order, preference, flags, services, regexp, replacement})
    }

    fn write_to<T: std::io::Write>(&self, out: &mut T) -> crate::Result<()> {
        out.write_all(&self.order.to_be_bytes())?;
        out.write_all(&self.preference.to_be_bytes())?;
        self.flags.write_to(out)?;
        self.services.write_to(out)?;
        self.regexp.write_to(out)?;
        self.replacement.write_to(out)
    }

    fn len(&self) -> usize {
        self.flags.len() + self.services.len() + self.regexp.len() + self.replacement.len() + 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_write_naptr() {
        let naptr = NAPTR {
            order: 0,
            preference: 1,
            flags: CharacterString::new(b"123abc").unwrap(),
            services: CharacterString::new(b"test").unwrap(),
            regexp: CharacterString::new(b"@\\w+\\.\\w{2,3}(\\.\\w{2,3})?").unwrap(),
            replacement: Name::new("e.exchange.com").unwrap(),
        };

        let mut data = Vec::new();
        assert!(naptr.write_to(&mut data).is_ok());

        let naptr = NAPTR::parse(&data, &mut 0);
        assert!(naptr.is_ok());
        let naptr = naptr.unwrap();

        assert_eq!(data.len(), naptr.len());
        assert_eq!(0, naptr.order);
        assert_eq!(1, naptr.preference);
        assert_eq!("123abc", naptr.flags.to_string());
        assert_eq!("test", naptr.services.to_string());
        assert_eq!("@\\w+\\.\\w{2,3}(\\.\\w{2,3})?", naptr.regexp.to_string());
        assert_eq!("e.exchange.com", naptr.replacement.to_string());
    }
}
