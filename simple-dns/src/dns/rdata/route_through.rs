use std::{collections::HashMap, convert::TryInto};

use crate::dns::{Name, PacketPart};

use super::RR;

/// The RT resource record provides a route-through binding for hosts that do not have their own direct wide area network addresses
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct RouteThrough<'a> {
    /// A 16 bit integer which specifies the preference given to this RR among others at the same owner.  
    /// Lower values are preferred.
    pub preference: u16,

    /// A [Name](`Name`) which specifies a host which will serve as an intermediate in reaching the host specified by <owner>.
    pub intermediate_host: Name<'a>,
}

impl<'a> RR for RouteThrough<'a> {
    const TYPE_CODE: u16 = 21;
}

impl<'a> RouteThrough<'a> {
    /// Transforms the inner data into it's owned type
    pub fn into_owned<'b>(self) -> RouteThrough<'b> {
        RouteThrough {
            preference: self.preference,
            intermediate_host: self.intermediate_host.into_owned(),
        }
    }
}

impl<'a> PacketPart<'a> for RouteThrough<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let preference = u16::from_be_bytes(data[position..position + 2].try_into()?);
        let intermediate_host = Name::parse(data, position + 2)?;

        Ok(Self {
            preference,
            intermediate_host,
        })
    }

    fn append_to_vec(
        &self,
        out: &mut Vec<u8>,
        name_refs: &mut Option<&mut HashMap<u64, usize>>,
    ) -> crate::Result<()> {
        out.extend(self.preference.to_be_bytes());
        self.intermediate_host.append_to_vec(out, name_refs)
    }

    fn len(&self) -> usize {
        self.intermediate_host.len() + 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_write_route_through() {
        let rt = RouteThrough {
            preference: 10,
            intermediate_host: Name::new("e.exchange.com").unwrap(),
        };

        let mut data = Vec::new();
        assert!(rt.append_to_vec(&mut data, &mut None).is_ok());

        let rt = RouteThrough::parse(&data, 0);
        assert!(rt.is_ok());
        let rt = rt.unwrap();

        assert_eq!(data.len(), rt.len());
        assert_eq!(10, rt.preference);
        assert_eq!("e.exchange.com", rt.intermediate_host.to_string());
    }
}
