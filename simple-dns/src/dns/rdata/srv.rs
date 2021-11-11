use std::convert::TryInto;

use crate::dns::DnsPacketContent;
use crate::Name;

/// SRV records specifies the location of the server(s) for a specific protocol and domain.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SRV<'a> {
    /// The priority of this target host.  
    /// A client MUST attempt to contact the target host with the lowest-numbered priority it can
    /// reach; target hosts with the same priority SHOULD be tried in an order defined by the weight field.
    pub priority: u16,
    /// A server selection mechanism.  
    /// The weight field specifies arelative weight for entries with the same priority.  
    /// Larger weights SHOULD be given a proportionately higher probability of being selected.
    pub weight: u16,
    /// The port on this target host of this service
    pub port: u16,
    /// The domain name of the target host
    pub target: Name<'a>,
}

impl<'a> SRV<'a> {
    /// Transforms the inner data into it's owned type
    pub fn into_owned<'b>(self) -> SRV<'b> {
        SRV {
            priority: self.priority,
            weight: self.weight,
            port: self.port,
            target: self.target.into_owned(),
        }
    }
}

impl<'a> DnsPacketContent<'a> for SRV<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self>
    where
        Self: Sized,
    {
        let priority = u16::from_be_bytes(data[position..position + 2].try_into()?);
        let weight = u16::from_be_bytes(data[position + 2..position + 4].try_into()?);
        let port = u16::from_be_bytes(data[position + 4..position + 6].try_into()?);
        let target = Name::parse(data, position + 6)?;

        Ok(Self {
            priority,
            weight,
            port,
            target,
        })
    }

    fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        out.extend(self.priority.to_be_bytes());
        out.extend(self.weight.to_be_bytes());
        out.extend(self.port.to_be_bytes());

        self.target.append_to_vec(out)
    }

    fn len(&self) -> usize {
        self.target.len() + 6
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_write_srv() {
        let srv = SRV {
            priority: 1,
            weight: 2,
            port: 3,
            target: Name::new("_srv._tcp.example.com").unwrap(),
        };

        let mut bytes = Vec::new();
        assert!(srv.append_to_vec(&mut bytes).is_ok());

        let srv = SRV::parse(&bytes, 0);
        assert!(srv.is_ok());
        let srv = srv.unwrap();

        assert_eq!(1, srv.priority);
        assert_eq!(2, srv.weight);
        assert_eq!(3, srv.port);
        assert_eq!(bytes.len(), srv.len());
    }
}
