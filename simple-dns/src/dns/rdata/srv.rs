use byteorder::{ByteOrder, BigEndian};

use crate::Name;
use crate::dns::DnsPacketContent;

/// SRV records specifies the location of the server(s) for a specific protocol and domain.
#[derive(Debug, PartialEq, Eq, Hash)]
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
    pub target: Name<'a>
}

impl <'a> DnsPacketContent<'a> for SRV<'a> {
    fn parse(data: &'a [u8], position: usize) -> crate::Result<Self> where Self: Sized {
        let priority = BigEndian::read_u16(&data[position..position+2]);
        let weight = BigEndian::read_u16(&data[position+2..position+4]);
        let port = BigEndian::read_u16(&data[position+4..position+6]);
        let target = Name::parse(data, position+6)?;

        Ok(Self {
            priority,
            weight,
            port,
            target
        })
    }

    fn append_to_vec(&self, out: &mut Vec<u8>) -> crate::Result<()> {
        let mut buf = [0u8; 6];
        BigEndian::write_u16(&mut buf[0..2], self.priority);
        BigEndian::write_u16(&mut buf[2..4], self.weight);
        BigEndian::write_u16(&mut buf[4..6], self.port);

        out.extend(&buf);
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
            target: Name::new("_srv._tcp.example.com").unwrap()
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
