use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const MULTICAST_PORT: u16 = 5353;
pub const MULTICAST_ADDR_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const MULTICAST_ADDR_IPV6: Ipv6Addr = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 0xFB);

/// Network scope to be used by service discovery
/// Default scope for services is to use IPV4 protocol
#[derive(Debug, Copy, Clone)]
pub enum NetworkScope {
    /// Uses IPV4 protocol with UNSPECIFIED network interface (0.0.0.0)
    V4,
    /// Uses IPV4 protocol and provided network interface
    V4WithInterface(Ipv4Addr),
    /// Uses IPV6 protocol with UNSPECIFIED network interface (0)
    V6,
    /// Uses IPV6 protocol with provided network interface
    V6WithInterface(u32),
}

impl NetworkScope {
    /// Returns `true` if the network scope is [`V4`] or [`V4WithInterface`].
    ///
    /// [`V4`]: NetworkScope::V4
    /// [`V4WithInterface`]: NetworkScope::V4WithInterface
    #[must_use]
    pub fn is_v4(&self) -> bool {
        matches!(&self, Self::V4 | Self::V4WithInterface(..))
    }

    pub(crate) fn socket_address(&self) -> SocketAddr {
        if self.is_v4() {
            SocketAddr::new(IpAddr::V4(MULTICAST_ADDR_IPV4), MULTICAST_PORT)
        } else {
            SocketAddr::new(IpAddr::V6(MULTICAST_ADDR_IPV6), MULTICAST_PORT)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_multicast() {
        assert!(MULTICAST_ADDR_IPV4.is_multicast());
    }

    #[test]
    fn test_ipv6_multicast() {
        assert!(MULTICAST_ADDR_IPV6.is_multicast());
    }
}
