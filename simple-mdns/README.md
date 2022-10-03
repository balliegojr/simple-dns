# Simple mDNS

Pure Rust implementation for mDNS and DNS-SD protocols

## ServiceDiscovery
Advertise registered addresses and query for available instances on the same network.  
It is necessary to provide instance and service name

```rust  
    use simple_mdns::ServiceDiscovery;
    use std::net::{SocketAddr, Ipv4Addr};
    use std::str::FromStr;

    let mut discovery = ServiceDiscovery::new("a", "_mysrv._tcp.local", 60, &Ipv4Addr::UNSPECIFIED).expect("Invalid Service Name");
    discovery.add_service_info(SocketAddr::from_str("192.168.1.22:8090").unwrap().into());
```


## OneShotMdnsResolver (Legacy mDNS)
One shot resolvers are considered legacy and not fully compliant with the mDNS protocol, but they are handy for service discovery if you have (or need) only one service instance

### How it works
One shot resolvers or queries send a multicast DNS question to discover available services in the network.  
- Only the IP address is necessary (port is fixed or already known), a A or AAAA question is sent.
- IP address and port are necessary, a SRV question is sent.

Since mDNS is a well known protocol, you can register your service in any mDNS responder inside your network, and they should be able to reply the requested information about your service.

Query example:
```rust  
    use simple_mdns::OneShotMdnsResolver;
    use std::net::Ipv4Addr;

    let resolver = OneShotMdnsResolver::new(&Ipv4Addr::UNSPECIFIED).expect("Failed to create resolver");
    // querying for IP Address
    let answer = resolver.query_service_address("_myservice._tcp.local").expect("Failed to query service address");
    println!("{:?}", answer);
    // IpV4Addr or IpV6Addr, depending on what was returned
    
    let answer = resolver.query_service_address_and_port("_myservice._tcp.local").expect("Failed to query service address and port");
    println!("{:?}", answer);
    // SocketAddr, "127.0.0.1:8080", with a ipv4 or ipv6
```

## SimpleMdnsResponder
In case you don't have a mDNS responder in your network, or for some reason don't want to use the ones available.

This responder will list for any mDNS query in the network via Multicast and will reply only to the resources that were added.

This struct relies on [`simple-dns`](https://crates.io/crates/simple-dns) crate and the same must be added as a dependency

```rust  
    use simple_mdns::SimpleMdnsResponder;
    use simple_dns::{Name, CLASS, ResourceRecord, rdata::{RData, A, SRV}};
    use std::net::Ipv4Addr;


    let mut responder = SimpleMdnsResponder::new(10, &Ipv4Addr::UNSPECIFIED);
    let srv_name = Name::new_unchecked("_srvname._tcp.local");

    responder.add_resource(ResourceRecord::new(
        srv_name.clone(),
        CLASS::IN,
        10,
        RData::A(A { address: Ipv4Addr::LOCALHOST.into() }),
    ));

    responder.add_resource(ResourceRecord::new(
        srv_name.clone(),
        CLASS::IN,
        10,
        RData::SRV(SRV {
            port: 8080,
            priority: 0,
            weight: 0,
            target: srv_name
        })
    ));
```


# TODOs
- IPv6 queries
