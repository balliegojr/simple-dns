use std::{net::{Ipv4Addr, SocketAddr}, time::Duration};
use simple_dns::Name;
use simple_mdns::ServiceDiscovery;

#[tokio::test]
async fn service_discovery_can_find_services() {
    let mut service_discovery_a = ServiceDiscovery::new(Name::new_unchecked("_srv3._tcp.com"), 50, true);
    let mut service_discovery_b = ServiceDiscovery::new(Name::new_unchecked("_srv3._tcp.com"), 50, true);

    service_discovery_a.add_socket_address(&("192.168.1.2:8080".parse().unwrap()));
    service_discovery_b.add_socket_address(&("192.168.1.3:8080".parse().unwrap()));

    tokio::time::sleep(Duration::from_secs(1)).await;

    let services_a = service_discovery_a.get_known_services();
    let services_b = service_discovery_b.get_known_services();

    assert_eq!(1, services_a.len());
    assert_eq!(1, services_b.len());

    assert_eq!(
        &("192.168.1.3:8080".parse::<SocketAddr>().unwrap()),
        &services_a[0]
    );

    assert_eq!(
        &("192.168.1.2:8080".parse::<SocketAddr>().unwrap()),
        &services_b[0]
    );
}

