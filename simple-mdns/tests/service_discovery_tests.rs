use simple_mdns::ServiceDiscovery;
use std::{error::Error, net::SocketAddr, str::FromStr, time::Duration};

// fn init_log() {
//     stderrlog::new()
//         .verbosity(5)
//         .timestamp(stderrlog::Timestamp::Second)
//         .init()
//         .unwrap();
// }

#[test]
fn service_discovery_can_find_services() -> Result<(), Box<dyn Error>> {
    // init_log();

    std::thread::sleep(Duration::from_secs(1));

    let mut service_discovery_a = ServiceDiscovery::new("a", "_srv3._tcp.local", 60)?;
    let mut service_discovery_b = ServiceDiscovery::new("b", "_srv3._tcp.local", 60)?;
    let mut service_discovery_c = ServiceDiscovery::new("c", "_srv3._tcp.local", 60)?;

    service_discovery_a.add_service_info(SocketAddr::from_str("192.168.1.2:8080")?.into());
    service_discovery_b.add_service_info(SocketAddr::from_str("192.168.1.3:8080")?.into());
    service_discovery_c.add_service_info(SocketAddr::from_str("192.168.1.4:8080")?.into());

    std::thread::sleep(Duration::from_secs(2));

    let mut from_a: Vec<SocketAddr> = service_discovery_a
        .get_known_services()
        .iter()
        .map(|x| x.combined_addresses())
        .flatten()
        .collect();

    let mut from_b: Vec<SocketAddr> = service_discovery_b
        .get_known_services()
        .iter()
        .map(|x| x.combined_addresses())
        .flatten()
        .collect();

    let mut from_c: Vec<SocketAddr> = service_discovery_c
        .get_known_services()
        .iter()
        .map(|x| x.combined_addresses())
        .flatten()
        .collect();

    from_a.sort();
    from_b.sort();
    from_c.sort();

    assert_eq!(2, from_a.len());
    assert_eq!(2, from_b.len());
    assert_eq!(2, from_c.len());

    assert_eq!(&("192.168.1.3:8080".parse::<SocketAddr>()?), &from_a[0]);
    assert_eq!(&("192.168.1.4:8080".parse::<SocketAddr>()?), &from_a[1]);

    assert_eq!(&("192.168.1.2:8080".parse::<SocketAddr>()?), &from_b[0]);
    assert_eq!(&("192.168.1.4:8080".parse::<SocketAddr>()?), &from_b[1]);

    assert_eq!(&("192.168.1.2:8080".parse::<SocketAddr>()?), &from_c[0]);
    assert_eq!(&("192.168.1.3:8080".parse::<SocketAddr>()?), &from_c[1]);
    Ok(())
}
