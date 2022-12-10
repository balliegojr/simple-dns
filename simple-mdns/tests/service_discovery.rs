#![cfg(feature = "sync")]

use simple_mdns::{sync_discovery::ServiceDiscovery, InstanceInformation};
use std::{collections::HashMap, error::Error, net::SocketAddr, str::FromStr, time::Duration};

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

    service_discovery_a
        .add_service_info(SocketAddr::from_str("192.168.1.2:8080")?.into())
        .expect("Failed to add service info");
    service_discovery_b
        .add_service_info(SocketAddr::from_str("192.168.1.3:8080")?.into())
        .expect("Failed to add service info");
    service_discovery_c
        .add_service_info(SocketAddr::from_str("192.168.1.4:8080")?.into())
        .expect("Failed to add service info");

    std::thread::sleep(Duration::from_secs(2));

    let mut from_a: Vec<SocketAddr> = service_discovery_a
        .get_known_services()
        .iter()
        .flat_map(|x| x.get_socket_addresses())
        .collect();

    let mut from_b: Vec<SocketAddr> = service_discovery_b
        .get_known_services()
        .iter()
        .flat_map(|x| x.get_socket_addresses())
        .collect();

    let mut from_c: Vec<SocketAddr> = service_discovery_c
        .get_known_services()
        .iter()
        .flat_map(|x| x.get_socket_addresses())
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

#[test]
fn service_discovery_receive_attributes() -> Result<(), Box<dyn Error>> {
    // init_log();

    std::thread::sleep(Duration::from_secs(1));

    let mut service_discovery_d = ServiceDiscovery::new("d", "_srv4._tcp.local", 60)?;
    let mut service_discovery_e = ServiceDiscovery::new("e", "_srv4._tcp.local", 60)?;

    let mut service_info: InstanceInformation = SocketAddr::from_str("192.168.1.2:8080")?.into();
    service_info
        .attributes
        .insert("id".to_string(), Some("id_d".to_string()));

    service_discovery_d
        .add_service_info(service_info)
        .expect("Failed to add service info");
    let mut service_info: InstanceInformation = SocketAddr::from_str("192.168.1.3:8080")?.into();
    service_info
        .attributes
        .insert("id".to_string(), Some("id_e".to_string()));
    service_discovery_e
        .add_service_info(service_info)
        .expect("Failed to add service info");

    std::thread::sleep(Duration::from_secs(2));

    let d_attr: HashMap<String, Option<String>> = service_discovery_d
        .get_known_services()
        .into_iter()
        .flat_map(|x| x.attributes)
        .collect();

    let e_attr: HashMap<String, Option<String>> = service_discovery_e
        .get_known_services()
        .into_iter()
        .flat_map(|x| x.attributes)
        .collect();

    assert_eq!(1, d_attr.len());
    assert_eq!(1, e_attr.len());

    assert_eq!("id_e", d_attr.get("id").as_ref().unwrap().as_ref().unwrap());
    assert_eq!("id_d", e_attr.get("id").as_ref().unwrap().as_ref().unwrap());

    Ok(())
}

#[test]
#[cfg(not(target_os = "macos"))]
fn service_discovery_can_find_services_ipv6() -> Result<(), Box<dyn Error>> {
    // init_log();

    std::thread::sleep(Duration::from_secs(1));

    let mut service_discovery_a = ServiceDiscovery::new_with_scope(
        "a",
        "_srv3._tcp.local",
        60,
        simple_mdns::NetworkScope::V6,
    )?;
    let mut service_discovery_b = ServiceDiscovery::new_with_scope(
        "b",
        "_srv3._tcp.local",
        60,
        simple_mdns::NetworkScope::V6,
    )?;
    let mut service_discovery_c = ServiceDiscovery::new_with_scope(
        "c",
        "_srv3._tcp.local",
        60,
        simple_mdns::NetworkScope::V6,
    )?;

    service_discovery_a
        .add_service_info(SocketAddr::from_str("[fe80::26fc:f50f:6755:7d67]:8080")?.into())
        .expect("Failed to add service info");
    service_discovery_b
        .add_service_info(SocketAddr::from_str("[fe80::26fc:f50f:6755:7d68]:8080")?.into())
        .expect("Failed to add service info");
    service_discovery_c
        .add_service_info(SocketAddr::from_str("[fe80::26fc:f50f:6755:7d69]:8080")?.into())
        .expect("Failed to add service info");

    std::thread::sleep(Duration::from_secs(2));

    let mut from_a: Vec<SocketAddr> = service_discovery_a
        .get_known_services()
        .iter()
        .flat_map(|x| x.get_socket_addresses())
        .collect();

    let mut from_b: Vec<SocketAddr> = service_discovery_b
        .get_known_services()
        .iter()
        .flat_map(|x| x.get_socket_addresses())
        .collect();

    let mut from_c: Vec<SocketAddr> = service_discovery_c
        .get_known_services()
        .iter()
        .flat_map(|x| x.get_socket_addresses())
        .collect();

    from_a.sort();
    from_b.sort();
    from_c.sort();

    assert_eq!(2, from_a.len());
    assert_eq!(2, from_b.len());
    assert_eq!(2, from_c.len());

    assert_eq!(
        &("[fe80::26fc:f50f:6755:7d68]:8080".parse::<SocketAddr>()?),
        &from_a[0]
    );
    assert_eq!(
        &("[fe80::26fc:f50f:6755:7d69]:8080".parse::<SocketAddr>()?),
        &from_a[1]
    );

    assert_eq!(
        &("[fe80::26fc:f50f:6755:7d67]:8080".parse::<SocketAddr>()?),
        &from_b[0]
    );
    assert_eq!(
        &("[fe80::26fc:f50f:6755:7d69]:8080".parse::<SocketAddr>()?),
        &from_b[1]
    );

    assert_eq!(
        &("[fe80::26fc:f50f:6755:7d67]:8080".parse::<SocketAddr>()?),
        &from_c[0]
    );
    assert_eq!(
        &("[fe80::26fc:f50f:6755:7d68]:8080".parse::<SocketAddr>()?),
        &from_c[1]
    );
    Ok(())
}
