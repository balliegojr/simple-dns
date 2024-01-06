#![cfg(feature = "async-tokio")]

use simple_mdns::{async_discovery::ServiceDiscovery, InstanceInformation};
use std::{collections::HashMap, error::Error, net::SocketAddr, time::Duration};

fn init_log() {
    let log_level = std::env::var("LOG_LEVEL")
        .as_deref()
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);

    let _ = stderrlog::new()
        .verbosity(log_level)
        .timestamp(stderrlog::Timestamp::Second)
        .init();
}

#[tokio::test]
async fn service_discovery_can_find_services() -> Result<(), Box<dyn Error>> {
    init_log();

    tokio::time::sleep(Duration::from_secs(1)).await;

    let service_discovery_a = ServiceDiscovery::new(
        InstanceInformation::new("a".to_string()).with_socket_address("192.168.1.2:8080".parse()?),
        "_async3._tcp.local",
        60,
    )?;
    let service_discovery_b = ServiceDiscovery::new(
        InstanceInformation::new("b".to_string()).with_socket_address("192.168.1.3:8080".parse()?),
        "_async3._tcp.local",
        60,
    )?;
    let service_discovery_c = ServiceDiscovery::new(
        InstanceInformation::new("c".to_string()).with_socket_address("192.168.1.4:8080".parse()?),
        "_async3._tcp.local",
        60,
    )?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    let from_a: HashMap<String, SocketAddr> = service_discovery_a
        .get_known_services()
        .await
        .into_iter()
        .map(|info| {
            (
                info.unescaped_instance_name(),
                info.get_socket_addresses().next().unwrap(),
            )
        })
        .collect();

    let from_b: HashMap<String, SocketAddr> = service_discovery_b
        .get_known_services()
        .await
        .into_iter()
        .map(|info| {
            (
                info.unescaped_instance_name(),
                info.get_socket_addresses().next().unwrap(),
            )
        })
        .collect();

    let from_c: HashMap<String, SocketAddr> = service_discovery_c
        .get_known_services()
        .await
        .into_iter()
        .map(|info| {
            (
                info.unescaped_instance_name(),
                info.get_socket_addresses().next().unwrap(),
            )
        })
        .collect();

    assert_eq!(2, from_a.len());
    assert_eq!(2, from_b.len());
    assert_eq!(2, from_c.len());

    assert_eq!(&("192.168.1.3:8080".parse::<SocketAddr>()?), &from_a["b"]);
    assert_eq!(&("192.168.1.4:8080".parse::<SocketAddr>()?), &from_a["c"]);

    assert_eq!(&("192.168.1.2:8080".parse::<SocketAddr>()?), &from_b["a"]);
    assert_eq!(&("192.168.1.4:8080".parse::<SocketAddr>()?), &from_b["c"]);

    assert_eq!(&("192.168.1.2:8080".parse::<SocketAddr>()?), &from_c["a"]);
    assert_eq!(&("192.168.1.3:8080".parse::<SocketAddr>()?), &from_c["b"]);
    Ok(())
}

#[tokio::test]
async fn service_discovery_is_notified_on_discovery() -> Result<(), Box<dyn Error>> {
    init_log();

    std::thread::sleep(Duration::from_secs(1));

    let (tx, mut rx) = tokio::sync::mpsc::channel(1);

    let _service_discovery_a = ServiceDiscovery::new_with_scope(
        InstanceInformation::new("a".to_string()).with_socket_address("192.168.1.2:8080".parse()?),
        "_async_notify._tcp.local",
        60,
        Some(tx),
        simple_mdns::NetworkScope::V4,
    )?;
    let _service_discovery_b = ServiceDiscovery::new(
        InstanceInformation::new("b".to_string()).with_socket_address("192.168.1.3:8080".parse()?),
        "_async_notify._tcp.local",
        60,
    )?;
    let _service_discovery_c = ServiceDiscovery::new(
        InstanceInformation::new("c".to_string()).with_socket_address("192.168.1.4:8080".parse()?),
        "_async_notify._tcp.local",
        60,
    )?;

    for _ in 0..2 {
        let Some(service_info) = rx.recv().await else {
            panic!("Did not receive enough packets");
        };

        let addr = service_info.get_socket_addresses().next().unwrap();
        match service_info.unescaped_instance_name().as_str() {
            "b" => assert_eq!(("192.168.1.3:8080".parse::<SocketAddr>()?), addr),
            "c" => assert_eq!(("192.168.1.4:8080".parse::<SocketAddr>()?), addr),
            _ => panic!("Received unexpected packet"),
        }
    }

    Ok(())
}

#[tokio::test]
async fn service_discovery_receive_attributes() -> Result<(), Box<dyn Error>> {
    init_log();

    tokio::time::sleep(Duration::from_secs(1)).await;

    let service_discovery_d = ServiceDiscovery::new(
        InstanceInformation::new("d".to_string())
            .with_socket_address("192.168.1.2:8080".parse()?)
            .with_attribute("id".to_string(), Some("id_d".to_string())),
        "_srv4._tcp.local",
        60,
    )?;
    let service_discovery_e = ServiceDiscovery::new(
        InstanceInformation::new("e".to_string())
            .with_socket_address("192.168.1.3:8080".parse()?)
            .with_attribute("id".to_string(), Some("id_e".to_string())),
        "_srv4._tcp.local",
        60,
    )?;

    tokio::time::sleep(Duration::from_secs(2)).await;

    let d_attr: HashMap<String, Option<String>> = service_discovery_d
        .get_known_services()
        .await
        .into_iter()
        .flat_map(|x| x.attributes)
        .collect();

    let e_attr: HashMap<String, Option<String>> = service_discovery_e
        .get_known_services()
        .await
        .into_iter()
        .flat_map(|x| x.attributes)
        .collect();

    assert_eq!(1, d_attr.len());
    assert_eq!(1, e_attr.len());

    assert_eq!("id_e", d_attr.get("id").as_ref().unwrap().as_ref().unwrap());
    assert_eq!("id_d", e_attr.get("id").as_ref().unwrap().as_ref().unwrap());

    Ok(())
}

#[tokio::test]
#[cfg(not(target_os = "macos"))]
async fn service_discovery_can_find_services_ipv6_bunda() -> Result<(), Box<dyn Error>> {
    init_log();

    tokio::time::sleep(Duration::from_secs(1)).await;

    let service_discovery_a = ServiceDiscovery::new_with_scope(
        InstanceInformation::new("a".to_string())
            .with_socket_address("[fe80::26fc:f50f:6755:7d67]:8080".parse()?),
        "_async3._tcp.local",
        60,
        None,
        simple_mdns::NetworkScope::V6,
    )?;
    let service_discovery_b = ServiceDiscovery::new_with_scope(
        InstanceInformation::new("b".to_string())
            .with_socket_address("[fe80::26fc:f50f:6755:7d68]:8080".parse()?),
        "_async3._tcp.local",
        60,
        None,
        simple_mdns::NetworkScope::V6,
    )?;
    let service_discovery_c = ServiceDiscovery::new_with_scope(
        InstanceInformation::new("c".to_string())
            .with_socket_address("[fe80::26fc:f50f:6755:7d69]:8080".parse()?),
        "_async3._tcp.local",
        60,
        None,
        simple_mdns::NetworkScope::V6,
    )?;

    tokio::time::sleep(Duration::from_secs(3)).await;

    let from_a: HashMap<String, SocketAddr> = service_discovery_a
        .get_known_services()
        .await
        .into_iter()
        .map(|info| {
            (
                info.unescaped_instance_name(),
                info.get_socket_addresses().next().unwrap(),
            )
        })
        .collect();

    let from_b: HashMap<String, SocketAddr> = service_discovery_b
        .get_known_services()
        .await
        .into_iter()
        .map(|info| {
            (
                info.unescaped_instance_name(),
                info.get_socket_addresses().next().unwrap(),
            )
        })
        .collect();

    let from_c: HashMap<String, SocketAddr> = service_discovery_c
        .get_known_services()
        .await
        .into_iter()
        .map(|info| {
            (
                info.unescaped_instance_name(),
                info.get_socket_addresses().next().unwrap(),
            )
        })
        .collect();

    assert_eq!(2, from_a.len());
    assert_eq!(2, from_b.len());
    assert_eq!(2, from_c.len());

    assert_eq!(
        &("[fe80::26fc:f50f:6755:7d68]:8080".parse::<SocketAddr>()?),
        &from_a["b"]
    );
    assert_eq!(
        &("[fe80::26fc:f50f:6755:7d69]:8080".parse::<SocketAddr>()?),
        &from_a["c"]
    );

    assert_eq!(
        &("[fe80::26fc:f50f:6755:7d67]:8080".parse::<SocketAddr>()?),
        &from_b["a"]
    );
    assert_eq!(
        &("[fe80::26fc:f50f:6755:7d69]:8080".parse::<SocketAddr>()?),
        &from_b["c"]
    );

    assert_eq!(
        &("[fe80::26fc:f50f:6755:7d67]:8080".parse::<SocketAddr>()?),
        &from_c["a"]
    );
    assert_eq!(
        &("[fe80::26fc:f50f:6755:7d68]:8080".parse::<SocketAddr>()?),
        &from_c["b"]
    );
    Ok(())
}
