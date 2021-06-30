use simple_dns::Name;
use simple_mdns::{
    conversion_utils::socket_addr_to_srv_and_address, ServiceDiscovery, SimpleMdnsResponder,
};
use std::{net::SocketAddr, time::Duration};

fn get_oneshot_responder(srv_name: Name<'static>) -> SimpleMdnsResponder {
    let mut responder = SimpleMdnsResponder::default();
    let (r1, r2) =
        socket_addr_to_srv_and_address(&srv_name, "192.168.1.3:8080".parse().unwrap(), 0);
    responder.add_resource(r1);
    responder.add_resource(r2);

    responder
}

#[test]
fn service_discovery_can_find_services() {
    let _responder = get_oneshot_responder(Name::new_unchecked("_srv3._tcp.com"));
    std::thread::sleep(Duration::from_millis(500));

    let mut service_discovery_a = ServiceDiscovery::new("_srv3._tcp.com", 500).unwrap();

    service_discovery_a.add_socket_address("192.168.1.2:8080".parse().unwrap());

    std::thread::sleep(Duration::from_secs(1));

    let services_a = service_discovery_a.get_known_services();

    assert_eq!(1, services_a.len());

    assert_eq!(
        &("192.168.1.3:8080".parse::<SocketAddr>().unwrap()),
        &services_a[0]
    );
}
