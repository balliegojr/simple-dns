#![cfg(feature = "sync")]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    thread,
    time::Duration,
};

use simple_dns::Name;
use simple_mdns::{
    conversion_utils::socket_addr_to_srv_and_address,
    sync_discovery::{OneShotMdnsResolver, SimpleMdnsResponder},
};

fn get_oneshot_responder(srv_name: Name<'static>) -> SimpleMdnsResponder {
    let mut responder = SimpleMdnsResponder::default();
    let (r1, r2) = socket_addr_to_srv_and_address(
        &srv_name,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
        0,
    );
    responder.add_resource(r1);
    responder.add_resource(r2);
    responder
}

#[test]
fn one_shot_resolver_address_query() {
    let _responder = get_oneshot_responder(Name::new_unchecked("_sync._tcp.local"));
    thread::sleep(Duration::from_millis(500));

    let mut resolver = OneShotMdnsResolver::new().expect("Failed to create resolver");
    resolver.set_unicast_response(false);
    let answer = resolver.query_service_address("_sync._tcp.local");

    assert!(answer.is_ok());
    let answer = answer.unwrap();
    assert!(answer.is_some());
    assert_eq!(Ipv4Addr::LOCALHOST, answer.unwrap());

    let answer = resolver.query_service_address_and_port("_sync._tcp.local");
    assert!(answer.is_ok());
    let answer = answer.unwrap();
    assert!(answer.is_some());
    assert_eq!(
        SocketAddr::from_str("127.0.0.1:8080").unwrap(),
        answer.unwrap()
    )
}

#[test]
fn one_shot_resolver_timeout() {
    let resolver = OneShotMdnsResolver::new().expect("Failed to create resolver");
    let answer = resolver.query_service_address("_sync_miss._tcp.local");
    assert!(answer.is_ok());
    let answer = answer.unwrap();
    assert!(answer.is_none());
}
