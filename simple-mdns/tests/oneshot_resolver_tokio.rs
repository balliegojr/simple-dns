#![cfg(feature = "async-tokio")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use simple_dns::Name;
use simple_mdns::async_discovery::{OneShotMdnsResolver, SimpleMdnsResponder};

use simple_mdns::conversion_utils::socket_addr_to_srv_and_address;

async fn get_oneshot_responder(srv_name: Name<'static>) -> SimpleMdnsResponder {
    let mut responder = SimpleMdnsResponder::default();
    let (r1, r2) = socket_addr_to_srv_and_address(
        &srv_name,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
        0,
    );
    responder.add_resource(r1).await;
    responder.add_resource(r2).await;
    responder
}

#[tokio::test]
async fn one_shot_resolver_address_query() {
    let _responder = get_oneshot_responder(Name::new_unchecked("_async._tcp.local")).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut resolver = OneShotMdnsResolver::new().expect("Failed to create resolver");
    resolver.set_unicast_response(false);
    let answer = resolver.query_service_address("_async._tcp.local").await;

    assert!(answer.is_ok());
    let answer = answer.unwrap();
    assert!(answer.is_some());
    assert_eq!(Ipv4Addr::LOCALHOST, answer.unwrap());

    let answer = resolver
        .query_service_address_and_port("_async._tcp.local")
        .await;
    assert!(answer.is_ok());
    let answer = answer.unwrap();
    assert!(answer.is_some());
    assert_eq!(
        SocketAddr::from_str("127.0.0.1:8080").unwrap(),
        answer.unwrap()
    )
}

#[tokio::test]
async fn one_shot_resolver_timeout() {
    let resolver = OneShotMdnsResolver::new().expect("Failed to create resolver");
    let answer = resolver
        .query_service_address("_async_miss._tcp.local")
        .await;
    assert!(answer.is_ok());
    let answer = answer.unwrap();
    assert!(answer.is_none());
}
