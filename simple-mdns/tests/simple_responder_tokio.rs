#![cfg(feature = "async-tokio")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use simple_dns::Name;
use simple_mdns::async_discovery::{OneShotMdnsResolver, SimpleMdnsResponder};
use simple_mdns::conversion_utils::socket_addr_to_srv_and_address;
use simple_mdns::NetworkScope;

fn make_resolver() -> OneShotMdnsResolver {
    let mut resolver = OneShotMdnsResolver::new().expect("Failed to create resolver");
    resolver.set_unicast_response(false);
    resolver.set_query_timeout(Duration::from_millis(500));
    resolver
}

#[tokio::test]
async fn responder_shuts_down_on_signal() {
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let srv_name = Name::new_unchecked("_shutdown_test._tcp.local");
    let mut responder =
        SimpleMdnsResponder::new_with_scope(10, NetworkScope::V4, Some(shutdown_rx));

    let (r1, r2) = socket_addr_to_srv_and_address(
        &srv_name,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
        0,
    );
    responder.add_resource(r1).await;
    responder.add_resource(r2).await;

    tokio::time::sleep(Duration::from_millis(300)).await;

    let answer = make_resolver()
        .query_service_address("_shutdown_test._tcp.local")
        .await
        .expect("Query failed");
    assert!(answer.is_some(), "responder should be active before shutdown");

    shutdown_tx.send(()).expect("Failed to send shutdown signal");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let answer = make_resolver()
        .query_service_address("_shutdown_test._tcp.local")
        .await
        .expect("Query failed");
    assert!(answer.is_none(), "responder should not reply after shutdown");
}
