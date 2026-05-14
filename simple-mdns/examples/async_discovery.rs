//! Async ServiceDiscovery example.
//!
//! Registers this process as `_example._tcp.local` and prints every peer
//! discovered on the same network until Ctrl+C is pressed.
//!
//! Run with:
//!   cargo run --example async_discovery --features async-tokio

use simple_mdns::{async_discovery::ServiceDiscovery, InstanceInformation, NetworkScope};

#[tokio::main]
async fn main() {
    stderrlog::new().verbosity(5).init().ok();

    let (tx, mut rx) = tokio::sync::mpsc::channel(32);

    // Replace the socket address with your machine's actual IP and the port
    // your service listens on.  The crate does not discover your IP for you.
    let _discovery = ServiceDiscovery::new_with_scope(
        InstanceInformation::new("my-instance".into())
            .with_socket_address("127.0.0.1:8080".parse().unwrap()),
        "_example._tcp.local",
        60,
        Some(tx),
        NetworkScope::V4,
    )
    .expect("Failed to create ServiceDiscovery");

    println!("Service discovery running — press Ctrl+C to exit");

    loop {
        tokio::select! {
            Some(instance) = rx.recv() => {
                println!("Discovered: {instance:?}");
            }
            _ = tokio::signal::ctrl_c() => {
                println!("Shutting down");
                break;
            }
        }
    }
}
