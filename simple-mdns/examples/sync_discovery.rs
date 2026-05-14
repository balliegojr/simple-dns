//! Sync ServiceDiscovery example.
//!
//! Registers this process as `_example._tcp.local` and prints every peer
//! discovered on the same network until Ctrl+C is pressed.
//!
//! Run with:
//!   cargo run --example sync_discovery --features sync

use std::sync::mpsc;

use simple_mdns::{
    sync_discovery::ServiceDiscovery, InstanceInformation, NetworkScope,
};

fn main() {
    stderrlog::new().verbosity(2).init().ok();

    let (tx, rx) = mpsc::channel();

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

    for instance in rx {
        println!("Discovered: {instance:?}");
    }
}
